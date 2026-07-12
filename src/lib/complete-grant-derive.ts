/**
 * FOR-344 offline grant completion. `register-grant` gets the receipt +
 * idtimestamp from the operator (register → 303 → poll → receipt);
 * `complete-grant` instead DERIVES them locally from the checkpoint + massif,
 * then runs the exact same merge (`completeGrantBase64`). Proving grants are
 * *derivable from log data*, not operator-issued.
 *
 * Pure over bytes: decode the grant, locate its leaf in the massif by content
 * hash (`findGrantLeafInMassif` — recovers mmrIndex + the sequenced
 * idtimestamp), rebuild the leaf's inclusion receipt against the checkpoint's
 * pre-signed peak (`deriveCheckpointReceipt`), and attach receipt (396) +
 * idtimestamp (−65537) into the grant's unprotected headers with NO re-signing.
 * No network, no key.
 */
import {
  decodeForestrieGrantCose,
  findGrantLeafInMassif,
  MissingIndexError,
} from "@forestrie/receipt-verify";
import { base64ToBytes } from "@forestrie/grant-builder";
import { completeGrantBase64 } from "./register-grant-complete.js";
import {
  CreateReceiptFailure,
  deriveCheckpointReceipt,
} from "./create-receipt-derive.js";

/** Where offline completion broke. */
export type CompleteGrantStage = "decode" | "locate" | "parse" | "derive";

/** Stable snake_case reasons — the `--json` error shape is a contract. */
export type CompleteGrantReason =
  | "grant_decode_failed"
  | "grant_leaf_not_found"
  | "massif_missing_index"
  | "idtimestamp_unresolved"
  // Passed through from the receipt derivation (create-receipt taxonomy).
  | "massif_parse_failed"
  | "checkpoint_parse_failed"
  | "checkpoint_missing_peak_receipts"
  | "checkpoint_missing_sealed_size"
  | "checkpoint_does_not_cover_leaf"
  | "leaf_not_in_massif"
  | "derive_failed";

export class CompleteGrantFailure extends Error {
  readonly stage: CompleteGrantStage;
  readonly reason: CompleteGrantReason;

  constructor(
    stage: CompleteGrantStage,
    reason: CompleteGrantReason,
    message: string,
  ) {
    super(message);
    this.name = "CompleteGrantFailure";
    this.stage = stage;
    this.reason = reason;
  }
}

/** Which input supplied the entry-id idtimestamp half. */
export type IdtimestampSource = "massif" | "override" | "grant";

export type DeriveCompletedGrantInput = {
  /** Registered (uncompleted) grant, Forestrie-Grant header base64 (trimmed). */
  grantBase64: string;
  massifBytes: Uint8Array;
  checkpointBytes: Uint8Array;
  /** 8-byte idtimestamp override (`--idtimestamp`), used only as a fallback. */
  idtimestampOverride?: Uint8Array | undefined;
};

export type CompletedGrant = {
  /** Completed grant, Forestrie-Grant header base64. */
  completedBase64: string;
  /** Permanent entry id (`idtimestamp_be8 || mmrIndex_be8`), 32 hex chars. */
  entryIdHex: string;
  mmrIndex: bigint;
  idtimestampBe8: Uint8Array;
  idtimestampSource: IdtimestampSource;
  receiptBytes: number;
  proofLength: number;
  peakIndex: number;
  peakCount: number;
  sealedSize: bigint;
  certCopied: boolean;
};

function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

function mmrIndexToBe8Hex(mmrIndex: bigint): string {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, mmrIndex & 0xffffffffffffffffn, false);
  return bytesToHex(out);
}

function isAllZero(bytes: Uint8Array): boolean {
  for (const b of bytes) if (b !== 0) return false;
  return true;
}

/**
 * Resolve the idtimestamp that goes into the entry id. The massif leaf key is
 * ground truth — it is exactly what the sequencer committed, so verification
 * (`leafHash = H(idtimestamp || contentHash)`) only reproduces the anchored
 * leaf when this value is used. `--idtimestamp` / an already-embedded grant
 * idtimestamp are fallbacks for the (unusual) case where the massif index
 * region did not record the key.
 */
function resolveIdtimestamp(
  fromMassif: Uint8Array,
  override: Uint8Array | undefined,
  fromGrant: Uint8Array,
): { idtimestampBe8: Uint8Array; source: IdtimestampSource } {
  if (!isAllZero(fromMassif)) {
    return { idtimestampBe8: fromMassif, source: "massif" };
  }
  if (override !== undefined && !isAllZero(override)) {
    return { idtimestampBe8: override, source: "override" };
  }
  if (!isAllZero(fromGrant)) {
    return { idtimestampBe8: fromGrant, source: "grant" };
  }
  throw new CompleteGrantFailure(
    "parse",
    "idtimestamp_unresolved",
    "could not resolve the leaf idtimestamp from the massif, --idtimestamp, " +
      "or the grant — supply --idtimestamp",
  );
}

/**
 * Derive the completed grant from local artefacts. Throws
 * {@link CompleteGrantFailure} with a stable stage + reason on any failure.
 */
export async function deriveCompletedGrant(
  input: DeriveCompletedGrantInput,
): Promise<CompletedGrant> {
  // 1. Decode the signed grant statement into its Grant payload (+ any
  //    already-embedded idtimestamp).
  let grant: ReturnType<typeof decodeForestrieGrantCose>["grant"];
  let grantIdtimestampBe8: Uint8Array;
  try {
    ({ grant, idtimestampBe8: grantIdtimestampBe8 } = decodeForestrieGrantCose(
      base64ToBytes(input.grantBase64),
    ));
  } catch (err) {
    throw new CompleteGrantFailure(
      "decode",
      "grant_decode_failed",
      `not a Forestrie-Grant COSE Sign1: ${errorMessage(err)}`,
    );
  }

  // 2. Locate the grant's leaf in the massif by its commitment hash — recovers
  //    both the mmrIndex and the sequenced idtimestamp, offline.
  let located: Awaited<ReturnType<typeof findGrantLeafInMassif>>;
  try {
    located = await findGrantLeafInMassif(input.massifBytes, grant);
  } catch (err) {
    if (err instanceof MissingIndexError) {
      throw new CompleteGrantFailure(
        "locate",
        "massif_missing_index",
        `massif has no index region to search: ${err.message}`,
      );
    }
    throw new CompleteGrantFailure("locate", "grant_leaf_not_found", errorMessage(err));
  }
  if (located === null) {
    throw new CompleteGrantFailure(
      "locate",
      "grant_leaf_not_found",
      "this grant's commitment hash is not a leaf in the supplied massif — " +
        "wrong massif, or the grant is not sequenced yet",
    );
  }

  const { idtimestampBe8, source } = resolveIdtimestamp(
    located.idtimestampBe8,
    input.idtimestampOverride,
    grantIdtimestampBe8,
  );

  // 3. Rebuild the leaf's inclusion receipt against the checkpoint's pre-signed
  //    peak (identical derivation to `create-receipt`).
  let derived: Awaited<ReturnType<typeof deriveCheckpointReceipt>>;
  try {
    derived = await deriveCheckpointReceipt({
      massifBytes: input.massifBytes,
      checkpointBytes: input.checkpointBytes,
      mmrIndex: located.mmrIndex,
    });
  } catch (err) {
    if (err instanceof CreateReceiptFailure) {
      // Reuse the create-receipt reason taxonomy verbatim (it is a subset of
      // CompleteGrantReason).
      throw new CompleteGrantFailure(
        err.stage === "parse" ? "parse" : "derive",
        err.reason,
        err.message,
      );
    }
    throw new CompleteGrantFailure("derive", "derive_failed", errorMessage(err));
  }

  // 4. Merge receipt (396) + idtimestamp (−65537) into the grant's unprotected
  //    headers — no re-signing — and emit the completed grant base64.
  const entryIdHex = bytesToHex(idtimestampBe8) + mmrIndexToBe8Hex(located.mmrIndex);
  const completedBase64 = completeGrantBase64(
    input.grantBase64,
    derived.receiptCbor,
    entryIdHex,
  );

  return {
    completedBase64,
    entryIdHex,
    mmrIndex: located.mmrIndex,
    idtimestampBe8,
    idtimestampSource: source,
    receiptBytes: derived.receiptCbor.length,
    proofLength: derived.details.proofLength,
    peakIndex: derived.details.peakIndex,
    peakCount: derived.details.peakCount,
    sealedSize: derived.details.sealedSize,
    certCopied: derived.details.certCopied,
  };
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
