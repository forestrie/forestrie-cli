import {
  buildReceiptOffline,
  openMassifNodeStore,
  parseCheckpoint,
  parseReceipt,
  peakMMRIndexes,
  type MassifNodeStore,
  type ParsedCheckpoint,
} from "@forestrie/receipt-verify";

/**
 * Checkpoint-mode receipt derivation for `forestrie create-receipt`
 * (FOR-345 phase 1, plan-2607-15 §6): stage the
 * `@forestrie/receipt-verify` primitives so every failure is a typed
 * `CreateReceiptFailure` with a stable stage + reason, and collect the
 * narration facts (massif index, proof length, selected peak, cert copy)
 * alongside the receipt bytes. Pure over bytes — no network, no key.
 */

/** Where derivation broke: artefact parsing vs. proof/receipt assembly. */
export type CreateReceiptStage = "parse" | "derive";

/** Stable snake_case reasons — the `--json` error shape is a contract. */
export type CreateReceiptReason =
  | "massif_parse_failed"
  | "checkpoint_parse_failed"
  | "checkpoint_missing_peak_receipts"
  | "checkpoint_missing_sealed_size"
  | "checkpoint_does_not_cover_leaf"
  | "leaf_not_in_massif"
  | "derive_failed";

export class CreateReceiptFailure extends Error {
  readonly stage: CreateReceiptStage;
  readonly reason: CreateReceiptReason;

  constructor(
    stage: CreateReceiptStage,
    reason: CreateReceiptReason,
    message: string,
  ) {
    super(message);
    this.name = "CreateReceiptFailure";
    this.stage = stage;
    this.reason = reason;
  }
}

/** Facts for narration / `--json` reporting (bigints stay bigint here). */
export type DerivedReceiptDetails = {
  massifIndex: bigint;
  massifHeight: number;
  firstIndex: bigint;
  lastIndex: bigint;
  /** Sealed tree size the checkpoint signature commits to. */
  sealedSize: bigint;
  /** Inclusion path length (leaf → accumulator peak). */
  proofLength: number;
  /** Accumulator slot of the selected pre-signed peak receipt. */
  peakIndex: number;
  /** Total accumulator peaks at the sealed size. */
  peakCount: number;
  /** MMR index of the selected peak. */
  peakMMRIndex: bigint;
  /** Delegation cert (label 1000) copied from checkpoint to receipt. */
  certCopied: boolean;
};

export type DerivedReceipt = {
  receiptCbor: Uint8Array;
  details: DerivedReceiptDetails;
};

function fail(
  stage: CreateReceiptStage,
  reason: CreateReceiptReason,
  message: string,
): never {
  throw new CreateReceiptFailure(stage, reason, message);
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Derive a receipt for `mmrIndex` from local massif + checkpoint bytes.
 * The assembly itself is `buildReceiptOffline`; this wrapper pre-parses
 * both artefacts so the precondition failures the taxonomy names —
 * leaf-not-in-massif, checkpoint-doesn't-cover-leaf — are classified
 * before derivation, and the checkpoint parse feeds the narration.
 */
export function deriveCheckpointReceipt(input: {
  massifBytes: Uint8Array;
  checkpointBytes: Uint8Array;
  mmrIndex: bigint;
}): DerivedReceipt {
  const { massifBytes, checkpointBytes, mmrIndex } = input;

  let checkpoint: ParsedCheckpoint;
  try {
    checkpoint = parseCheckpoint(checkpointBytes);
  } catch (err) {
    fail(
      "parse",
      "checkpoint_parse_failed",
      `checkpoint is not a format-v3 COSE Sign1: ${errorMessage(err)}`,
    );
  }
  if (!checkpoint.peakReceipts) {
    fail(
      "parse",
      "checkpoint_missing_peak_receipts",
      "checkpoint carries no pre-signed peak receipts (label -65931)",
    );
  }
  const sealedSize = checkpoint.mmrSize;
  if (sealedSize === null || sealedSize <= 0n) {
    fail(
      "parse",
      "checkpoint_missing_sealed_size",
      "checkpoint carries no consistency proof (cannot determine sealed size)",
    );
  }

  let store: MassifNodeStore;
  try {
    store = openMassifNodeStore(massifBytes);
  } catch (err) {
    fail(
      "parse",
      "massif_parse_failed",
      `massif blob is not v2 layout: ${errorMessage(err)}`,
    );
  }

  if (mmrIndex >= sealedSize) {
    fail(
      "derive",
      "checkpoint_does_not_cover_leaf",
      `checkpoint does not cover the leaf: mmrIndex ${mmrIndex} >= sealed ` +
        `size ${sealedSize} — the entry postdates this checkpoint`,
    );
  }
  if (mmrIndex < store.firstIndex || mmrIndex > store.lastIndex) {
    fail(
      "derive",
      "leaf_not_in_massif",
      `leaf mmrIndex ${mmrIndex} is not in this massif blob (massif ` +
        `${store.massifIndex} holds mmr indexes ${store.firstIndex}..` +
        `${store.lastIndex})`,
    );
  }

  let receiptCbor: Uint8Array;
  try {
    receiptCbor = buildReceiptOffline({ massifBytes, checkpointBytes, mmrIndex });
  } catch (err) {
    fail("derive", "derive_failed", errorMessage(err));
  }

  // Narration facts. The proof length comes from the assembled receipt;
  // the selected peak is the first accumulator peak at or after the leaf
  // (peaks ascend by MMR index), matching the slot buildReceiptOffline
  // committed to via peak-index-for-leaf-proof.
  const proofLength = parseReceipt(receiptCbor).proof.path.length;
  const peaks = peakMMRIndexes(sealedSize - 1n);
  const peakIndex = peaks.findIndex((p) => p >= mmrIndex);
  const peakMMRIndex = peaks[peakIndex];
  if (peakIndex === -1 || peakMMRIndex === undefined) {
    // Unreachable given mmrIndex < sealedSize; keep the failure typed.
    fail("derive", "derive_failed", "no accumulator peak covers the leaf");
  }

  return {
    receiptCbor,
    details: {
      massifIndex: store.massifIndex,
      massifHeight: store.massifHeight,
      firstIndex: store.firstIndex,
      lastIndex: store.lastIndex,
      sealedSize,
      proofLength,
      peakIndex,
      peakCount: peaks.length,
      peakMMRIndex,
      certCopied: checkpoint.delegationCert !== null,
    },
  };
}
