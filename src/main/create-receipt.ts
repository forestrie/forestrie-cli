import { writeFileSync } from "node:fs";
import type { Out } from "@forestrie/cli-kit/reporting";
import type { CreateReceiptOptions } from "../options/create-receipt.js";
import {
  CreateReceiptFailure,
  deriveCheckpointReceipt,
  type CreateReceiptReason,
  type DerivedReceipt,
} from "../lib/create-receipt-derive.js";
import {
  loadCreateReceiptArtifacts,
  type CreateReceiptArtifacts,
} from "../lib/create-receipt-inputs.js";

/** Where an operational error broke the run. */
export type CreateReceiptErrorStage = "input" | "parse" | "derive";

/**
 * `--json` operational-error shape on stdout — stable stage + reason
 * tokens (input load/decode; artefact parse; proof/receipt derivation,
 * including `leaf_not_in_massif` / `checkpoint_does_not_cover_leaf`).
 */
export type CreateReceiptErrorReport = {
  error:
    | "create_receipt_input_failed"
    | "create_receipt_parse_failed"
    | "create_receipt_derive_failed";
  command: "create-receipt";
  stage: CreateReceiptErrorStage;
  reason?: CreateReceiptReason;
  message: string;
};

/** `--json` chain-mode stub shape — phase 2 of plan-2607-15. */
export type CreateReceiptNotImplementedReport = {
  error: "not_implemented";
  command: "create-receipt";
  mode: "chain";
  issue: "FOR-345";
  message: string;
};

/** Structured `--json` success report — the shape is a contract. */
export type CreateReceiptReport = {
  command: "create-receipt";
  anchor: "checkpoint";
  leaf: {
    mmrIndex: string;
    source: "mmr-index" | "entry-id";
    entryId?: string;
    idtimestamp?: string;
  };
  massif: {
    massifIndex: string;
    massifHeight: number;
    firstIndex: string;
    lastIndex: string;
  };
  checkpoint: {
    sealedSize: string;
    peakCount: number;
  };
  proof: {
    length: number;
    peakIndex: number;
    peakMMRIndex: string;
  };
  certCopied: boolean;
  receiptBytes: number;
  /** Output path, when `--out` was given. */
  out?: string;
  /** Base64 receipt bytes, when no `--out` (JSON owns stdout). */
  receiptB64?: string;
};

const ERROR_CODES: Record<
  CreateReceiptErrorStage,
  CreateReceiptErrorReport["error"]
> = {
  input: "create_receipt_input_failed",
  parse: "create_receipt_parse_failed",
  derive: "create_receipt_derive_failed",
};

/** Structured envelope under `--json`; one clean line on stderr otherwise. */
function reportRunError(
  out: Out,
  options: CreateReceiptOptions,
  stage: CreateReceiptErrorStage,
  err: unknown,
): void {
  const message = err instanceof Error ? err.message : String(err);
  const reason = err instanceof CreateReceiptFailure ? err.reason : undefined;
  if (options.json) {
    const report: CreateReceiptErrorReport = {
      error: ERROR_CODES[stage],
      command: "create-receipt",
      stage,
      ...(reason !== undefined ? { reason } : {}),
      message,
    };
    out.out(JSON.stringify(report, null, 2));
  } else {
    out.warn("forestrie create-receipt: %s: %s", stage, message);
  }
  process.exitCode = 1;
}

/**
 * Chain-anchored mode is phase 2 of plan-2607-15 (report-only peak check
 * against the on-chain accumulator via `computeAccumulatorPeak` + the
 * verify-anchored logState plumbing). The arg surface is real; the
 * behaviour is a structured stub until then.
 */
function reportChainModeNotImplemented(
  out: Out,
  options: CreateReceiptOptions,
): void {
  const message =
    "forestrie create-receipt: chain-anchored mode (--univocity) is not " +
    "implemented yet — lands with plan-2607-15 phase 2 (FOR-345); use " +
    "--checkpoint for offline receipt derivation";
  if (options.json) {
    const report: CreateReceiptNotImplementedReport = {
      error: "not_implemented",
      command: "create-receipt",
      mode: "chain",
      issue: "FOR-345",
      message,
    };
    out.out(JSON.stringify(report, null, 2));
  } else {
    out.warn(message);
  }
  process.exitCode = 1;
}

/**
 * FOR-345 (phase 1, plan-2607-15 §6): self-serve COSE receipt from local
 * artifacts — rebuild the leaf→peak inclusion path from the massif blob
 * and attach it to the checkpoint's pre-signed peak receipt
 * (`buildReceiptOffline`). No network, no key, no operator API call; the
 * result is verify-equivalent with an API-issued receipt. Receipt bytes
 * go to `--out`, or raw to stdout — except under `--json` without
 * `--out`, where they ride base64 inside the report (JSON owns stdout).
 */
export async function runCreateReceipt(
  out: Out,
  options: CreateReceiptOptions,
): Promise<void> {
  if (options.anchor === "chain") {
    reportChainModeNotImplemented(out, options);
    return;
  }

  let artifacts: CreateReceiptArtifacts;
  try {
    artifacts = loadCreateReceiptArtifacts(options);
  } catch (err) {
    reportRunError(out, options, "input", err);
    return;
  }

  let derived: DerivedReceipt;
  try {
    derived = deriveCheckpointReceipt({
      massifBytes: artifacts.massifBytes,
      // Checkpoint mode: options parsing guarantees --checkpoint.
      checkpointBytes: artifacts.checkpointBytes!,
      mmrIndex: artifacts.leaf.mmrIndex,
    });
  } catch (err) {
    const stage = err instanceof CreateReceiptFailure ? err.stage : "derive";
    reportRunError(out, options, stage, err);
    return;
  }

  const { receiptCbor, details } = derived;
  try {
    if (options.out !== undefined) {
      writeFileSync(options.out, receiptCbor);
    }
  } catch (err) {
    reportRunError(out, options, "input", err);
    return;
  }

  const leaf = artifacts.leaf;
  if (options.json) {
    const report: CreateReceiptReport = {
      command: "create-receipt",
      anchor: "checkpoint",
      leaf: {
        mmrIndex: leaf.mmrIndex.toString(10),
        source: leaf.source,
        ...(leaf.entryId !== undefined ? { entryId: leaf.entryId } : {}),
        ...(leaf.idtimestamp !== undefined
          ? { idtimestamp: leaf.idtimestamp.toString(10) }
          : {}),
      },
      massif: {
        massifIndex: details.massifIndex.toString(10),
        massifHeight: details.massifHeight,
        firstIndex: details.firstIndex.toString(10),
        lastIndex: details.lastIndex.toString(10),
      },
      checkpoint: {
        sealedSize: details.sealedSize.toString(10),
        peakCount: details.peakCount,
      },
      proof: {
        length: details.proofLength,
        peakIndex: details.peakIndex,
        peakMMRIndex: details.peakMMRIndex.toString(10),
      },
      certCopied: details.certCopied,
      receiptBytes: receiptCbor.length,
      ...(options.out !== undefined
        ? { out: options.out }
        : { receiptB64: Buffer.from(receiptCbor).toString("base64") }),
    };
    out.out(JSON.stringify(report, null, 2));
    return;
  }

  if (options.out === undefined) {
    // Raw CBOR to stdout (pipeable); the narration stays on stderr.
    writeFileSync(1, receiptCbor);
  }
  out.print(
    "create-receipt: massif     — index %s (height %d, mmr indexes %s..%s)",
    details.massifIndex.toString(10),
    details.massifHeight,
    details.firstIndex.toString(10),
    details.lastIndex.toString(10),
  );
  out.print(
    "create-receipt: leaf       — mmrIndex %s (from --%s)",
    leaf.mmrIndex.toString(10),
    leaf.source,
  );
  out.print(
    "create-receipt: checkpoint — sealed size %s, %d peak(s)",
    details.sealedSize.toString(10),
    details.peakCount,
  );
  out.print(
    "create-receipt: proof      — %d node(s) to peak %d/%d (mmrIndex %s)",
    details.proofLength,
    details.peakIndex + 1,
    details.peakCount,
    details.peakMMRIndex.toString(10),
  );
  out.print(
    "create-receipt: cert       — delegation cert copied: %s",
    details.certCopied ? "yes" : "no",
  );
  out.print(
    "create-receipt: receipt    — %d bytes -> %s",
    receiptCbor.length,
    options.out ?? "stdout",
  );
}
