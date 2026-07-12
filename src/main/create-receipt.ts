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
import {
  ChainVerifyFailure,
  verifyChainAnchored,
  type ChainVerifyOutcome,
  type ChainVerifyReason,
  type ChainVerifyResult,
} from "../lib/create-receipt-chain-verify.js";

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

/**
 * Exit codes for chain-anchored (`--univocity`) mode — one code per
 * verification outcome so scripts can branch without parsing text. Operational
 * errors (bad input / RPC) stay on the shared exit 1.
 */
export const CHAIN_EXIT_CODE: Record<ChainVerifyOutcome, number> = {
  verified: 0,
  not_yet_anchored: 2,
  coverage: 3,
  peak_mismatch: 4,
  // plan-2607-18 W3: `wrong_massif` (V2/V3) and `accumulator_short` (V4) split
  // out of the coverage / peak_mismatch buckets; next free codes in the 2/3/4
  // scheme. No collision with `verify`, which only uses 0/1.
  wrong_massif: 5,
  accumulator_short: 6,
};

/**
 * `--json` chain-mode success/verdict shape (report-only — NO signed
 * receipt; the selling point is receipt-free, on-chain verification). The
 * shape is a contract: `outcome` + the on-chain size, computed peak, matched
 * slot, and PASS/FAIL.
 */
export type CreateReceiptChainReport = {
  command: "create-receipt";
  anchor: "chain";
  /** True only when `outcome === "verified"`. */
  ok: boolean;
  outcome: ChainVerifyOutcome;
  univocity: string;
  logId: string;
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
  onchain: {
    size: string;
    peakCount: number;
  };
  peakCheck?: {
    proofLength: number;
    peakIndex: number;
    peakMMRIndex: string;
    computedPeakHex: string;
    onchainPeakHex: string;
    matched: boolean;
  };
};

/** `--json` chain-mode operational-error shape (bad massif / RPC). */
export type CreateReceiptChainErrorReport = {
  error: "create_receipt_chain_failed";
  command: "create-receipt";
  anchor: "chain";
  stage: "parse" | "chain";
  reason?: ChainVerifyReason;
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

/** One-line human explanation for each non-verified outcome. */
const CHAIN_OUTCOME_NARRATION: Record<ChainVerifyOutcome, string> = {
  verified: "computed peak matches the on-chain accumulator",
  not_yet_anchored:
    "leaf postdates the last on-chain anchor (mmrIndex >= on-chain size) — anchor lag",
  wrong_massif:
    "the massif blob is for a different massif than the leaf",
  coverage:
    "local massif blob does not hold nodes up to the on-chain size — fetch the covering massif",
  accumulator_short:
    "the on-chain accumulator holds fewer peaks than the leaf's proof selects — chain state is behind or truncated",
  peak_mismatch:
    "computed peak differs from the anchored peak — local node data does not match the chain",
};

/**
 * FOR-345 (phase 2, plan-2607-15 §3/§6): chain-anchored, REPORT-ONLY
 * verification. No `.sth`, no signed receipt — the selling point is
 * receipt-free verification, because the checkpoint signature was already
 * enforced on-chain at publish. Reads `logState(bytes32)`, rebuilds the
 * leaf's inclusion path at the on-chain size, and compares the computed peak
 * with `accumulator[peakIndex]`. There is NO exact-size constraint: any
 * `mmrIndex < size` works given local node data to that size.
 */
async function runChainAnchored(
  out: Out,
  options: CreateReceiptOptions,
  artifacts: CreateReceiptArtifacts,
): Promise<void> {
  let result: ChainVerifyResult;
  try {
    result = await verifyChainAnchored({
      massifBytes: artifacts.massifBytes,
      mmrIndex: artifacts.leaf.mmrIndex,
      // Options parsing guarantees these in chain mode.
      univocity: options.univocity!,
      logId: options.logId!,
      rpcUrl: options.rpcUrl!,
    });
  } catch (err) {
    reportChainRunError(out, options, err);
    return;
  }

  const leaf = artifacts.leaf;
  const ok = result.outcome === "verified";

  if (options.json) {
    const report: CreateReceiptChainReport = {
      command: "create-receipt",
      anchor: "chain",
      ok,
      outcome: result.outcome,
      univocity: options.univocity!,
      logId: options.logId!,
      leaf: {
        mmrIndex: leaf.mmrIndex.toString(10),
        source: leaf.source,
        ...(leaf.entryId !== undefined ? { entryId: leaf.entryId } : {}),
        ...(leaf.idtimestamp !== undefined
          ? { idtimestamp: leaf.idtimestamp.toString(10) }
          : {}),
      },
      massif: {
        massifIndex: result.massif.massifIndex.toString(10),
        massifHeight: result.massif.massifHeight,
        firstIndex: result.massif.firstIndex.toString(10),
        lastIndex: result.massif.lastIndex.toString(10),
      },
      onchain: {
        size: result.onchain.size.toString(10),
        peakCount: result.onchain.peakCount,
      },
      ...(result.peakCheck !== undefined
        ? {
            peakCheck: {
              proofLength: result.peakCheck.proofLength,
              peakIndex: result.peakCheck.peakIndex,
              peakMMRIndex: result.peakCheck.peakMMRIndex.toString(10),
              computedPeakHex: result.peakCheck.computedPeakHex,
              onchainPeakHex: result.peakCheck.onchainPeakHex,
              matched: result.peakCheck.matched,
            },
          }
        : {}),
    };
    out.out(JSON.stringify(report, null, 2));
    process.exitCode = CHAIN_EXIT_CODE[result.outcome];
    return;
  }

  // Human narration: on-chain size, computed peak, matched slot, PASS/FAIL.
  out.print(
    "create-receipt: on-chain   — %s @ log %s: size %s, %d peak(s)",
    options.univocity,
    options.logId,
    result.onchain.size.toString(10),
    result.onchain.peakCount,
  );
  out.print(
    "create-receipt: leaf       — mmrIndex %s (from --%s)",
    leaf.mmrIndex.toString(10),
    leaf.source,
  );
  if (result.peakCheck !== undefined) {
    out.print(
      "create-receipt: proof      — %d node(s) to peak %d/%d (mmrIndex %s)",
      result.peakCheck.proofLength,
      result.peakCheck.peakIndex + 1,
      result.onchain.peakCount,
      result.peakCheck.peakMMRIndex.toString(10),
    );
    out.print(
      "create-receipt: computed   — %s",
      result.peakCheck.computedPeakHex,
    );
    out.print(
      "create-receipt: on-chain   — %s (slot %d)",
      result.peakCheck.onchainPeakHex,
      result.peakCheck.peakIndex,
    );
  }
  if (ok) {
    out.out(
      `PASS: leaf verified against the on-chain accumulator (size ${result.onchain.size}, peak slot ${result.peakCheck!.peakIndex}) — no receipt needed`,
    );
  } else {
    // `wrong_massif` names the concrete mmrIndex the caller must supply the
    // massif for (plan-2607-18 W3: "supply the massif containing mmrIndex N").
    const detail =
      result.outcome === "wrong_massif"
        ? `${CHAIN_OUTCOME_NARRATION.wrong_massif} (supply the massif containing mmrIndex ${leaf.mmrIndex})`
        : CHAIN_OUTCOME_NARRATION[result.outcome];
    out.out(`FAIL: ${result.outcome} — ${detail}`);
  }
  process.exitCode = CHAIN_EXIT_CODE[result.outcome];
}

/** Structured envelope for chain-mode operational errors (input / RPC). */
function reportChainRunError(
  out: Out,
  options: CreateReceiptOptions,
  err: unknown,
): void {
  const message = err instanceof Error ? err.message : String(err);
  const stage = err instanceof ChainVerifyFailure ? err.stage : "chain";
  const reason = err instanceof ChainVerifyFailure ? err.reason : undefined;
  if (options.json) {
    const report: CreateReceiptChainErrorReport = {
      error: "create_receipt_chain_failed",
      command: "create-receipt",
      anchor: "chain",
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
 * FOR-345 self-serve receipt derivation, two anchor modes:
 *
 * - `checkpoint` (phase 1, plan-2607-15 §6): rebuild the leaf→peak inclusion
 *   path from the massif blob and attach it to the checkpoint's pre-signed
 *   peak receipt (`buildReceiptOffline`). No network, no key, no operator
 *   API call; the result is verify-equivalent with an API-issued receipt.
 *   Receipt bytes go to `--out`, or raw to stdout — except under `--json`
 *   without `--out`, where they ride base64 inside the report.
 * - `chain` (phase 2, plan-2607-15 §3): REPORT-ONLY verification of the
 *   computed peak against the on-chain accumulator (`--univocity`). No
 *   `.sth`, no signed receipt — its selling point is receipt-free
 *   verification. Distinct exit codes per outcome (see `CHAIN_EXIT_CODE`).
 */
export async function runCreateReceipt(
  out: Out,
  options: CreateReceiptOptions,
): Promise<void> {
  let artifacts: CreateReceiptArtifacts;
  try {
    artifacts = loadCreateReceiptArtifacts(options);
  } catch (err) {
    reportRunError(out, options, "input", err);
    return;
  }

  if (options.anchor === "chain") {
    await runChainAnchored(out, options, artifacts);
    return;
  }

  let derived: DerivedReceipt;
  try {
    derived = await deriveCheckpointReceipt({
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
