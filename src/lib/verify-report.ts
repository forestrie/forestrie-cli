import type {
  ReceiptVerifyResult,
  ReceiptVerifyStage,
} from "@forestrie/receipt-verify";
import type { AnchorCheck } from "./verify-anchored.js";

/**
 * Result → report shaping for `forestrie verify` (FOR-347). Pure — the
 * `--json` shape emitted from here is a contract for demo scripting.
 */

/** Verification pipeline in narration order (ADR-0045 layers A–C). */
export const VERIFY_STAGES: readonly ReceiptVerifyStage[] = [
  "parse",
  "signature",
  "inclusion",
  "binding",
];

/** One line per stage: what the audience sees at every demo step. */
export const STAGE_NARRATION: Record<ReceiptVerifyStage, string> = {
  parse: "receipt COSE decodes; genesis trust root loads (ES256)",
  signature: "checkpoint signature verifies under the genesis trust key",
  inclusion: "proof path recomputes the checkpoint peak",
  binding: "leaf binds the grant commitment at the receipt idtimestamp",
};

export type StageStatus = "ok" | "failed" | "skipped";

export type StageRow = {
  stage: ReceiptVerifyStage;
  status: StageStatus;
  reason?: string;
};

/**
 * Expand the library's `{ok, stage, reason}` into one row per stage:
 * on success all four pass; on failure the reported stage failed, earlier
 * stages passed, later stages were not reached.
 */
export function stageRows(result: ReceiptVerifyResult): StageRow[] {
  if (result.ok) {
    return VERIFY_STAGES.map((stage) => ({ stage, status: "ok" }));
  }
  const failedAt = VERIFY_STAGES.indexOf(result.stage);
  return VERIFY_STAGES.map((stage, i) => {
    if (i < failedAt) return { stage, status: "ok" as const };
    if (i === failedAt) {
      return {
        stage,
        status: "failed" as const,
        reason: result.reason ?? "unknown",
      };
    }
    return { stage, status: "skipped" as const };
  });
}

/** `--json` anchor block (chain mode only). Sizes are decimal strings. */
export type AnchorReport = {
  univocity: string;
  logId: string;
  anchored: boolean;
  anchoredSize: string;
  peakCount: number;
  matchedPeak: number | null;
  reason?: string;
};

/** `--json` report on stdout — stable shape for demo scripting. */
export type VerifyReport = {
  command: "verify";
  mode: "offline" | "chain-anchored";
  ok: boolean;
  stage: ReceiptVerifyStage;
  reason?: string;
  stages: StageRow[];
  anchor?: AnchorReport;
};

export function buildVerifyReport(opts: {
  ok: boolean;
  result: ReceiptVerifyResult;
  mode: "offline" | "chain-anchored";
  anchor?: AnchorCheck | undefined;
  univocity?: string | undefined;
  logId?: string | undefined;
}): VerifyReport {
  const report: VerifyReport = {
    command: "verify",
    mode: opts.mode,
    ok: opts.ok,
    stage: opts.result.stage,
    stages: stageRows(opts.result),
  };
  if (opts.result.reason !== undefined) {
    report.reason = opts.result.reason;
  }
  if (opts.anchor !== undefined) {
    const anchor: AnchorReport = {
      univocity: opts.univocity ?? "",
      logId: opts.logId ?? "",
      anchored: opts.anchor.anchored,
      anchoredSize: opts.anchor.size.toString(),
      peakCount: opts.anchor.accumulator.length,
      matchedPeak: opts.anchor.matchedPeak,
    };
    if (opts.anchor.reason !== undefined) {
      anchor.reason = opts.anchor.reason;
    }
    report.anchor = anchor;
  }
  return report;
}
