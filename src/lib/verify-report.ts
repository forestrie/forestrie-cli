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
  binding: "leaf commits the payload (SHA-256) at the receipt idtimestamp",
};

export type StageStatus = "ok" | "failed" | "skipped";

export type StageRow = {
  stage: ReceiptVerifyStage;
  status: StageStatus;
  reason?: string;
};

/**
 * Anchor-only chain verification (FOR-297 approach C): the checkpoint was
 * sealed under a delegation the offline verifier cannot resolve (a child
 * log's per-log delegation does not chain to the root genesis), so the
 * signature stage is deliberately NOT evaluated — trust is externalised to
 * the on-chain accumulator. Inclusion and binding hold by construction: the
 * peak is recomputed locally from `leaf(payload, idtimestamp)` + the
 * receipt's proof path, so an on-chain match proves both.
 */
export const SIGNATURE_EXTERNALISED_REASON =
  "delegated seal not root-resolvable offline; trust externalised to the on-chain accumulator";

export function anchorOnlyStageRows(): StageRow[] {
  return [
    { stage: "parse", status: "ok" },
    {
      stage: "signature",
      status: "skipped",
      reason: SIGNATURE_EXTERNALISED_REASON,
    },
    { stage: "inclusion", status: "ok" },
    { stage: "binding", status: "ok" },
  ];
}

/**
 * Expand the library's `{ok, stage, reason}` into one row per stage:
 * on success all four pass; on failure the reported stage failed, earlier
 * stages passed, later stages were not reached.
 *
 * A stage this CLI does not know (a future `@forestrie/receipt-verify`
 * addition) still renders explicitly as the failed row — degrading it to
 * four silent "skipped" rows would hide the failure (F3, plan-2607-14
 * W1.3). We cannot order an unknown stage among the known ones, so the
 * known stages read "skipped" (not evaluated by this CLI's knowledge) and
 * the unknown stage carries the failure.
 */
export function stageRows(result: ReceiptVerifyResult): StageRow[] {
  if (result.ok) {
    return VERIFY_STAGES.map((stage) => ({ stage, status: "ok" }));
  }
  const failedAt = VERIFY_STAGES.indexOf(result.stage);
  if (failedAt === -1) {
    return [
      ...VERIFY_STAGES.map((stage) => ({
        stage,
        status: "skipped" as const,
      })),
      {
        stage: result.stage,
        status: "failed" as const,
        reason: result.reason ?? "unknown",
      },
    ];
  }
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
  /** Anchor-only mode: rows that reflect the skipped signature stage. */
  stagesOverride?: StageRow[] | undefined;
}): VerifyReport {
  const report: VerifyReport = {
    command: "verify",
    mode: opts.mode,
    ok: opts.ok,
    stage: opts.result.stage,
    stages: opts.stagesOverride ?? stageRows(opts.result),
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
