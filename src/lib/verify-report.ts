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
 * log's per-log delegation does not chain to the root genesis). The
 * signature stage still reports **ok** — not because the COSE check re-ran
 * locally, but because a match against the on-chain accumulator *implies*
 * it: univocity only accepts a checkpoint whose signature verifies under
 * the log's live delegation, whose publish grant's inclusion is re-proven
 * against the parent's on-chain state on EVERY publish, and whose
 * accumulator is consistency-gated against the previously published state.
 * So if the locally-recomputed peak (from `leaf(payload, idtimestamp)` +
 * the receipt's proof path) appears in the accumulator, the publishing
 * signature was valid and a fresh grant chain to the bootstrap existed at
 * publish time — the anchor match combines inclusion, binding, signature
 * validity AND a split-view check (status-2607-09 D2).
 *
 * Enforcement cited from `_Univocity.sol publishCheckpoint` @ univocity
 * ea410d5a90e4c2337fc1dec288d660551daf36ab:
 * - signature under the live delegation: `_verifyCheckpointSignature`,
 *   src/contracts/_Univocity.sol#L199-L208 (reverts on failure)
 * - grant inclusion re-verified each publish (rules 1–3):
 *   `_applyInclusionGrant`, src/contracts/_Univocity.sol#L211-L219
 * - grant bounds (rule 4): src/contracts/_Univocity.sol#L181-L188
 * - consistency gating: `verifyConsistencyProofChain`,
 *   src/contracts/_Univocity.sol#L189-L193
 */
export const SIGNATURE_ANCHORED_REASON =
  "verified against accumulator from chain — signature enforced by univocity at publish";

export function anchorOnlyStageRows(): StageRow[] {
  return [
    { stage: "parse", status: "ok" },
    {
      stage: "signature",
      status: "ok",
      reason: SIGNATURE_ANCHORED_REASON,
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
/**
 * Caller-known trust anchor (FOR-297 D1): the claim is verified under a key
 * the CALLER supplied out of band, not one derived from genesis — the output
 * must name that anchor so the two claims are never confusable. The known key
 * asserts the key↔log binding (its provenance is the only defence), gives no
 * grant-lifecycle visibility and no split-view protection.
 */
export const KNOWN_KEY_PARSE_REASON =
  "receipt COSE decodes; caller-known log key loads (ES256)";
export const KNOWN_KEY_SIGNATURE_REASON =
  "verifies under caller-known log key (not genesis-derived)";

/** Stage rows for a verify run anchored on `--known-log-key` (FOR-297 D1). */
export function knownKeyStageRows(result: ReceiptVerifyResult): StageRow[] {
  return stageRows(result).map((row) => {
    if (row.status !== "ok") return row;
    if (row.stage === "parse") return { ...row, reason: KNOWN_KEY_PARSE_REASON };
    if (row.stage === "signature")
      return { ...row, reason: KNOWN_KEY_SIGNATURE_REASON };
    return row;
  });
}

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

/** `--json` anchor block (chain / known-accumulator modes). Sizes are
 * decimal strings. */
export type AnchorReport = {
  univocity: string;
  logId: string;
  anchored: boolean;
  anchoredSize: string;
  peakCount: number;
  matchedPeak: number | null;
  reason?: string;
  /** known-accumulator anchors only: the audited chain read (FOR-297 D5). */
  blockNumber?: string;
  blockHash?: string;
  /** True when the match required proof-path extension via massif nodes. */
  extended?: boolean;
  /** Historical event-scan anchor (FOR-368): the peak matched a prior
   * CheckpointPublished accumulator; consistency-gated forward. */
  historical?: boolean;
  anchoredAtBlock?: string;
  txHash?: string;
};

export type VerifyMode = "offline" | "chain-anchored" | "accumulator-anchored";

/** `--json` report on stdout — stable shape for demo scripting. */
export type VerifyReport = {
  command: "verify";
  mode: VerifyMode;
  ok: boolean;
  stage: ReceiptVerifyStage;
  reason?: string;
  stages: StageRow[];
  anchor?: AnchorReport;
};

/** Extra anchor facts present only for known-accumulator checks. */
type SnapshotAnchorFacts = {
  blockNumber?: bigint;
  blockHashHex?: string;
  extended?: boolean;
};

export function buildVerifyReport(opts: {
  ok: boolean;
  result: ReceiptVerifyResult;
  mode: VerifyMode;
  anchor?: (AnchorCheck & SnapshotAnchorFacts) | undefined;
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
    if (opts.anchor.blockNumber !== undefined) {
      anchor.blockNumber = opts.anchor.blockNumber.toString();
      anchor.blockHash = `0x${opts.anchor.blockHashHex ?? ""}`;
      anchor.extended = opts.anchor.extended === true;
    }
    const historical = opts.anchor as {
      historical?: boolean;
      anchoredAtBlock?: bigint;
      txHash?: string;
    };
    if (historical.historical === true) {
      anchor.historical = true;
      if (historical.anchoredAtBlock !== undefined) {
        anchor.anchoredAtBlock = historical.anchoredAtBlock.toString();
      }
      if (historical.txHash !== undefined) {
        anchor.txHash = historical.txHash;
      }
    }
    report.anchor = anchor;
  }
  return report;
}
