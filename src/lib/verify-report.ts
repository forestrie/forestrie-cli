import type {
  ReceiptVerifyResult,
  ReceiptVerifyStage,
} from "@forestrie/receipt-verify";
import type {
  Ks256Attestation,
  Ks256AttestationUsage,
} from "@forestrie/receipt-verify";
import { ANCHOR_FOREST_MISMATCH, type AnchorCheck } from "./verify-anchored.js";

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

/**
 * `anchored`: the stage was not checked locally; its authority is the
 * on-chain accumulator (approach-C fallback). Never rendered as `ok`.
 */
export type StageStatus = "ok" | "failed" | "skipped" | "anchored";

export type StageRow = {
  stage: ReceiptVerifyStage;
  status: StageStatus;
  reason?: string;
};

/**
 * Anchor-only chain verification (FOR-297 approach C): the checkpoint was
 * sealed under a signature chain the offline verifier cannot resolve (a
 * child log's per-log delegation does not chain to the root genesis, or a
 * KS256 root it cannot recover). The signature stage is NOT reported `ok`:
 * it was not verified here. The row says `anchored` — the authority is the
 * on-chain accumulator. A match implies univocity accepted a checkpoint
 * whose receipt verified under the log's root key or a delegate the root
 * signed (including KS256 roots: ecrecover / ERC-1271), with the grant
 * inclusion re-proven and the accumulator consistency-gated at publish.
 * Univocity does NOT check delegation expiry, so neither does this path.
 * If the locally-recomputed peak (from `leaf(payload, idtimestamp)` + the
 * receipt's proof path) appears in the accumulator, inclusion and binding
 * hold and the split-view check is the contract's own state.
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
export function signatureAnchoredReason(offlineReason: string): string {
  return (
    `not verified offline (${offlineReason}); authority from the on-chain accumulator — ` +
    "univocity verified the checkpoint signature and delegation at publish " +
    "(expiry is not checked on-chain)"
  );
}

export function anchorOnlyStageRows(offlineReason: string): StageRow[] {
  return [
    { stage: "parse", status: "ok" },
    {
      stage: "signature",
      status: "anchored",
      reason: signatureAnchoredReason(offlineReason),
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

/**
 * KS256 root facts for the report: whether the root is a KS256 address, how
 * it was supplied, and every attestation given (list, in order) with the
 * receipt-verify usage accounting: each is either used (it carried a
 * certificate that does not verify by ecrecover alone) or unused with a
 * reason — never silently ignored.
 */
export type Ks256ReportInfo = {
  ks256Root: boolean;
  knownKey: boolean;
  attestations: Ks256Attestation[];
  usage: Ks256AttestationUsage;
};

/** Short narration of which attestations carried the verdict. */
export function describeUsedAttestations(info: Ks256ReportInfo): string {
  const parts = info.usage.used.map((u) => {
    const a = info.attestations[u.index]!;
    return `#${u.index} (chain ${a.chainId}, block ${a.blockNumber})`;
  });
  return `ERC-1271 attestation${parts.length > 1 ? "s" : ""} ${parts.join(", ")}`;
}

/** Reword the parse/signature rows for a KS256 root or an attestation. */
export function applyKs256Rows(
  rows: StageRow[],
  info: Ks256ReportInfo,
): StageRow[] {
  return rows.map((row) => {
    if (row.status !== "ok") return row;
    if (row.stage === "parse" && info.ks256Root) {
      return {
        ...row,
        reason: `receipt COSE decodes; ${info.knownKey ? "caller-known log key" : "genesis trust root"} loads (KS256 address)`,
      };
    }
    if (row.stage === "signature" && info.ks256Root) {
      const anchorName = info.knownKey ? "caller-known log key" : "genesis root";
      return {
        ...row,
        reason:
          info.usage.used.length > 0
            ? `delegation certificate valid under the contract's signers (${describeUsedAttestations(info)}) — not a signature by one key`
            : `delegation certificate recovers to the KS256 ${anchorName} (ecrecover)`,
      };
    }
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
  /** Human detail for a failed anchor (e.g. a forest mismatch). */
  detail?: string;
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
  /** Checkpoint-chain anchors only (FOR-368 Phase 3): links folded and the
   * sealed size of the link that held the peak. */
  linkCount?: number;
  matchedLinkSize?: string;
  /** Consistency-proof top-up (FOR-368 Phase 3): base size the untrusted
   * artifact extended the receipt from into the trusted snapshot. */
  topUpBaseSize?: string;
};

export type VerifyMode =
  | "offline"
  | "chain-anchored"
  | "accumulator-anchored"
  | "checkpoint-chain-anchored";

/** `--json` report on stdout — stable shape for demo scripting. */
export type VerifyReport = {
  command: "verify";
  mode: VerifyMode;
  ok: boolean;
  stage: ReceiptVerifyStage | "anchor";
  reason?: string;
  /** Approach-C fallback only: why the signature was not verified offline. */
  offlineReason?: string;
  /** Approach-C fallback only: the verdict's authority is the chain. */
  authority?: "on-chain";
  stages: StageRow[];
  anchor?: AnchorReport;
  /** KS256 root and ERC-1271 attestation facts (present for a KS256 root). */
  ks256?: {
    root: boolean;
    /** Every supplied attestation, by position: used (with what it was
     * read at) or unused with a reason. An unused attestation's fields
     * were never checked against anything, so they are not echoed. */
    attestations?: {
      used: {
        index: number;
        digest: string;
        chainId: string;
        address: string;
        blockNumber: string;
        blockHash: string;
        /** Chain links that needed it (checkpoint-chain only). */
        links?: number[];
      }[];
      /** Tried for a certificate and refused (own checks failed there). */
      rejected: {
        index: number;
        digest: string;
        links?: number[];
      }[];
      unused: { index: number; digest: string; reason: string }[];
    };
  };
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
  ks256?: Ks256ReportInfo | undefined;
  /** Approach-C fallback: the offline signature failure this verdict skipped. */
  offlineReason?: string | undefined;
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
  if (opts.offlineReason !== undefined) {
    report.offlineReason = opts.offlineReason;
    report.authority = "on-chain";
  }
  const mismatch = opts.anchor as { forestMismatch?: string } | undefined;
  if (mismatch?.forestMismatch !== undefined) {
    report.stage = "anchor";
    report.reason = ANCHOR_FOREST_MISMATCH;
  }
  if (opts.ks256 !== undefined) {
    const info = opts.ks256;
    report.ks256 = {
      root: info.ks256Root,
      ...(info.attestations.length > 0
        ? {
            attestations: {
              used: info.usage.used.map((u) => {
                const a = info.attestations[u.index]!;
                return {
                  index: u.index,
                  digest: `0x${u.digestHex}`,
                  chainId: a.chainId.toString(),
                  address: toHex(a.address),
                  blockNumber: a.blockNumber.toString(),
                  blockHash: toHex(a.blockHash),
                  ...(u.links.length > 0 ? { links: u.links } : {}),
                };
              }),
              rejected: info.usage.rejected.map((u) => ({
                index: u.index,
                digest: `0x${u.digestHex}`,
                ...(u.links.length > 0 ? { links: u.links } : {}),
              })),
              unused: info.usage.unused.map((u) => ({
                index: u.index,
                digest: `0x${u.digestHex}`,
                reason: u.reason,
              })),
            },
          }
        : {}),
    };
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
    if (mismatch?.forestMismatch !== undefined) {
      anchor.detail = mismatch.forestMismatch;
    }
    const failure = opts.anchor as { chainFailure?: string };
    if (failure.chainFailure !== undefined) {
      anchor.detail = failure.chainFailure;
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
    const chained = opts.anchor as {
      linkCount?: number;
      matchedLinkSize?: bigint | null;
    };
    if (chained.linkCount !== undefined) {
      anchor.linkCount = chained.linkCount;
      if (chained.matchedLinkSize !== undefined && chained.matchedLinkSize !== null) {
        anchor.matchedLinkSize = chained.matchedLinkSize.toString();
      }
    }
    const topUp = opts.anchor as { topUpBaseSize?: bigint };
    if (topUp.topUpBaseSize !== undefined) {
      anchor.topUpBaseSize = topUp.topUpBaseSize.toString();
    }
    report.anchor = anchor;
  }
  return report;
}

function toHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}
