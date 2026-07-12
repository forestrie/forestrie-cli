import {
  computeAccumulatorPeak,
  openMassifNodeStore,
  peakMMRIndexes,
  type MassifNodeStore,
} from "@forestrie/receipt-verify";
import {
  fetchOnChainLogState,
  type OnChainLogState,
} from "./verify-anchored.js";

/**
 * Chain-anchored, report-only verification for `forestrie create-receipt`
 * (FOR-345 phase 2, plan-2607-15 §3/§6). This is the option-B path: it emits
 * NO signed receipt. Its selling point is receipt-free verification — the
 * checkpoint signature was already enforced on-chain at `publishCheckpoint`
 * time, so no `.sth` is needed at all.
 *
 * The computation:
 *   1. read the on-chain `logState(bytes32) -> {accumulator, size}`;
 *   2. build the leaf's inclusion path AT the on-chain size
 *      (`mmrLastIndex = size - 1`) from the local massif blob and compute the
 *      accumulator peak it commits to (`computeAccumulatorPeak`);
 *   3. compare that peak against `accumulator[peakIndex]`, where `peakIndex`
 *      is the same proof-length -> accumulator-slot selection the contract's
 *      own verifier uses (returned by `computeAccumulatorPeak`).
 *
 * Because the path is built at the CURRENT size, the target peak is by
 * construction a member of the current accumulator — burial cannot occur at
 * creation time. There is NO exact-accumulator-size constraint: any leaf with
 * `mmrIndex < size` works, given local node data up to that size (plan §3,
 * decision 4).
 *
 * Pure over bytes plus exactly one `eth_call`; no signing key, no operator.
 */

/** Outcome token — the `--json` shape and exit-code mapping are a contract. */
export type ChainVerifyOutcome =
  | "verified"
  | "not_yet_anchored"
  | "coverage"
  | "peak_mismatch";

/**
 * Where a chain-mode *operational* error (as opposed to a verification
 * outcome) broke the run: massif parse, or the on-chain read/decode.
 */
export type ChainVerifyErrorStage = "parse" | "chain";

/** Stable snake_case reasons for operational failures (`--json` contract). */
export type ChainVerifyReason = "massif_parse_failed";

export class ChainVerifyFailure extends Error {
  readonly stage: ChainVerifyErrorStage;
  readonly reason: ChainVerifyReason;

  constructor(
    stage: ChainVerifyErrorStage,
    reason: ChainVerifyReason,
    message: string,
  ) {
    super(message);
    this.name = "ChainVerifyFailure";
    this.stage = stage;
    this.reason = reason;
  }
}

/** Facts for narration / `--json` reporting (bigints stay bigint here). */
export type ChainVerifyResult = {
  outcome: ChainVerifyOutcome;
  leaf: { mmrIndex: bigint };
  massif: {
    massifIndex: bigint;
    massifHeight: number;
    firstIndex: bigint;
    lastIndex: bigint;
  };
  onchain: {
    /** Anchored MMR size read from the contract. */
    size: bigint;
    /** Number of accumulator peaks the contract holds. */
    peakCount: number;
  };
  /**
   * Peak-check facts. Absent on `not_yet_anchored` / `coverage` (the peak was
   * never computed) — present on `verified` and `peak_mismatch`.
   */
  peakCheck?: {
    /** Inclusion path length (leaf -> accumulator peak) at the on-chain size. */
    proofLength: number;
    /** Accumulator slot selected for a proof of this length. */
    peakIndex: number;
    /** MMR index of the selected accumulator peak. */
    peakMMRIndex: bigint;
    /** The peak recomputed from local node data (hex). */
    computedPeakHex: string;
    /** The peak the contract holds at `peakIndex` (hex). */
    onchainPeakHex: string;
    /** True iff the two peaks match byte-for-byte. */
    matched: boolean;
  };
};

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let x = 0;
  for (let i = 0; i < a.length; i++) x |= a[i]! ^ b[i]!;
  return x === 0;
}

/** Dependencies, injectable so tests can mock the on-chain read. */
export type ChainVerifyDeps = {
  fetchOnChainLogState: (opts: {
    univocity: string;
    logId: string;
    rpcUrl: string;
  }) => Promise<OnChainLogState>;
};

const defaultDeps: ChainVerifyDeps = { fetchOnChainLogState };

/**
 * Run the report-only chain-anchored peak check.
 *
 * Failure taxonomy (plan §3, all reported — never thrown):
 * - `not_yet_anchored` — `mmrIndex >= size`: the leaf postdates the last
 *   anchor ("anchor lag"); the local massif may hold it, but the chain does
 *   not attest it yet.
 * - `coverage` — the local blob does not hold nodes up to the on-chain size
 *   (the on-chain size lives in a later massif); a later blob is required.
 * - `peak_mismatch` — the computed peak differs from the anchored one: the
 *   local node data has been tampered with (or is for the wrong log).
 *
 * Operational errors (bad massif bytes, RPC transport/decode) throw
 * `ChainVerifyFailure` / propagate — the caller maps them to exit 1.
 */
export async function verifyChainAnchored(
  input: {
    massifBytes: Uint8Array;
    mmrIndex: bigint;
    univocity: string;
    logId: string;
    rpcUrl: string;
  },
  deps: ChainVerifyDeps = defaultDeps,
): Promise<ChainVerifyResult> {
  let store: MassifNodeStore;
  try {
    store = openMassifNodeStore(input.massifBytes);
  } catch (err) {
    throw new ChainVerifyFailure(
      "parse",
      "massif_parse_failed",
      `massif blob is not v2 layout: ${errorMessage(err)}`,
    );
  }

  // The on-chain read is the one networked call (throws -> operational error).
  const state = await deps.fetchOnChainLogState({
    univocity: input.univocity,
    logId: input.logId,
    rpcUrl: input.rpcUrl,
  });

  const massif = {
    massifIndex: store.massifIndex,
    massifHeight: store.massifHeight,
    firstIndex: store.firstIndex,
    lastIndex: store.lastIndex,
  };
  const onchain = { size: state.size, peakCount: state.accumulator.length };
  const base = { leaf: { mmrIndex: input.mmrIndex }, massif, onchain };

  // Anchor lag: the entry is newer than the last on-chain checkpoint.
  if (input.mmrIndex >= state.size) {
    return { outcome: "not_yet_anchored", ...base };
  }

  // Coverage: the path is built at `size - 1`, so the local blob must hold
  // the log tip up to `size - 1`. Nodes below `firstIndex` resolve through
  // the ancestor peak stack, so only the upper bound can be short here.
  const mmrLastIndex = state.size - 1n;
  if (mmrLastIndex > store.lastIndex) {
    return { outcome: "coverage", ...base };
  }

  // Build the path AT the on-chain size and compute the accumulator peak it
  // commits to (no exact-size constraint — this works for any covered leaf).
  let computed: Awaited<ReturnType<typeof computeAccumulatorPeak>>;
  try {
    computed = await computeAccumulatorPeak({
      massifBytes: input.massifBytes,
      mmrIndex: input.mmrIndex,
      mmrSize: state.size,
    });
  } catch (err) {
    // A throw here means the blob could not furnish a proof node up to the
    // on-chain size despite the range check — treat as coverage, not a crash.
    return { outcome: "coverage", ...base };
  }

  const peaks = peakMMRIndexes(mmrLastIndex);
  const peakMMRIndex = peaks[computed.peakIndex] ?? -1n;
  const onchainPeak = state.accumulator[computed.peakIndex];
  if (onchainPeak === undefined) {
    // The contract holds fewer peaks than the selected slot — the on-chain
    // accumulator disagrees with the computed shape: tamper-shaped.
    return {
      outcome: "peak_mismatch",
      ...base,
      peakCheck: {
        proofLength: computed.proof.length,
        peakIndex: computed.peakIndex,
        peakMMRIndex,
        computedPeakHex: toHex(computed.peak),
        onchainPeakHex: "",
        matched: false,
      },
    };
  }

  const matched = bytesEqual(computed.peak, onchainPeak);
  return {
    outcome: matched ? "verified" : "peak_mismatch",
    ...base,
    peakCheck: {
      proofLength: computed.proof.length,
      peakIndex: computed.peakIndex,
      peakMMRIndex,
      computedPeakHex: toHex(computed.peak),
      onchainPeakHex: toHex(onchainPeak),
      matched,
    },
  };
}
