/**
 * Tile-free freshen for `resolve-receipt` (FOR-418 Phase 3c, plan-2607-32 D1/D3).
 *
 * "Freshen" is `resolve-receipt --receipt <stale> + a tile-free source`: re-anchor
 * a stale receipt to the CURRENT sealed state without massif tiles. The stale
 * receipt supplies the leaf's MMR index and its old inclusion path (leaf → old
 * peak); a checkpoint chain supplies the climb from that old peak to the latest
 * accumulator; the latest checkpoint supplies the signature to emit under. The
 * result is a native receipt that verifies with the offline verifier.
 *
 * The leaf VALUE is not in the stale receipt (its payload is detached — verify
 * recomputes it), so freshen recomputes it exactly as `verify-grant` does:
 * `univocityLeafHash(idtimestamp, grantCommitmentHash(grant))`. `freshenReceipt`
 * needs it for its fail-closed self-check (recomputed peak == folded accumulator
 * peak), so a bad chain/leaf throws here rather than minting a bad receipt.
 *
 * Two tile-free sources, both folding to `freshenReceipt`:
 * - **`.sth` chain** (`freshenFromSthChain`): retained checkpoints → genesis-
 *   verifiable. The last checkpoint in the chain is the emission checkpoint.
 * - **chain calldata** (`freshenFromCalldataChain`): the `publishCheckpoint`
 *   transactions carry the consistency-proof chain (known-key rung). Calldata
 *   carries no pre-signed peak receipts / cert, so emission still needs a latest
 *   `.sth` supplied separately (plan-2607-32 Phase 3 finding).
 */
import {
  freshenReceipt,
  parseReceipt,
} from "@forestrie/receipt-verify";
import {
  calldataCheckpointChain,
  sthCheckpointChain,
  type CheckpointLink,
} from "./checkpoint-provider.js";
import { univocityLeafHash } from "./verify-anchored.js";
import { bytesEqual } from "./bytes.js";
import type { KnownAccumulator } from "./verify-known-accumulator.js";

function accumulatorsEqual(a: Uint8Array[], b: Uint8Array[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (!bytesEqual(a[i]!, b[i]!)) return false;
  return true;
}

/** Structured detail for the `--json` report and human narration. */
export type FreshenDetails = {
  /** The stale receipt's leaf, addressed by MMR index. */
  leafMmrIndex: bigint;
  /** Sealed size the freshened receipt is anchored at (latest checkpoint). */
  sealedSize: bigint;
  /** Number of consistency-proof links folded from the chain. */
  chainLinks: number;
  /** Length of the emitted (extended) inclusion path. */
  proofLength: number;
  /** The chain sources, ascending (`.sth` filenames or tx hashes), for narration. */
  sourceRefs: string[];
  /** The folded latest accumulator matched a `--known-accumulator` snapshot
   * (present only when one was supplied). */
  knownAccumulatorMatched?: boolean;
};

export type FreshenResult = {
  receiptCbor: Uint8Array;
  details: FreshenDetails;
};

// The leaf value the freshened receipt must root to is recomputed exactly as
// `verify` does: `univocityLeafHash(idtimestamp, inner)`, where `inner` is the
// leaf ContentHash — `SHA-256(payload)` for a statement, or the grant commitment
// hash for a grant. The caller supplies `inner`, so freshen is source-agnostic.

/**
 * Shared emission: take the provider's links + a latest checkpoint, extend the
 * stale receipt's path, and re-emit. `freshenReceipt` cross-checks the chain
 * against the latest checkpoint and self-checks the recomputed peak.
 *
 * When a `knownAccumulator` is supplied, the folded latest accumulator is bound
 * to that trusted snapshot BEFORE the receipt is returned: the state we folded
 * must equal the snapshot at the same size, or we fail closed. This is the
 * accumulator trust rung (a chain-captured `logState`, `fetch-accumulator`) — it
 * confirms the leaf roots into the genuine current state without a genesis walk,
 * and, for the calldata source (whose fold is already cross-checked against the
 * on-chain `CheckpointPublished` accumulator), adds an independent, RPC-agnostic
 * anchor that catches a lying/stale RPC.
 */
async function emitFreshened(opts: {
  oldReceiptBytes: Uint8Array;
  leafValue: Uint8Array;
  links: readonly CheckpointLink[];
  latestCheckpointBytes: Uint8Array;
  sourceRefs: string[];
  knownAccumulator?: KnownAccumulator | undefined;
}): Promise<FreshenResult> {
  const result = await freshenReceipt({
    oldReceiptBytes: opts.oldReceiptBytes,
    leafValue: opts.leafValue,
    consistencyProofs: opts.links.map((l) => l.proof),
    latestCheckpointBytes: opts.latestCheckpointBytes,
  });

  let knownAccumulatorMatched: boolean | undefined;
  if (opts.knownAccumulator !== undefined) {
    const snap = opts.knownAccumulator;
    const aLatest = opts.links[opts.links.length - 1]!.accumulator;
    if (snap.size !== result.sealedSize) {
      throw new Error(
        `--known-accumulator is size ${snap.size} but the freshened state is size ${result.sealedSize} — capture a snapshot at the current sealed size (freshen cannot extend tile-free)`,
      );
    }
    if (!accumulatorsEqual(aLatest, snap.accumulator)) {
      throw new Error(
        "freshened accumulator does not match --known-accumulator — the chain/checkpoint disagrees with your trusted snapshot",
      );
    }
    knownAccumulatorMatched = true;
  }

  const { proof } = parseReceipt(result.receipt);
  return {
    receiptCbor: result.receipt,
    details: {
      leafMmrIndex: proof.mmrIndex!,
      sealedSize: result.sealedSize,
      chainLinks: opts.links.length,
      proofLength: proof.path.length,
      sourceRefs: opts.sourceRefs,
      ...(knownAccumulatorMatched !== undefined ? { knownAccumulatorMatched } : {}),
    },
  };
}

/**
 * Freshen a stale receipt against a retained `.sth` checkpoint chain.
 *
 * `checkpoints` are the raw `.sth` bytes in ascending massif order (a contiguous
 * chain from the log's base); the last checkpoint is the emission checkpoint.
 * `sourceRefs` optionally names them. Throws (with the underlying reason) if the
 * chain is not a contiguous cover to the leaf, if the chain does not match the
 * latest checkpoint, or if the recomputed peak does not match the fold.
 */
export async function freshenFromSthChain(opts: {
  oldReceiptBytes: Uint8Array;
  /** Leaf ContentHash: `SHA-256(payload)` (statement) or the grant commitment. */
  inner: Uint8Array;
  idtimestampBe8: Uint8Array;
  checkpoints: readonly Uint8Array[];
  sourceRefs?: readonly string[];
  knownAccumulator?: KnownAccumulator | undefined;
}): Promise<FreshenResult> {
  if (opts.checkpoints.length === 0) {
    throw new Error("--checkpoint-chain resolved to no checkpoints");
  }
  const leafValue = await univocityLeafHash(opts.idtimestampBe8, opts.inner);
  const links = await sthCheckpointChain(
    opts.checkpoints,
    opts.sourceRefs !== undefined ? { sourceRefs: opts.sourceRefs } : {},
  );
  return emitFreshened({
    oldReceiptBytes: opts.oldReceiptBytes,
    leafValue,
    links,
    latestCheckpointBytes: opts.checkpoints[opts.checkpoints.length - 1]!,
    sourceRefs: [...(opts.sourceRefs ?? [])],
    knownAccumulator: opts.knownAccumulator,
  });
}

/**
 * Freshen a stale receipt against the on-chain `publishCheckpoint` calldata.
 *
 * Reads the log's checkpoint chain from the `CheckpointPublished` transactions
 * (trustless climb material), then re-emits under `latestCheckpointBytes` — a
 * latest `.sth` supplied by the caller, because the calldata carries no
 * pre-signed peak receipts or delegation cert. The calldata chain's sealed size
 * must equal the latest checkpoint's (enforced by `freshenReceipt`). This is the
 * known-key rung: trust flows from the sealer key in the seal, not genesis.
 */
export async function freshenFromCalldataChain(opts: {
  oldReceiptBytes: Uint8Array;
  /** Leaf ContentHash: `SHA-256(payload)` (statement) or the grant commitment. */
  inner: Uint8Array;
  idtimestampBe8: Uint8Array;
  univocity: string;
  logId: string;
  rpcUrl: string;
  latestCheckpointBytes: Uint8Array;
  knownAccumulator?: KnownAccumulator | undefined;
  fetchImpl?: typeof fetch;
}): Promise<FreshenResult> {
  const leafValue = await univocityLeafHash(opts.idtimestampBe8, opts.inner);
  const links = await calldataCheckpointChain({
    univocity: opts.univocity,
    logId: opts.logId,
    rpcUrl: opts.rpcUrl,
    ...(opts.fetchImpl !== undefined ? { fetchImpl: opts.fetchImpl } : {}),
  });
  if (links.length === 0) {
    throw new Error(
      "no CheckpointPublished history found on-chain for this log — nothing to freshen against",
    );
  }
  return emitFreshened({
    oldReceiptBytes: opts.oldReceiptBytes,
    leafValue,
    links,
    latestCheckpointBytes: opts.latestCheckpointBytes,
    sourceRefs: links.map((l) => l.sourceRef ?? ""),
    knownAccumulator: opts.knownAccumulator,
  });
}
