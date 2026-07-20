/**
 * Checkpoint-chain providers (FOR-418 Phase 2, plan-2607-32).
 *
 * A *provider* yields the same thing from any source: the log's ordered chain
 * of consistency-proof links, folded into the authenticated accumulator at each
 * seal. Consumers (verify, `resolve-receipt`) then work over `CheckpointLink[]`
 * without caring where it came from. Two tile-free sources here:
 *
 * - **chain calldata** (`calldataCheckpointChain`) — the `publishCheckpoint`
 *   transactions carry the whole `ConsistencyReceipt` (Phase 1); trust is the
 *   chain itself (a mined tx passed the contract's consistency + signature
 *   gate).
 * - **retained `.sth`** (`sthCheckpointChain`) — the store's signed checkpoints;
 *   trust is the sealer key (verified where the chain is consumed).
 *
 * Both decode to the identical `CheckpointConsistencyProof` shape and fold
 * identically — the parity that makes them interchangeable (see the tests). The
 * tile provider is `resolve-receipt`'s `--massif` path (later phase).
 */
import {
  computeCheckpointAccumulator,
  checkpointConsistencyProof,
  type CheckpointConsistencyProof,
} from "@forestrie/receipt-verify";
import { fetchPublishedCheckpoints } from "./verify-eventscan.js";
import { fetchPublishCheckpointCalldata } from "./decode-checkpoint-calldata.js";

/** One authenticated link: the accumulator committed at `treeSize2`. */
export type CheckpointLink = {
  treeSize1: bigint;
  treeSize2: bigint;
  /** Folded accumulator at `treeSize2` (descending-height / contract order). */
  accumulator: Uint8Array[];
  /** Where this link came from (a tx hash, an `.sth` name) — for narration. */
  sourceRef?: string;
};

/**
 * Fold an ordered consistency-proof chain into per-link accumulators. Each
 * link's base must equal the previous link's sealed size — a mismatch is the
 * legacy / non-contiguous signature and throws (the caller falls back to
 * another provider). `accumulatorFrom` seeds a suffix chain (default: base 0).
 */
export async function foldProofChain(
  proofs: readonly CheckpointConsistencyProof[],
  opts: { accumulatorFrom?: Uint8Array[]; sourceRefs?: readonly string[] } = {},
): Promise<CheckpointLink[]> {
  const links: CheckpointLink[] = [];
  let accumulator = opts.accumulatorFrom ?? [];
  let expectedBase: bigint | null =
    opts.accumulatorFrom !== undefined ? null : 0n;
  for (let i = 0; i < proofs.length; i++) {
    const p = proofs[i]!;
    if (expectedBase !== null && p.treeSize1 !== expectedBase) {
      throw new Error(
        `checkpoint chain is not contiguous at link ${i}: base ${p.treeSize1} != expected ${expectedBase}`,
      );
    }
    accumulator = await computeCheckpointAccumulator(p, accumulator);
    const link: CheckpointLink = {
      treeSize1: p.treeSize1,
      treeSize2: p.treeSize2,
      accumulator,
    };
    const ref = opts.sourceRefs?.[i];
    if (ref !== undefined) link.sourceRef = ref;
    links.push(link);
    expectedBase = p.treeSize2;
  }
  return links;
}

/**
 * Retained-`.sth` provider: decode each checkpoint's embedded consistency proof
 * and fold. `checkpoints` are the raw `.sth` bytes in ascending massif order.
 */
export async function sthCheckpointChain(
  checkpoints: readonly Uint8Array[],
  opts: { accumulatorFrom?: Uint8Array[] } = {},
): Promise<CheckpointLink[]> {
  const proofs = checkpoints.map((bytes) => checkpointConsistencyProof(bytes));
  return foldProofChain(proofs, {
    ...(opts.accumulatorFrom !== undefined
      ? { accumulatorFrom: opts.accumulatorFrom }
      : {}),
  });
}

/**
 * Chain-calldata provider: find the log's `CheckpointPublished` transactions
 * (ascending), read each one's `publishCheckpoint` calldata, concatenate the
 * embedded consistency-proof chains, and fold. Trust is the chain — every tx
 * mined only because the contract accepted its signature + consistency proof.
 */
export async function calldataCheckpointChain(opts: {
  univocity: string;
  logId: string;
  rpcUrl: string;
  fromBlock?: bigint | undefined;
  fetchImpl?: typeof fetch;
}): Promise<CheckpointLink[]> {
  const published = await fetchPublishedCheckpoints({
    univocity: opts.univocity,
    logId: opts.logId,
    rpcUrl: opts.rpcUrl,
    fromBlock: opts.fromBlock,
    ...(opts.fetchImpl !== undefined ? { fetchImpl: opts.fetchImpl } : {}),
  });
  const proofs: CheckpointConsistencyProof[] = [];
  const sourceRefs: string[] = [];
  for (const cp of published) {
    const decoded = await fetchPublishCheckpointCalldata({
      rpcUrl: opts.rpcUrl,
      txHash: cp.txHash,
      ...(opts.fetchImpl !== undefined ? { fetchImpl: opts.fetchImpl } : {}),
    });
    for (const p of decoded.consistencyProofs) {
      proofs.push(p);
      sourceRefs.push(cp.txHash);
    }
  }
  return foldProofChain(proofs, { sourceRefs });
}

/**
 * Find the newest link whose folded accumulator contains `peak` (a receipt's
 * recomputed peak). Newest-first: the freshest cover gives the most useful
 * report, and a match at any authenticated link proves the receipt — later
 * links' proofs commit it forward. Null when no link covers it.
 */
export function findPeakInChain(
  links: readonly CheckpointLink[],
  peak: Uint8Array,
): { link: CheckpointLink; matchedPeak: number } | null {
  for (let i = links.length - 1; i >= 0; i--) {
    const link = links[i]!;
    for (let j = 0; j < link.accumulator.length; j++) {
      if (bytesEqual(peak, link.accumulator[j]!)) {
        return { link, matchedPeak: j };
      }
    }
  }
  return null;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let x = 0;
  for (let i = 0; i < a.length; i++) x |= a[i]! ^ b[i]!;
  return x === 0;
}
