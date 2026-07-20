/**
 * Checkpoint-chain providers (FOR-418 Phase 2, plan-2607-32).
 *
 * A *provider* yields the log's ordered chain of consistency-proof links folded
 * into the accumulator at each seal, so consumers (verify, `resolve-receipt`)
 * work over `CheckpointLink[]` regardless of source. Two tile-free sources:
 *
 * - **chain calldata** (`calldataCheckpointChain`) — the `publishCheckpoint`
 *   transactions carry the whole `ConsistencyReceipt` (Phase 1).
 * - **retained `.sth`** (`sthCheckpointChain`) — the store's signed checkpoints.
 *
 * TRUST (important — see the Phase 2 review, plan-2607-32 R1): a `CheckpointLink`
 * accumulator here is **RPC-/store-asserted, NOT authenticated by this module**.
 * The provider folds and does a cheap self-consistency cross-check (calldata
 * fold vs the `CheckpointPublished` event accumulator), but it does **not**
 * verify the COSE signature. So that the consumer *can*, each directly-signed
 * link carries its `seal` (the signature + delegation for calldata; the
 * checkpoint bytes for `.sth`); the consumer applies the genesis/known-key trust
 * root against those seals (Phase 4). Both sources decode to the identical
 * `CheckpointConsistencyProof` shape and fold identically — the parity that
 * makes them interchangeable (see the tests).
 */
import {
  computeCheckpointAccumulator,
  checkpointConsistencyProof,
  type CheckpointConsistencyProof,
} from "@forestrie/receipt-verify";
import { fetchPublishedCheckpoints } from "./verify-eventscan.js";
import {
  fetchPublishCheckpointCalldata,
  type CalldataDelegation,
} from "./decode-checkpoint-calldata.js";
import { bytesEqual } from "./bytes.js";

/**
 * The signed checkpoint a link's accumulator is sealed by, retained so the
 * consumer can verify it (this module does not). Present on the directly-signed
 * link of each unit — every `.sth`; the FINAL link of each calldata tx's proof
 * segment (intermediate links in a multi-proof tx are unsigned, transitively
 * trusted via the fold to the next sealed link).
 */
export type CheckpointSeal =
  | {
      kind: "calldata";
      protectedHeader: Uint8Array;
      signature: Uint8Array;
      delegation: CalldataDelegation;
    }
  | { kind: "sth"; checkpointBytes: Uint8Array };

/** One folded link: the accumulator committed at `treeSize2`. */
export type CheckpointLink = {
  treeSize1: bigint;
  treeSize2: bigint;
  /** Folded accumulator at `treeSize2` (descending-height / contract order). */
  accumulator: Uint8Array[];
  /** The signature material to verify this link's accumulator, when directly
   * signed (see {@link CheckpointSeal}). The provider does NOT verify it. */
  seal?: CheckpointSeal;
  /** Where this link came from (a tx hash, an `.sth` name) — for narration. */
  sourceRef?: string;
};

/**
 * Fold an ordered consistency-proof chain into per-link accumulators. Each
 * link's base must equal the previous link's sealed size — a mismatch is the
 * legacy / non-contiguous signature and throws. For a suffix chain, pass BOTH
 * `accumulatorFrom` and `accumulatorFromSize` (the size that seed is for); the
 * first link's `treeSize1` is bound to it (R2). Without a seed the chain must
 * start at base 0.
 */
export async function foldProofChain(
  proofs: readonly CheckpointConsistencyProof[],
  opts: {
    accumulatorFrom?: Uint8Array[];
    accumulatorFromSize?: bigint;
    seals?: readonly (CheckpointSeal | undefined)[];
    sourceRefs?: readonly string[];
  } = {},
): Promise<CheckpointLink[]> {
  let accumulator = opts.accumulatorFrom ?? [];
  let expectedBase: bigint;
  if (opts.accumulatorFrom !== undefined) {
    if (opts.accumulatorFromSize === undefined) {
      throw new Error(
        "foldProofChain: accumulatorFrom requires accumulatorFromSize (the size the seed accumulator is for)",
      );
    }
    expectedBase = opts.accumulatorFromSize;
  } else {
    expectedBase = 0n;
  }
  const links: CheckpointLink[] = [];
  for (let i = 0; i < proofs.length; i++) {
    const p = proofs[i]!;
    if (p.treeSize1 !== expectedBase) {
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
    const seal = opts.seals?.[i];
    if (seal !== undefined) link.seal = seal;
    const ref = opts.sourceRefs?.[i];
    if (ref !== undefined) link.sourceRef = ref;
    links.push(link);
    expectedBase = p.treeSize2;
  }
  return links;
}

/**
 * Retained-`.sth` provider: decode each checkpoint's embedded consistency proof
 * and fold. `checkpoints` are the raw `.sth` bytes in ascending massif order;
 * `sourceRefs` optionally names them (e.g. filenames) for narration.
 */
export async function sthCheckpointChain(
  checkpoints: readonly Uint8Array[],
  opts: {
    accumulatorFrom?: Uint8Array[];
    accumulatorFromSize?: bigint;
    sourceRefs?: readonly string[];
  } = {},
): Promise<CheckpointLink[]> {
  const proofs = checkpoints.map((bytes) => checkpointConsistencyProof(bytes));
  const seals: CheckpointSeal[] = checkpoints.map((bytes) => ({
    kind: "sth",
    checkpointBytes: bytes,
  }));
  return foldProofChain(proofs, {
    seals,
    ...(opts.accumulatorFrom !== undefined
      ? { accumulatorFrom: opts.accumulatorFrom }
      : {}),
    ...(opts.accumulatorFromSize !== undefined
      ? { accumulatorFromSize: opts.accumulatorFromSize }
      : {}),
    ...(opts.sourceRefs !== undefined ? { sourceRefs: opts.sourceRefs } : {}),
  });
}

/** Run `fn` over `items` with bounded concurrency, preserving order (R5). */
async function mapBounded<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  async function worker(): Promise<void> {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i]!, i);
    }
  }
  const n = Math.min(Math.max(1, limit), items.length || 1);
  await Promise.all(Array.from({ length: n }, () => worker()));
  return out;
}

function accumulatorsEqual(a: Uint8Array[], b: Uint8Array[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (!bytesEqual(a[i]!, b[i]!)) return false;
  return true;
}

/**
 * Chain-calldata provider: find the log's `CheckpointPublished` transactions
 * (ascending), read each `publishCheckpoint`'s calldata, concatenate the
 * embedded consistency-proof chains, and fold. Cross-checks each tx's folded
 * accumulator against the `CheckpointPublished` event's accumulator (R3), and
 * retains each tx's seal for the consumer to verify (R1); it does NOT verify
 * signatures here (Phase 4). A bounded `--from-block` scan is only valid with a
 * trusted seed at that block (R2): pass `accumulatorFrom` + `accumulatorFromSize`.
 */
export async function calldataCheckpointChain(opts: {
  univocity: string;
  logId: string;
  rpcUrl: string;
  fromBlock?: bigint | undefined;
  accumulatorFrom?: Uint8Array[] | undefined;
  accumulatorFromSize?: bigint | undefined;
  fetchImpl?: typeof fetch;
}): Promise<CheckpointLink[]> {
  if (opts.fromBlock !== undefined && opts.accumulatorFrom === undefined) {
    throw new Error(
      "calldataCheckpointChain: --from-block must be paired with a trusted seed (accumulatorFrom + accumulatorFromSize) — a bounded scan starts mid-chain and cannot fold from base 0",
    );
  }
  const published = await fetchPublishedCheckpoints({
    univocity: opts.univocity,
    logId: opts.logId,
    rpcUrl: opts.rpcUrl,
    fromBlock: opts.fromBlock,
    ...(opts.fetchImpl !== undefined ? { fetchImpl: opts.fetchImpl } : {}),
  });
  const decoded = await mapBounded(published, 8, (cp) =>
    fetchPublishCheckpointCalldata({
      rpcUrl: opts.rpcUrl,
      txHash: cp.txHash,
      ...(opts.fetchImpl !== undefined ? { fetchImpl: opts.fetchImpl } : {}),
    }),
  );

  const proofs: CheckpointConsistencyProof[] = [];
  const seals: (CheckpointSeal | undefined)[] = [];
  const sourceRefs: string[] = [];
  const finalLinkIndex: number[] = []; // link index of each tx's last proof
  for (let t = 0; t < published.length; t++) {
    const d = decoded[t]!;
    const n = d.consistencyProofs.length;
    d.consistencyProofs.forEach((p, k) => {
      proofs.push(p);
      sourceRefs.push(published[t]!.txHash);
      seals.push(
        k === n - 1
          ? {
              kind: "calldata",
              protectedHeader: d.protectedHeader,
              signature: d.signature,
              delegation: d.delegation,
            }
          : undefined,
      );
    });
    finalLinkIndex.push(proofs.length - 1);
  }

  const links = await foldProofChain(proofs, {
    seals,
    sourceRefs,
    ...(opts.accumulatorFrom !== undefined
      ? { accumulatorFrom: opts.accumulatorFrom }
      : {}),
    ...(opts.accumulatorFromSize !== undefined
      ? { accumulatorFromSize: opts.accumulatorFromSize }
      : {}),
  });

  // R3: the folded accumulator at each tx's seal MUST equal the accumulator the
  // CheckpointPublished event reported (both from the RPC — this catches a fold
  // bug or an RPC serving inconsistent event/calldata, not a fully malicious
  // RPC; the signature seal is the real anchor, applied by the consumer).
  for (let t = 0; t < published.length; t++) {
    const link = links[finalLinkIndex[t]!]!;
    const cp = published[t]!;
    if (link.treeSize2 !== cp.size) {
      throw new Error(
        `calldata size ${link.treeSize2} disagrees with CheckpointPublished size ${cp.size} (tx ${cp.txHash})`,
      );
    }
    if (!accumulatorsEqual(link.accumulator, cp.accumulator)) {
      throw new Error(
        `folded calldata accumulator disagrees with the CheckpointPublished event at size ${cp.size} (tx ${cp.txHash}) — inconsistent RPC data`,
      );
    }
  }
  return links;
}

/**
 * Find the newest link whose folded accumulator contains `peak` (a receipt's
 * recomputed peak). Newest-first: a match at any authenticated link proves the
 * receipt — later links' proofs commit it forward. Null when no link covers it.
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
