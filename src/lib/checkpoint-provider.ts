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
 * verify the COSE signature. So that the consumer *can*, every link carries its
 * `seal` (the signature + delegation for calldata; the checkpoint bytes for
 * `.sth`) — one link per checkpoint / `publishCheckpoint` transaction, whether
 * it relays one sealed step or several (ADR-0066 D2), matching receipt-verify
 * 3.0.0's own `CheckpointConsistencyProof` shape (`proofs`, one entry per
 * relayed step); the consumer applies the genesis/known-key trust root against
 * those seals (Phase 4). Both sources decode to the identical shape and fold
 * identically — the parity that makes them interchangeable (see the tests).
 *
 * Each link also carries the raw `proof` it was folded from — every relayed
 * step's per-peak `paths`, not just the last — so a consumer that needs the
 * climb material rather than just the folded accumulator —
 * `resolve-receipt`'s freshen (Phase 3c), which extends an old inclusion path
 * to the latest peak — gets it in one pass with no re-decode and no second RPC
 * sweep: `links.map((l) => l.proof)` is exactly freshen's ordered
 * `consistencyProofs`. Consumers that only fold (verify) ignore it.
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
 * consumer can verify it (this module does not). Present on every link —
 * one per `.sth`, one per calldata `publishCheckpoint` transaction — since a
 * link now folds a whole relayed proof chain (ADR-0066 D2) under the one
 * signature that covers its last step.
 */
export type CheckpointSeal =
  | {
      kind: "calldata";
      protectedHeader: Uint8Array;
      signature: Uint8Array;
      delegation: CalldataDelegation;
    }
  | { kind: "sth"; checkpointBytes: Uint8Array };

/**
 * Fold-relevant fields of a consistency proof (receipt-verify 3.0.0): a
 * checkpoint's relayed proof CHAIN, one entry per relayed step
 * (`proofs`, ADR-0066 D2), plus the chain's overall `treeSize1` (the
 * first step's) and `treeSize2` (the last step's). Shared by
 * calldata-decoded proofs (`CalldataConsistencyProof[]` — on-chain calldata
 * carries no protected header, so no per-proof signed size) and sth-decoded
 * `CheckpointConsistencyProof` (which adds `signedTreeSize2`, cross-checked
 * against the checkpoint's protected header at decode time). Neither
 * `computeCheckpointAccumulator` nor `freshenReceipt` reads `signedTreeSize2`
 * — only the trusted base SIZE (passed separately, never off the proof) and
 * `proofs`/`treeSize1`/`treeSize2` matter to the fold — so this provider
 * carries the narrower shape and backfills `signedTreeSize2` with
 * `treeSize2` only where receipt-verify's stricter parameter type demands it.
 */
export type FoldableConsistencyProof = Pick<
  CheckpointConsistencyProof,
  "proofs" | "treeSize1" | "treeSize2"
>;

/**
 * One folded link: the accumulator committed at `treeSize2`. One link per
 * checkpoint / calldata transaction, whether it relays one sealed step or
 * several (ADR-0066 D2) — receipt-verify 3.0.0 folds a checkpoint's whole
 * relayed chain under one signature, so there is no intermediate,
 * separately-authenticated accumulator to expose as its own link.
 */
export type CheckpointLink = {
  treeSize1: bigint;
  treeSize2: bigint;
  /** Folded accumulator at `treeSize2` (descending-height / contract order). */
  accumulator: Uint8Array[];
  /** The raw consistency-proof chain this link was folded from — every
   * relayed step's per-peak `paths` (the tile-free climb material), not
   * just the last. Retained so a path-extending consumer (freshen) gets it
   * without a re-decode; folding consumers ignore it. */
  proof: FoldableConsistencyProof;
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
  proofs: readonly FoldableConsistencyProof[],
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
    // receipt-verify 3.0.0: the trusted base size is a parameter, never read
    // off the proof (ADR-0066 D5.4) — `expectedBase` is exactly that, already
    // checked against `p.treeSize1` above. `signedTreeSize2` is backfilled
    // from `treeSize2` only to satisfy the parameter type; the fold does not
    // read it (see `FoldableConsistencyProof`'s doc comment above).
    // `p.proofs` may hold several relayed steps (ADR-0066 D2);
    // `computeCheckpointAccumulator` folds them all and requires the result
    // to land exactly on `p.treeSize2`.
    accumulator = await computeCheckpointAccumulator(
      { ...p, signedTreeSize2: p.treeSize2 },
      accumulator,
      expectedBase,
    );
    const link: CheckpointLink = {
      treeSize1: p.treeSize1,
      treeSize2: p.treeSize2,
      accumulator,
      proof: p,
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
 * (ascending), read each `publishCheckpoint`'s calldata, and fold. Each tx's
 * WHOLE relayed proof chain (`ConsistencyProof[]`, one or more steps —
 * ADR-0066 D2, a relayed transaction has several) becomes ONE
 * {@link CheckpointLink}, matching how `.sth` decodes and folds
 * (`checkpointConsistencyProof`, receipt-verify 3.0.0): only the LAST
 * relayed step is directly signed, so there is no separately-authenticated
 * accumulator at an intermediate step to expose as its own link. Cross-
 * checks each tx's folded accumulator against the `CheckpointPublished`
 * event's accumulator (R3), and retains each tx's seal for the consumer to
 * verify (R1); it does NOT verify signatures here (Phase 4). A bounded
 * `--from-block` scan is only valid with a trusted seed at that block (R2):
 * pass `accumulatorFrom` + `accumulatorFromSize`.
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

  // One FoldableConsistencyProof per tx: every step it relays goes into
  // `proofs` (not only the last — a relayed transaction has several,
  // ADR-0066 D2), spanning the tx's first step's tree-size-1 to its last
  // step's tree-size-2. `computeCheckpointAccumulator` folds every step in
  // order and requires the result to land exactly on that tree-size-2.
  const proofs: FoldableConsistencyProof[] = decoded.map((d) => {
    const first = d.consistencyProofs[0]!;
    const last = d.consistencyProofs[d.consistencyProofs.length - 1]!;
    return {
      proofs: d.consistencyProofs,
      treeSize1: first.treeSize1,
      treeSize2: last.treeSize2,
    };
  });
  const seals: CheckpointSeal[] = decoded.map((d) => ({
    kind: "calldata",
    protectedHeader: d.protectedHeader,
    signature: d.signature,
    delegation: d.delegation,
  }));
  const sourceRefs: string[] = published.map((cp) => cp.txHash);

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

  // R3: the folded accumulator at each tx's link MUST equal the accumulator the
  // CheckpointPublished event reported (both from the RPC — this catches a fold
  // bug or an RPC serving inconsistent event/calldata, not a fully malicious
  // RPC; the signature seal is the real anchor, applied by the consumer).
  for (let t = 0; t < published.length; t++) {
    const link = links[t]!;
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
