import { bytesEqual } from "./bytes.js";
import {
  assertSnapshotBinding,
  computeAccumulatorPeak,
  decodeKnownAccumulator,
  encodeKnownAccumulator,
  parseReceipt,
  univocityLeafHash,
  type KnownAccumulator,
} from "@forestrie/receipt-verify";
import { type AnchorCheck } from "./verify-anchored.js";

/**
 * Snapshot artifact (type, encode, decode, binding assertion) hoisted to
 * `@forestrie/receipt-verify` (FOR-297 D5, plan-2607-34 slice 02 Part B) so
 * the CLI and other consumers share one implementation. Re-exported here so
 * existing local imports (`from "./verify-known-accumulator.js"`) keep
 * working unchanged.
 */
export {
  assertSnapshotBinding,
  decodeKnownAccumulator,
  encodeKnownAccumulator,
  type KnownAccumulator,
};

/**
 * Known-accumulator snapshot (FOR-297 D5): a cached, auditable chain read of
 * the log's `logState`, letting chain-anchored verification run fully
 * offline. The artifact type, encode/decode, and binding assertion moved to
 * `@forestrie/receipt-verify` (plan-2607-34 slice 02 Part B) — re-exported
 * above. See that package's `known-accumulator.ts` module doc for the trust
 * model.
 *
 * What stays CLI-local: `checkReceiptAnchoredToSnapshot` below adds
 * proof-path extension for stale snapshots (needs a local massif blob) —
 * a bigger, file-shaped input the package's pure-bytes API doesn't take
 * yet. The package's own `verifyReceiptOfflineAgainstKnownAccumulator`
 * covers the same exact-peak-match case (its case 2) for callers that don't
 * need extension.
 */

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export type SnapshotAnchorCheck = AnchorCheck & {
  /** True when the match required proof-path extension via massif nodes. */
  extended: boolean;
  blockNumber: bigint;
  blockHashHex: string;
};

/**
 * Assert the receipt's peak is anchored in the known-accumulator snapshot —
 * fully offline. Strategies, in order:
 *
 * 1. Fail closed when the receipt's leaf postdates the snapshot (refresh).
 * 2. Exact peak match: the recomputed receipt peak is still a snapshot peak.
 * 3. Proof-path extension (needs `massifBytes`): the receipt's peak is an
 *    interior node of the snapshot state; rebuild the leaf's inclusion path
 *    at the snapshot size from massif nodes and match the covering peak. The
 *    massif's leaf value must equal the locally derived leaf commitment —
 *    the payload stays bound even though the extension nodes come from the
 *    (untrusted) massif: every node on the path is recomputed.
 */
export async function checkReceiptAnchoredToSnapshot(opts: {
  snapshot: KnownAccumulator;
  receiptCbor: Uint8Array;
  idtimestampBe8: Uint8Array;
  /** Leaf ContentHash: SHA-256(payload) or the grant commitment hash. */
  inner: Uint8Array;
  /** Recomputed receipt peak (leaf + receipt proof path, no signature). */
  recomputedPeak: Uint8Array;
  /** Local massif blob enabling proof-path extension for stale snapshots. */
  massifBytes?: Uint8Array | undefined;
}): Promise<SnapshotAnchorCheck> {
  const { snapshot } = opts;
  const base = {
    accumulator: snapshot.accumulator,
    size: snapshot.size,
    blockNumber: snapshot.blockNumber,
    blockHashHex: bytesToHex(snapshot.blockHash),
  };

  const { proof } = parseReceipt(opts.receiptCbor);
  const leafMmrIndex =
    proof.leafIndex !== undefined ? proof.leafIndex : proof.mmrIndex!;

  // 1. Newer-than-snapshot fails CLOSED — staleness limits coverage, never
  // validity, so the remedy is a refresh, not a pass.
  if (leafMmrIndex >= snapshot.size) {
    return {
      ...base,
      anchored: false,
      matchedPeak: null,
      extended: false,
      reason: "receipt_newer_than_known_accumulator",
    };
  }

  // 2. Exact peak match — receipt state is a snapshot-covered accumulator.
  for (let i = 0; i < snapshot.accumulator.length; i++) {
    if (bytesEqual(opts.recomputedPeak, snapshot.accumulator[i]!)) {
      return { ...base, anchored: true, matchedPeak: i, extended: false };
    }
  }

  // 3. Extension: the old peak should be interior to the snapshot state.
  if (opts.massifBytes === undefined) {
    return {
      ...base,
      anchored: false,
      matchedPeak: null,
      extended: false,
      reason: "peak_not_in_known_accumulator",
    };
  }

  const leafHash = await univocityLeafHash(opts.idtimestampBe8, opts.inner);
  let computed: Awaited<ReturnType<typeof computeAccumulatorPeak>>;
  try {
    computed = await computeAccumulatorPeak({
      massifBytes: opts.massifBytes,
      mmrIndex: leafMmrIndex,
      mmrSize: snapshot.size,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(
      `proof-path extension failed (massif does not cover the snapshot?): ${message}`,
    );
  }
  if (!bytesEqual(computed.leafValue, leafHash)) {
    // The massif's leaf disagrees with the payload-derived commitment — the
    // extension cannot bind this payload.
    return {
      ...base,
      anchored: false,
      matchedPeak: null,
      extended: false,
      reason: "massif_leaf_mismatch",
    };
  }
  const target = snapshot.accumulator[computed.peakIndex];
  if (target !== undefined && bytesEqual(computed.peak, target)) {
    return {
      ...base,
      anchored: true,
      matchedPeak: computed.peakIndex,
      extended: true,
    };
  }
  return {
    ...base,
    anchored: false,
    matchedPeak: null,
    extended: false,
    reason: "peak_not_in_known_accumulator",
  };
}
