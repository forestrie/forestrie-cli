import {
  decodeCborDeterministic,
  encodeCborDeterministic,
} from "@forestrie/encoding";
import { computeAccumulatorPeak, parseReceipt } from "@forestrie/receipt-verify";
import { normalizeHexAddress } from "@forestrie/chain-rpc";
import {
  toContractLogId,
  univocityLeafHash,
  type AnchorCheck,
} from "./verify-anchored.js";

/**
 * Known-accumulator snapshot (FOR-297 D5): a cached, auditable chain read of
 * the log's `logState`, letting chain-anchored verification run fully offline.
 *
 * Trust model: `--rpc-url` was never trust-free — the RPC provider is itself
 * a trusted chain reader. The snapshot makes that trust explicit, portable,
 * and cacheable. It binds `(chainId, univocity, logId, size, block)` so anyone
 * with RPC can re-run the read at that block and confirm or disprove it —
 * auditable, falsifiable trust, unlike a bare known key.
 *
 * Staleness limits coverage, never validity: the contract's consistency
 * gating makes every anchored state a committed prefix of every later one, so
 * a peak match at snapshot size N proves inclusion at N and forever after.
 * Entries newer than the snapshot fail closed with a refresh hint; entries
 * older than the snapshot verify via proof-path extension (Reyzin & Yakoubov
 * old-accumulator compatibility): the receipt's peak at size N is an interior
 * node of the size-M state, and local massif nodes extend the path to the
 * covering snapshot peak — the whole extended path is recomputed, so a match
 * is sound by hash collision resistance.
 *
 * NEVER source the snapshot unauthenticated from the same store as the tiles
 * (the log operator's massif/checkpoint store) — that silently re-internalises
 * the operator trust this anchor exists to remove. Fetch it yourself over RPC
 * (`forestrie fetch-accumulator`) or obtain it from a party you trust as a
 * chain reader.
 */

/** CBOR map labels for the snapshot artifact (strict RFC 8949 §4.2). */
const LABEL_VERSION = 1;
const LABEL_CHAIN_ID = 2;
const LABEL_UNIVOCITY = 3;
const LABEL_LOG_ID = 4;
const LABEL_SIZE = 5;
const LABEL_ACCUMULATOR = 6;
const LABEL_BLOCK_NUMBER = 7;
const LABEL_BLOCK_HASH = 8;

const SNAPSHOT_VERSION = 1;

export type KnownAccumulator = {
  version: number;
  chainId: bigint;
  /** Univocity contract address (20 bytes). */
  univocity: Uint8Array;
  /** Contract log id (32 bytes, UUID zero-padded on the left). */
  logId: Uint8Array;
  /** Anchored MMR size at the snapshot block. */
  size: bigint;
  /** Anchored accumulator peaks (32 bytes each), contract order. */
  accumulator: Uint8Array[];
  blockNumber: bigint;
  /** Block hash of the read (32 bytes) — the falsifiability handle. */
  blockHash: Uint8Array;
};

/** Encode a snapshot as canonical CBOR (RFC 8949 §4.2 — hard policy). */
export function encodeKnownAccumulator(snapshot: KnownAccumulator): Uint8Array {
  return encodeCborDeterministic(
    new Map<number, unknown>([
      [LABEL_VERSION, snapshot.version],
      [LABEL_CHAIN_ID, snapshot.chainId],
      [LABEL_UNIVOCITY, snapshot.univocity],
      [LABEL_LOG_ID, snapshot.logId],
      [LABEL_SIZE, snapshot.size],
      [LABEL_ACCUMULATOR, snapshot.accumulator],
      [LABEL_BLOCK_NUMBER, snapshot.blockNumber],
      [LABEL_BLOCK_HASH, snapshot.blockHash],
    ]),
  );
}

function asBigint(v: unknown, what: string): bigint {
  if (typeof v === "bigint") return v;
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0)
    return BigInt(v);
  throw new Error(`known accumulator: ${what} must be an unsigned integer`);
}

function asBytes(v: unknown, length: number, what: string): Uint8Array {
  if (!(v instanceof Uint8Array) || v.length !== length) {
    throw new Error(`known accumulator: ${what} must be ${length} bytes`);
  }
  return v;
}

/** Strict decode + shape validation of a snapshot artifact. */
export function decodeKnownAccumulator(bytes: Uint8Array): KnownAccumulator {
  let decoded: unknown;
  try {
    decoded = decodeCborDeterministic(bytes);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`known accumulator is not canonical CBOR: ${message}`);
  }
  if (!(decoded instanceof Map)) {
    throw new Error("known accumulator must be a CBOR map");
  }
  const version = Number(asBigint(decoded.get(LABEL_VERSION), "version"));
  if (version !== SNAPSHOT_VERSION) {
    throw new Error(`known accumulator version ${version} not supported`);
  }
  const accRaw = decoded.get(LABEL_ACCUMULATOR);
  if (!Array.isArray(accRaw)) {
    throw new Error("known accumulator: accumulator must be an array");
  }
  const accumulator = accRaw.map((p, i) =>
    asBytes(p, 32, `accumulator peak ${i}`),
  );
  return {
    version,
    chainId: asBigint(decoded.get(LABEL_CHAIN_ID), "chainId"),
    univocity: asBytes(decoded.get(LABEL_UNIVOCITY), 20, "univocity"),
    logId: asBytes(decoded.get(LABEL_LOG_ID), 32, "logId"),
    size: asBigint(decoded.get(LABEL_SIZE), "size"),
    accumulator,
    blockNumber: asBigint(decoded.get(LABEL_BLOCK_NUMBER), "blockNumber"),
    blockHash: asBytes(decoded.get(LABEL_BLOCK_HASH), 32, "blockHash"),
  };
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Reject a snapshot whose binding does not match the caller's stated target
 * BEFORE any peak math — a snapshot for the wrong log or contract must never
 * be silently accepted as an anchor.
 */
export function assertSnapshotBinding(
  snapshot: KnownAccumulator,
  opts: { univocity?: string | undefined; logId?: string | undefined },
): void {
  if (opts.univocity !== undefined) {
    const given = normalizeHexAddress(opts.univocity);
    if (given === null || given !== bytesToHex(snapshot.univocity)) {
      throw new Error(
        `known accumulator is bound to univocity 0x${bytesToHex(snapshot.univocity)}, not --univocity ${opts.univocity}`,
      );
    }
  }
  if (opts.logId !== undefined) {
    const given = toContractLogId(opts.logId).slice(2);
    if (given !== bytesToHex(snapshot.logId)) {
      throw new Error(
        `known accumulator is bound to log 0x${bytesToHex(snapshot.logId)}, not --log-id ${opts.logId}`,
      );
    }
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let x = 0;
  for (let i = 0; i < a.length; i++) x |= a[i]! ^ b[i]!;
  return x === 0;
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
