import { bytesEqual } from "./bytes.js";
import { ethCall, normalizeHexAddress } from "@forestrie/chain-rpc";
import { verifyCoseSign1WithParsedKey } from "@forestrie/encoding";
import {
  calculateRoot,
  verifyInclusion,
  type Hasher,
} from "@forestrie/merklelog";
import {
  decodeTrustRootFromGenesis,
  parseReceipt,
} from "@forestrie/receipt-verify";

/**
 * Chain-anchored receipt check (FOR-347 / demo step 5a): read the
 * Univocity `logState(bytes32)` accumulator over JSON-RPC and assert the
 * receipt's peak is one of the anchored accumulator peaks. This is the
 * ONLY networked path in `forestrie verify`; the core verify stays pure
 * over bytes.
 *
 * Anchoring test: for a detached-payload receipt the checkpoint signature
 * covers the peak (COSE detached content), so the peak the receipt commits
 * to is exactly the one the signature verifies over. We therefore try the
 * genesis trust key against each on-chain accumulator peak as the detached
 * payload — a match proves the signed peak is on-chain, and the offline
 * verify already proved leaf inclusion under that same signed peak. For an
 * attached-payload receipt the peak is explicit and byte-compared.
 */

/** Selector for `logState(bytes32)` (arbor publishproof Univocity ABI). */
const LOG_STATE_SELECTOR = "0xeecac1b7";

export type OnChainLogState = {
  /** Anchored accumulator peaks (32 bytes each), contract order. */
  accumulator: Uint8Array[];
  /** Anchored MMR size. */
  size: bigint;
};

export type AnchorCheck = OnChainLogState & {
  /** True when the receipt's peak is one of the anchored accumulator peaks. */
  anchored: boolean;
  /** Index of the matched accumulator peak, or null. */
  matchedPeak: number | null;
  /** Stable failure token when not anchored. */
  reason?: string;
};

/**
 * Classify an unanchored peak so honest receipts never fail tamper-shaped
 * (FOR-368 Phase 0, plan-2607-29):
 * - the leaf predates the anchored size but its peak is absent — the log
 *   grew and BURIED the peak (`peak_not_current`): an honest-receipt
 *   condition needing growth evidence, not a tamper verdict;
 * - the leaf is at/after the anchored size — the entry simply is not
 *   anchored yet (`receipt_newer_than_anchored_state`).
 * Tampered receipts surface earlier (signature/inclusion) or as a
 * recomputed peak that matches no anchored state ever; the chain rungs
 * that PROVE the buried case land in later plan phases.
 */
export function classifyUnanchoredPeak(
  leafMmrIndex: bigint,
  anchoredSize: bigint,
): string {
  if (leafMmrIndex >= anchoredSize) {
    return "receipt_newer_than_anchored_state";
  }
  return "peak_not_current";
}

/** Leaf MMR index from a parsed receipt proof. */
export function receiptLeafIndex(receiptCbor: Uint8Array): bigint {
  const { proof } = parseReceipt(receiptCbor);
  return proof.leafIndex !== undefined ? proof.leafIndex : proof.mmrIndex!;
}

/**
 * Normalize a log id (UUID with dashes, 32-hex UUID form, or 64-hex
 * contract form) to the 32-byte contract key: Univocity stores logs with
 * the UUID in the low 16 bytes, zero-padded on the left.
 */
export function toContractLogId(logId: string): string {
  const hex = logId.replace(/-/g, "").replace(/^0x/, "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex) && !/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error(
      `--log-id must be a UUID or 16/32-byte hex id, got '${logId}'`,
    );
  }
  return "0x" + hex.padStart(64, "0");
}

function readWord(hex: string, wordIndex: number): bigint {
  const start = wordIndex * 64;
  if (hex.length < start + 64) {
    throw new Error(
      `logState result too short: need word ${wordIndex}, have ${hex.length} hex chars`,
    );
  }
  return BigInt("0x" + hex.slice(start, start + 64));
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Decode the `logState(bytes32)` return — the dynamic tuple
 * `(bytes32[] accumulator, uint64 size)`: word0 = offset to the tuple,
 * then relative to the tuple start: word = offset to the accumulator
 * array, word = `size`, and the array as length + elements.
 */
export function decodeLogStateResult(resultHex: string): OnChainLogState {
  const hex = resultHex.replace(/^0x/, "");
  if (hex.length === 0) {
    throw new Error("logState returned empty result (log not found?)");
  }
  const tupleOffset = readWord(hex, 0);
  const base = Number(tupleOffset) / 32; // word index of the tuple start
  const accumulatorOffset = readWord(hex, base);
  const size = readWord(hex, base + 1);
  const arrayBase = base + Number(accumulatorOffset) / 32;
  const length = Number(readWord(hex, arrayBase));
  const accumulator: Uint8Array[] = [];
  for (let i = 0; i < length; i++) {
    const start = (arrayBase + 1 + i) * 64;
    if (hex.length < start + 64) {
      throw new Error(
        `logState accumulator truncated at peak ${i} of ${length}`,
      );
    }
    accumulator.push(hexToBytes(hex.slice(start, start + 64)));
  }
  return { accumulator, size };
}

/** `eth_call` `logState(logId)` via `@forestrie/chain-rpc`. */
export async function fetchOnChainLogState(opts: {
  univocity: string;
  logId: string;
  rpcUrl: string;
}): Promise<OnChainLogState> {
  const address = normalizeHexAddress(opts.univocity);
  if (address === null) {
    throw new Error(`--univocity is not a valid address: '${opts.univocity}'`);
  }
  const data = LOG_STATE_SELECTOR + toContractLogId(opts.logId).slice(2);
  const result = await ethCall(opts.rpcUrl, `0x${address}`, data);
  if (typeof result !== "string" || result === "0x") {
    throw new Error(
      `logState eth_call returned no data for log ${opts.logId} at ${opts.univocity}`,
    );
  }
  return decodeLogStateResult(result);
}


/** Web Crypto SHA-256 hasher (mirrors @forestrie/receipt-verify SubtleHasher). */
class SubtleHasher implements Hasher {
  private chunks: Uint8Array[] = [];
  reset(): void {
    this.chunks = [];
  }
  update(data: Uint8Array): void {
    this.chunks.push(data);
  }
  async digest(): Promise<Uint8Array> {
    const total = this.chunks.reduce((s, c) => s + c.length, 0);
    const combined = new Uint8Array(total);
    let offset = 0;
    for (const c of this.chunks) {
      combined.set(c, offset);
      offset += c.length;
    }
    return new Uint8Array(await crypto.subtle.digest("SHA-256", combined));
  }
}

/**
 * Univocity leaf commitment: `SHA-256(idtimestamp_be8 ‖ inner)` where `inner`
 * is the leaf ContentHash (`SHA-256(payload)` for a statement leaf, the grant
 * commitment hash for a grant leaf). Mirrors
 * `@forestrie/receipt-verify` `univocityLeafHash` (not exported there); hoist
 * to the library when the FOR-297 multi-hop resolver lands.
 */
export async function univocityLeafHash(
  idtimestampBe8: Uint8Array,
  inner: Uint8Array,
): Promise<Uint8Array> {
  if (idtimestampBe8.length < 8) {
    throw new Error("idtimestamp must be at least 8 bytes");
  }
  const id8 =
    idtimestampBe8.length > 8 ? idtimestampBe8.slice(-8) : idtimestampBe8;
  const preimage = new Uint8Array(8 + inner.length);
  preimage.set(id8);
  preimage.set(inner, 8);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", preimage));
}

export type RecomputedPeak = {
  /** The accumulator peak the leaf's inclusion proof commits to. */
  peak: Uint8Array;
  /**
   * True when the proof path checks out: always for a detached receipt (the
   * peak IS the path recomputation), byte-verified for an attached peak.
   */
  inclusionOk: boolean;
};

/**
 * Recompute the receipt's accumulator peak from the leaf commitment and the
 * receipt's own inclusion proof — pure bytes, NO signature involved. This is
 * the signature-free half of chain-anchored verification (FOR-297 approach C):
 * `leaf = SHA-256(idtimestamp ‖ inner)`, walk the label-396 proof path to the
 * peak, then the caller matches that peak against the on-chain accumulator.
 * Binding and inclusion are inherent: a wrong payload or tampered path yields
 * a peak that cannot appear in the anchored accumulator.
 */
export async function recomputeReceiptPeak(opts: {
  receiptCbor: Uint8Array;
  idtimestampBe8: Uint8Array;
  /** Leaf ContentHash: SHA-256(payload) or the grant commitment hash. */
  inner: Uint8Array;
}): Promise<RecomputedPeak> {
  const { explicitPeak, proof } = parseReceipt(opts.receiptCbor);
  const leafHash = await univocityLeafHash(opts.idtimestampBe8, opts.inner);
  const hasher = new SubtleHasher();
  const leafIdx =
    proof.leafIndex !== undefined ? proof.leafIndex : proof.mmrIndex!;
  if (explicitPeak !== null) {
    const inclusionOk = await verifyInclusion(
      hasher,
      leafHash,
      proof,
      explicitPeak,
    );
    return { peak: explicitPeak, inclusionOk };
  }
  const peak = await calculateRoot(hasher, leafHash, proof, leafIdx);
  return { peak, inclusionOk: true };
}

/**
 * Assert the receipt's peak is anchored in the on-chain accumulator.
 * Two peak-location strategies:
 * - default (offline verify passed): a detached receipt's peak is located by
 *   trying the genesis trust key against each on-chain peak as the detached
 *   payload; an attached peak is byte-compared.
 * - `recomputedPeak` (anchor-only, FOR-297 approach C): the caller recomputed
 *   the peak from leaf + proof via {@link recomputeReceiptPeak}; byte-compare
 *   it directly — no signature, no trust key. Trust is the contract anchor.
 */
export async function checkReceiptAnchored(opts: {
  /** Required unless `recomputedPeak` locates the peak without a trust key. */
  genesisCbor: Uint8Array | undefined;
  receiptCbor: Uint8Array;
  univocity: string;
  logId: string;
  rpcUrl: string;
  recomputedPeak?: Uint8Array;
}): Promise<AnchorCheck> {
  if (opts.recomputedPeak !== undefined) {
    const state = await fetchOnChainLogState(opts);
    let matchedPeak: number | null = null;
    for (let i = 0; i < state.accumulator.length; i++) {
      if (bytesEqual(opts.recomputedPeak, state.accumulator[i]!)) {
        matchedPeak = i;
        break;
      }
    }
    const anchored = matchedPeak !== null;
    return {
      ...state,
      anchored,
      matchedPeak,
      ...(anchored
        ? {}
        : {
            reason: classifyUnanchoredPeak(
              receiptLeafIndex(opts.receiptCbor),
              state.size,
            ),
          }),
    };
  }

  const { explicitPeak } = parseReceipt(opts.receiptCbor);
  if (opts.genesisCbor === undefined) {
    throw new Error(
      "genesis is required to locate the receipt peak on-chain without a recomputed peak",
    );
  }
  const trustRoot = await decodeTrustRootFromGenesis(opts.genesisCbor);
  if (explicitPeak === null && !(trustRoot instanceof CryptoKey)) {
    // Detached receipts locate their peak via the ES256 signature; a
    // KS256 root cannot verify here (same surface as `no_es256_trust_key`).
    return {
      accumulator: [],
      size: 0n,
      anchored: false,
      matchedPeak: null,
      reason: "no_es256_trust_key",
    };
  }

  const state = await fetchOnChainLogState(opts);

  let matchedPeak: number | null = null;
  for (let i = 0; i < state.accumulator.length; i++) {
    const peak = state.accumulator[i]!;
    if (explicitPeak !== null) {
      if (bytesEqual(explicitPeak, peak)) {
        matchedPeak = i;
        break;
      }
    } else if (
      await verifyCoseSign1WithParsedKey(opts.receiptCbor, trustRoot as CryptoKey, {
        detachedPayload: peak,
      })
    ) {
      matchedPeak = i;
      break;
    }
  }

  const anchored = matchedPeak !== null;
  return {
    ...state,
    anchored,
    matchedPeak,
    ...(anchored
      ? {}
      : {
          reason: classifyUnanchoredPeak(
            receiptLeafIndex(opts.receiptCbor),
            state.size,
          ),
        }),
  };
}
