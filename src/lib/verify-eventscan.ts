/**
 * Historical anchor scan over `CheckpointPublished` events (FOR-368
 * Phase 2, plan-2607-29).
 *
 * Univocity's `publishCheckpoint` verifies consistency from the current
 * on-chain state before accepting a new accumulator, so **every anchored
 * accumulator is a committed prefix of every later one**. A receipt whose
 * recomputed peak appears in ANY historical anchored accumulator is
 * therefore proven — consistency to the present is carried by the
 * contract, not by a client-side grow proof. The event log is the durable
 * record of those accumulators (`CheckpointPublished` carries `size` and
 * `accumulator`; the contract stores nothing retrievable historically).
 *
 * This rung depends only on public blockchain data — deliberately
 * independent of the log store (the retained-checkpoint chain rung is its
 * complement with the opposite dependency; see plan-2607-29).
 */
import { normalizeHexAddress } from "@forestrie/chain-rpc";
import { toContractLogId } from "./verify-anchored.js";

/**
 * keccak256 of
 * `CheckpointPublished(bytes32,bytes32,bytes,address,bytes8,uint8,uint64,bytes32[],uint64,bytes32[])`
 * (univocity `IUnivocityEvents.sol`). The contract is immutable per forest,
 * so this signature is stable for every deployed instance.
 */
export const CHECKPOINT_PUBLISHED_TOPIC0 =
  "0x156942b408823cb05a16027962ea485fa7171d99779ee04094280b2569482426";

export type PublishedCheckpoint = {
  /** Anchored MMR size. */
  size: bigint;
  /** Anchored accumulator peaks (32 bytes each), contract order. */
  accumulator: Uint8Array[];
  /** Block the anchor landed in. */
  blockNumber: bigint;
  /** Transaction that published it. */
  txHash: string;
  /** Hash of that block (falsifiability handle for the snapshot). */
  blockHash: string;
};

export type HistoricalAnchor = PublishedCheckpoint & {
  /** Index of the matching accumulator peak. */
  matchedPeak: number;
};

type EthLog = {
  data?: string;
  blockNumber?: string;
  transactionHash?: string;
  blockHash?: string;
};

function readWord(hex: string, wordIndex: number): bigint {
  const start = wordIndex * 64;
  if (hex.length < start + 64) {
    throw new Error(
      `CheckpointPublished data too short: need word ${wordIndex}, have ${hex.length} hex chars`,
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
 * Decode the non-indexed `CheckpointPublished` fields we need. Data layout
 * (ABI, after the three indexed params): word0 `sender`, word1
 * `grantIDTimestampBe` (padded bytes8), word2 `logKind`, word3 `size`,
 * word4 offset→`accumulator`, word5 `grantIndex`, word6 offset→`grantPath`.
 */
export function decodeCheckpointPublishedData(dataHex: string): {
  size: bigint;
  accumulator: Uint8Array[];
} {
  const hex = dataHex.replace(/^0x/, "");
  const size = readWord(hex, 3);
  const accumulatorOffset = readWord(hex, 4);
  const arrayBase = Number(accumulatorOffset) / 32;
  const length = Number(readWord(hex, arrayBase));
  const accumulator: Uint8Array[] = [];
  for (let i = 0; i < length; i++) {
    const start = (arrayBase + 1 + i) * 64;
    if (hex.length < start + 64) {
      throw new Error(
        `CheckpointPublished accumulator truncated at peak ${i} of ${length}`,
      );
    }
    accumulator.push(hexToBytes(hex.slice(start, start + 64)));
  }
  return { size, accumulator };
}

/** Minimal JSON-RPC fetch (mirrors fetch-accumulator's raw pattern). */
async function rpc(
  rpcUrl: string,
  method: string,
  params: unknown[],
  fetchImpl: typeof fetch,
): Promise<unknown> {
  const res = await fetchImpl(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!res.ok) {
    throw new Error(`${method}: HTTP ${res.status}`);
  }
  const body = (await res.json()) as { result?: unknown; error?: { message?: string } };
  if (body.error) {
    throw new Error(`${method}: ${body.error.message ?? "rpc error"}`);
  }
  return body.result;
}

/**
 * Fetch every `CheckpointPublished` for a log (topic1 = contract log id),
 * ascending block order as returned by `eth_getLogs`.
 */
export async function fetchPublishedCheckpoints(opts: {
  univocity: string;
  logId: string;
  rpcUrl: string;
  /** First block to scan (the forest's deploy block bounds the range). */
  fromBlock?: bigint | undefined;
  fetchImpl?: typeof fetch;
}): Promise<PublishedCheckpoint[]> {
  const address = normalizeHexAddress(opts.univocity);
  if (address === null) {
    throw new Error(`--univocity is not a valid address: '${opts.univocity}'`);
  }
  const logs = (await rpc(
    opts.rpcUrl,
    "eth_getLogs",
    [
      {
        address: `0x${address}`,
        fromBlock:
          opts.fromBlock !== undefined
            ? `0x${opts.fromBlock.toString(16)}`
            : "earliest",
        toBlock: "latest",
        topics: [CHECKPOINT_PUBLISHED_TOPIC0, toContractLogId(opts.logId)],
      },
    ],
    opts.fetchImpl ?? fetch,
  )) as EthLog[] | null;
  const out: PublishedCheckpoint[] = [];
  for (const log of logs ?? []) {
    if (!log.data) continue;
    const { size, accumulator } = decodeCheckpointPublishedData(log.data);
    out.push({
      size,
      accumulator,
      blockNumber: BigInt(log.blockNumber ?? "0x0"),
      txHash: log.transactionHash ?? "",
      blockHash: log.blockHash ?? "",
    });
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let x = 0;
  for (let i = 0; i < a.length; i++) x |= a[i]! ^ b[i]!;
  return x === 0;
}

/**
 * Find the recomputed receipt peak in any historically anchored
 * accumulator. Newest-first: recent anchors are the likeliest cover for a
 * recently buried peak, and the freshest match gives the most useful
 * report. A match at ANY anchored state proves the receipt: univocity's
 * consistency gating commits it forward to the present.
 */
export async function findPeakInPublishedHistory(opts: {
  peak: Uint8Array;
  univocity: string;
  logId: string;
  rpcUrl: string;
  fromBlock?: bigint | undefined;
  fetchImpl?: typeof fetch;
}): Promise<HistoricalAnchor | null> {
  const published = await fetchPublishedCheckpoints(opts);
  for (let i = published.length - 1; i >= 0; i--) {
    const cp = published[i]!;
    for (let p = 0; p < cp.accumulator.length; p++) {
      if (bytesEqual(opts.peak, cp.accumulator[p]!)) {
        return { ...cp, matchedPeak: p };
      }
    }
  }
  return null;
}

/**
 * Latest anchored state at or before `atBlock` (FOR-368 Phase 2:
 * `fetch-accumulator --at-block`): historical snapshots come from the
 * event record, so no archive-state RPC is needed.
 */
export function selectPublishedAtBlock(
  published: PublishedCheckpoint[],
  atBlock: bigint,
): PublishedCheckpoint | null {
  let best: PublishedCheckpoint | null = null;
  for (const cp of published) {
    if (cp.blockNumber > atBlock) continue;
    if (best === null || cp.blockNumber > best.blockNumber) best = cp;
  }
  return best;
}
