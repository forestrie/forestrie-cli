import { writeFileSync } from "node:fs";
import type { Out } from "@forestrie/cli-kit/reporting";
import { ethRpc, hexAddressToBytes, normalizeHexAddress } from "@forestrie/chain-rpc";
import type { FetchAccumulatorOptions } from "../options/fetch-accumulator.js";
import { decodeLogStateResult, toContractLogId } from "../lib/verify-anchored.js";
import {
  encodeKnownAccumulator,
  type KnownAccumulator,
} from "../lib/verify-known-accumulator.js";
import {
  fetchPublishedCheckpoints,
  selectPublishedAtBlock,
} from "../lib/verify-eventscan.js";

/** Selector for `logState(bytes32)` (mirrors verify-anchored). */
const LOG_STATE_SELECTOR = "0xeecac1b7";

/** `--json` success shape on stdout — stable for demo scripting. */
export type FetchAccumulatorReport = {
  command: "fetch-accumulator";
  chainId: string;
  univocity: string;
  logId: string;
  anchoredSize: string;
  peakCount: number;
  blockNumber: string;
  blockHash: string;
  out: string;
};

export type FetchAccumulatorErrorReport = {
  error: "fetch_accumulator_failed";
  command: "fetch-accumulator";
  message: string;
};

function hexToBigint(v: unknown, what: string): bigint {
  if (typeof v !== "string" || !/^0x[0-9a-fA-F]+$/.test(v)) {
    throw new Error(`${what}: expected a hex quantity, got ${String(v)}`);
  }
  return BigInt(v);
}

function hexToBytes32(v: unknown, what: string): Uint8Array {
  if (typeof v !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(v)) {
    throw new Error(`${what}: expected a 32-byte hex value, got ${String(v)}`);
  }
  const hex = v.slice(2);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Read `logState(logId)` pinned to a specific block: fetch the latest block
 * header first, then `eth_call` AT that block number, so the snapshot's
 * `(blockNumber, blockHash)` binding is exact — the falsifiability handle
 * that lets anyone re-run the read and confirm or disprove the snapshot.
 */
export async function runFetchAccumulator(
  out: Out,
  options: FetchAccumulatorOptions,
): Promise<void> {
  try {
    const address = normalizeHexAddress(options.univocity);
    if (address === null) {
      throw new Error(
        `--univocity is not a valid address: '${options.univocity}'`,
      );
    }
    const contractLogId = toContractLogId(options.logId);

    const chainId = hexToBigint(
      await ethRpc(options.rpcUrl, "eth_chainId", []),
      "eth_chainId",
    );

    let state: { size: bigint; accumulator: Uint8Array[] };
    let blockNumber: bigint;
    let blockHash: Uint8Array;
    if (options.atBlock !== undefined) {
      // FOR-368: historical snapshot from the CheckpointPublished record —
      // events survive where contract state does not, so no archive node
      // is needed. The snapshot binds to the block the anchor landed in.
      const published = await fetchPublishedCheckpoints({
        univocity: options.univocity,
        logId: options.logId,
        rpcUrl: options.rpcUrl,
        fromBlock: options.fromBlock,
      });
      const chosen = selectPublishedAtBlock(published, options.atBlock);
      if (chosen === null) {
        throw new Error(
          `no CheckpointPublished at or before block ${options.atBlock} for log ${options.logId}` +
            (published.length > 0
              ? ` (earliest anchor is block ${published[0]!.blockNumber})`
              : " (no anchors found in the scanned range)"),
        );
      }
      state = { size: chosen.size, accumulator: chosen.accumulator };
      blockNumber = chosen.blockNumber;
      blockHash = hexToBytes32(chosen.blockHash, "event block hash");
    } else {
      const block = (await ethRpc(options.rpcUrl, "eth_getBlockByNumber", [
        "latest",
        false,
      ])) as { number?: unknown; hash?: unknown } | null;
      if (block === null || typeof block !== "object") {
        throw new Error("eth_getBlockByNumber returned no block");
      }
      blockNumber = hexToBigint(block.number, "block number");
      blockHash = hexToBytes32(block.hash, "block hash");

      const data = LOG_STATE_SELECTOR + contractLogId.slice(2);
      const result = await ethRpc(options.rpcUrl, "eth_call", [
        { to: `0x${address}`, data },
        `0x${blockNumber.toString(16)}`,
      ]);
      if (typeof result !== "string" || result === "0x") {
        throw new Error(
          `logState eth_call returned no data for log ${options.logId} at ${options.univocity}`,
        );
      }
      state = decodeLogStateResult(result);
    }

    const snapshot: KnownAccumulator = {
      version: 1,
      chainId,
      univocity: hexAddressToBytes(`0x${address}`),
      logId: hexToBytes32(contractLogId, "log id"),
      size: state.size,
      accumulator: state.accumulator,
      blockNumber,
      blockHash,
    };
    writeFileSync(options.out, encodeKnownAccumulator(snapshot));

    if (options.json) {
      const report: FetchAccumulatorReport = {
        command: "fetch-accumulator",
        chainId: chainId.toString(),
        univocity: `0x${address}`,
        logId: contractLogId,
        anchoredSize: state.size.toString(),
        peakCount: state.accumulator.length,
        blockNumber: blockNumber.toString(),
        blockHash: `0x${Array.from(blockHash, (b) =>
          b.toString(16).padStart(2, "0"),
        ).join("")}`,
        out: options.out,
      };
      out.out(JSON.stringify(report, null, 2));
    } else {
      out.print(
        "fetch-accumulator: read logState at block %s (chain %s)",
        blockNumber.toString(),
        chainId.toString(),
      );
      out.out(
        `wrote known accumulator: ${options.out} (anchored size ${state.size}, ${state.accumulator.length} peaks, block ${blockNumber})`,
      );
    }
    process.exitCode = 0;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (options.json) {
      const report: FetchAccumulatorErrorReport = {
        error: "fetch_accumulator_failed",
        command: "fetch-accumulator",
        message,
      };
      out.out(JSON.stringify(report, null, 2));
    } else {
      out.warn("forestrie fetch-accumulator: %s", message);
    }
    process.exitCode = 1;
  }
}
