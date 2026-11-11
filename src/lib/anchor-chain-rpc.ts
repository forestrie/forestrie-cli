/**
 * The univocity contract reads `forestrie log wait-anchored` needs, over
 * JSON-RPC (`@forestrie/chain-rpc`). Public chain data only: the contract's
 * views, its code, and the `publishCheckpoint` calldata of a log's
 * `CheckpointPublished` transactions. Contract ABI: univocity
 * `src/interfaces/IUnivocity.sol`.
 */
import {
  ethCall,
  ethRpc,
  hasContractCodeAt,
  normalizeHexAddress,
} from "@forestrie/chain-rpc";
import { decodeAbiParameters, type Hex } from "viem";
import type { AnchorChain, PublishedStep } from "./anchor-wait.js";
import { calldataCheckpointChain } from "./checkpoint-provider.js";
import { fetchOnChainLogState } from "./verify-anchored.js";

/** `bootstrapConfig()` → `(int64 bootstrapAlg, bytes bootstrapKey)`. */
const BOOTSTRAP_CONFIG_SELECTOR = "0x198865fe";
/** `rootLogId()` → `bytes32`, zero until the root's first checkpoint. */
const ROOT_LOG_ID_SELECTOR = "0x72b76e4d";

export function rpcAnchorChain(opts: {
  univocity: string;
  rpcUrl: string;
  fetchImpl?: typeof fetch;
}): AnchorChain {
  const address = normalizeHexAddress(opts.univocity);
  if (address === null) {
    throw new Error(`--univocity is not a valid address: '${opts.univocity}'`);
  }
  const rpc = opts.fetchImpl !== undefined ? { fetchImpl: opts.fetchImpl } : {};
  const call = async (selector: string): Promise<Hex> => {
    const result = await ethCall(opts.rpcUrl, `0x${address}`, selector, rpc);
    if (typeof result !== "string" || !result.startsWith("0x")) {
      throw new Error(`eth_call ${selector} returned no data`);
    }
    return result as Hex;
  };
  return {
    logState: (logId) =>
      fetchOnChainLogState({
        univocity: opts.univocity,
        logId,
        rpcUrl: opts.rpcUrl,
        ...rpc,
      }),
    async publishedSteps(logId): Promise<PublishedStep[]> {
      const links = await calldataCheckpointChain({
        univocity: opts.univocity,
        logId,
        rpcUrl: opts.rpcUrl,
        ...rpc,
      });
      return links.map((l) => ({ size: l.treeSize2, accumulator: l.accumulator }));
    },
    hasCode: () => hasContractCodeAt(opts.rpcUrl, address, rpc),
    async bootstrapConfig() {
      const [alg, key] = decodeAbiParameters(
        [{ type: "int64" }, { type: "bytes" }],
        await call(BOOTSTRAP_CONFIG_SELECTOR),
      );
      return { alg, key: Buffer.from(key.slice(2), "hex") };
    },
    async rootLogId() {
      const [word] = decodeAbiParameters(
        [{ type: "bytes32" }],
        await call(ROOT_LOG_ID_SELECTOR),
      );
      const hex = word.slice(2).toLowerCase();
      if (/^0+$/.test(hex)) return undefined;
      // Log ids are UUIDs in the low 16 bytes. Anything wider is some
      // other log, named in full so it can never equal a UUID.
      if (!/^0{32}/.test(hex)) return `0x${hex}`;
      const u = hex.slice(32);
      return `${u.slice(0, 8)}-${u.slice(8, 12)}-${u.slice(12, 16)}-${u.slice(16, 20)}-${u.slice(20)}`;
    },
    async chainId() {
      const v = await ethRpc(opts.rpcUrl, "eth_chainId", [], rpc);
      if (typeof v !== "string" || !/^0x[0-9a-fA-F]+$/.test(v)) {
        throw new Error(`eth_chainId: expected a hex quantity, got ${String(v)}`);
      }
      return BigInt(v);
    },
  };
}
