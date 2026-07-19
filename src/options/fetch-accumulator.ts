import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/**
 * `forestrie fetch-accumulator` (FOR-297 D5): read the log's on-chain
 * `logState` and cache it as a structured snapshot artifact — the
 * `--known-accumulator` input for fully offline chain-anchored verification.
 * The snapshot binds `(chainId, univocity, logId, size, block)` so the read
 * is auditable and falsifiable: anyone with RPC can re-run it at that block.
 */
export type FetchAccumulatorOptions = ForestrieCommonOptions & {
  /** ImutableUnivocity contract address. */
  univocity: string;
  /** Log id (UUID or hex). */
  logId: string;
  /** JSON-RPC endpoint (`RPC_URL`) — the trusted chain reader. */
  rpcUrl: string;
  /** Output path for the snapshot CBOR. */
  out: string;
  /** Snapshot the latest anchored state at/before this block, sourced
   * from CheckpointPublished events (FOR-368; no archive node needed). */
  atBlock: bigint | undefined;
  /** Lower bound for the event scan (`--at-block` mode). */
  fromBlock: bigint | undefined;
};

function optionalBlockOption(
  args: LooseParsedArgs,
  name: string,
): bigint | undefined {
  const raw = optionalStringOption(args, name);
  if (raw === undefined) return undefined;
  let value: bigint;
  try {
    value = BigInt(raw);
  } catch {
    throw new Error(`--${name} must be a block number`);
  }
  if (value < 0n) {
    throw new Error(`--${name} must be a non-negative block number`);
  }
  return value;
}

export function parseFetchAccumulatorOptions(
  args: LooseParsedArgs,
): FetchAccumulatorOptions {
  return {
    ...parseForestrieCommonOptions(args),
    univocity: requiredStringOption(args, "univocity"),
    logId: requiredStringOption(args, "log-id"),
    rpcUrl: requiredStringOption(args, "rpc-url", "RPC_URL"),
    out: requiredStringOption(args, "out"),
    atBlock: optionalBlockOption(args, "at-block"),
    fromBlock: optionalBlockOption(args, "from-block"),
  };
}
