import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/**
 * `forestrie fetch-ks256-attestation` (plan-2610-03 D4): ask a KS256 contract
 * root (a Safe) over ERC-1271 whether it signs the receipt's delegation
 * certificate, and cache the block-bound answer as a `--ks256-attestation`
 * artifact for offline `verify`. The twin of `fetch-accumulator`.
 */
export type FetchKs256AttestationOptions = ForestrieCommonOptions & {
  /** Receipt whose label-1000 KS256 delegation certificate is attested. */
  receipt: string;
  /** Contract root address override (`0x` + 40 hex). */
  root: string | undefined;
  /** Forest genesis: supplies the KS256 root (unless `--root`) and chain id. */
  genesis: string | undefined;
  /** JSON-RPC endpoint (`RPC_URL`) — the trusted chain reader. */
  rpcUrl: string;
  /** Block to pin the calls to; `latest` resolves to the current block. */
  block: bigint | "latest";
  /** Output path for the attestation CBOR. */
  out: string;
};

export function parseFetchKs256AttestationOptions(
  args: LooseParsedArgs,
): FetchKs256AttestationOptions {
  const root = optionalStringOption(args, "root");
  const genesis = optionalStringOption(args, "genesis");
  if (root === undefined && genesis === undefined) {
    throw new Error(
      "--root (contract address) and/or --genesis (KS256 bootstrap root) is required",
    );
  }
  const blockRaw = optionalStringOption(args, "block") ?? "latest";
  let block: bigint | "latest";
  if (blockRaw === "latest") {
    block = "latest";
  } else {
    try {
      block = BigInt(blockRaw);
    } catch {
      throw new Error("--block must be a block number or 'latest'");
    }
    if (block < 0n) throw new Error("--block must be a non-negative block number");
  }
  return {
    ...parseForestrieCommonOptions(args),
    receipt: requiredStringOption(args, "receipt"),
    root,
    genesis,
    rpcUrl: requiredStringOption(args, "rpc-url", "RPC_URL"),
    block,
    out: requiredStringOption(args, "out"),
  };
}
