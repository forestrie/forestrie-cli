import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";
import { durationOptionMs } from "./register.js";

/**
 * Default anchoring budget (`--timeout`), seconds: a log anchors at its
 * owner's next published checkpoint, which is minutes away at most.
 */
export const DEFAULT_ANCHOR_TIMEOUT_SECONDS = 600;
/** Default pacing between chain reads (`--interval`), seconds. */
export const DEFAULT_ANCHOR_INTERVAL_SECONDS = 10;

/** Where and how long to wait for a log to anchor. */
export type AnchorWaitOptions = {
  /**
   * Forest genesis (genesis.cbor). Alone, it names a forest root to wait
   * for; with a child's create grant it binds the contract and chain.
   */
  genesis: string | undefined;
  /** Univocity contract; defaults to the genesis's. */
  univocity: string | undefined;
  /** JSON-RPC endpoint for the contract's chain (`RPC_URL`). */
  rpcUrl: string;
  /** Overall budget, milliseconds. */
  timeoutMs: number;
  /** Pacing between chain reads, milliseconds. */
  intervalMs: number;
};

/** `forestrie log wait-anchored`. */
export type LogWaitAnchoredOptions = ForestrieCommonOptions &
  AnchorWaitOptions & {
    /**
     * File holding a child log's completed create grant, base64, as
     * `create-log --out-b64` writes it.
     */
    createGrant: string | undefined;
    /**
     * The create grant's SCRAPI receipt URL, as `create-log` prints it.
     * Each round re-fetches the receipt there, so a log anchors even when
     * the seal its first receipt came from never reached the chain.
     */
    receiptUrl: string | undefined;
  };

/**
 * The anchoring flags `log wait-anchored` and `create-log --wait-anchored`
 * share; only the budget flags' names differ.
 */
export function parseAnchorWaitOptions(
  args: LooseParsedArgs,
  budgetFlags: { timeout: string; interval: string },
): AnchorWaitOptions {
  const genesis = optionalStringOption(args, "genesis");
  const univocity = optionalStringOption(args, "univocity");
  if (univocity === undefined && genesis === undefined) {
    throw new Error(
      "pass --univocity or --genesis (whose contract it names) to read the chain",
    );
  }
  return {
    genesis,
    univocity,
    rpcUrl: requiredStringOption(args, "rpc-url", "RPC_URL"),
    timeoutMs: durationOptionMs(
      args,
      budgetFlags.timeout,
      DEFAULT_ANCHOR_TIMEOUT_SECONDS,
    ),
    intervalMs: durationOptionMs(
      args,
      budgetFlags.interval,
      DEFAULT_ANCHOR_INTERVAL_SECONDS,
    ),
  };
}

export function parseLogWaitAnchoredOptions(
  args: LooseParsedArgs,
): LogWaitAnchoredOptions {
  const createGrant = optionalStringOption(args, "create-grant");
  if (createGrant === undefined && optionalStringOption(args, "genesis") === undefined) {
    throw new Error(
      "pass --create-grant (a child log's completed create grant) or --genesis (a forest root)",
    );
  }
  const receiptUrl = optionalStringOption(args, "receipt-url");
  if (receiptUrl !== undefined && createGrant === undefined) {
    throw new Error(
      "--receipt-url needs --create-grant: it refreshes a child log's create grant receipt",
    );
  }
  return {
    ...parseForestrieCommonOptions(args),
    createGrant,
    receiptUrl,
    ...parseAnchorWaitOptions(args, { timeout: "timeout", interval: "interval" }),
  };
}
