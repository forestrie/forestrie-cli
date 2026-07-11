import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/**
 * `forestrie create-receipt` — FOR-345.
 *
 * Two anchor modes:
 * - `checkpoint`: attach the locally-rebuilt leaf→peak path to the
 *   pre-signed peak receipt from a format-v3 checkpoint — bytes identical
 *   to an API-issued receipt, no operator call.
 * - `chain`: verify the computed peak against the on-chain accumulator
 *   (`--univocity` + `--log-id` + `--rpc-url`) — no operator, only the
 *   contract (FOR-334 variant B).
 */
export type CreateReceiptOptions = ForestrieCommonOptions & {
  anchor: "checkpoint" | "chain";
  /** Massif .log blob holding the leaf and its proof nodes. */
  massif: string;
  /** MMR index of the leaf to prove. */
  mmrIndex: number;
  /** Checkpoint (.sth) with pre-signed peak receipts (checkpoint mode). */
  checkpoint: string | undefined;
  /** ImutableUnivocity contract address (chain mode). */
  univocity: string | undefined;
  /** Log id for the on-chain accumulator read (chain mode). */
  logId: string | undefined;
  /** JSON-RPC endpoint (`RPC_URL`, chain mode). */
  rpcUrl: string | undefined;
  /** Receipt output path (default: stdout). */
  out: string | undefined;
};

export function parseCreateReceiptOptions(
  args: LooseParsedArgs,
): CreateReceiptOptions {
  const raw = requiredStringOption(args, "mmr-index");
  const mmrIndex = Number(raw);
  if (!Number.isInteger(mmrIndex) || mmrIndex < 0) {
    throw new Error(
      `invalid --mmr-index '${raw}' (expected a non-negative integer)`,
    );
  }
  const checkpoint = optionalStringOption(args, "checkpoint");
  const univocity = optionalStringOption(args, "univocity");
  const logId = optionalStringOption(args, "log-id");
  const rpcUrl = optionalStringOption(args, "rpc-url", "RPC_URL");

  let anchor: CreateReceiptOptions["anchor"];
  if (checkpoint !== undefined && univocity === undefined) {
    anchor = "checkpoint";
  } else if (checkpoint === undefined && univocity !== undefined) {
    if (logId === undefined || rpcUrl === undefined) {
      throw new Error(
        "chain-anchored mode requires --univocity, --log-id and --rpc-url",
      );
    }
    anchor = "chain";
  } else {
    throw new Error(
      "exactly one of --checkpoint (offline) or --univocity (chain-anchored) is required",
    );
  }

  return {
    ...parseForestrieCommonOptions(args),
    anchor,
    massif: requiredStringOption(args, "massif"),
    mmrIndex,
    checkpoint,
    univocity,
    logId,
    rpcUrl,
    out: optionalStringOption(args, "out"),
  };
}
