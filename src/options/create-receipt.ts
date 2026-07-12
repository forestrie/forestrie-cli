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
 *   pre-signed peak receipt from a format-v3 checkpoint —
 *   verify-equivalent with an API-issued receipt, no operator call.
 * - `chain`: verify the computed peak against the on-chain accumulator
 *   (`--univocity` + `--log-id` + `--rpc-url`) — no operator, only the
 *   contract (FOR-334 variant B; plan-2607-15 phase 2).
 *
 * Leaf addressing (exactly one):
 * - `--mmr-index`: the leaf's MMR index directly;
 * - `--entry-id`: the permanent SCRAPI entry id (32 hex chars =
 *   idtimestamp_be8 || mmrIndex_be8) — the mmrIndex is decoded from its
 *   second half, no index-region lookup needed.
 */
export type CreateReceiptOptions = ForestrieCommonOptions & {
  anchor: "checkpoint" | "chain";
  /** Massif .log blob holding the leaf and its proof nodes. */
  massif: string;
  /** MMR index of the leaf to prove (`--mmr-index` addressing). */
  mmrIndex: bigint | undefined;
  /** Permanent SCRAPI entry id (`--entry-id` addressing). */
  entryId: string | undefined;
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

function parseMMRIndex(raw: string): bigint {
  if (!/^\d+$/.test(raw)) {
    throw new Error(
      `invalid --mmr-index '${raw}' (expected a non-negative integer)`,
    );
  }
  return BigInt(raw);
}

export function parseCreateReceiptOptions(
  args: LooseParsedArgs,
): CreateReceiptOptions {
  const rawMMRIndex = optionalStringOption(args, "mmr-index");
  const entryId = optionalStringOption(args, "entry-id");
  if ((rawMMRIndex === undefined) === (entryId === undefined)) {
    throw new Error(
      "exactly one of --mmr-index or --entry-id is required to address the leaf",
    );
  }
  const mmrIndex =
    rawMMRIndex !== undefined ? parseMMRIndex(rawMMRIndex) : undefined;

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
    entryId,
    checkpoint,
    univocity,
    logId,
    rpcUrl,
    out: optionalStringOption(args, "out"),
  };
}
