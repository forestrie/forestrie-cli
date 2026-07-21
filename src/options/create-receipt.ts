import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/**
 * `forestrie resolve-receipt` (alias `create-receipt`) — FOR-345 / FOR-418.
 *
 * ONE receipt producer; the source is chosen by the flags present, not a
 * `--mode` (plan-2607-32 D3). Three sources, mutually exclusive:
 *
 * - **tiles** (`--massif`): rebuild the leaf→peak path from a massif blob and
 *   either attach it to a checkpoint's pre-signed peak receipt (`--checkpoint`,
 *   offline) or verify the computed peak against the on-chain accumulator
 *   (`--univocity` + `--log-id` + `--rpc-url`, report-only). Leaf addressing:
 *   exactly one of `--mmr-index` / `--entry-id`.
 * - **`.sth` chain** (`--checkpoint-chain`): tile-free FRESHEN of a stale
 *   `--receipt` — fold the retained checkpoint chain, extend the receipt's old
 *   path to the latest peak, re-emit under the latest `.sth`. Genesis-verifiable.
 *
 * Freshen (`--receipt` + a tile-free source) recomputes the leaf value exactly
 * as `verify-grant` does, so it takes the same grant inputs: `--committed-grant`
 * / `--committed-grant-file` + `--entry-id`.
 *
 * Multiple sources → error ("choose one source"); an under-specified source →
 * error naming what's missing. No implicit pick — every ambiguous invocation
 * fails closed with guidance.
 */
export type CreateReceiptOptions = ForestrieCommonOptions & {
  anchor: "checkpoint" | "chain" | "freshen-sth" | "freshen-calldata";
  /** Tiles source: massif .log blob holding the leaf and its proof nodes. */
  massif: string | undefined;
  /** MMR index of the leaf to prove (`--mmr-index` addressing, tiles source). */
  mmrIndex: bigint | undefined;
  /** Permanent SCRAPI entry id (leaf addressing / freshen idtimestamp). */
  entryId: string | undefined;
  /** Checkpoint (.sth) with pre-signed peak receipts (tiles + `--checkpoint`). */
  checkpoint: string | undefined;
  /** ImutableUnivocity contract address (tiles + chain-anchored mode). */
  univocity: string | undefined;
  /** Log id for the on-chain accumulator read (chain mode). */
  logId: string | undefined;
  /** JSON-RPC endpoint (`RPC_URL`, chain mode). */
  rpcUrl: string | undefined;
  /** Stale receipt to freshen (`.sth`-chain / calldata source). */
  receipt: string | undefined;
  /** Retained `.sth` checkpoint chain (dir or comma-separated files). */
  checkpointChain: string | undefined;
  /** Committed grant, base64 (freshen leaf-value source, grant receipts). */
  committedGrant: string | undefined;
  /** Committed grant CBOR file (freshen leaf-value source, grant receipts). */
  committedGrantFile: string | undefined;
  /** Registered statement payload (freshen leaf-value source, statement
   * receipts) — the leaf ContentHash is `SHA-256(payload)`, as in `verify`. */
  payload: string | undefined;
  /** Receipt output path (default: stdout). */
  out: string | undefined;
  /** Rewrite the `--receipt` file in place with the freshened receipt (freshen
   * only; mutually exclusive with `--out`). */
  inPlace: boolean;
  /** Trusted accumulator snapshot (`fetch-accumulator` output) to bind the
   * freshened state against — the accumulator trust rung, freshen only. */
  knownAccumulator: string | undefined;
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
  const massif = optionalStringOption(args, "massif");
  const receipt = optionalStringOption(args, "receipt");
  const checkpointChain = optionalStringOption(args, "checkpoint-chain");
  const checkpoint = optionalStringOption(args, "checkpoint");
  const univocity = optionalStringOption(args, "univocity");
  const logId = optionalStringOption(args, "log-id");
  const rpcUrl = optionalStringOption(args, "rpc-url", "RPC_URL");
  const committedGrant = optionalStringOption(args, "committed-grant");
  const committedGrantFile = optionalStringOption(args, "committed-grant-file");
  const payload = optionalStringOption(args, "payload");
  const entryId = optionalStringOption(args, "entry-id");
  const out = optionalStringOption(args, "out");
  const inPlace = args["in-place"] === true;
  const knownAccumulator = optionalStringOption(args, "known-accumulator");
  const common = parseForestrieCommonOptions(args);

  const base = {
    massif,
    checkpoint,
    univocity,
    logId,
    rpcUrl,
    receipt,
    checkpointChain,
    committedGrant,
    committedGrantFile,
    payload,
    entryId,
    out,
    inPlace,
    knownAccumulator,
  };

  if (inPlace && out !== undefined) {
    throw new Error("choose --out or --in-place, not both");
  }

  // Source selection is exclusive: tiles (--massif) vs freshen (--receipt).
  if (massif !== undefined && receipt !== undefined) {
    throw new Error(
      "choose one source: --massif (build from tiles) or --receipt (freshen a stale receipt) — not both",
    );
  }
  if (inPlace && receipt === undefined) {
    throw new Error(
      "--in-place only applies to freshen (--receipt) — there is no receipt file to rewrite",
    );
  }
  if (knownAccumulator !== undefined && receipt === undefined) {
    throw new Error(
      "--known-accumulator only applies to freshen (--receipt)",
    );
  }

  // --- FRESHEN source (--receipt + a tile-free chain) ---
  if (receipt !== undefined) {
    // Leaf value: a statement payload (--payload, as in `verify`) or a committed
    // grant (--committed-grant/-file, as in `verify-grant`) — exactly one.
    const hasGrant =
      committedGrant !== undefined || committedGrantFile !== undefined;
    const hasPayload = payload !== undefined;
    if (hasGrant && hasPayload) {
      throw new Error(
        "choose one leaf source: --payload (statement) or --committed-grant/--committed-grant-file (grant)",
      );
    }
    if (!hasGrant && !hasPayload) {
      throw new Error(
        "freshen needs the leaf's content: --payload (statement) or --committed-grant/--committed-grant-file (grant)",
      );
    }
    if (hasPayload && entryId === undefined) {
      throw new Error(
        "freshen from --payload needs the SCRAPI entry id (idtimestamp): --entry-id",
      );
    }
    if (committedGrantFile !== undefined && entryId === undefined) {
      throw new Error(
        "freshen from a raw grant file needs the SCRAPI entry id (idtimestamp): --entry-id",
      );
    }
    const hasSth = checkpointChain !== undefined;
    const hasCalldata =
      univocity !== undefined || rpcUrl !== undefined || logId !== undefined;
    if (hasSth && hasCalldata) {
      throw new Error(
        "choose one freshen source: --checkpoint-chain (.sth) or --rpc-url/--univocity/--log-id (calldata)",
      );
    }
    if (hasSth) {
      return { ...common, ...base, anchor: "freshen-sth", mmrIndex: undefined };
    }
    if (hasCalldata) {
      if (univocity === undefined || logId === undefined || rpcUrl === undefined) {
        throw new Error(
          "calldata freshen requires --univocity, --log-id and --rpc-url",
        );
      }
      if (checkpoint === undefined) {
        throw new Error(
          "calldata freshen requires --checkpoint (the latest .sth) for emission — calldata carries no pre-signed peak receipts",
        );
      }
      return {
        ...common,
        ...base,
        anchor: "freshen-calldata",
        mmrIndex: undefined,
      };
    }
    throw new Error(
      "freshen (--receipt) needs a tile-free source: --checkpoint-chain (.sth) or --rpc-url/--univocity/--log-id (calldata)",
    );
  }

  // --- TILES source (--massif) ---
  if (massif === undefined) {
    throw new Error(
      "a source is required: --massif (build from tiles) or --receipt + --checkpoint-chain (freshen)",
    );
  }
  const rawMMRIndex = optionalStringOption(args, "mmr-index");
  if ((rawMMRIndex === undefined) === (entryId === undefined)) {
    throw new Error(
      "exactly one of --mmr-index or --entry-id is required to address the leaf",
    );
  }
  const mmrIndex =
    rawMMRIndex !== undefined ? parseMMRIndex(rawMMRIndex) : undefined;

  let anchor: "checkpoint" | "chain";
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
    ...common,
    ...base,
    anchor,
    massif: requiredStringOption(args, "massif"),
    mmrIndex,
  };
}
