import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/**
 * `forestrie verify` — FOR-347.
 *
 * Offline verification against a cached checkpoint — no network access
 * during the core verify. The SAME verify command closes every demo step.
 * ES256 only (`@forestrie/receipt-verify`; error `no_es256_trust_key`).
 *
 * Two anchor modes:
 * - `offline` (default): pure over bytes — genesis trust root, receipt,
 *   grant. Strictly no network.
 * - `chain`: additionally read the on-chain `logState(bytes32)`
 *   accumulator (`--univocity` + `--log-id` + `--rpc-url`) and assert the
 *   receipt's peak is anchored there. Network only in this explicit mode.
 *
 * Acceptance (ex FOR-282): exit 0 on a valid receipt, non-zero on a
 * tampered one.
 */
export type VerifyOptions = ForestrieCommonOptions & {
  anchor: "offline" | "chain";
  /** Cached public genesis (genesis.cbor) — the offline trust root. */
  genesis: string;
  /** COSE receipt file to verify. */
  receipt: string;
  /** Completed grant credential, base64 (or file via --grant + --entry-id). */
  grantB64: string | undefined;
  /** Grant CBOR file (alternative to --grant-b64). */
  grant: string | undefined;
  /** Entry id within the grant CBOR (used with --grant). */
  entryId: string | undefined;
  /** ImutableUnivocity contract address (chain mode). */
  univocity: string | undefined;
  /** Log id for the on-chain accumulator read (chain mode). */
  logId: string | undefined;
  /** JSON-RPC endpoint (`RPC_URL`, chain mode). */
  rpcUrl: string | undefined;
};

export function parseVerifyOptions(args: LooseParsedArgs): VerifyOptions {
  const univocity = optionalStringOption(args, "univocity");
  const logId = optionalStringOption(args, "log-id");
  const rpcUrl = optionalStringOption(args, "rpc-url", "RPC_URL");

  let anchor: VerifyOptions["anchor"] = "offline";
  if (univocity !== undefined) {
    if (logId === undefined || rpcUrl === undefined) {
      throw new Error(
        "chain-anchored verify requires --univocity, --log-id and --rpc-url",
      );
    }
    anchor = "chain";
  }

  const options: VerifyOptions = {
    ...parseForestrieCommonOptions(args),
    anchor,
    genesis: requiredStringOption(args, "genesis"),
    receipt: requiredStringOption(args, "receipt"),
    grantB64: optionalStringOption(args, "grant-b64", "GRANT_B64"),
    grant: optionalStringOption(args, "grant"),
    entryId: optionalStringOption(args, "entry-id"),
    univocity,
    logId,
    rpcUrl,
  };
  if (options.grantB64 === undefined && options.grant === undefined) {
    throw new Error(
      "either --grant-b64 or --grant (grant CBOR, with --entry-id) is required",
    );
  }
  if (options.grant !== undefined && options.entryId === undefined) {
    throw new Error("--grant requires --entry-id");
  }
  return options;
}
