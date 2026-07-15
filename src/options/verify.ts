import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/**
 * `forestrie verify` / `verify-grant` — FOR-347.
 *
 * Offline verification against a cached checkpoint — no network during the core
 * verify. Every receipt is a standard COSE Receipt (MMR profile); the two
 * commands differ only in how the leaf ContentHash payload is obtained:
 *
 * - `verify` (this file, {@link VerifyOptions}): the generic, SCITT-compatible
 *   path. The caller supplies the EXACT registered payload (`--payload`, e.g. a
 *   signed statement COSE); the leaf commits `SHA-256(idtimestamp ‖ SHA-256(payload))`.
 * - `verify-grant` ({@link VerifyGrantOptions}): a thin wrapper for forestrie
 *   authority grants — it derives the grant commitment preimage from a
 *   structured grant and verifies it as the payload.
 *
 * Both add `--univocity --log-id --rpc-url` for the chain-anchored check (the
 * only networked path).
 */

type AnchorFields = {
  anchor: "offline" | "chain";
  univocity: string | undefined;
  logId: string | undefined;
  rpcUrl: string | undefined;
};

function parseAnchorFields(args: LooseParsedArgs): AnchorFields {
  const univocity = optionalStringOption(args, "univocity");
  const logId = optionalStringOption(args, "log-id");
  const rpcUrl = optionalStringOption(args, "rpc-url", "RPC_URL");
  let anchor: AnchorFields["anchor"] = "offline";
  if (univocity !== undefined) {
    if (logId === undefined || rpcUrl === undefined) {
      throw new Error(
        "chain-anchored verify requires --univocity, --log-id and --rpc-url",
      );
    }
    anchor = "chain";
  }
  return { anchor, univocity, logId, rpcUrl };
}

// ---------------------------------------------------------------------------
// verify (generic, payload)
// ---------------------------------------------------------------------------

export type VerifyOptions = ForestrieCommonOptions &
  AnchorFields & {
    /** Cached public genesis (genesis.cbor) — the offline trust root. */
    genesis: string;
    /** COSE receipt file to verify. */
    receipt: string;
    /** The EXACT registered payload (leaf commits SHA-256 of these bytes). */
    payload: string;
    /** SCRAPI entry id — supplies the leaf idtimestamp. */
    entryId: string;
  };

export function parseVerifyOptions(args: LooseParsedArgs): VerifyOptions {
  const options: VerifyOptions = {
    ...parseForestrieCommonOptions(args),
    ...parseAnchorFields(args),
    genesis: requiredStringOption(args, "genesis"),
    receipt: requiredStringOption(args, "receipt"),
    payload: requiredStringOption(args, "payload"),
    entryId: requiredStringOption(args, "entry-id"),
  };
  return options;
}

// ---------------------------------------------------------------------------
// verify-grant (wraps: derives the grant commitment payload)
// ---------------------------------------------------------------------------

export type VerifyGrantOptions = ForestrieCommonOptions &
  AnchorFields & {
    genesis: string;
    receipt: string;
    /** Completed grant credential, base64 (env GRANT_B64). */
    committedGrant: string | undefined;
    /** Grant CBOR file (alternative to --committed-grant). */
    committedGrantFile: string | undefined;
    /** Entry id within the grant CBOR (used with --committed-grant-file). */
    entryId: string | undefined;
  };

export function parseVerifyGrantOptions(
  args: LooseParsedArgs,
): VerifyGrantOptions {
  const options: VerifyGrantOptions = {
    ...parseForestrieCommonOptions(args),
    ...parseAnchorFields(args),
    genesis: requiredStringOption(args, "genesis"),
    receipt: requiredStringOption(args, "receipt"),
    committedGrant: optionalStringOption(args, "committed-grant", "GRANT_B64"),
    committedGrantFile: optionalStringOption(args, "committed-grant-file"),
    entryId: optionalStringOption(args, "entry-id"),
  };
  if (
    options.committedGrant === undefined &&
    options.committedGrantFile === undefined
  ) {
    throw new Error(
      "either --committed-grant or --committed-grant-file (grant CBOR, with --entry-id) is required",
    );
  }
  if (
    options.committedGrantFile !== undefined &&
    options.entryId === undefined
  ) {
    throw new Error("--committed-grant-file requires --entry-id");
  }
  return options;
}
