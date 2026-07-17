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
  /**
   * Caller-known log OWNER key (the delegation-cert issuer), base64 `x||y`
   * (64 bytes, `KNOWN_LOG_KEY`) — FOR-297 D1. An offline trust anchor that
   * replaces the genesis-derived roots: the "known hosts" rung of the trust
   * ladder. It asserts (does not prove) the key↔log binding, and gives no
   * grant-lifecycle visibility or split-view protection — the grant-chain
   * walk (approach A) derives the binding; chain anchors add split-view.
   */
  knownLogKey: string | undefined;
};

function parseAnchorFields(args: LooseParsedArgs): AnchorFields {
  const univocity = optionalStringOption(args, "univocity");
  const logId = optionalStringOption(args, "log-id");
  const rpcUrl = optionalStringOption(args, "rpc-url", "RPC_URL");
  const knownLogKey = optionalStringOption(args, "known-log-key", "KNOWN_LOG_KEY");
  let anchor: AnchorFields["anchor"] = "offline";
  if (univocity !== undefined) {
    if (logId === undefined || rpcUrl === undefined) {
      throw new Error(
        "chain-anchored verify requires --univocity, --log-id and --rpc-url",
      );
    }
    anchor = "chain";
  }
  return { anchor, univocity, logId, rpcUrl, knownLogKey };
}

/** `--genesis` is only optional when another trust anchor is supplied. */
function requiredTrustAnchor(
  args: LooseParsedArgs,
  knownLogKey: string | undefined,
): string | undefined {
  const genesis = optionalStringOption(args, "genesis");
  if (genesis === undefined && knownLogKey === undefined) {
    throw new Error(
      "a trust anchor is required: --genesis (genesis-derived roots) or --known-log-key (caller-known log owner key)",
    );
  }
  return genesis;
}

// ---------------------------------------------------------------------------
// verify (generic, payload)
// ---------------------------------------------------------------------------

export type VerifyOptions = ForestrieCommonOptions &
  AnchorFields & {
    /** Cached public genesis (genesis.cbor) — the genesis-derived trust
     * anchor. Optional when `--known-log-key` supplies the anchor instead. */
    genesis: string | undefined;
    /** COSE receipt file to verify. */
    receipt: string;
    /** The EXACT registered payload (leaf commits SHA-256 of these bytes). */
    payload: string;
    /** SCRAPI entry id — supplies the leaf idtimestamp. */
    entryId: string;
  };

export function parseVerifyOptions(args: LooseParsedArgs): VerifyOptions {
  const anchorFields = parseAnchorFields(args);
  const options: VerifyOptions = {
    ...parseForestrieCommonOptions(args),
    ...anchorFields,
    genesis: requiredTrustAnchor(args, anchorFields.knownLogKey),
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
    genesis: string | undefined;
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
  const anchorFields = parseAnchorFields(args);
  const options: VerifyGrantOptions = {
    ...parseForestrieCommonOptions(args),
    ...anchorFields,
    genesis: requiredTrustAnchor(args, anchorFields.knownLogKey),
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
