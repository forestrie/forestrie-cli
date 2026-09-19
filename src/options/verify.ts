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
 *
 * Trust roots (protocol: spec/receipt-trust-model.md). They are alternatives,
 * not an ordering — each answers a different subset of the four trust
 * questions, and the report says which root was used:
 * - `--known-log-key` — the known log key root: an owner key the caller holds
 *   out of band; offline, no genesis; the key↔log binding is asserted by the
 *   key's provenance, not proven; no split-view protection.
 * - `--genesis` — the genesis root: the forest genesis document's bootstrap
 *   key, which roots the root log or a delegation directly under it. A deeper
 *   child log's authority needs the off-chain grant-chain walk, which no
 *   verifier implements (spec/implementation-status.md).
 * - `--known-accumulator` — the known accumulator root, from a cached,
 *   auditable chain read: the contract-anchored state, fully offline;
 *   `--massif` (tiles) or `--consistency-proof` (portable top-up artifact)
 *   extends older receipts to a newer snapshot.
 * - `--checkpoint-chain` — the checkpoint chain root: a retained fold of
 *   checkpoint objects, an authenticated accumulator at every retained seal
 *   from the public log store alone; signatures root in the genesis or known
 *   log key root.
 * - `--rpc-url` — the known accumulator root from a live chain read, plus
 *   freshness (the RPC provider is itself a trusted chain reader); buried
 *   peaks resolve via the CheckpointPublished history scan (public chain
 *   data only).
 */

type AnchorFields = {
  anchor: "offline" | "chain" | "accumulator" | "checkpoints";
  univocity: string | undefined;
  logId: string | undefined;
  rpcUrl: string | undefined;
  /**
   * Cached on-chain accumulator snapshot (FOR-297 D5) — chain-anchored
   * verification without `--rpc-url`. Produced by `forestrie
   * fetch-accumulator`; never source it unauthenticated from the log
   * operator's tile store.
   */
  knownAccumulator: string | undefined;
  /** Local massif blob enabling stale-snapshot proof-path extension. */
  massif: string | undefined;
  /**
   * Retained `.sth` checkpoint chain (FOR-368 Phase 3): a directory of
   * `.sth` objects or a comma-separated list in chain order. Folding the
   * chain authenticates the accumulator at every retained seal from the
   * public log store alone — no tiles, no RPC. Signature trust roots in
   * `--genesis` / `--known-log-key`.
   */
  checkpointChain: string | undefined;
  /**
   * Portable top-up artifact (`forestrie create-consistency-proof`,
   * FOR-368 Phase 3): tile-free extension of an old receipt to the
   * `--known-accumulator` snapshot. Unsigned and untrusted — soundness is
   * by recomputation into the trusted snapshot.
   */
  consistencyProof: string | undefined;
  /** Lower bound for the CheckpointPublished history scan (FOR-368). */
  fromBlock: bigint | undefined;
  /**
   * Caller-known log OWNER key (the delegation-cert issuer), base64 `x||y`
   * (64 bytes, `KNOWN_LOG_KEY`) — FOR-297 D1. An offline trust anchor that
   * replaces the genesis root: the known log key root of the trust model.
   * It asserts (does not prove) the key↔log binding, and gives no
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
  const knownAccumulator = optionalStringOption(args, "known-accumulator");
  const massif = optionalStringOption(args, "massif");
  const checkpointChain = optionalStringOption(args, "checkpoint-chain");
  const consistencyProof = optionalStringOption(args, "consistency-proof");
  const fromBlockRaw = optionalStringOption(args, "from-block");
  let fromBlock: bigint | undefined;
  if (fromBlockRaw !== undefined) {
    try {
      fromBlock = BigInt(fromBlockRaw);
    } catch {
      throw new Error("--from-block must be a block number");
    }
    if (fromBlock < 0n) {
      throw new Error("--from-block must be a non-negative block number");
    }
  }
  // Anchor modes are mutually exclusive. Conflict keys on --univocity (the
  // live-read mode selector), NOT on rpcUrl: RPC_URL is commonly ambient in
  // the environment and must not block the offline anchors.
  const selected = [
    knownAccumulator !== undefined ? "--known-accumulator" : null,
    univocity !== undefined ? "--univocity" : null,
    checkpointChain !== undefined ? "--checkpoint-chain" : null,
  ].filter((s) => s !== null);
  if (selected.length > 1) {
    throw new Error(
      `choose one anchor: a live read (--univocity/--log-id/--rpc-url), a cached --known-accumulator, or a retained --checkpoint-chain (got ${selected.join(" + ")})`,
    );
  }
  let anchor: AnchorFields["anchor"] = "offline";
  if (knownAccumulator !== undefined) {
    anchor = "accumulator";
  } else if (univocity !== undefined) {
    if (logId === undefined || rpcUrl === undefined) {
      throw new Error(
        "chain-anchored verify requires --univocity, --log-id and --rpc-url",
      );
    }
    anchor = "chain";
  } else if (checkpointChain !== undefined) {
    anchor = "checkpoints";
  } else if (massif !== undefined) {
    throw new Error("--massif only applies with --known-accumulator");
  }
  if (massif !== undefined && anchor !== "accumulator") {
    throw new Error("--massif only applies with --known-accumulator");
  }
  if (consistencyProof !== undefined && anchor !== "accumulator") {
    throw new Error(
      "--consistency-proof only applies with --known-accumulator (the trusted target state)",
    );
  }
  if (fromBlock !== undefined && anchor !== "chain") {
    throw new Error(
      "--from-block only applies to the live chain anchor (--univocity)",
    );
  }
  return {
    anchor,
    univocity,
    logId,
    rpcUrl,
    knownLogKey,
    knownAccumulator,
    massif,
    checkpointChain,
    consistencyProof,
    fromBlock,
  };
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
