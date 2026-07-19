import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runVerify } from "../main/verify.js";
import { parseVerifyOptions } from "../options/verify.js";

export default defineForestrieCommand({
  meta: {
    name: "verify",
    description:
      "Verify a receipt offline against the cached checkpoint (ES256; no network) — the standard, SCITT-compatible closer. Give the EXACT registered payload (--payload, e.g. the signed statement) + its --entry-id. Add --univocity/--log-id/--rpc-url to also check the on-chain accumulator [FOR-347]",
  },
  args: {
    genesis: {
      type: "string",
      description:
        "Cached public genesis (genesis.cbor) — genesis-derived offline trust root (or supply --known-log-key instead)",
      valueHint: "path",
    },
    "known-log-key": {
      type: "string",
      description:
        "Caller-known log OWNER key (the delegation issuer), base64 x||y (64 bytes) (env KNOWN_LOG_KEY). Offline trust anchor that replaces --genesis; asserts (does not prove) the key-to-log binding — the genesis grant-chain walk derives it, and chain anchoring adds split-view protection",
      valueHint: "base64",
    },
    receipt: {
      type: "string",
      description: "COSE receipt file to verify",
      valueHint: "path",
      required: true,
    },
    payload: {
      type: "string",
      description:
        "The EXACT registered payload whose SHA-256 the leaf commits (e.g. the signed statement COSE). A standard COSE Receipt proves leaf = SHA-256(idtimestamp || SHA-256(payload))",
      valueHint: "path",
      required: true,
    },
    "entry-id": {
      type: "string",
      description: "SCRAPI entry id — supplies the leaf idtimestamp",
      valueHint: "id",
      required: true,
    },
    univocity: {
      type: "string",
      description:
        "ImutableUnivocity contract address — enables the chain-anchored check (with --log-id and --rpc-url)",
      valueHint: "address",
    },
    "log-id": {
      type: "string",
      description: "Log id (UUID or hex) for the on-chain accumulator read",
      valueHint: "uuid",
    },
    "rpc-url": {
      type: "string",
      description:
        "JSON-RPC endpoint for the chain-anchored check (default: ${env} → RPC_URL)",
      valueHint: "url",
    },
    "from-block": {
      type: "string",
      description:
        "Lower bound for the buried-peak CheckpointPublished history scan (the forest's deploy block; default earliest) [FOR-368]",
      valueHint: "block",
    },
    "known-accumulator": {
      type: "string",
      description:
        "Cached on-chain accumulator snapshot (CBOR from `forestrie fetch-accumulator`) — the chain-anchored check fully offline, no --rpc-url. Never source it unauthenticated from the log operator's tile store (that re-internalises operator trust). Older receipts extend to a newer snapshot via --massif; newer receipts fail closed",
      valueHint: "path",
    },
    massif: {
      type: "string",
      description:
        "Local massif blob — enables proof-path extension when the receipt predates the --known-accumulator snapshot",
      valueHint: "path",
    },
    "consistency-proof": {
      type: "string",
      description:
        "Portable top-up artifact (`forestrie create-consistency-proof`) — tile-free extension of an older receipt into the --known-accumulator snapshot. Untrusted input: it can only fail, never mint trust [FOR-368]",
      valueHint: "path",
    },
    "checkpoint-chain": {
      type: "string",
      description:
        "Retained .sth checkpoint chain — a directory of .sth objects or comma-separated files in chain order. Folds the chain from size 0, authenticating the accumulator at every retained seal from the public log store alone (no tiles, no RPC); the receipt peak may match ANY link [FOR-368]",
      valueHint: "dir|paths",
    },
  },
  run: defineCommandRunner(parseVerifyOptions, runVerify),
});
