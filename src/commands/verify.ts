import {
  defineCommandRunner,
  defineForestrieCommand,
  withRepeatedFlags,
} from "../commoncli.js";
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
        "Caller-known log OWNER key (the delegation issuer): base64 x||y (64-byte ES256 key) or a 20-byte KS256 address (0x + 40 hex, or base64) (env KNOWN_LOG_KEY). Offline signer-provenance anchor that replaces --genesis (give --genesis too and it only supplies the forest chain id an attestation must match); asserts (does not prove) the key-to-log binding — --genesis roots it in the forest genesis document's bootstrap key (the root log, or a delegation directly under it), while the accumulator roots (--known-accumulator / --rpc-url) supply split-view (freshness is a weaker, separate axis bearing only on coverage). See https://github.com/forestrie/protocol/blob/main/spec/receipt-trust-model.md",
      valueHint: "base64|0xaddress",
    },
    "ks256-attestation": {
      type: "string",
      description:
        "ERC-1271 attestation (CBOR from `forestrie fetch-ks256-attestation`) for a KS256 contract root such as a Safe; repeatable (or comma-separated) — a Safe that rotated its delegate needs one per certificate, matched to each by certificate digest, and every one is reported used or unused with a reason: the delegation certificate then verifies offline as valid under the contract's signers at the attested block, not as a signature by one key. Needs the forest chain id from --genesis. verify never calls the chain. Trust: an attestation is unsigned and only as good as whoever fetched it — accept one only from a party you would trust to read the chain for you, or fetch it yourself",
      valueHint: "path",
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
        "ImutableUnivocity contract address — enables the chain-anchored check (with --log-id and --rpc-url). With --genesis the anchor must be the genesis forest's contract and chain (else anchor_forest_mismatch); without --genesis (known-key runs) it is trusted as named. When offline verify cannot resolve the signature (delegation_invalid, or a KS256 root it cannot recover) a matching anchor still passes, reported as `anchored` — signature not checked offline, authority is the chain (univocity checks signature and delegation at publish, not expiry); delegation_expired and out-of-range delegations do not fall back (a diagnostic, not a guarantee: the fallback never checks the receipt signature and the certificate header is unprotected — what it guarantees is inclusion in the log state univocity authorised). A --known-accumulator snapshot is unsigned: forest binding catches mistakes, not a malicious supplier — trust it as you would its fetcher, and pass --log-id",
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
        "Retained .sth checkpoint chain — a directory of .sth objects or comma-separated files in chain order. Folds the chain from size 0, authenticating the accumulator at every retained seal from the public log store alone (no tiles, no RPC); the receipt peak may match ANY link [FOR-368]. Signatures root in --genesis and/or --known-log-key (ES256 or KS256); each certificate's mmrStart/mmrEnd window is enforced per link and its expiry at the leaf time once the receipt matches; --ks256-attestation vouches for contract-root certificates (needs --genesis)",
      valueHint: "dir|paths",
    },
  },
  run: withRepeatedFlags(
    ["ks256-attestation"],
    defineCommandRunner(parseVerifyOptions, runVerify),
  ),
});
