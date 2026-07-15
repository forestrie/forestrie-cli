import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runVerifyGrant } from "../main/verify.js";
import { parseVerifyGrantOptions } from "../options/verify.js";

export default defineForestrieCommand({
  meta: {
    name: "verify-grant",
    description:
      "Verify a forestrie authority/grant receipt offline. A thin wrapper over `verify`: it derives the grant commitment preimage from a structured grant and verifies it as the leaf payload. The receipt is a standard COSE Receipt; only the payload is forestrie-specific (matches the on-chain univocity accumulator) [FOR-347]",
  },
  args: {
    genesis: {
      type: "string",
      description: "Cached public genesis (genesis.cbor) — offline trust root",
      valueHint: "path",
      required: true,
    },
    receipt: {
      type: "string",
      description: "COSE receipt file to verify",
      valueHint: "path",
      required: true,
    },
    "committed-grant": {
      type: "string",
      description:
        "Grant committed at the receipt's leaf, base64 (env GRANT_B64); or use --committed-grant-file + --entry-id",
      valueHint: "base64",
    },
    "committed-grant-file": {
      type: "string",
      description: "Grant CBOR file (alternative to --committed-grant)",
      valueHint: "path",
    },
    "entry-id": {
      type: "string",
      description: "Entry id within the grant CBOR (with --committed-grant-file)",
      valueHint: "id",
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
  },
  run: defineCommandRunner(parseVerifyGrantOptions, runVerifyGrant),
});
