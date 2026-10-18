import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runFetchKs256Attestation } from "../main/fetch-ks256-attestation.js";
import { parseFetchKs256AttestationOptions } from "../options/fetch-ks256-attestation.js";

export default defineForestrieCommand({
  meta: {
    name: "fetch-ks256-attestation",
    description:
      "Ask a KS256 contract root (a Safe) over ERC-1271 whether it signs the receipt's delegation certificate, and cache the block-bound answer as a --ks256-attestation artifact (CBOR binding chainId/address/digest/signature hash/block) — verify then accepts the contract-rooted receipt offline as valid under the contract's signers at that block. Auditable: anyone with RPC can re-run the call at that block. An EOA root needs no attestation (verify recovers it)",
  },
  args: {
    receipt: {
      type: "string",
      description: "Receipt carrying the KS256 delegation certificate (label 1000)",
      valueHint: "path",
      required: true,
    },
    root: {
      type: "string",
      description:
        "Contract root address (0x + 40 hex); overrides the genesis root",
      valueHint: "address",
    },
    genesis: {
      type: "string",
      description:
        "Forest genesis (genesis.cbor): supplies the KS256 root unless --root is given, and the chain id the RPC must match",
      valueHint: "path",
    },
    "rpc-url": {
      type: "string",
      description: "JSON-RPC endpoint (default: ${env} → RPC_URL)",
      valueHint: "url",
    },
    block: {
      type: "string",
      description:
        "Block number to pin the calls to, or 'latest' (default) — needs an archive node for old blocks",
      valueHint: "number|latest",
    },
    out: {
      type: "string",
      description: "Output path for the attestation CBOR",
      valueHint: "path",
      required: true,
    },
  },
  run: defineCommandRunner(
    parseFetchKs256AttestationOptions,
    runFetchKs256Attestation,
  ),
});
