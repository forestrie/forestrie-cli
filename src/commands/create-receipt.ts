import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runCreateReceipt } from "../main/create-receipt.js";
import { parseCreateReceiptOptions } from "../options/create-receipt.js";

export default defineForestrieCommand({
  meta: {
    name: "create-receipt",
    description:
      "Self-serve COSE receipt from log data + checkpoint (or chain-anchored via --univocity) — no operator API call [FOR-345]",
  },
  args: {
    massif: {
      type: "string",
      description: "Massif .log blob holding the leaf and its proof nodes",
      valueHint: "path",
      required: true,
    },
    "mmr-index": {
      type: "string",
      description:
        "MMR index of the leaf to prove (exactly one of --mmr-index / --entry-id)",
      valueHint: "n",
    },
    "entry-id": {
      type: "string",
      description:
        "Permanent SCRAPI entry id addressing the leaf (idtimestamp_be8 || mmrIndex_be8, 32 hex chars)",
      valueHint: "hex",
    },
    checkpoint: {
      type: "string",
      description:
        "Checkpoint (.sth) with pre-signed peak receipts (offline mode)",
      valueHint: "path",
    },
    univocity: {
      type: "string",
      description:
        "ImutableUnivocity contract address (chain-anchored mode; needs --log-id and --rpc-url)",
      valueHint: "0x…",
    },
    "log-id": {
      type: "string",
      description: "Log id for the on-chain accumulator read (chain mode)",
      valueHint: "uuid",
    },
    "rpc-url": {
      type: "string",
      description: "JSON-RPC endpoint (env RPC_URL; chain mode)",
      valueHint: "url",
    },
    out: {
      type: "string",
      description: "Receipt output path (default: stdout)",
      valueHint: "path",
    },
  },
  run: defineCommandRunner(parseCreateReceiptOptions, runCreateReceipt),
});
