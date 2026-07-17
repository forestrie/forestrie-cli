import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runFetchAccumulator } from "../main/fetch-accumulator.js";
import { parseFetchAccumulatorOptions } from "../options/fetch-accumulator.js";

export default defineForestrieCommand({
  meta: {
    name: "fetch-accumulator",
    description:
      "Read the log's on-chain logState and cache it as a --known-accumulator snapshot (CBOR binding chainId/univocity/logId/size/block) — verify runs chain-anchored fully offline against it. The snapshot is auditable: anyone with RPC can re-run the read at that block. Trust the party that fetched it as a chain reader; never take it unauthenticated from the log operator's tile store [FOR-297]",
  },
  args: {
    univocity: {
      type: "string",
      description: "ImutableUnivocity contract address",
      valueHint: "address",
      required: true,
    },
    "log-id": {
      type: "string",
      description: "Log id (UUID or hex) for the on-chain accumulator read",
      valueHint: "uuid",
      required: true,
    },
    "rpc-url": {
      type: "string",
      description: "JSON-RPC endpoint (default: ${env} → RPC_URL)",
      valueHint: "url",
    },
    out: {
      type: "string",
      description: "Output path for the snapshot CBOR",
      valueHint: "path",
      required: true,
    },
  },
  run: defineCommandRunner(parseFetchAccumulatorOptions, runFetchAccumulator),
});
