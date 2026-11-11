import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runLogWaitAnchored } from "../main/log-wait-anchored.js";
import { parseLogWaitAnchoredOptions } from "../options/log-wait-anchored.js";

export default defineForestrieCommand({
  meta: {
    name: "wait-anchored",
    description:
      "Wait until a log is anchored, proven from public chain data alone: a child log once a checkpoint its owner published on chain covers its create grant, a forest root once its contract holds the genesis key and is rooted at no other log. Exits 0 once anchored; non-zero at once for a conflicted log, and on timeout, printing the last answer. No operator answer is trusted: with --receipt-url, canopy supplies only a receipt path, checked against the chain",
  },
  args: {
    "create-grant": {
      type: "string",
      description:
        "File holding the child log's completed create grant, base64, as create-log --out-b64 writes it (its receipt and idtimestamp are attached)",
      valueHint: "path",
    },
    "receipt-url": {
      type: "string",
      description:
        "The create grant's SCRAPI receipt URL, as create-log prints it (receiptUrl). Each round re-fetches the receipt there and recomputes its peak from the grant's own leaf, so a log still anchors when the seal its first receipt came from never reached the chain (a re-seal replaced it before publishing). The receipt is proof material only: the answer comes from the chain",
      valueHint: "url",
    },
    genesis: {
      type: "string",
      description:
        "Forest genesis (genesis.cbor). Alone, it names the forest root to wait for; with --create-grant, the contract and the RPC's chain must be the genesis forest's",
      valueHint: "path",
    },
    univocity: {
      type: "string",
      description:
        "ImutableUnivocity contract address (default: the genesis's)",
      valueHint: "address",
    },
    "rpc-url": {
      type: "string",
      description: "JSON-RPC endpoint for the contract's chain (env RPC_URL)",
      valueHint: "url",
    },
    timeout: {
      type: "string",
      description: "Overall wait budget in seconds (default 600)",
      valueHint: "seconds",
    },
    interval: {
      type: "string",
      description: "Pacing between chain reads in seconds (default 10)",
      valueHint: "seconds",
    },
  },
  run: defineCommandRunner(parseLogWaitAnchoredOptions, runLogWaitAnchored),
});
