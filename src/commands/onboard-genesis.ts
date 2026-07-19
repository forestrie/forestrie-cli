import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runOnboardGenesis } from "../main/onboard-genesis.js";
import { parseOnboardGenesisOptions } from "../options/onboard-genesis.js";

export default defineForestrieCommand({
  meta: {
    name: "onboard-genesis",
    description:
      "Operator genesis onboarding: POST the direct-sign ES256 genesis for a deployed forest under a pre-minted onboard token, wire sealing callbacks, and cache the public genesis [FOR-406]",
  },
  args: {
    "base-url": {
      type: "string",
      description: "SCRAPI origin, no trailing slash (env FORESTRIE_BASE_URL)",
      valueHint: "url",
    },
    deployment: {
      type: "string",
      description:
        "deploy --out artifact (supplies imutableUnivocity + genesisLogId)",
      valueHint: "path",
    },
    univocity: {
      type: "string",
      description: "ImutableUnivocity address (with --log-id, instead of --deployment)",
      valueHint: "address",
    },
    "log-id": {
      type: "string",
      description: "Forest (genesis) log id (with --univocity)",
      valueHint: "uuid",
    },
    "bootstrap-pem": {
      type: "string",
      description:
        "ES256 bootstrap key PEM from deploy (private or public; only the public key is sent)",
      valueHint: "path",
      required: true,
    },
    "chain-id": {
      type: "string",
      description: "Chain id recorded in the genesis (env CHAIN_ID; default 84532)",
      valueHint: "id",
    },
    "coordinator-url": {
      type: "string",
      description:
        "Delegation coordinator origin; the signing-route webhook is derived per log",
      valueHint: "url",
    },
    "webhook-url": {
      type: "string",
      description: "Explicit sealing webhook (overrides --coordinator-url derivation)",
      valueHint: "url",
    },
    "onboard-token": {
      type: "string",
      description:
        "Pre-minted onboard token (env ONBOARD_TOKEN) — mint with 'forestrie admin onboard-token'; x402 settlement is the future public source",
      valueHint: "token",
    },
    out: {
      type: "string",
      description:
        "Fetch the public genesis back to this path (the offline trust root for verify --genesis)",
      valueHint: "path",
    },
  },
  run: defineCommandRunner(parseOnboardGenesisOptions, runOnboardGenesis),
});
