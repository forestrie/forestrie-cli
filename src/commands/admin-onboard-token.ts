import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runAdminOnboardToken } from "../main/admin-onboard-token.js";
import { parseAdminOnboardTokenOptions } from "../options/admin-onboard-token.js";

export default defineForestrieCommand({
  meta: {
    name: "onboard-token",
    description:
      "Mint a forest onboard token under the operator credential; prints only the token so it composes into onboard-genesis --onboard-token [FOR-406]",
  },
  args: {
    "base-url": {
      type: "string",
      description: "SCRAPI origin, no trailing slash (env FORESTRIE_BASE_URL)",
      valueHint: "url",
    },
    "ops-token": {
      type: "string",
      description:
        "Operator credential (env CANOPY_OPS_ADMIN_TOKEN); never logged",
      valueHint: "token",
    },
    label: {
      type: "string",
      description: "Token label recorded by the mint (default forestrie-cli)",
      valueHint: "text",
    },
    deployment: {
      type: "string",
      description:
        "forestrie deploy --out artifact supplying the mandatory chain binding (ADR-0059 D7)",
      valueHint: "path",
    },
    "chain-id": {
      type: "string",
      description: "Chain id for the binding (with --univocity; or use --deployment)",
      valueHint: "id",
    },
    univocity: {
      type: "string",
      description: "Univocity contract address for the binding",
      valueHint: "0xaddr",
    },
    out: {
      type: "string",
      description: "Write the minted token to this path instead of stdout",
      valueHint: "path",
    },
  },
  run: defineCommandRunner(parseAdminOnboardTokenOptions, runAdminOnboardToken),
});
