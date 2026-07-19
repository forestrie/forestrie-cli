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
    out: {
      type: "string",
      description: "Write the minted token to this path instead of stdout",
      valueHint: "path",
    },
  },
  run: defineCommandRunner(parseAdminOnboardTokenOptions, runAdminOnboardToken),
});
