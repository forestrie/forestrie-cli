import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runRegisterGrant } from "../main/register-grant.js";
import { parseRegisterGrantOptions } from "../options/register-grant.js";

export default defineForestrieCommand({
  meta: {
    name: "register-grant",
    description:
      "Authorize a signer for a child/data log — one grant per signer, recorded in the owner (auth) log [FOR-343]",
  },
  args: {
    "base-url": {
      type: "string",
      description:
        "SCRAPI origin, no trailing slash (env FORESTRIE_BASE_URL)",
      valueHint: "url",
    },
    "owner-log": {
      type: "string",
      description: "Owner (auth) log the grant leaf is sequenced into",
      valueHint: "uuid",
      required: true,
    },
    "data-log": {
      type: "string",
      description: "Child/data log the grant authorizes",
      valueHint: "uuid",
      required: true,
    },
    "sign-with": {
      type: "string",
      description:
        "PKCS#8 PEM key that signs the grant statement (the granting authority)",
      valueHint: "path",
      required: true,
    },
    "signer-pem": {
      type: "string",
      description:
        "PEM of the signer being authorized (grantData = ES256 x||y); omit for self grants",
      valueHint: "path",
    },
    "self-referential": {
      type: "boolean",
      description:
        "Bootstrap-shaped root grant (logId == ownerLogId, first leaf of the root log)",
      default: false,
    },
    "auth-log": {
      type: "boolean",
      description: "Create a child auth log rather than a data log",
      default: false,
    },
    "parent-grant-b64": {
      type: "string",
      description: "Parent grant credential authorizing this registration",
      valueHint: "base64",
    },
    "out-b64": {
      type: "string",
      description: "Completed grant base64 output path (default: stdout)",
      valueHint: "path",
    },
  },
  run: defineCommandRunner(parseRegisterGrantOptions, runRegisterGrant),
});
