import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runRegisterGrant } from "../main/register-grant.js";
import { parseRegisterGrantOptions } from "../options/register-grant.js";

export default defineForestrieCommand({
  meta: {
    name: "register-grant",
    description:
      "Authorize a statement writer on a data log (extend-only; grant recorded in the parent auth log) [FOR-343]",
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
        "PEM of the signer being authorized (grantData = ES256 x||y)",
      valueHint: "path",
      required: true,
    },
    "parent-grant-b64": {
      type: "string",
      description: "Parent grant credential authorizing this registration",
      valueHint: "base64",
      required: true,
    },
    "out-b64": {
      type: "string",
      description: "Completed grant base64 output path (default: stdout)",
      valueHint: "path",
    },
    "bootstrap-log": {
      type: "string",
      description:
        "Forest bootstrap/root log id — first /register/ path segment (default: --owner-log)",
      valueHint: "uuid",
    },
    timeout: {
      type: "string",
      description:
        "Wait budget in seconds: for admission while canopy answers 409 authority-pending (a last attempt is made at the deadline), then again for the receipt once admitted (default 60)",
      valueHint: "seconds",
    },
    "poll-interval": {
      type: "string",
      description:
        "Pacing between registration/receipt polls in seconds (default 1; Retry-After wins when longer)",
      valueHint: "seconds",
    },
  },
  run: defineCommandRunner(parseRegisterGrantOptions, runRegisterGrant),
});
