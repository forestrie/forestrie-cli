import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runRegister } from "../main/register.js";
import { parseRegisterOptions } from "../options/register.js";

export default defineForestrieCommand({
  meta: {
    name: "register",
    description:
      "Register a signed statement via SCRAPI and download the receipt (any SCRAPI client, plain COSE Sign1) [FOR-342]",
  },
  args: {
    "base-url": {
      type: "string",
      description:
        "SCRAPI origin, no trailing slash (env FORESTRIE_BASE_URL)",
      valueHint: "url",
    },
    "log-id": {
      type: "string",
      description: "Target log id (UUID)",
      valueHint: "uuid",
      required: true,
    },
    statement: {
      type: "string",
      description:
        "COSE Sign1 signed statement file ('-' or omitted: read stdin)",
      valueHint: "path",
    },
    "grant-b64": {
      type: "string",
      description:
        "Authorization: Forestrie-Grant bearer credential, base64 (env GRANT_B64)",
      valueHint: "base64",
    },
    out: {
      type: "string",
      description: "Write the receipt bytes to this path",
      valueHint: "path",
    },
    timeout: {
      type: "string",
      description: "Overall receipt wait budget in seconds (default 60)",
      valueHint: "seconds",
    },
    "poll-interval": {
      type: "string",
      description:
        "Pacing between registration/receipt polls in seconds (default 1; Retry-After wins when longer)",
      valueHint: "seconds",
    },
  },
  run: defineCommandRunner(parseRegisterOptions, runRegister),
});
