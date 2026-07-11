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
      description: "COSE Sign1 signed statement file",
      valueHint: "path",
      required: true,
    },
    "grant-b64": {
      type: "string",
      description:
        "Authorization: Forestrie-Grant bearer credential, base64 (env GRANT_B64)",
      valueHint: "base64",
    },
    out: {
      type: "string",
      description: "Receipt output path (default: stdout)",
      valueHint: "path",
    },
  },
  run: defineCommandRunner(parseRegisterOptions, runRegister),
});
