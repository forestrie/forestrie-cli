import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runSignStatement } from "../main/sign-statement.js";
import { parseSignStatementOptions } from "../options/sign-statement.js";

export default defineForestrieCommand({
  meta: {
    name: "sign-statement",
    description:
      "Produce a plain COSE Sign1 signed statement (ES256; kid = first 32 bytes of x||y) [FOR-341]",
  },
  args: {
    key: {
      type: "string",
      description: "ES256 P-256 private signing key (PEM or JWK file)",
      valueHint: "path",
      required: true,
    },
    payload: {
      type: "string",
      description: "Payload file to sign ('-' reads stdin)",
      valueHint: "path",
      required: true,
    },
    "content-type": {
      type: "string",
      description: "Payload content type (COSE header label 3)",
      default: "application/json",
    },
    out: {
      type: "string",
      description: "Signed statement output path (default: stdout)",
      valueHint: "path",
    },
  },
  run: defineCommandRunner(parseSignStatementOptions, runSignStatement),
});
