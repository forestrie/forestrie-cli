import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runSignStatement } from "../main/sign-statement.js";
import { parseSignStatementOptions } from "../options/sign-statement.js";

export default defineForestrieCommand({
  meta: {
    name: "sign-statement",
    description:
      "Produce a SCITT signed statement: plain COSE Sign1 (ES256) with alg, content type, kid and CWT claims (iss/sub, label 15) all in the protected header [FOR-341, FOR-371]",
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
      description: "Payload content type (protected COSE header, label 3)",
      default: "application/json",
    },
    iss: {
      type: "string",
      description:
        "Issuer (CWT claim 1, protected label 15): a StringOrURI, or 'ckt' for the RFC 9679 key-thumbprint URI (default: hex kid)",
    },
    sub: {
      type: "string",
      description:
        "Subject (CWT claim 2, protected label 15): what the statement speaks about (default: sha-256:<hex> of the payload)",
      valueHint: "string-or-uri",
    },
    iat: {
      type: "string",
      description:
        "Issued-at (CWT claim 6): unix seconds or 'now' (default: omitted, keeping output deterministic)",
      valueHint: "now|seconds",
    },
    out: {
      type: "string",
      description: "Signed statement output path (default: stdout)",
      valueHint: "path",
    },
  },
  run: defineCommandRunner(parseSignStatementOptions, runSignStatement),
});
