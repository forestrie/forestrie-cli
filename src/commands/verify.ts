import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runVerify } from "../main/verify.js";
import { parseVerifyOptions } from "../options/verify.js";

export default defineForestrieCommand({
  meta: {
    name: "verify",
    description:
      "Verify a receipt offline against the cached checkpoint (ES256 only; no network) — the same closer for every demo step [FOR-347]",
  },
  args: {
    genesis: {
      type: "string",
      description: "Cached public genesis (genesis.cbor) — offline trust root",
      valueHint: "path",
      required: true,
    },
    receipt: {
      type: "string",
      description: "COSE receipt file to verify",
      valueHint: "path",
      required: true,
    },
    "grant-b64": {
      type: "string",
      description:
        "Completed grant credential, base64 (env GRANT_B64); or use --grant + --entry-id",
      valueHint: "base64",
    },
    grant: {
      type: "string",
      description: "Grant CBOR file (alternative to --grant-b64)",
      valueHint: "path",
    },
    "entry-id": {
      type: "string",
      description: "Entry id within the grant CBOR (with --grant)",
      valueHint: "id",
    },
  },
  run: defineCommandRunner(parseVerifyOptions, runVerify),
});
