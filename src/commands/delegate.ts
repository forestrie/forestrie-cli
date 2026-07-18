import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runDelegate } from "../main/delegate.js";
import { parseDelegateOptions } from "../options/delegate.js";

export default defineForestrieCommand({
  meta: {
    name: "delegate",
    description:
      "Authorize a custodian-vouched sealer to publish checkpoints for a log you own (K(L)); public coordinator endpoints only [FOR-390]",
  },
  args: {
    "coordinator-url": {
      type: "string",
      description:
        "Delegation coordinator origin, no trailing slash (env DELEGATION_COORDINATOR_URL)",
      valueHint: "url",
    },
    "log-id": {
      type: "string",
      description: "Target log id",
      valueHint: "uuid",
      required: true,
    },
    "sign-with": {
      type: "string",
      description: "ES256 log-root PEM (K(L)) that authorizes the delegation",
      valueHint: "path",
      required: true,
    },
    "known-sealer-key": {
      type: "string",
      description:
        "The known key that vouches for the operator's sealer (the registrar's voucher-signing key), base64 x||y (64 bytes) (env KNOWN_SEALER_KEY)",
      valueHint: "base64",
    },
    "horizon-mmr-end": {
      type: "string",
      description:
        "Exclusive MMR end of the horizon lease (default 9007199254740991; mmrStart is fixed 0)",
      valueHint: "number",
    },
    "ttl-seconds": {
      type: "string",
      description:
        "Lease TTL in seconds (default: standing entry suggestedTtlSeconds)",
      valueHint: "seconds",
    },
    "out-b64": {
      type: "string",
      description: "Write the submitted certificate base64 to this path",
      valueHint: "path",
    },
  },
  run: defineCommandRunner(parseDelegateOptions, runDelegate),
});
