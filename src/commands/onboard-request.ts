import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runOnboardRequest } from "../main/onboard-request.js";
import { parseOnboardRequestOptions } from "../options/onboard-request.js";

export default defineForestrieCommand({
  meta: {
    name: "onboard-request",
    description:
      "Create a bootstrap-key-attested onboard request and redeem it into an onboard token (paying the x402 challenge when asked); prints only the token so it composes into onboard-genesis --onboard-token [ADR-0059 D8]",
  },
  args: {
    "base-url": {
      type: "string",
      description: "SCRAPI origin, no trailing slash (env FORESTRIE_BASE_URL)",
      valueHint: "url",
    },
    deployment: {
      type: "string",
      description:
        "forestrie deploy --out artifact (chain binding + bootstrap alg)",
      valueHint: "path",
      required: true,
    },
    "bootstrap-pem": {
      type: "string",
      description:
        "Bootstrap private key PEM (ES256) — signs the registrant attestation",
      valueHint: "path",
    },
    "bootstrap-key-hex": {
      type: "string",
      description:
        "Bootstrap private key hex (KS256) — signs the registrant attestation",
      valueHint: "hex",
    },
    "contact-email": {
      type: "string",
      description: "Contact email for the request (env ONBOARD_CONTACT_EMAIL)",
      valueHint: "email",
    },
    label: {
      type: "string",
      description: "Request label (default forestrie-cli)",
      valueHint: "text",
    },
    "payer-key": {
      type: "string",
      description:
        "x402 payer private key (env X402_PAYER_KEY); pays the redeem 402 challenge — real funds move on settlement",
      valueHint: "hex",
    },
    out: {
      type: "string",
      description: "Write the redeemed token to this path instead of stdout",
      valueHint: "path",
    },
  },
  run: defineCommandRunner(parseOnboardRequestOptions, runOnboardRequest),
});
