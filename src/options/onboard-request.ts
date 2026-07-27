import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/** Default request label when `--label` is absent. */
export const DEFAULT_ONBOARD_REQUEST_LABEL = "forestrie-cli";

/**
 * `forestrie onboard-request` — the self-service front door (plan-2607-43
 * slice 06): create a bootstrap-key-attested onboard request and redeem it
 * into an onboard token, paying the x402 challenge when the deployment asks.
 */
export type OnboardRequestOptions = ForestrieCommonOptions & {
  /** SCRAPI origin, no trailing slash (`FORESTRIE_BASE_URL`). */
  baseUrl: string;
  /** `forestrie deploy --out` artifact — the chain binding + alg source. */
  deployment: string;
  /** Bootstrap private key PEM (ES256 deployments) — signs the attestation. */
  bootstrapPem: string | undefined;
  /** Bootstrap private key hex (KS256 deployments) — signs the attestation. */
  bootstrapKeyHex: string | undefined;
  /** Contact email recorded on the request (`ONBOARD_CONTACT_EMAIL`). */
  contactEmail: string;
  label: string;
  /**
   * x402 payer key (`X402_PAYER_KEY`). Optional: without it, only requests
   * the deployment approves (ops/auto) can redeem; with it, a 402 challenge
   * at redeem is paid. REAL funds move on settlement.
   */
  payerKey: string | undefined;
  /** Write the redeemed token here instead of stdout. */
  out: string | undefined;
};

export function parseOnboardRequestOptions(
  args: LooseParsedArgs,
): OnboardRequestOptions {
  return {
    ...parseForestrieCommonOptions(args),
    baseUrl: requiredStringOption(args, "base-url", "FORESTRIE_BASE_URL"),
    deployment: requiredStringOption(args, "deployment"),
    bootstrapPem: optionalStringOption(args, "bootstrap-pem"),
    bootstrapKeyHex: optionalStringOption(args, "bootstrap-key-hex"),
    contactEmail: requiredStringOption(
      args,
      "contact-email",
      "ONBOARD_CONTACT_EMAIL",
    ),
    label: optionalStringOption(args, "label") ?? DEFAULT_ONBOARD_REQUEST_LABEL,
    payerKey: optionalStringOption(args, "payer-key", "X402_PAYER_KEY"),
    out: optionalStringOption(args, "out"),
  };
}
