import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/** Default chain id (Base Sepolia) when `--chain-id`/`CHAIN_ID` absent. */
export const DEFAULT_CHAIN_ID = "84532";

/** `forestrie onboard-genesis` — FOR-406 (plan-2607-27 W2). */
export type OnboardGenesisOptions = ForestrieCommonOptions & {
  /** SCRAPI origin, no trailing slash (`FORESTRIE_BASE_URL`). */
  baseUrl: string;
  /** deploy's `--out` JSON; supplies univocity + logId when set. */
  deployment: string | undefined;
  /** ImutableUnivocity contract address (from `--deployment` when absent). */
  univocity: string | undefined;
  /** Forest (genesis) log id (from `--deployment` when absent). */
  logId: string | undefined;
  /** ES256 bootstrap key PEM (private or public; only the pubkey is used). */
  bootstrapPem: string;
  /** Chain id recorded in the genesis (`CHAIN_ID`, default 84532). */
  chainId: string;
  /** Delegation coordinator origin; signing-route webhook is derived. */
  coordinatorUrl: string | undefined;
  /** Explicit webhook override (wins over `--coordinator-url`). */
  webhookUrl: string | undefined;
  /**
   * Pre-minted onboard token (`ONBOARD_TOKEN`) — from
   * `forestrie admin onboard-token` today, x402 settlement (ARC-0015) in
   * future. This command never touches the operator credential.
   */
  onboardToken: string;
  /** Fetch the public genesis back to this path after onboarding. */
  out: string | undefined;
};

export function parseOnboardGenesisOptions(
  args: LooseParsedArgs,
): OnboardGenesisOptions {
  const deployment = optionalStringOption(args, "deployment");
  const univocity = optionalStringOption(args, "univocity");
  const logId = optionalStringOption(args, "log-id");
  if (deployment === undefined && (univocity === undefined || logId === undefined)) {
    throw new Error(
      "onboard-genesis needs --deployment <deployment.json> (from deploy --out) " +
        "or both --univocity and --log-id",
    );
  }
  const coordinatorUrl = optionalStringOption(args, "coordinator-url");
  const webhookUrl = optionalStringOption(args, "webhook-url");
  if (coordinatorUrl === undefined && webhookUrl === undefined) {
    throw new Error(
      "onboard-genesis needs --coordinator-url (signing-route webhook derived) " +
        "or an explicit --webhook-url",
    );
  }
  return {
    ...parseForestrieCommonOptions(args),
    baseUrl: requiredStringOption(args, "base-url", "FORESTRIE_BASE_URL"),
    deployment,
    univocity,
    logId,
    bootstrapPem: requiredStringOption(args, "bootstrap-pem"),
    chainId:
      optionalStringOption(args, "chain-id", "CHAIN_ID") ?? DEFAULT_CHAIN_ID,
    coordinatorUrl,
    webhookUrl,
    onboardToken: requiredStringOption(args, "onboard-token", "ONBOARD_TOKEN"),
    out: optionalStringOption(args, "out"),
  };
}
