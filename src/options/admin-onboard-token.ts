import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/** Default onboard-token label when `--label` is absent. */
export const DEFAULT_ONBOARD_TOKEN_LABEL = "forestrie-cli";

/** `forestrie admin onboard-token` — FOR-406 (plan-2607-27 W1). */
export type AdminOnboardTokenOptions = ForestrieCommonOptions & {
  /** SCRAPI origin, no trailing slash (`FORESTRIE_BASE_URL`). */
  baseUrl: string;
  /**
   * Operator credential (`CANOPY_OPS_ADMIN_TOKEN`). The `admin` family is
   * the operator-credential surface (ADR-0052); participant commands never
   * read this secret.
   */
  opsToken: string;
  /** Token label recorded by the mint endpoint. */
  label: string;
  /** Write the minted token here instead of stdout. */
  out: string | undefined;
};

export function parseAdminOnboardTokenOptions(
  args: LooseParsedArgs,
): AdminOnboardTokenOptions {
  return {
    ...parseForestrieCommonOptions(args),
    baseUrl: requiredStringOption(args, "base-url", "FORESTRIE_BASE_URL"),
    opsToken: requiredStringOption(args, "ops-token", "CANOPY_OPS_ADMIN_TOKEN"),
    label: optionalStringOption(args, "label") ?? DEFAULT_ONBOARD_TOKEN_LABEL,
    out: optionalStringOption(args, "out"),
  };
}
