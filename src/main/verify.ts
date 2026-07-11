import type { Out } from "@forestrie/cli-kit/reporting";
import type { VerifyOptions } from "../options/verify.js";
import { reportNotImplemented } from "./not-implemented.js";

/**
 * FOR-347: verify a receipt offline against the cached checkpoint /
 * on-chain accumulator trust root (`@forestrie/receipt-verify`, ES256
 * only). No network access during verify; exit 0 iff the receipt is valid.
 */
export async function runVerify(
  out: Out,
  options: VerifyOptions,
): Promise<void> {
  reportNotImplemented(out, options, "verify", "FOR-347", { ...options });
}
