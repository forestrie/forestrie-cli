import type { Out } from "@forestrie/cli-kit/reporting";
import type { RegisterOptions } from "../options/register.js";
import { reportNotImplemented } from "./not-implemented.js";

/**
 * FOR-342: register a signed statement via SCRAPI
 * (`@forestrie/scrapi-client`) — POST with the `Authorization:
 * Forestrie-Grant` header, follow the 303, poll, download the receipt.
 */
export async function runRegister(
  out: Out,
  options: RegisterOptions,
): Promise<void> {
  reportNotImplemented(out, options, "register", "FOR-342", { ...options });
}
