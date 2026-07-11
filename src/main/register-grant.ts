import type { Out } from "@forestrie/cli-kit/reporting";
import type { RegisterGrantOptions } from "../options/register-grant.js";
import { reportNotImplemented } from "./not-implemented.js";

/**
 * FOR-343: register a grant statement authorizing use of a child/data log
 * (`@forestrie/grant-builder`). One grant per signer, all recorded in the
 * owner (auth) log.
 */
export async function runRegisterGrant(
  out: Out,
  options: RegisterGrantOptions,
): Promise<void> {
  reportNotImplemented(out, options, "register-grant", "FOR-343", {
    ...options,
  });
}
