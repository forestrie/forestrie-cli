import type { Out } from "@forestrie/cli-kit/reporting";
import type { CompleteGrantOptions } from "../options/complete-grant.js";
import { reportNotImplemented } from "./not-implemented.js";

/**
 * FOR-344: self-create the `Authorization: Forestrie-Grant` header content
 * from a checkpoint (`@forestrie/grant-builder`) — grants are derivable
 * from log data, not operator-issued.
 */
export async function runCompleteGrant(
  out: Out,
  options: CompleteGrantOptions,
): Promise<void> {
  reportNotImplemented(out, options, "complete-grant", "FOR-344", {
    ...options,
  });
}
