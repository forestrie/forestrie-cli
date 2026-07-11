import type { Out } from "@forestrie/cli-kit/reporting";
import type { DeployOptions } from "../options/deploy.js";
import { reportNotImplemented } from "./not-implemented.js";

/**
 * FOR-340: wrap `@forestrie/deploy-core` to deploy a univocity instance.
 * ES256 bootstrap is the paved path (`--bootstrap-alg es256`).
 */
export async function runDeploy(
  out: Out,
  options: DeployOptions,
): Promise<void> {
  reportNotImplemented(out, options, "deploy", "FOR-340", { ...options });
}
