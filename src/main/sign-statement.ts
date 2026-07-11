import type { Out } from "@forestrie/cli-kit/reporting";
import type { SignStatementOptions } from "../options/sign-statement.js";
import { reportNotImplemented } from "./not-implemented.js";

/**
 * FOR-341: build a plain COSE Sign1 signed statement
 * (`@forestrie/encoding`). `kid` = first 32 bytes of x||y under ES256.
 */
export async function runSignStatement(
  out: Out,
  options: SignStatementOptions,
): Promise<void> {
  reportNotImplemented(out, options, "sign-statement", "FOR-341", {
    ...options,
  });
}
