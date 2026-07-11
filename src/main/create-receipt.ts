import type { Out } from "@forestrie/cli-kit/reporting";
import type { CreateReceiptOptions } from "../options/create-receipt.js";
import { reportNotImplemented } from "./not-implemented.js";

/**
 * FOR-345: self-serve COSE receipt (Sign1 + MMR inclusion path to an
 * accumulator peak) from log data + a checkpoint, with no operator API
 * call (`@forestrie/receipt-verify`, `@forestrie/merklelog`). Chain mode
 * checks the computed peak against the on-chain accumulator.
 */
export async function runCreateReceipt(
  out: Out,
  options: CreateReceiptOptions,
): Promise<void> {
  reportNotImplemented(out, options, "create-receipt", "FOR-345", {
    ...options,
  });
}
