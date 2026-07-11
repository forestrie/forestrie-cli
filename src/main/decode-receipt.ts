import type { Out } from "@forestrie/cli-kit/reporting";
import type { DecodeReceiptOptions } from "../options/decode-receipt.js";
import { reportNotImplemented } from "./not-implemented.js";

/**
 * FOR-346: decode a COSE receipt so the audience sees it is just COSE
 * (Sign1 + MMR inclusion) — `@forestrie/encoding`.
 */
export async function runDecodeReceipt(
  out: Out,
  options: DecodeReceiptOptions,
): Promise<void> {
  reportNotImplemented(out, options, "decode-receipt", "FOR-346", {
    ...options,
  });
}
