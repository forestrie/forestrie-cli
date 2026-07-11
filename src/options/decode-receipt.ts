import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  parseForestrieCommonOptions,
  type ForestrieCommonOptions,
} from "./common.js";

/** `forestrie decode-receipt` — FOR-346. */
export type DecodeReceiptOptions = ForestrieCommonOptions & {
  /**
   * COSE receipt file to decode (Sign1 + MMR inclusion).
   * Omitted or `-`: read the receipt CBOR from stdin.
   */
  receipt?: string;
};

export function parseDecodeReceiptOptions(
  args: LooseParsedArgs,
): DecodeReceiptOptions {
  const options: DecodeReceiptOptions = parseForestrieCommonOptions(args);
  const receipt = typeof args["receipt"] === "string" ? args["receipt"] : "";
  if (receipt !== "") {
    options.receipt = receipt;
  }
  return options;
}
