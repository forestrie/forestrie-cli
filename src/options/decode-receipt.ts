import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  parseForestrieCommonOptions,
  type ForestrieCommonOptions,
} from "./common.js";

/** `forestrie decode-receipt` — FOR-346. */
export type DecodeReceiptOptions = ForestrieCommonOptions & {
  /** COSE receipt file to decode (Sign1 + MMR inclusion). */
  receipt: string;
};

export function parseDecodeReceiptOptions(
  args: LooseParsedArgs,
): DecodeReceiptOptions {
  const receipt = typeof args["receipt"] === "string" ? args["receipt"] : "";
  if (receipt === "") {
    throw new Error("missing required positional: receipt file");
  }
  return {
    ...parseForestrieCommonOptions(args),
    receipt,
  };
}
