import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/** `forestrie sign-statement` — FOR-341. */
export type SignStatementOptions = ForestrieCommonOptions & {
  /** ES256 P-256 private signing key path (SEC1/PKCS#8 PEM or JWK). */
  key: string;
  /** Payload file to wrap as the COSE Sign1 payload (`-` = stdin). */
  payload: string;
  /** Payload content type (COSE `content type` header, label 3). */
  contentType: string;
  /** Signed statement output path (default: stdout). */
  out: string | undefined;
};

export function parseSignStatementOptions(
  args: LooseParsedArgs,
): SignStatementOptions {
  return {
    ...parseForestrieCommonOptions(args),
    key: requiredStringOption(args, "key"),
    payload: requiredStringOption(args, "payload"),
    contentType:
      optionalStringOption(args, "content-type") ?? "application/json",
    out: optionalStringOption(args, "out"),
  };
}
