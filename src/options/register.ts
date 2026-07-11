import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/** `forestrie register` — FOR-342. */
export type RegisterOptions = ForestrieCommonOptions & {
  /** SCRAPI origin, no trailing slash (`FORESTRIE_BASE_URL`). */
  baseUrl: string;
  /** Target log id (UUID). */
  logId: string;
  /** COSE Sign1 signed statement file to register. */
  statement: string;
  /** `Authorization: Forestrie-Grant` bearer credential (`GRANT_B64`). */
  grantB64: string;
  /** Receipt output path (default: stdout). */
  out: string | undefined;
};

export function parseRegisterOptions(args: LooseParsedArgs): RegisterOptions {
  return {
    ...parseForestrieCommonOptions(args),
    baseUrl: requiredStringOption(args, "base-url", "FORESTRIE_BASE_URL"),
    logId: requiredStringOption(args, "log-id"),
    statement: requiredStringOption(args, "statement"),
    grantB64: requiredStringOption(args, "grant-b64", "GRANT_B64"),
    out: optionalStringOption(args, "out"),
  };
}
