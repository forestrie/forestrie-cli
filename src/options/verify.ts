import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/**
 * `forestrie verify` — FOR-347.
 *
 * Offline verification against a cached checkpoint — no network access.
 * The SAME verify command closes every demo step. ES256 only
 * (`@forestrie/receipt-verify`; error `no_es256_trust_key`).
 *
 * Acceptance (ex FOR-282): exit 0 on a valid receipt, non-zero on a
 * tampered one.
 */
export type VerifyOptions = ForestrieCommonOptions & {
  /** Cached public genesis (genesis.cbor) — the offline trust root. */
  genesis: string;
  /** COSE receipt file to verify. */
  receipt: string;
  /** Completed grant credential, base64 (or file via --grant + --entry-id). */
  grantB64: string | undefined;
  /** Grant CBOR file (alternative to --grant-b64). */
  grant: string | undefined;
  /** Entry id within the grant CBOR (used with --grant). */
  entryId: string | undefined;
};

export function parseVerifyOptions(args: LooseParsedArgs): VerifyOptions {
  const options: VerifyOptions = {
    ...parseForestrieCommonOptions(args),
    genesis: requiredStringOption(args, "genesis"),
    receipt: requiredStringOption(args, "receipt"),
    grantB64: optionalStringOption(args, "grant-b64", "GRANT_B64"),
    grant: optionalStringOption(args, "grant"),
    entryId: optionalStringOption(args, "entry-id"),
  };
  if (options.grantB64 === undefined && options.grant === undefined) {
    throw new Error(
      "either --grant-b64 or --grant (grant CBOR, with --entry-id) is required",
    );
  }
  if (options.grant !== undefined && options.entryId === undefined) {
    throw new Error("--grant requires --entry-id");
  }
  return options;
}
