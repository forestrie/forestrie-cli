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
  /** Payload content type (COSE `content type` header, label 3, protected). */
  contentType: string;
  /**
   * Issuer (CWT claim 1): literal StringOrURI, or `ckt` for the RFC 9679
   * thumbprint URI. Default (unset): hex kid (devdocs ADR-0055).
   */
  iss: string | undefined;
  /** Subject (CWT claim 2). Default (unset): `sha-256:<hex>` of payload. */
  sub: string | undefined;
  /** Issued-at (CWT claim 6): unix seconds, or `now` resolved at run. */
  iat: number | "now" | undefined;
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
    iss: optionalStringOption(args, "iss"),
    sub: optionalStringOption(args, "sub"),
    iat: parseIatOption(optionalStringOption(args, "iat")),
    out: optionalStringOption(args, "out"),
  };
}

/** `--iat now` or unsigned integer seconds; anything else is an error. */
function parseIatOption(raw: string | undefined): number | "now" | undefined {
  if (raw === undefined || raw === "now") return raw;
  if (!/^\d+$/.test(raw)) {
    throw new Error(`--iat must be 'now' or unix seconds, got '${raw}'`);
  }
  return Number.parseInt(raw, 10);
}
