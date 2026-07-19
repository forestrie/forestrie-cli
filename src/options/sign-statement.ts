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
   * An explicit empty string is preserved so the run layer can reject it
   * through the structured error path (a silent default substitution
   * would sign a different issuer than the caller asked for).
   */
  iss: string | undefined;
  /** Subject (CWT claim 2). Default (unset): `sha-256:<hex>` of payload. */
  sub: string | undefined;
  /**
   * Issued-at (CWT claim 6), raw: `now` or unix-seconds digits. Validated
   * and resolved in the run layer so a bad value produces the structured
   * error report, not a parse-time stack trace.
   */
  iat: string | undefined;
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
    iss: claimStringOption(args, "iss"),
    sub: claimStringOption(args, "sub"),
    iat: optionalStringOption(args, "iat"),
    out: optionalStringOption(args, "out"),
  };
}

/**
 * As `optionalStringOption`, but an explicit `""` survives (that helper
 * folds it into "unset", which for signed-claim inputs would silently
 * substitute the default).
 */
function claimStringOption(
  args: LooseParsedArgs,
  name: string,
): string | undefined {
  if (args[name] === "") return "";
  return optionalStringOption(args, name);
}
