/**
 * Payload intake and COSE Sign1 assembly for `forestrie sign-statement`
 * (FOR-341).
 *
 * The signed statement is a plain COSE Sign1 (forestrie-demo-01.md, answer
 * 5) with **all interpretable labels in the protected header**:
 * `{1: alg (ES256, -7), 3: cty, 4: kid}`, signed via `@forestrie/encoding`
 * `signCoseSign1Statement` (encoding >= 0.2.0). Nothing rides unprotected —
 * per SCITT, the content type that tells a relying party how to interpret
 * the signed bytes must be covered by the signature (review F1,
 * plan-2607-14 W1.2), and the algorithm is pinned the same way.
 *
 * The encoder emits canonical tag-free CBOR, so the wire stays a plain
 * untagged four-tuple (`84 58 xx ...`) that strict "plain COSE Sign1"
 * consumers (any SCRAPI client) accept — no cbor-x tag 64 re-encode
 * workaround is needed now that no unprotected header is merged in.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  COSE_ALG_ES256,
  coseKeyThumbprintUriP256,
  signCoseSign1Statement,
} from "@forestrie/encoding";
import { errorMessage, type Es256SigningKey } from "./sign-statement-key.js";

/** COSE header label for content type (RFC 9052 §3.1) — protected. */
export const COSE_CONTENT_TYPE = 3;

/**
 * Read the statement payload from a file, or stdin when `pathOrDash`
 * is `-`.
 */
export function readPayloadBytes(pathOrDash: string): Uint8Array {
  try {
    const data =
      pathOrDash === "-" ? readFileSync(0) : readFileSync(pathOrDash);
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  } catch (err) {
    const source =
      pathOrDash === "-" ? "stdin" : `payload file ${pathOrDash}`;
    throw new Error(`cannot read ${source}: ${errorMessage(err)}`);
  }
}

/** `--iss` keyword deriving the RFC 9679 COSE Key Thumbprint URI. */
export const ISS_CKT_KEYWORD = "ckt";

/** Statement content type plus CWT claims inputs (FOR-371). */
export type SignStatementBuildOptions = {
  /** COSE content type header value (label 3, protected). */
  contentType: string;
  /**
   * Issuer (CWT claim 1): literal StringOrURI, or {@link ISS_CKT_KEYWORD}
   * to derive the RFC 9679 thumbprint URI from the signing key.
   * Default: lowercase hex of the kid bytes (devdocs ADR-0055).
   */
  iss?: string | undefined;
  /**
   * Subject (CWT claim 2): issuer-scoped StringOrURI.
   * Default: `sha-256:<hex>` of the payload bytes.
   */
  sub?: string | undefined;
  /** Issued-at (CWT claim 6), seconds since epoch. Omitted by default. */
  iat?: number | undefined;
};

/** A signed statement plus the claims that were actually bound into it. */
export type SignedStatement = {
  /** CBOR COSE Sign1 bytes (untagged array(4)). */
  statement: Uint8Array;
  /** Resolved issuer (CWT claim 1). */
  iss: string;
  /** Resolved subject (CWT claim 2). */
  sub: string;
  /** Issued-at (CWT claim 6), when requested. */
  iat?: number;
};

/**
 * Sign `payload` as a plain COSE Sign1 signed statement.
 *
 * Protected header carries `{1: ES256, 3: contentType, 4: kid, 15: CWT
 * claims}` (SCITT signed statement, FOR-371); the unprotected header is
 * empty. The signature covers everything interpretable — alg, cty, and the
 * claims are all inside the protected bstr in the Sig_structure.
 *
 * @param payload - Statement payload bytes
 * @param key - Loaded ES256 signing key (kid = first 32 bytes of `x||y`)
 * @param options - Content type and claims; iss/sub default per ADR-0055
 * @returns Statement bytes plus the resolved iss/sub (and iat when set)
 */
export async function buildSignedStatement(
  payload: Uint8Array,
  key: Es256SigningKey,
  options: SignStatementBuildOptions,
): Promise<SignedStatement> {
  const iss =
    options.iss === ISS_CKT_KEYWORD
      ? await coseKeyThumbprintUriP256(key.publicXY)
      : (options.iss ??
        Buffer.from(key.kid).toString("hex"));
  const sub =
    options.sub ??
    `sha-256:${createHash("sha256").update(payload).digest("hex")}`;
  const statement = await signCoseSign1Statement(
    payload,
    key.kid,
    key.privateKey,
    {
      alg: COSE_ALG_ES256,
      cty: options.contentType,
      cwtClaims: { iss, sub, ...(options.iat !== undefined && { iat: options.iat }) },
    },
  );
  return { statement, iss, sub, ...(options.iat !== undefined && { iat: options.iat }) };
}
