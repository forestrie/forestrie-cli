/**
 * Payload intake and COSE Sign1 assembly for `forestrie sign-statement`
 * (FOR-341).
 *
 * The signed statement is a plain COSE Sign1 (forestrie-demo-01.md, answer
 * 5): protected header `{4: kid}`, ES256 signature via
 * `@forestrie/encoding` `signCoseSign1Statement`. The payload content type
 * (COSE header label 3, RFC 9052 §3.1) rides in the unprotected header.
 *
 * The final four-tuple is emitted with the canonical raw-CBOR helpers
 * rather than `mergeUnprotectedIntoCoseSign1`: the cbor-x re-encode path
 * wraps bstrs in tag 64 (typed array), which strict "plain COSE Sign1"
 * consumers (any SCRAPI client) may reject. The signed bytes (protected
 * header, payload, signature) are byte-identical either way — unprotected
 * headers are outside the Sig_structure.
 */
import { readFileSync } from "node:fs";
import {
  appendCborBstr,
  appendCborText,
  decodeCoseSign1,
  signCoseSign1Statement,
} from "@forestrie/encoding";
import {
  errorMessage,
  type Es256SigningKey,
} from "./sign-statement-key.js";

/** COSE header label for content type (RFC 9052 §3.1). */
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

/**
 * Sign `payload` as a plain COSE Sign1 signed statement.
 *
 * @param payload - Statement payload bytes
 * @param key - Loaded ES256 signing key (kid = first 32 bytes of `x||y`)
 * @param contentType - COSE content type header value (label 3)
 * @returns CBOR COSE Sign1 bytes
 */
export async function buildSignedStatement(
  payload: Uint8Array,
  key: Es256SigningKey,
  contentType: string,
): Promise<Uint8Array> {
  const coseSign1 = await signCoseSign1Statement(
    payload,
    key.kid,
    key.privateKey,
  );
  const decoded = decodeCoseSign1(coseSign1);
  if (decoded === null) {
    throw new Error("signCoseSign1Statement produced invalid COSE Sign1");
  }

  // Canonical plain COSE Sign1: array(4) of untagged bstrs, unprotected
  // map(1) { 3: contentType }.
  const bytes: number[] = [0x84]; // array(4)
  appendCborBstr(bytes, decoded.protectedBstr);
  bytes.push(0xa1, COSE_CONTENT_TYPE); // map(1) { 3: tstr }
  appendCborText(bytes, contentType);
  appendCborBstr(bytes, payload);
  appendCborBstr(bytes, decoded.signature);
  return new Uint8Array(bytes);
}
