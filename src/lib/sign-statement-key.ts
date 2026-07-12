/**
 * ES256 signing-key loading and kid derivation for `forestrie
 * sign-statement` (FOR-341).
 *
 * Key import follows @forestrie/grant-builder `es256-pem-grant`:
 * node:crypto `createPrivateKey` accepts SEC1 or PKCS#8 EC PEMs (WebCrypto
 * alone imports only PKCS#8); JWK key files are routed through the same
 * call so every input is validated identically. The normalized private JWK
 * is then imported into WebCrypto because `@forestrie/encoding`
 * `signCoseSign1Statement` signs with `crypto.subtle`.
 *
 * kid binding (forestrie-demo-01.md, answer 5): first 32 bytes of the
 * uncompressed public point `x||y` under ES256.
 */
import {
  createPrivateKey,
  type KeyObject,
  type webcrypto,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { parsePemResilient } from "./openssl-error-queue.js";

/** kid length: first 32 bytes of `x||y` (i.e. the x coordinate). */
export const ES256_KID_BYTES = 32;

/** P-256 coordinate length in bytes. */
const P256_COORD_BYTES = 32;

/** Loaded ES256 signing key, ready for `signCoseSign1Statement`. */
export type Es256SigningKey = {
  /** WebCrypto ECDSA P-256 private key (usage: sign). */
  privateKey: CryptoKey;
  /** Signer binding: first {@link ES256_KID_BYTES} bytes of `x||y`. */
  kid: Uint8Array;
  /** Uncompressed public point `x||y` (64 bytes). */
  publicXY: Uint8Array;
};

/** `Error.message` (or stringified value) for wrapped error causes. */
export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Load an ES256 (EC P-256) private key from a PEM or JWK file.
 *
 * @param keyPath - SEC1/PKCS#8 PEM or JWK JSON private key file
 * @returns WebCrypto sign key plus the derived kid and public point
 */
export async function loadEs256SigningKey(
  keyPath: string,
): Promise<Es256SigningKey> {
  let text: string;
  try {
    text = readFileSync(keyPath, "utf8");
  } catch (err) {
    throw new Error(`cannot read key file ${keyPath}: ${errorMessage(err)}`);
  }
  return es256SigningKeyFromText(text, keyPath);
}

/** As {@link loadEs256SigningKey}, from key material already in memory. */
export async function es256SigningKeyFromText(
  text: string,
  source: string,
): Promise<Es256SigningKey> {
  const keyObject = importPrivateKeyObject(text, source);
  const jwk = keyObject.export({ format: "jwk" });
  if (
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    typeof jwk.x !== "string" ||
    typeof jwk.y !== "string" ||
    typeof jwk.d !== "string"
  ) {
    throw new Error(
      `${source}: sign-statement requires an ES256 (EC P-256) private key`,
    );
  }

  const x = base64UrlToBytes(jwk.x);
  const y = base64UrlToBytes(jwk.y);
  if (x.length !== P256_COORD_BYTES || y.length !== P256_COORD_BYTES) {
    throw new Error(
      `${source}: P-256 public key coordinates must be 32 bytes each`,
    );
  }
  const publicXY = new Uint8Array(P256_COORD_BYTES * 2);
  publicXY.set(x, 0);
  publicXY.set(y, P256_COORD_BYTES);

  const privateKey = await crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d, ext: true },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );

  return {
    privateKey,
    kid: publicXY.slice(0, ES256_KID_BYTES),
    publicXY,
  };
}

/** Route PEM or JWK-JSON key text through node:crypto for validation. */
function importPrivateKeyObject(text: string, source: string): KeyObject {
  if (text.includes("-----BEGIN")) {
    try {
      // `parsePemResilient` retries once so a valid key is never rejected
      // because the OpenSSL error queue was poisoned elsewhere (FOR-343).
      return parsePemResilient(() =>
        createPrivateKey({ key: text, format: "pem" }),
      );
    } catch (err) {
      throw new Error(
        `${source}: not a readable EC private key PEM: ${errorMessage(err)}`,
      );
    }
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(
      `${source}: key file is neither a PEM nor a JWK JSON document`,
    );
  }
  try {
    return createPrivateKey({
      key: parsed as webcrypto.JsonWebKey,
      format: "jwk",
    });
  } catch (err) {
    throw new Error(
      `${source}: not a usable private JWK: ${errorMessage(err)}`,
    );
  }
}

/** Decode base64url (JWK coordinate encoding) to bytes. */
function base64UrlToBytes(b64url: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64url, "base64url"));
}
