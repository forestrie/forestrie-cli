import {
  knownLogKeyFromBytes,
  type RootVerifyKey,
} from "@forestrie/receipt-verify";

/** The accepted `--known-log-key` forms, for error messages and help. */
export const KNOWN_LOG_KEY_FORMS =
  "base64 x||y (64-byte ES256 public key) or a 20-byte KS256 address (0x + 40 hex, or base64)";

/**
 * Parse the caller-known log OWNER key (`--known-log-key`). Forms:
 *
 * - base64 of 64 bytes: an ES256 public key, x||y;
 * - `0x` + 40 hex, or base64 of 20 bytes: a KS256 (Ethereum) address.
 *
 * Length alone decides the algorithm (via `knownLogKeyFromBytes`, the same
 * rule univocity applies). Either way the caller ASSERTS the key owns the log.
 */
export async function parseKnownLogKey(value: string): Promise<RootVerifyKey> {
  const v = value.trim();
  const bytes = /^0x[0-9a-fA-F]{40}$/.test(v)
    ? new Uint8Array(Buffer.from(v.slice(2), "hex"))
    : new Uint8Array(Buffer.from(v, "base64"));
  if (bytes.length !== 64 && bytes.length !== 20) {
    throw new Error(
      `--known-log-key must be ${KNOWN_LOG_KEY_FORMS}; decoded ${bytes.length} bytes`,
    );
  }
  return knownLogKeyFromBytes(bytes);
}

/** True for a KS256 root (a `ParsedKs256RootKey`, not a WebCrypto key). */
export function isKs256Root(key: RootVerifyKey): boolean {
  return !(key instanceof CryptoKey);
}
