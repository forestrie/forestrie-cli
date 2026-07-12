/**
 * OpenSSL/BoringSSL thread-local error-queue hygiene (FOR-343).
 *
 * On bun (BoringSSL), a FAILED `crypto.subtle.importKey` over malformed DER
 * leaves one unconsumed error on the thread-local OpenSSL error queue. The
 * NEXT `node:crypto` PEM parse (`createPrivateKey` / `createPublicKey`) reads
 * that stale error and misreports a perfectly valid key as
 * `error:0c00007b:ASN.1 encoding routines:OPENSSL_internal:HEADER_TOO_LONG`.
 * A single subsequent parse consumes the stale entry, so the corruption
 * "poisons" exactly one following operation.
 *
 * This bites cross-module in the single bun test runtime: `forestrie deploy`'s
 * negative-path test (a deliberately invalid bootstrap PEM routed through
 * `@forestrie/deploy-core`'s WebCrypto importKey) poisons the queue, and a
 * later `sign-statement` / `register-grant` PEM parse in another test file
 * then fails spuriously. See the FOR-343 repro.
 *
 * These helpers keep the failure contained: {@link drainOpenSslErrorQueue}
 * consumes the stale entry at the source (right after a known crypto failure),
 * and {@link parsePemResilient} retries once so a valid key is never rejected
 * because of a queue poisoned elsewhere.
 */
import { createPublicKey } from "node:crypto";

/**
 * Consume any single stale entry left on the OpenSSL error queue by a prior
 * failed crypto operation. Parses a deliberately invalid PEM and swallows the
 * (expected) throw: that parse reads and clears the stale entry. Best-effort
 * and never throws.
 */
export function drainOpenSslErrorQueue(): void {
  try {
    createPublicKey({
      key: "-----BEGIN PUBLIC KEY-----\nAA\n-----END PUBLIC KEY-----\n",
      format: "pem",
    });
  } catch {
    // Expected: the invalid PEM consumes the stale queue entry (and its own).
  }
}

/**
 * Run a PEM `parse` that may spuriously throw because the OpenSSL error queue
 * was poisoned by an unrelated prior crypto failure. On the first failure the
 * stale entry is consumed, so a single retry either succeeds (the input was
 * always valid) or throws the genuine error (the input is truly invalid).
 */
export function parsePemResilient<T>(parse: () => T): T {
  try {
    return parse();
  } catch {
    // Retry once: the failed attempt above drained any poisoning entry, so a
    // valid key now parses; a genuinely-invalid key throws the real error here.
    return parse();
  }
}
