/**
 * FOR-390 / ADR-0052 registrar delegate-key voucher verification, composed
 * from published `@forestrie/encoding` primitives.
 *
 * A voucher is a COSE Sign1 signed by the pinned registrar key over a CBOR
 * claims map `{1: sealerId, 2: epoch, 3: publicKey}`. It binds a sealer's
 * delegated checkpoint-signing key to a registrar-attested identity; the CLI
 * refuses to bind a delegation certificate to a delegate key whose voucher
 * does not verify against the operator-pinned registrar key.
 *
 * This mirrors canopy `@forestrie/encoding`'s `verify-delegate-key-voucher.ts`.
 * The published encoding v0.3.0 does NOT yet export
 * `verifyDelegateKeyVoucher` / `parseRegistrarKeyXY`, so they are composed here
 * from `decodeCoseSign1`, `verifyCoseSign1WithParsedKey`, and
 * `decodeCborDeterministic`. Adopt the published helper once encoding ships it.
 */
import {
  decodeCborDeterministic,
  decodeCoseSign1,
  verifyCoseSign1WithParsedKey,
  type ParsedEcPublicKey,
} from "@forestrie/encoding";

const REGISTRAR_KEY_XY_BYTES = 64;
const P256_COORD_BYTES = 32;

/** Claims map labels in the registrar voucher payload. */
const CLAIM_SEALER_ID = 1;
const CLAIM_EPOCH = 2;
const CLAIM_PUBLIC_KEY = 3;

/**
 * Parse a raw registrar key (uncompressed `x||y`, 64 bytes) into a
 * {@link ParsedEcPublicKey}. Returns null when the input is not 64 bytes.
 */
export function parseRegistrarKeyXY(raw: Uint8Array): ParsedEcPublicKey | null {
  if (raw.length !== REGISTRAR_KEY_XY_BYTES) return null;
  return {
    x: raw.slice(0, P256_COORD_BYTES),
    y: raw.slice(P256_COORD_BYTES),
    curve: "P-256",
  };
}

/** Claims the voucher must attest to for the binding to proceed. */
export type VoucherExpectation = {
  /** Sealer identity (claim 1). */
  sealerId: string;
  /** Registrar key epoch (claim 2); a JSON string epoch is parsed to bigint. */
  epoch: bigint | number | string;
  /** Delegated public key CBOR bytes (claim 3). */
  publicKey: Uint8Array;
};

/** Voucher verification outcome (fail-closed with a machine reason). */
export type VoucherResult = { ok: true } | { ok: false; reason: string };

/** Constant-time byte comparison (no early exit on first mismatch). */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

function toBigIntOrNull(value: unknown): bigint | null {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isInteger(value)) return BigInt(value);
  if (typeof value === "string" && /^-?\d+$/.test(value)) return BigInt(value);
  return null;
}

/**
 * Verify a registrar delegate-key voucher:
 *   1. COSE Sign1 signature verifies against the pinned registrar key.
 *   2. The payload decodes to a CBOR claims map.
 *   3. Claims 1/2/3 (sealerId / epoch / publicKey) match {@link expect}, with a
 *      constant-time compare on the public key bytes.
 *
 * @returns `{ok:true}` when everything matches, otherwise `{ok:false, reason}`.
 */
export async function verifyDelegateKeyVoucher(
  voucherBytes: Uint8Array,
  pinnedKey: ParsedEcPublicKey,
  expect: VoucherExpectation,
): Promise<VoucherResult> {
  // 1. Signature against the pinned registrar key.
  const sigOk = await verifyCoseSign1WithParsedKey(voucherBytes, pinnedKey);
  if (!sigOk) return { ok: false, reason: "signature" };

  // 2. Decode envelope + claims map.
  const decoded = decodeCoseSign1(voucherBytes);
  if (decoded === null) return { ok: false, reason: "decode" };
  let claims: unknown;
  try {
    claims = decodeCborDeterministic(decoded.payloadBstr);
  } catch {
    return { ok: false, reason: "decode" };
  }
  if (!(claims instanceof Map)) return { ok: false, reason: "decode" };

  // 3. Claim-by-claim comparison.
  const sealerId = claims.get(CLAIM_SEALER_ID);
  if (typeof sealerId !== "string" || sealerId !== expect.sealerId) {
    return { ok: false, reason: "sealerId" };
  }
  const epoch = toBigIntOrNull(claims.get(CLAIM_EPOCH));
  const expectedEpoch = toBigIntOrNull(expect.epoch);
  if (epoch === null || expectedEpoch === null || epoch !== expectedEpoch) {
    return { ok: false, reason: "epoch" };
  }
  const publicKey = claims.get(CLAIM_PUBLIC_KEY);
  if (
    !(publicKey instanceof Uint8Array) ||
    !constantTimeEqual(publicKey, expect.publicKey)
  ) {
    return { ok: false, reason: "publicKey" };
  }
  return { ok: true };
}
