/**
 * FOR-343 grant statement assembly: deterministic Forestrie-Grant v0
 * construction on top of `@forestrie/grant-builder` / `@forestrie/encoding`.
 *
 * A grant binds exactly ONE signer (`grantData` = the signer's ES256
 * `x||y`); several signers on one data log means several grants, each
 * naming that log. The grant leaf is sequenced into the OWNER (auth) log
 * (`ownerLogId`); the target/data log holds only statements. Flag shapes
 * follow grants.md §5:
 *
 * - `--auth-log` / `--self-referential` → `GF_CREATE|GF_EXTEND` +
 *   `GF_AUTH_LOG` (`authLogBootstrapShapedFlags`).
 * - default (data log) → `GF_CREATE|GF_EXTEND` + `GF_DATA_LOG`
 *   (`dataLogCreateExtendFlags`).
 *
 * ES256 is the paved path (mirrors grant-builder's node-only
 * `es256-pem-grant` profile: COSE Sign1 with a 32-byte digest payload and
 * the full grant v0 CBOR in unprotected -65538). KS256 wallet grants need
 * the univocity chain-binding material (`signGrantWithKs256WalletKey`
 * takes the on-chain delegation context), so they are a follow-up, not a
 * flag here.
 *
 * Node-only module (node:crypto PEM handling); no HTTP, no env.
 */
import { createPublicKey } from "node:crypto";
import { parsePemResilient } from "./openssl-error-queue.js";
import {
  authLogBootstrapShapedFlags,
  bytesToForestrieGrantBase64,
  dataLogCreateExtendFlags,
  signGrantPayloadWithEs256Pem,
} from "@forestrie/grant-builder";
import {
  encodeGrantPayloadV0Canonical,
  uuidToBytes,
  type Grant,
} from "@forestrie/encoding";

/** Grant construction failure (bad key material / inconsistent shape). */
export class RegisterGrantBuildError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RegisterGrantBuildError";
  }
}

const ES256_XY_BYTES = 64;

function base64UrlToBytes(b64url: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64url, "base64url"));
}

/**
 * ES256 P-256 public key as uncompressed `x||y` (64 bytes) from a PEM.
 * Accepts a public (SPKI) PEM or a private (SEC1/PKCS#8) PEM — the demo
 * flow points `--signer-pem` at the same key file `sign-statement --key`
 * uses, and the authorized signer's PUBLIC key is all the grant commits
 * to (grant-builder only ships the private-PEM variant).
 */
export function es256PublicKeyXyFromPem(pem: string): Uint8Array {
  let jwk: { crv?: string; x?: unknown; y?: unknown };
  try {
    // `parsePemResilient` retries once so a valid key is never rejected
    // because the OpenSSL error queue was poisoned elsewhere (FOR-343).
    jwk = parsePemResilient(() =>
      createPublicKey({ key: pem, format: "pem" }),
    ).export({
      format: "jwk",
    });
  } catch (err) {
    throw new RegisterGrantBuildError(
      `not an EC PEM (public or private): ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new RegisterGrantBuildError(
      "signer key must be a P-256 (ES256) EC key",
    );
  }
  const x = base64UrlToBytes(jwk.x);
  const y = base64UrlToBytes(jwk.y);
  if (x.length !== 32 || y.length !== 32) {
    throw new RegisterGrantBuildError(
      "ES256 public key coordinates must be 32 bytes each",
    );
  }
  const out = new Uint8Array(ES256_XY_BYTES);
  out.set(x, 0);
  out.set(y, 32);
  return out;
}

export type BuildGrantStatementParams = {
  /** Target log the grant authorizes (`grant.logId`, UUID). */
  targetLog: string;
  /** Owner (auth) log the grant leaf is sequenced into (`grant.ownerLogId`, UUID). */
  ownerLog: string;
  /** PKCS#8/SEC1 ES256 PEM that signs the grant envelope (the granting authority). */
  signWithPem: string;
  /**
   * PEM of the ONE signer being authorized (`grantData` = ES256 x||y).
   * Public or private PEM; when absent the grant is a self grant binding
   * the signing key itself.
   */
  signerPem?: string | undefined;
  /** Bootstrap-shaped root grant: first leaf of the root log, logId == ownerLogId. */
  selfReferential: boolean;
  /** Child auth log (auth-log flag class) rather than a data log. */
  authLog: boolean;
};

export type BuiltGrantStatement = {
  /** Signed grant transparent statement, Forestrie-Grant header base64. */
  grantBase64: string;
  /** Canonical grant v0 payload CBOR (keys 1-6) that was signed. */
  grantPayloadBytes: Uint8Array;
  /** The ONE authorized signer this grant binds (ES256 x||y, 64 bytes). */
  grantData: Uint8Array;
  /** 8-byte GF_* flags bitmap that went on the wire. */
  flags: Uint8Array;
};

/**
 * Build and sign the grant transparent statement:
 * canonical grant v0 CBOR (`encodeGrantPayloadV0Canonical`) signed via the
 * Custodian ES256 PEM profile (`signGrantPayloadWithEs256Pem`), returned
 * as `Authorization: Forestrie-Grant` base64.
 */
export function buildGrantStatement(
  params: BuildGrantStatementParams,
): BuiltGrantStatement {
  let logId: Uint8Array;
  let ownerLogId: Uint8Array;
  try {
    logId = uuidToBytes(params.targetLog);
  } catch {
    throw new RegisterGrantBuildError(
      `--data-log is not a UUID: ${params.targetLog}`,
    );
  }
  try {
    ownerLogId = uuidToBytes(params.ownerLog);
  } catch {
    throw new RegisterGrantBuildError(
      `--owner-log is not a UUID: ${params.ownerLog}`,
    );
  }

  if (params.selfReferential) {
    // Root bootstrap shape: the grant is its own authority (first leaf of
    // the root log), so the target IS the owner and grantData IS the
    // envelope signer (arbor's root-grant check compares them).
    if (params.targetLog.toLowerCase() !== params.ownerLog.toLowerCase()) {
      throw new RegisterGrantBuildError(
        "--self-referential requires --data-log and --owner-log to be the same log (logId == ownerLogId)",
      );
    }
    if (params.signerPem !== undefined) {
      throw new RegisterGrantBuildError(
        "--self-referential grants bind the --sign-with key itself; omit --signer-pem",
      );
    }
  }

  // One grant, ONE signer: the authorized signer's public key is the
  // committed grantData; self grants bind the granting key.
  const grantData = es256PublicKeyXyFromPem(
    params.signerPem ?? params.signWithPem,
  );

  const flags =
    params.authLog || params.selfReferential
      ? authLogBootstrapShapedFlags()
      : dataLogCreateExtendFlags();

  const grant: Grant = {
    logId,
    ownerLogId,
    grant: flags,
    maxHeight: 0,
    minGrowth: 0,
    grantData,
  };
  const grantPayloadBytes = encodeGrantPayloadV0Canonical(grant);
  let sign1: Uint8Array;
  try {
    sign1 = signGrantPayloadWithEs256Pem(grantPayloadBytes, params.signWithPem);
  } catch (err) {
    throw new RegisterGrantBuildError(
      `--sign-with key rejected: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  return {
    grantBase64: bytesToForestrieGrantBase64(sign1),
    grantPayloadBytes,
    grantData,
    flags,
  };
}
