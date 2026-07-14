/**
 * FOR-390 / ADR-0052 create-log grant assembly: build the grant that CREATES
 * a log and sets its owner (K(L)). Lifted out of the old register-grant-build
 * (plan-2607-21) — register-grant is now writer-only.
 *
 * Three shapes, all `GF_CREATE|GF_EXTEND` in byte 3 (grants.md §5):
 *
 * - `--self-referential` — root bootstrap leaf (`logId == ownerLogId`); the
 *   grant is its own authority, so grantData IS the envelope signer and
 *   `--signer-pem` is forbidden. Auth-log shaped (`authLogBootstrapShapedFlags`).
 * - `--auth-log` — create a child auth log; grantData = `--signer-pem` (the new
 *   log's owner). Auth-log shaped (`authLogBootstrapShapedFlags`).
 * - default — create a data log; grantData = `--signer-pem`. Data-log shaped
 *   (`dataLogCreateExtendFlags`).
 *
 * grantData is the new log owner's ES256 `x||y`. Reuses the register-grant
 * ES256 PEM parser and error class. Node-only (node:crypto PEM handling); no
 * HTTP, no env.
 */
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
import {
  RegisterGrantBuildError,
  es256PublicKeyXyFromPem,
} from "./register-grant-build.js";

export { RegisterGrantBuildError };

export type BuildCreateLogGrantParams = {
  /** The log being created (`grant.logId`, UUID). */
  newLog: string;
  /** Parent/auth log the create grant is sequenced into (`grant.ownerLogId`, UUID). */
  ownerLog: string;
  /** PKCS#8/SEC1 ES256 PEM that signs the grant envelope (the granting authority, K(L)). */
  signWithPem: string;
  /**
   * PEM of the new log's owner (`grantData` = ES256 x||y). Required unless
   * `--self-referential` (which binds the `--sign-with` key itself).
   */
  signerPem?: string | undefined;
  /** Root bootstrap: first leaf of the root log, `logId == ownerLogId`. */
  selfReferential: boolean;
  /** Create a child auth log (auth-log flag class) rather than a data log. */
  authLog: boolean;
};

export type BuiltCreateLogGrant = {
  /** Signed grant transparent statement, Forestrie-Grant header base64. */
  grantBase64: string;
  /** Canonical grant v0 payload CBOR (keys 1-6) that was signed. */
  grantPayloadBytes: Uint8Array;
  /** The new log owner this grant commits (ES256 x||y, 64 bytes). */
  grantData: Uint8Array;
  /** 8-byte GF_* flags bitmap that went on the wire. */
  flags: Uint8Array;
};

/**
 * Build and sign the create-log grant transparent statement: canonical grant
 * v0 CBOR (`encodeGrantPayloadV0Canonical`) with `GF_CREATE|GF_EXTEND` flags,
 * signed via the Custodian ES256 PEM profile (`signGrantPayloadWithEs256Pem`),
 * returned as `Authorization: Forestrie-Grant` base64.
 */
export function buildCreateLogGrant(
  params: BuildCreateLogGrantParams,
): BuiltCreateLogGrant {
  let logId: Uint8Array;
  let ownerLogId: Uint8Array;
  try {
    logId = uuidToBytes(params.newLog);
  } catch {
    throw new RegisterGrantBuildError(`--new-log is not a UUID: ${params.newLog}`);
  }
  try {
    ownerLogId = uuidToBytes(params.ownerLog);
  } catch {
    throw new RegisterGrantBuildError(
      `--owner-log is not a UUID: ${params.ownerLog}`,
    );
  }

  if (params.selfReferential) {
    // Root bootstrap shape: the grant is its own authority (first leaf of the
    // root log), so the new log IS the owner and grantData IS the envelope
    // signer (arbor's root-grant check compares them).
    if (params.newLog.toLowerCase() !== params.ownerLog.toLowerCase()) {
      throw new RegisterGrantBuildError(
        "--self-referential requires --new-log and --owner-log to be the same log (logId == ownerLogId)",
      );
    }
    if (params.signerPem !== undefined) {
      throw new RegisterGrantBuildError(
        "--self-referential grants bind the --sign-with key itself; omit --signer-pem",
      );
    }
  } else if (params.signerPem === undefined) {
    throw new RegisterGrantBuildError(
      "--signer-pem is required (the new log's owner) unless --self-referential",
    );
  }

  // The new log owner's public key is the committed grantData; the
  // self-referential bootstrap binds the granting key itself.
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
