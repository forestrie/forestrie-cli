/**
 * FOR-390 / ADR-0052 delegation flow: authorize a custodian-vouched sealer to
 * publish checkpoints for a log the caller owns (K(L)), using only PUBLIC
 * coordinator endpoints (no operator token, no RPC).
 *
 * Port of canopy's `signAdvanceDelegation` + `buildByokDelegationMaterial`
 * composed on published `@forestrie/delegation-cose` + `@forestrie/encoding`:
 *
 *   1. Import the ES256 root PEM (K(L)) as a WebCrypto CryptoKeyPair.
 *   2. GET the coordinator's pending-delegation entries (range bounds are
 *      canonical decimal strings, plan-2611-01 D1); find the STANDING
 *      delegate-key entry (has `suggestedTtlSeconds`, no `mmrStart`).
 *   3. Verify the registrar voucher against the caller-known registrar key
 *      (mandatory — fail closed).
 *   4. Build the delegation certificate + on-chain delegation proof over the
 *      horizon `mmr 0..end`.
 *   5. POST the certificate to the coordinator (range as decimal strings).
 *
 * The range is a uint64 carried as `bigint` end to end (FOR-613).
 *
 * Node-only (node:crypto PEM import). WebCrypto (`crypto.subtle`) does the
 * ES256 signing inside delegation-cose.
 */
import { createPrivateKey, createPublicKey } from "node:crypto";
import {
  buildDelegationCertificateEs256,
  decodeDelegatedCoseKeyFromBytes,
  parseDelegatedCoseKeyFromPayload,
  parseDelegationCertificate,
  signOnchainDelegationEs256,
  type DelegationInput,
} from "@forestrie/delegation-cose";
import { uuidToBytes } from "@forestrie/encoding";
import { formatDecimalUint64, parseDecimalUint64 } from "./decimal-uint64.js";
import {
  parseRegistrarKeyXY,
  verifyDelegateKeyVoucher,
} from "./delegate-voucher.js";

import { responseProblemDetail } from "./http-problem.js";

/** Fixed inclusive MMR start for a horizon delegation lease. */
const MMR_START = 0n;

function b64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

function bytesToB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

/**
 * A coordinator pending-delegation entry. The STANDING delegate-key entry
 * (registered by C1/C3) carries `suggestedTtlSeconds` and no `mmrStart`; lease
 * entries carry `mmrStart` / `mmrEnd` as canonical decimal uint64 strings
 * (plan-2611-01 D1). {@link runDelegateFlow} rejects any other range shape.
 */
export type StandingDelegationEntry = {
  /** base64 CBOR EC2 P-256 COSE_Key for the delegated checkpoint signer. */
  delegatedPublicKey: string;
  /** Present on the standing entry only. */
  suggestedTtlSeconds?: number;
  /** Present on lease entries only; canonical decimal uint64 string. */
  mmrStart?: string;
  /** Present on lease entries only; canonical decimal uint64 string. */
  mmrEnd?: string;
  /** base64 COSE Sign1 registrar voucher. */
  voucher?: string;
  /** Sealer identity attested by the voucher. */
  sealerId?: string;
  /** Registrar key epoch attested by the voucher. */
  epoch?: number | string;
};

/** Failure raised by the delegation flow (submit / verify / precondition). */
export class DelegateFlowError extends Error {
  readonly httpStatus?: number;
  /** Structured error code for `--json` reporting (default: delegation_failed). */
  readonly code?: "key_read_failed" | "delegation_failed";
  constructor(
    message: string,
    httpStatus?: number,
    code?: "key_read_failed" | "delegation_failed",
  ) {
    super(message);
    this.name = "DelegateFlowError";
    if (httpStatus !== undefined) this.httpStatus = httpStatus;
    if (code !== undefined) this.code = code;
  }
}

export type DelegateFlowParams = {
  /** Delegation coordinator origin, no trailing slash. */
  coordinatorUrl: string;
  /** Target log id (UUID). */
  logId: string;
  /** ES256 log-root PEM (K(L)) that authorizes the delegation. */
  rootPem: string;
  /** Pinned registrar key, base64 `x||y` (64 bytes). */
  knownSealerKey: string;
  /** Exclusive MMR end of the horizon lease (mmrStart is fixed 0); uint64. */
  horizonMmrEnd: bigint;
  /** Lease TTL seconds; defaults to the standing entry's suggestedTtlSeconds. */
  ttlSeconds?: number | undefined;
};

export type DelegateFlowDeps = {
  fetchImpl?: typeof fetch;
};

/**
 * The submitted lease. The range is `bigint` (uint64); renderers format it
 * with {@link formatDecimalUint64} — never `JSON.stringify` it directly.
 */
export type DelegateFlowResult = {
  sealerId: string;
  epoch: number | string;
  mmrStart: bigint;
  mmrEnd: bigint;
  /** base64 delegated public key COSE_Key passed through to the coordinator. */
  delegatedPublicKey: string;
  expiresAt: number;
  certificate: Uint8Array;
};

/**
 * Import an ES256 PKCS#8/SEC1 PEM as a WebCrypto CryptoKeyPair (private for
 * signing, public for verification). Mirrors canopy's `importEs256PemKeyPair`.
 */
async function importEs256PemKeyPair(pem: string): Promise<CryptoKeyPair> {
  const priv = createPrivateKey({ key: pem, format: "pem" });
  const pkcs8 = priv.export({ format: "der", type: "pkcs8" });
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  // Derive the public key from the private PEM (round-trip through PEM keeps
  // the @types/node overloads happy — createPublicKey(KeyObject) is untyped
  // in this toolchain).
  const pubPem = priv.export({ format: "pem", type: "pkcs8" }) as string;
  const spki = createPublicKey({ key: pubPem, format: "pem" }).export({
    format: "der",
    type: "spki",
  });
  const publicKey = await crypto.subtle.importKey(
    "spki",
    spki,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
  return { privateKey, publicKey };
}

/**
 * Validate the range bounds of every coordinator entry: a present `mmrStart`
 * or `mmrEnd` must be a canonical decimal uint64 string (D1, hard cutover).
 * A JSON number or malformed string fails the flow rather than being read as
 * absent — absence is what marks the standing entry.
 */
function checkEntryRanges(entries: readonly unknown[]): void {
  entries.forEach((entry, i) => {
    if (typeof entry !== "object" || entry === null) {
      throw new DelegateFlowError(
        `pending-delegation entry ${i} is not an object`,
      );
    }
    const record = entry as Record<string, unknown>;
    for (const field of ["mmrStart", "mmrEnd"] as const) {
      if (record[field] === undefined) continue;
      try {
        parseDecimalUint64(record[field], `pending-delegation entry ${i} ${field}`);
      } catch (err) {
        throw new DelegateFlowError((err as Error).message);
      }
    }
  });
}

/**
 * Run the public delegation flow end-to-end, returning the submitted
 * certificate and the bound lease scope.
 */
export async function runDelegateFlow(
  params: DelegateFlowParams,
  deps: DelegateFlowDeps = {},
): Promise<DelegateFlowResult> {
  const fetchImpl = deps.fetchImpl ?? fetch;

  // 1. Root key pair (K(L)). A malformed or wrong-curve PEM must surface as a
  // structured error (not an unhandled throw that leaks the key path / stack).
  let rootKeyPair: CryptoKeyPair;
  try {
    rootKeyPair = await importEs256PemKeyPair(params.rootPem);
  } catch {
    throw new DelegateFlowError(
      "--sign-with is not a usable ES256 (P-256) root PEM (K(L))",
      undefined,
      "key_read_failed",
    );
  }

  // 2. Fetch pending delegation entries and find the standing entry.
  const pendingUrl = `${params.coordinatorUrl}/api/logs/${params.logId}/pending-delegation`;
  const pendingRes = await fetchImpl(pendingUrl);
  if (!pendingRes.ok) {
    const preview = await responseProblemDetail(pendingRes, 200);
    throw new DelegateFlowError(
      `pending-delegation fetch failed: HTTP ${pendingRes.status} ${preview}`,
      pendingRes.status,
    );
  }
  const pending = (await pendingRes.json()) as {
    entries?: unknown;
  };
  const rawEntries = pending.entries ?? [];
  if (!Array.isArray(rawEntries)) {
    throw new DelegateFlowError("pending-delegation entries is not an array");
  }
  checkEntryRanges(rawEntries);
  const entries = rawEntries as StandingDelegationEntry[];
  const standing = entries.find(
    (e) => e.suggestedTtlSeconds !== undefined && e.mmrStart === undefined,
  );
  if (standing === undefined) {
    throw new DelegateFlowError(
      "no standing delegate-key entry for log — register a public root and a sealer delegate key first (C1/C3)",
    );
  }

  // 3. Verify the registrar voucher (mandatory — fail closed).
  if (
    standing.voucher === undefined ||
    standing.sealerId === undefined ||
    standing.epoch === undefined
  ) {
    throw new DelegateFlowError(
      "standing entry is missing its registrar voucher — refusing to bind",
    );
  }
  const pinned = parseRegistrarKeyXY(b64ToBytes(params.knownSealerKey));
  if (pinned === null) {
    throw new DelegateFlowError(
      "known-sealer-key must be base64 x||y (64 bytes)",
    );
  }
  const voucherResult = await verifyDelegateKeyVoucher(
    b64ToBytes(standing.voucher),
    pinned,
    {
      sealerId: standing.sealerId,
      epoch: standing.epoch,
      publicKey: b64ToBytes(standing.delegatedPublicKey),
    },
  );
  if (!voucherResult.ok) {
    throw new DelegateFlowError(
      `registrar voucher failed verification (${voucherResult.reason}) — refusing to bind`,
    );
  }

  // 4. Build the delegation certificate + on-chain proof over mmr 0..end.
  const mmrStart = MMR_START;
  const mmrEnd = params.horizonMmrEnd;
  const logIdHex32 = Buffer.from(uuidToBytes(params.logId)).toString("hex");
  const delegatedPublicKeyBytes = b64ToBytes(standing.delegatedPublicKey);

  const ttlSeconds = params.ttlSeconds ?? standing.suggestedTtlSeconds;
  const certInput: DelegationInput = {
    logIdHex32,
    mmrStart,
    mmrEnd,
    delegatedPublicKeyCbor: delegatedPublicKeyBytes,
  };
  if (ttlSeconds !== undefined) certInput.ttlSeconds = ttlSeconds;
  const certificate = await buildDelegationCertificateEs256(
    certInput,
    rootKeyPair,
  );
  const info = parseDelegationCertificate(certificate);
  const delegated = parseDelegatedCoseKeyFromPayload(
    decodeDelegatedCoseKeyFromBytes(delegatedPublicKeyBytes),
  );
  const onchainProof = await signOnchainDelegationEs256(
    {
      logIdHex: logIdHex32,
      mmrStart,
      mmrEnd,
      delegatedKeyX: delegated.x,
      delegatedKeyY: delegated.y,
    },
    rootKeyPair,
  );

  // 5. Submit the certificate to the coordinator.
  const submitUrl = `${params.coordinatorUrl}/api/delegations/certificate`;
  const submitRes = await fetchImpl(submitUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      logId: params.logId,
      mmrStart: formatDecimalUint64(mmrStart),
      mmrEnd: formatDecimalUint64(mmrEnd),
      delegatedPublicKey: standing.delegatedPublicKey,
      certificate: bytesToB64(certificate),
      issuedAt: info.issuedAt,
      expiresAt: info.expiresAt,
      onchainSignature: bytesToB64(onchainProof.signature),
    }),
  });
  if (!submitRes.ok) {
    const preview = await responseProblemDetail(submitRes, 200);
    throw new DelegateFlowError(
      `certificate submit failed: HTTP ${submitRes.status} ${preview}`,
      submitRes.status,
    );
  }

  return {
    sealerId: standing.sealerId,
    epoch: standing.epoch,
    mmrStart,
    mmrEnd,
    delegatedPublicKey: standing.delegatedPublicKey,
    expiresAt: info.expiresAt,
    certificate,
  };
}
