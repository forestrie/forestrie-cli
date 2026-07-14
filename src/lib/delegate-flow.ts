/**
 * FOR-390 / ADR-0052 delegation flow: authorize a custodian-vouched sealer to
 * publish checkpoints for a log the caller owns (K(L)), using only PUBLIC
 * coordinator endpoints (no operator token, no RPC).
 *
 * Port of canopy's `signAdvanceDelegation` + `buildByokDelegationMaterial`
 * composed on published `@forestrie/delegation-cose` + `@forestrie/encoding`:
 *
 *   1. Import the ES256 root PEM (K(L)) as a WebCrypto CryptoKeyPair.
 *   2. GET the coordinator's pending-delegation entries; find the STANDING
 *      delegate-key entry (has `suggestedTtlSeconds`, no `mmrStart`).
 *   3. Verify the registrar voucher against the operator-pinned registrar key
 *      (mandatory — fail closed).
 *   4. Build the delegation certificate + on-chain delegation proof over the
 *      horizon `mmr 0..end`.
 *   5. POST the certificate to the coordinator.
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
import {
  parseRegistrarKeyXY,
  verifyDelegateKeyVoucher,
} from "./delegate-voucher.js";

/** Fixed inclusive MMR start for a horizon delegation lease. */
const MMR_START = 0;

function b64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

function bytesToB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

/**
 * A coordinator pending-delegation entry. The STANDING delegate-key entry
 * (registered by C1/C3) carries `suggestedTtlSeconds` and no `mmrStart`; lease
 * entries carry `mmrStart`.
 */
export type StandingDelegationEntry = {
  /** base64 CBOR EC2 P-256 COSE_Key for the delegated checkpoint signer. */
  delegatedPublicKey: string;
  /** Present on the standing entry only. */
  suggestedTtlSeconds?: number;
  /** Present on lease entries only. */
  mmrStart?: number;
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
  constructor(message: string, httpStatus?: number) {
    super(message);
    this.name = "DelegateFlowError";
    if (httpStatus !== undefined) this.httpStatus = httpStatus;
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
  pinnedRegistrarKey: string;
  /** Exclusive MMR end of the horizon lease (mmrStart is fixed 0). */
  horizonMmrEnd: number;
  /** Lease TTL seconds; defaults to the standing entry's suggestedTtlSeconds. */
  ttlSeconds?: number | undefined;
};

export type DelegateFlowDeps = {
  fetchImpl?: typeof fetch;
};

export type DelegateFlowResult = {
  sealerId: string;
  epoch: number | string;
  mmrStart: number;
  mmrEnd: number;
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
 * Run the public delegation flow end-to-end, returning the submitted
 * certificate and the bound lease scope.
 */
export async function runDelegateFlow(
  params: DelegateFlowParams,
  deps: DelegateFlowDeps = {},
): Promise<DelegateFlowResult> {
  const fetchImpl = deps.fetchImpl ?? fetch;

  // 1. Root key pair (K(L)).
  const rootKeyPair = await importEs256PemKeyPair(params.rootPem);

  // 2. Fetch pending delegation entries and find the standing entry.
  const pendingUrl = `${params.coordinatorUrl}/api/logs/${params.logId}/pending-delegation`;
  const pendingRes = await fetchImpl(pendingUrl);
  if (!pendingRes.ok) {
    const preview = (await pendingRes.text()).slice(0, 200);
    throw new DelegateFlowError(
      `pending-delegation fetch failed: HTTP ${pendingRes.status} ${preview}`,
      pendingRes.status,
    );
  }
  const pending = (await pendingRes.json()) as {
    entries?: StandingDelegationEntry[];
  };
  const entries = pending.entries ?? [];
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
  const pinned = parseRegistrarKeyXY(b64ToBytes(params.pinnedRegistrarKey));
  if (pinned === null) {
    throw new DelegateFlowError(
      "pinned-registrar-key must be base64 x||y (64 bytes)",
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
      mmrStart,
      mmrEnd,
      delegatedPublicKey: standing.delegatedPublicKey,
      certificate: bytesToB64(certificate),
      issuedAt: info.issuedAt,
      expiresAt: info.expiresAt,
      onchainSignature: bytesToB64(onchainProof.signature),
    }),
  });
  if (!submitRes.ok) {
    const preview = (await submitRes.text()).slice(0, 200);
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
