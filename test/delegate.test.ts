import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { createCaptureOut } from "@forestrie/cli-kit/reporting";
import {
  encodeCborDeterministic,
  signCoseSign1Statement,
} from "@forestrie/encoding";
import {
  COSE_CRV,
  COSE_CRV_P256,
  COSE_KTY,
  COSE_KTY_EC2,
  COSE_X,
  COSE_Y,
  parseDelegationCertificate,
} from "@forestrie/delegation-cose";
import {
  DelegateFlowError,
  runDelegateFlow,
  VOUCHER_CLOCK_SKEW_SECONDS,
  type StandingDelegationEntry,
} from "../src/lib/delegate-flow.js";
import { runDelegate } from "../src/main/delegate.js";
import type { DelegateOptions } from "../src/options/delegate.js";

const LOG_ID = "11111111-2222-3333-4444-555555555555";
const COORD = "https://coordinator.example";
const SEALER_ID = "sealer-1";
const EPOCH = 7;
const NOW = Math.floor(Date.now() / 1000);
const DAY = 24 * 3600;

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

async function p256Pair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
}

/** Raw uncompressed public key minus the 0x04 prefix → x||y (64 bytes). */
async function rawXY(pub: CryptoKey): Promise<Uint8Array> {
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pub));
  return raw.slice(1);
}

/** CBOR EC2 P-256 COSE_Key for the delegated (sealer) checkpoint key. */
async function delegatedCoseKey(pub: CryptoKey): Promise<Uint8Array> {
  const jwk = await crypto.subtle.exportKey("jwk", pub);
  const x = new Uint8Array(Buffer.from(jwk.x!, "base64url"));
  const y = new Uint8Array(Buffer.from(jwk.y!, "base64url"));
  return encodeCborDeterministic(
    new Map<number, unknown>([
      [COSE_KTY, COSE_KTY_EC2],
      [COSE_CRV, COSE_CRV_P256],
      [COSE_X, x],
      [COSE_Y, y],
    ]),
  );
}

/**
 * COSE Sign1 registrar voucher over `{1:sealerId, 2:epoch, 3:publicKey,
 * 4:notAfter}`. `notAfter` defaults to a day from now; `null` omits claim 4,
 * the shape vouchers had before plan-2609-12 slice 07.
 */
async function makeVoucher(
  signerPriv: CryptoKey,
  claims: {
    sealerId: string;
    epoch: number;
    publicKey: Uint8Array;
    notAfter?: number | null;
  },
): Promise<Uint8Array> {
  const map = new Map<number, unknown>([
    [1, claims.sealerId],
    [2, claims.epoch],
    [3, claims.publicKey],
  ]);
  const notAfter =
    claims.notAfter === undefined ? NOW + DAY : claims.notAfter;
  if (notAfter !== null) map.set(4, notAfter);
  const payload = encodeCborDeterministic(map);
  return signCoseSign1Statement(payload, new Uint8Array(0), signerPriv, {
    alg: -7,
  });
}

// --- fixtures (built once) ----------------------------------------------

const registrar = await p256Pair();
const attacker = await p256Pair();
const sealer = await p256Pair();
const { privateKey: ROOT_PEM } = generateKeyPairSync("ec", {
  namedCurve: "P-256",
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
}) as unknown as { privateKey: string };

const DELEGATED_KEY = await delegatedCoseKey(sealer.publicKey);
const DELEGATED_KEY_B64 = b64(DELEGATED_KEY);
const PINNED_KEY_B64 = b64(await rawXY(registrar.publicKey));
const VOUCHER_B64 = b64(
  await makeVoucher(registrar.privateKey, {
    sealerId: SEALER_ID,
    epoch: EPOCH,
    publicKey: DELEGATED_KEY,
  }),
);
const BAD_SIG_VOUCHER_B64 = b64(
  await makeVoucher(attacker.privateKey, {
    sealerId: SEALER_ID,
    epoch: EPOCH,
    publicKey: DELEGATED_KEY,
  }),
);

const STANDING: StandingDelegationEntry = {
  delegatedPublicKey: DELEGATED_KEY_B64,
  suggestedTtlSeconds: 3600,
  voucher: VOUCHER_B64,
  sealerId: SEALER_ID,
  epoch: EPOCH,
};

// --- fetch mock ----------------------------------------------------------

type Captured = { url: string; init?: RequestInit | undefined };

/**
 * A lease entry exactly as the coordinator's `GET /pending-delegation`
 * returns it: range bounds are canonical decimal strings (plan-2611-01 D1).
 */
const LEASE_ENTRY = {
  id: "lease-1",
  authLogIdHex32: "00".repeat(32),
  logIdHex32: "00".repeat(32),
  mmrStart: "9007199254740993",
  mmrEnd: "18446744073709551615",
  delegatedPublicKeyHash: "00".repeat(32),
  delegatedPublicKey: "",
  requestedAt: 1_700_000_000_000,
};

/** Coordinator entries are untrusted JSON: tests may send any shape. */
type WireEntry = StandingDelegationEntry | Record<string, unknown>;

function mockCoordinator(
  entries: WireEntry[],
  captured: Captured[],
): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = String(input);
    captured.push({ url, init });
    if (url.endsWith(`/api/logs/${LOG_ID}/pending-delegation`)) {
      return new Response(JSON.stringify({ entries }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (url.endsWith("/api/delegations/certificate")) {
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }
    return new Response("unexpected", { status: 500 });
  }) as typeof fetch;
}

const baseParams = {
  coordinatorUrl: COORD,
  logId: LOG_ID,
  rootPem: ROOT_PEM,
  knownSealerKey: PINNED_KEY_B64,
  horizonMmrEnd: 1000n,
};

/** The certificate POST body the flow sent, decoded. */
function postedBody(captured: Captured[]): Record<string, unknown> {
  const post = captured.find((c) =>
    c.url.endsWith("/api/delegations/certificate"),
  )!;
  return JSON.parse(String(post.init?.body)) as Record<string, unknown>;
}

async function flowError(
  entries: WireEntry[],
  captured: Captured[],
): Promise<unknown> {
  return runDelegateFlow(baseParams, {
    fetchImpl: mockCoordinator(entries, captured),
  }).then(
    () => null,
    (e: unknown) => e,
  );
}

// --- delegation flow -----------------------------------------------------

describe("runDelegateFlow", () => {
  test("happy path builds a cert + onchain sig and POSTs the right body", async () => {
    const captured: Captured[] = [];
    const result = await runDelegateFlow(baseParams, {
      fetchImpl: mockCoordinator([STANDING], captured),
    });
    expect(result.sealerId).toBe(SEALER_ID);
    expect(result.epoch).toBe(EPOCH);
    expect(result.mmrStart).toBe(0n);
    expect(result.mmrEnd).toBe(1000n);
    expect(result.delegatedPublicKey).toBe(DELEGATED_KEY_B64);
    expect(typeof result.expiresAt).toBe("number");

    const post = captured.find((c) =>
      c.url.endsWith("/api/delegations/certificate"),
    )!;
    expect((post.init?.headers as Record<string, string>)["Content-Type"]).toBe(
      "application/json",
    );
    const body = JSON.parse(String(post.init?.body)) as Record<string, unknown>;
    expect(body["logId"]).toBe(LOG_ID);
    // Range bounds travel as canonical decimal strings (plan-2611-01 D1).
    expect(body["mmrStart"]).toBe("0");
    expect(body["mmrEnd"]).toBe("1000");
    expect(body["delegatedPublicKey"]).toBe(DELEGATED_KEY_B64);
    expect(typeof body["certificate"]).toBe("string");
    expect(typeof body["issuedAt"]).toBe("number");
    expect(typeof body["expiresAt"]).toBe("number");
    expect(typeof body["onchainSignature"]).toBe("string");
    // onchain signature is a 64-byte IEEE P1363 ES256 signature.
    expect(Buffer.from(String(body["onchainSignature"]), "base64").length).toBe(
      64,
    );
  });

  test("a horizon above 2^53 round-trips exactly into the certificate", async () => {
    for (const horizonMmrEnd of [9007199254740993n, 18446744073709551615n]) {
      const captured: Captured[] = [];
      const result = await runDelegateFlow(
        { ...baseParams, horizonMmrEnd },
        { fetchImpl: mockCoordinator([STANDING], captured) },
      );
      expect(result.mmrEnd).toBe(horizonMmrEnd);
      const body = postedBody(captured);
      expect(body["mmrStart"]).toBe("0");
      expect(body["mmrEnd"]).toBe(horizonMmrEnd.toString(10));
      const posted = new Uint8Array(
        Buffer.from(String(body["certificate"]), "base64"),
      );
      const info = parseDelegationCertificate(posted);
      expect(info.mmrStart).toBe(0n);
      expect(info.mmrEnd).toBe(horizonMmrEnd);
    }
  });

  test("accepts lease entries whose range is a decimal string", async () => {
    const captured: Captured[] = [];
    const result = await runDelegateFlow(baseParams, {
      fetchImpl: mockCoordinator([LEASE_ENTRY, STANDING], captured),
    });
    expect(result.sealerId).toBe(SEALER_ID);
  });

  test("rejects a JSON-number range in a coordinator entry (no POST)", async () => {
    for (const bad of [
      { ...LEASE_ENTRY, mmrStart: 0 },
      { ...LEASE_ENTRY, mmrEnd: 1000 },
    ]) {
      const captured: Captured[] = [];
      const err = await flowError([bad, STANDING], captured);
      expect(err).toBeInstanceOf(DelegateFlowError);
      expect((err as Error).message).toMatch(
        /pending-delegation entry 0 mmr(Start|End) must be a decimal string \(got number\)/,
      );
      expect(
        captured.some((c) => c.url.endsWith("/api/delegations/certificate")),
      ).toBe(false);
    }
  });

  test("rejects a malformed decimal range in a coordinator entry", async () => {
    for (const mmrEnd of ["01", "-1", "1.5", " 7", "18446744073709551616"]) {
      const captured: Captured[] = [];
      const err = await flowError([{ ...LEASE_ENTRY, mmrEnd }, STANDING], captured);
      expect(err).toBeInstanceOf(DelegateFlowError);
      expect((err as Error).message).toContain(
        "pending-delegation entry 0 mmrEnd",
      );
    }
  });

  test("a malformed root PEM fails closed as key_read_failed (no unhandled throw)", async () => {
    const captured: Captured[] = [];
    const err = await runDelegateFlow(
      {
        ...baseParams,
        rootPem:
          "-----BEGIN PRIVATE KEY-----\nbm90LWEta2V5\n-----END PRIVATE KEY-----",
      },
      { fetchImpl: mockCoordinator([STANDING], captured) },
    ).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(DelegateFlowError);
    expect((err as DelegateFlowError).code).toBe("key_read_failed");
    // Failed before any coordinator round-trip; message does not leak a path.
    expect((err as Error).message).not.toContain("/");
  });

  test("fails closed when the standing entry has no voucher", async () => {
    const captured: Captured[] = [];
    const entry: StandingDelegationEntry = {
      delegatedPublicKey: DELEGATED_KEY_B64,
      suggestedTtlSeconds: 3600,
    };
    const err = await runDelegateFlow(baseParams, {
      fetchImpl: mockCoordinator([entry], captured),
    }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(DelegateFlowError);
    expect((err as Error).message).toContain("missing its registrar voucher");
    // Never POSTed a certificate.
    expect(
      captured.some((c) => c.url.endsWith("/api/delegations/certificate")),
    ).toBe(false);
  });

  test("fails closed when the voucher signature does not verify", async () => {
    const captured: Captured[] = [];
    const err = await runDelegateFlow(baseParams, {
      fetchImpl: mockCoordinator(
        [{ ...STANDING, voucher: BAD_SIG_VOUCHER_B64 }],
        captured,
      ),
    }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(DelegateFlowError);
    expect((err as Error).message).toContain("failed verification (signature)");
    expect(
      captured.some((c) => c.url.endsWith("/api/delegations/certificate")),
    ).toBe(false);
  });

  test("errors when there is no standing delegate-key entry", async () => {
    const captured: Captured[] = [];
    const err = await runDelegateFlow(baseParams, {
      fetchImpl: mockCoordinator([], captured),
    }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(DelegateFlowError);
    expect((err as Error).message).toContain("no standing delegate-key entry");
  });
});

// --- voucher expiry (claim 4, plan-2609-12 slice 07 part 4) ---------------

/** Run the flow at `NOW` against one standing entry with this voucher. */
async function delegateWith(
  voucher: Uint8Array,
  entry: Partial<StandingDelegationEntry> = {},
): Promise<{ err: unknown; captured: Captured[] }> {
  const captured: Captured[] = [];
  const err = await runDelegateFlow(baseParams, {
    fetchImpl: mockCoordinator(
      [{ ...STANDING, voucher: b64(voucher), ...entry }],
      captured,
    ),
    now: () => NOW,
  }).then(
    () => null,
    (e: unknown) => e,
  );
  return { err, captured };
}

function posted(captured: Captured[]): boolean {
  return captured.some((c) => c.url.endsWith("/api/delegations/certificate"));
}

function voucherFor(notAfter: number | null): Promise<Uint8Array> {
  return makeVoucher(registrar.privateKey, {
    sealerId: SEALER_ID,
    epoch: EPOCH,
    publicKey: DELEGATED_KEY,
    notAfter,
  });
}

describe("runDelegateFlow voucher expiry", () => {
  test("refuses a voucher without claim 4 and says so", async () => {
    const { err, captured } = await delegateWith(await voucherFor(null));
    expect(err).toBeInstanceOf(DelegateFlowError);
    expect((err as Error).message).toContain(
      "failed verification (not_after_missing)",
    );
    expect((err as Error).message).toContain("no expiry");
    expect(posted(captured)).toBe(false);
  });

  test("refuses a voucher expired beyond the clock-skew allowance", async () => {
    const { err, captured } = await delegateWith(
      await voucherFor(NOW - VOUCHER_CLOCK_SKEW_SECONDS - 1),
    );
    expect(err).toBeInstanceOf(DelegateFlowError);
    expect((err as Error).message).toContain("failed verification (expired)");
    expect(posted(captured)).toBe(false);
  });

  test("accepts a voucher expired within the clock-skew allowance", async () => {
    const { err, captured } = await delegateWith(
      await voucherFor(NOW - VOUCHER_CLOCK_SKEW_SECONDS + 1),
    );
    expect(err).toBeNull();
    expect(posted(captured)).toBe(true);
  });

  test("allows 5 minutes of clock skew", () => {
    expect(VOUCHER_CLOCK_SKEW_SECONDS).toBe(300);
  });

  test("accepts an epoch the coordinator sends as a decimal string", async () => {
    const { err } = await delegateWith(await voucherFor(NOW + DAY), {
      epoch: String(EPOCH),
    });
    expect(err).toBeNull();
  });

  test("refuses a voucher attesting a different sealer", async () => {
    const { err, captured } = await delegateWith(await voucherFor(NOW + DAY), {
      sealerId: "sealer-other",
    });
    expect((err as Error).message).toContain("failed verification (sealerId)");
    expect(posted(captured)).toBe(false);
  });

  test("refuses a voucher for a key other than the advertised one", async () => {
    const other = await delegatedCoseKey((await p256Pair()).publicKey);
    const voucher = await makeVoucher(registrar.privateKey, {
      sealerId: SEALER_ID,
      epoch: EPOCH,
      publicKey: other,
    });
    const { err, captured } = await delegateWith(voucher);
    expect((err as Error).message).toContain("failed verification (publicKey)");
    expect(posted(captured)).toBe(false);
  });

  test("refuses a voucher for an epoch other than the advertised one", async () => {
    const voucher = await makeVoucher(registrar.privateKey, {
      sealerId: SEALER_ID,
      epoch: EPOCH + 1,
      publicKey: DELEGATED_KEY,
    });
    const { err, captured } = await delegateWith(voucher);
    expect((err as Error).message).toContain("failed verification (epoch)");
    expect(posted(captured)).toBe(false);
  });

  test("refuses a malformed coordinator epoch as the coordinator's fault", async () => {
    const { err, captured } = await delegateWith(await voucherFor(NOW + DAY), {
      epoch: "seven",
    });
    expect((err as Error).message).toContain(
      "failed verification (coordinator_epoch)",
    );
    expect((err as Error).message).toContain("coordinator");
    expect(posted(captured)).toBe(false);
  });
});

// --- main runner ---------------------------------------------------------

const tmp = mkdtempSync(path.join(os.tmpdir(), "forestrie-delegate-"));
const ROOT_PEM_PATH = path.join(tmp, "root.es256.pem");
writeFileSync(ROOT_PEM_PATH, ROOT_PEM);

describe("runDelegate (main)", () => {
  const baseOptions: DelegateOptions = {
    json: true,
    verbosity: 0,
    coordinatorUrl: COORD,
    logId: LOG_ID,
    signWith: ROOT_PEM_PATH,
    knownSealerKey: PINNED_KEY_B64,
    horizonMmrEnd: 1000n,
    ttlSeconds: undefined,
    outB64: undefined,
  };

  test("--json success reports the bound lease and writes --out-b64", async () => {
    const outPath = path.join(tmp, "cert.b64");
    const captured: Captured[] = [];
    const out = createCaptureOut();
    process.exitCode = 0;
    await runDelegate(
      out,
      { ...baseOptions, outB64: outPath },
      { fetchImpl: mockCoordinator([STANDING], captured) },
    );
    expect(process.exitCode).toBe(0);
    const report = JSON.parse(
      out.lines.filter((l) => l.stream === "stdout").map((l) => l.text).join("\n"),
    ) as Record<string, unknown>;
    expect(report["command"]).toBe("delegate");
    expect(report["status"]).toBe("submitted");
    expect(report["sealerId"]).toBe(SEALER_ID);
    // Range bounds are decimal strings in --json output (plan-2611-01 D1).
    expect(report["mmrStart"]).toBe("0");
    expect(report["mmrEnd"]).toBe("1000");
    expect(report["outB64"]).toBe(outPath);
    const written = await Bun.file(outPath).text();
    expect(written.length).toBeGreaterThan(0);
  });

  test("--json reports a horizon above 2^53 exactly", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    await runDelegate(
      out,
      { ...baseOptions, horizonMmrEnd: 18446744073709551615n },
      { fetchImpl: mockCoordinator([STANDING], []) },
    );
    expect(process.exitCode).toBe(0);
    const report = JSON.parse(
      out.lines.filter((l) => l.stream === "stdout").map((l) => l.text).join("\n"),
    ) as Record<string, unknown>;
    expect(report["mmrEnd"]).toBe("18446744073709551615");
  });

  test("human output prints the horizon range as plain integers", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    await runDelegate(
      out,
      { ...baseOptions, json: false, horizonMmrEnd: 9007199254740993n },
      { fetchImpl: mockCoordinator([STANDING], []) },
    );
    expect(process.exitCode).toBe(0);
    const text = out.lines.map((l) => l.text).join("\n");
    expect(text).toContain("horizon: mmr 0..9007199254740993");
    expect(text).not.toMatch(/\d+n\b/);
  });

  test("fail-closed voucher mismatch exits 1 with delegation_failed", async () => {
    const captured: Captured[] = [];
    const out = createCaptureOut();
    process.exitCode = 0;
    await runDelegate(
      out,
      baseOptions,
      {
        fetchImpl: mockCoordinator(
          [{ ...STANDING, voucher: BAD_SIG_VOUCHER_B64 }],
          captured,
        ),
      },
    );
    expect(process.exitCode).toBe(1);
    process.exitCode = 0;
    const report = JSON.parse(
      out.lines.filter((l) => l.stream === "stdout").map((l) => l.text).join("\n"),
    ) as Record<string, unknown>;
    expect(report["error"]).toBe("delegation_failed");
    expect(String(report["message"])).toContain("failed verification");
  });
});
