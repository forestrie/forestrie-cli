import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { decode as decodeCbor } from "cbor-x";
import { createCaptureOut } from "@forestrie/cli-kit/reporting";
import {
  assertRootGrantTransparentStatement,
  base64ToBytes,
  hasAuthLogClass,
  hasCreateAndExtend,
  hasDataLogClass,
} from "@forestrie/grant-builder";
import {
  coseUnprotectedToMap,
  decodeCoseSign1,
  decodeGrantPayload,
  grantDataToBytes,
  verifyCoseSign1WithParsedKey,
} from "@forestrie/encoding";
import {
  RegisterGrantBuildError,
  buildGrantStatement,
  es256PublicKeyXyFromPem,
} from "../src/lib/register-grant-build.js";
import {
  completeGrantBase64,
  entryIdHexToIdtimestampBe8,
} from "../src/lib/register-grant-complete.js";
import {
  RegisterFlowError,
  runRegisterGrantFlow,
  type RegisterGrantProgress,
} from "../src/lib/register-grant-flow.js";
import { runRegisterGrant } from "../src/main/register-grant.js";
import type { RegisterGrantOptions } from "../src/options/register-grant.js";
import { ROOT, type CliResult } from "./support.js";

// --- fixed key material (pinned; the golden below is bound to SIGNER) ---

/** Granting authority (owner/auth custody key) — signs the grant envelope. */
const OWNER_PRIV_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGxrJpl9sjlCQwltR
3btD0brmwtbMn5gWiC4vwone2NGhRANCAAT0JXX0XeSdWqIiq7RwycaHZm6nc9XT
XRpnVj/zLQsUOTiI3knG8j4WmckJE2MDOZFfNtp74x4Lc0/jhfS3yg/J
-----END PRIVATE KEY-----
`;

/** The ONE signer being authorized (grantData = its ES256 x||y). */
const SIGNER_PRIV_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAMYyTIYwhL/QISGo
yv5+8bVI8mxFiaXhnlXrBFl7GLWhRANCAASBburTjdDo6prpdr0aIqf3EbRIZ0MO
/PtlMzBLzPxZeDhnwRusngCXhNzUBoLu3ooB1a2ufuuK9LrasunOO32o
-----END PRIVATE KEY-----
`;

/** SIGNER's public half (SPKI) — the CLI accepts public PEMs for --signer-pem. */
const SIGNER_PUB_PEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgW7q043Q6Oqa6Xa9GiKn9xG0SGdD
Dvz7ZTMwS8z8WXg4Z8EbrJ4Al4Tc1AaC7t6KAdWtrn7rivS62rLpzjt9qA==
-----END PUBLIC KEY-----
`;

/** SIGNER's ES256 x||y (64 bytes, hex) — grantData for the golden vector. */
const SIGNER_XY_HEX =
  "816eead38dd0e8ea9ae976bd1a22a7f711b44867430efcfb6533304bccfc5978" +
  "3867c11bac9e009784dcd40682eede8a01d5adae7eeb8af4badab2e9ce3b7da8";

const DATA_LOG = "11111111-1111-1111-1111-111111111111";
const OWNER_LOG = "22222222-2222-2222-2222-222222222222";
const BOOT_LOG = "00000000-0000-0000-0000-000000000000";

/**
 * Golden canonical grant v0 payload CBOR (grant-builder 0.1.1 /
 * encoding `encodeGrantPayloadV0Canonical`) for
 * `{logId: DATA_LOG, ownerLogId: OWNER_LOG, dataLogCreateExtendFlags,
 * maxHeight: 0, minGrowth: 0, grantData: SIGNER_XY}`. Structure
 * hand-verified: map(6), keys 1/2 = 32-byte padded log ids, key 3 =
 * 8-byte flags (byte 3 = GF_CREATE|GF_EXTEND = 0x03, byte 7 =
 * GF_DATA_LOG = 0x02), keys 4/5 = 0, key 6 = 64-byte grantData.
 */
const GOLDEN_DATA_GRANT_PAYLOAD_HEX =
  "a601582000000000000000000000000000000000" +
  "11111111111111111111111111111111" +
  "02582000000000000000000000000000000000" +
  "22222222222222222222222222222222" +
  "0348000000030000000204000500065840" +
  SIGNER_XY_HEX;

const HEADER_RECEIPT = 396;
const HEADER_IDTIMESTAMP = -65537;
const HEADER_FORESTRIE_GRANT_V0 = -65538;

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function xyKey(pem: string): { x: Uint8Array; y: Uint8Array; curve: "P-256" } {
  const xy = es256PublicKeyXyFromPem(pem);
  return { x: xy.slice(0, 32), y: xy.slice(32), curve: "P-256" };
}

// --- grant construction -------------------------------------------------

describe("buildGrantStatement", () => {
  test("data-log grant payload matches the grant-builder golden vector", () => {
    const built = buildGrantStatement({
      targetLog: DATA_LOG,
      ownerLog: OWNER_LOG,
      signWithPem: OWNER_PRIV_PEM,
      signerPem: SIGNER_PRIV_PEM,
      selfReferential: false,
      authLog: false,
    });
    expect(hex(built.grantPayloadBytes)).toBe(GOLDEN_DATA_GRANT_PAYLOAD_HEX);
    expect(hex(built.grantData)).toBe(SIGNER_XY_HEX);
    expect(hasCreateAndExtend(built.flags)).toBe(true);
    expect(hasDataLogClass(built.flags)).toBe(true);
  });

  test("statement is Custodian-profile COSE Sign1 whose ES256 signature verifies", async () => {
    const built = buildGrantStatement({
      targetLog: DATA_LOG,
      ownerLog: OWNER_LOG,
      signWithPem: OWNER_PRIV_PEM,
      signerPem: SIGNER_PUB_PEM, // public PEM works for --signer-pem
      selfReferential: false,
      authLog: false,
    });
    // grant-builder's own transparent-statement shape assertion.
    assertRootGrantTransparentStatement(built.grantBase64);
    const wire = base64ToBytes(built.grantBase64);
    // Signature verifies against the OWNER (envelope signer) key via the
    // independent @forestrie/encoding verifier.
    expect(await verifyCoseSign1WithParsedKey(wire, xyKey(OWNER_PRIV_PEM))).toBe(
      true,
    );
    // ...and NOT against the authorized signer's key.
    expect(
      await verifyCoseSign1WithParsedKey(wire, xyKey(SIGNER_PRIV_PEM)),
    ).toBe(false);
    // The embedded grant v0 CBOR round-trips with ONE signer committed.
    const decoded = decodeCoseSign1(wire);
    expect(decoded).not.toBeNull();
    const unprotected = coseUnprotectedToMap(decoded!.unprotected);
    const embedded = unprotected.get(HEADER_FORESTRIE_GRANT_V0) as Uint8Array;
    expect(hex(embedded)).toBe(hex(built.grantPayloadBytes));
    const grant = decodeGrantPayload(embedded);
    expect(hex(grantDataToBytes(grant.grantData))).toBe(SIGNER_XY_HEX);
  });

  test("--auth-log selects the bootstrap-shaped auth flag class", () => {
    const built = buildGrantStatement({
      targetLog: DATA_LOG,
      ownerLog: OWNER_LOG,
      signWithPem: OWNER_PRIV_PEM,
      signerPem: SIGNER_PRIV_PEM,
      selfReferential: false,
      authLog: true,
    });
    expect(hasAuthLogClass(built.flags)).toBe(true);
    expect(hasCreateAndExtend(built.flags)).toBe(true);
  });

  test("omitting --signer-pem binds the signing key itself (self grant)", () => {
    const built = buildGrantStatement({
      targetLog: DATA_LOG,
      ownerLog: OWNER_LOG,
      signWithPem: OWNER_PRIV_PEM,
      signerPem: undefined,
      selfReferential: false,
      authLog: false,
    });
    expect(hex(built.grantData)).toBe(hex(es256PublicKeyXyFromPem(OWNER_PRIV_PEM)));
  });

  test("self-referential: logId == ownerLogId, auth-shaped, grantData == envelope signer", () => {
    const built = buildGrantStatement({
      targetLog: BOOT_LOG,
      ownerLog: BOOT_LOG,
      signWithPem: OWNER_PRIV_PEM,
      signerPem: undefined,
      selfReferential: true,
      authLog: false,
    });
    expect(hasAuthLogClass(built.flags)).toBe(true);
    expect(hex(built.grantData)).toBe(hex(es256PublicKeyXyFromPem(OWNER_PRIV_PEM)));
  });

  test("self-referential with differing logs is rejected", () => {
    expect(() =>
      buildGrantStatement({
        targetLog: DATA_LOG,
        ownerLog: OWNER_LOG,
        signWithPem: OWNER_PRIV_PEM,
        signerPem: undefined,
        selfReferential: true,
        authLog: false,
      }),
    ).toThrow(RegisterGrantBuildError);
  });

  test("self-referential with --signer-pem is rejected (binds the signing key)", () => {
    expect(() =>
      buildGrantStatement({
        targetLog: BOOT_LOG,
        ownerLog: BOOT_LOG,
        signWithPem: OWNER_PRIV_PEM,
        signerPem: SIGNER_PRIV_PEM,
        selfReferential: true,
        authLog: false,
      }),
    ).toThrow(/omit --signer-pem/);
  });

  test("non-P-256 signer key is rejected", () => {
    // Ed25519 PEM — valid key, wrong curve for ES256.
    const ed25519 = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----`;
    expect(() =>
      buildGrantStatement({
        targetLog: DATA_LOG,
        ownerLog: OWNER_LOG,
        signWithPem: OWNER_PRIV_PEM,
        signerPem: ed25519,
        selfReferential: false,
        authLog: false,
      }),
    ).toThrow(/P-256/);
  });

  test("non-UUID logs are rejected with the offending flag named", () => {
    expect(() =>
      buildGrantStatement({
        targetLog: "not-a-uuid",
        ownerLog: OWNER_LOG,
        signWithPem: OWNER_PRIV_PEM,
        signerPem: undefined,
        selfReferential: false,
        authLog: false,
      }),
    ).toThrow(/--data-log/);
    expect(() =>
      buildGrantStatement({
        targetLog: DATA_LOG,
        ownerLog: "nope",
        signWithPem: OWNER_PRIV_PEM,
        signerPem: undefined,
        selfReferential: false,
        authLog: false,
      }),
    ).toThrow(/--owner-log/);
  });
});

// --- completed grant assembly -------------------------------------------

const ENTRY_ID = "0123456789abcdef0123456789abcdef";
const RECEIPT = Uint8Array.from([0xd2, 0x84, 0x40, 0xa0, 0x58, 0x20, 7]);

describe("completeGrantBase64", () => {
  test("entryIdHexToIdtimestampBe8 takes the first 8 bytes big-endian", () => {
    expect(hex(entryIdHexToIdtimestampBe8(ENTRY_ID))).toBe("0123456789abcdef");
    expect(() => entryIdHexToIdtimestampBe8("abc")).toThrow(/32 hex/);
  });

  test("attaches receipt + idtimestamp to unprotected without touching the signature", async () => {
    const built = buildGrantStatement({
      targetLog: DATA_LOG,
      ownerLog: OWNER_LOG,
      signWithPem: OWNER_PRIV_PEM,
      signerPem: SIGNER_PRIV_PEM,
      selfReferential: false,
      authLog: false,
    });
    const completedB64 = completeGrantBase64(built.grantBase64, RECEIPT, ENTRY_ID);
    const completed = base64ToBytes(completedB64);
    const before = decodeCoseSign1(base64ToBytes(built.grantBase64))!;
    const after = decodeCoseSign1(completed)!;
    expect(hex(after.protectedBstr)).toBe(hex(before.protectedBstr));
    expect(hex(after.payloadBstr)).toBe(hex(before.payloadBstr));
    expect(hex(after.signature)).toBe(hex(before.signature));
    const unprotected = coseUnprotectedToMap(after.unprotected);
    expect(hex(unprotected.get(HEADER_RECEIPT) as Uint8Array)).toBe(hex(RECEIPT));
    expect(hex(unprotected.get(HEADER_IDTIMESTAMP) as Uint8Array)).toBe(
      "0123456789abcdef",
    );
    expect(
      hex(unprotected.get(HEADER_FORESTRIE_GRANT_V0) as Uint8Array),
    ).toBe(hex(built.grantPayloadBytes));
    // Still a verifiable transparent statement (unprotected is unsigned).
    expect(
      await verifyCoseSign1WithParsedKey(completed, xyKey(OWNER_PRIV_PEM)),
    ).toBe(true);
  });
});

// --- registration flow (fake fetch) --------------------------------------

const GRANT_B64 = "Z3JhbnQ="; // opaque for flow-level tests
const PARENT_B64 = Buffer.from("parent-grant-wire").toString("base64");
const STATUS_PATH = `/logs/boot/${BOOT_LOG}/grants/${"ab".repeat(32)}`;
const RECEIPT_PATH = `/logs/boot/${BOOT_LOG}/14/entries/${ENTRY_ID}/receipt`;
const BASE = "https://scrapi.example";

function cborText(value: string): number[] {
  const bytes = [...new TextEncoder().encode(value)];
  if (bytes.length > 255) throw new Error("test cbor: text too long");
  if (bytes.length > 23) return [0x78, bytes.length, ...bytes];
  return [0x60 + bytes.length, ...bytes];
}

function cborUint(value: number): number[] {
  if (value < 24) return [value];
  if (value < 256) return [0x18, value];
  return [0x19, value >> 8, value & 0xff];
}

/** Encode an RFC 9457 problem-details map the way canopy-api does (CBOR). */
function cborProblem(fields: Record<string, string | number>): Uint8Array {
  const entries = Object.entries(fields);
  const out = [0xa0 + entries.length];
  for (const [key, value] of entries) {
    out.push(...cborText(key));
    out.push(...(typeof value === "string" ? cborText(value) : cborUint(value)));
  }
  return Uint8Array.from(out);
}

type FakeRequest = {
  method: string;
  url: URL;
  headers: Headers;
  body: Uint8Array | undefined;
};

function fakeFetch(route: (req: FakeRequest) => Response | undefined): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    const body =
      init?.body instanceof Uint8Array ? new Uint8Array(init.body) : undefined;
    const response = route({ method, url, headers: new Headers(init?.headers), body });
    if (!response) throw new Error(`fake fetch: unexpected ${method} ${url}`);
    return response;
  }) as typeof fetch;
}

const see = (location: string): Response =>
  new Response(null, { status: 303, headers: { Location: location } });

/** Deterministic clock: `sleep` advances `now` instead of waiting. */
function fakeClock() {
  let t = 0;
  const waits: number[] = [];
  return {
    now: () => t,
    sleep: async (ms: number) => {
      waits.push(ms);
      t += ms;
    },
    waits,
  };
}

const flowParams = {
  baseUrl: BASE,
  bootstrapLogId: BOOT_LOG,
  grantBase64: GRANT_B64,
  timeoutMs: 5_000,
  pollIntervalMs: 100,
};

describe("runRegisterGrantFlow", () => {
  test("POSTs /grants with the Forestrie-Grant header and no body when there is no parent", async () => {
    const phases: RegisterGrantProgress["phase"][] = [];
    const result = await runRegisterGrantFlow(flowParams, {
      fetchImpl: fakeFetch(({ method, url, headers, body }) => {
        if (method === "POST" && url.pathname === `/register/${BOOT_LOG}/grants`) {
          expect(headers.get("authorization")).toBe(`Forestrie-Grant ${GRANT_B64}`);
          expect(body).toBeUndefined();
          return see(STATUS_PATH);
        }
        if (method === "GET" && url.pathname === STATUS_PATH) return see(RECEIPT_PATH);
        if (method === "GET" && url.pathname === RECEIPT_PATH) {
          return new Response(RECEIPT, {
            status: 200,
            headers: { "Content-Type": "application/cbor" },
          });
        }
        return undefined;
      }),
      ...fakeClock(),
      onProgress: (p) => phases.push(p.phase),
    });
    expect(result.entryIdHex).toBe(ENTRY_ID);
    expect(result.statusUrl).toBe(`${BASE}${STATUS_PATH}`);
    expect(result.receiptUrl).toBe(`${BASE}${RECEIPT_PATH}`);
    expect(result.receipt).toEqual(RECEIPT);
    expect(phases).toEqual(["registered", "receipt-located"]);
  });

  test("parent grant travels as CBOR body evidence {parentGrant: bytes}", async () => {
    let postBody: Uint8Array | undefined;
    let postContentType: string | null | undefined;
    await runRegisterGrantFlow(
      { ...flowParams, parentGrantBase64: PARENT_B64 },
      {
        fetchImpl: fakeFetch(({ method, url, headers, body }) => {
          if (method === "POST") {
            postBody = body;
            postContentType = headers.get("content-type");
            return see(STATUS_PATH);
          }
          if (url.pathname === STATUS_PATH) return see(RECEIPT_PATH);
          return new Response(RECEIPT, { status: 200 });
        }),
        ...fakeClock(),
      },
    );
    expect(postContentType).toBe("application/cbor");
    expect(postBody).toBeDefined();
    const evidence = decodeCbor(postBody!) as { parentGrant: Uint8Array };
    expect(new Uint8Array(evidence.parentGrant)).toEqual(
      new Uint8Array(Buffer.from(PARENT_B64, "base64")),
    );
  });

  test("polls pending status (Retry-After paced) and pending receipt", async () => {
    const clock = fakeClock();
    let statusGets = 0;
    let receiptGets = 0;
    const result = await runRegisterGrantFlow(flowParams, {
      fetchImpl: fakeFetch(({ method, url }) => {
        if (method === "POST") return see(STATUS_PATH);
        if (method === "GET" && url.pathname === STATUS_PATH) {
          statusGets++;
          if (statusGets < 3) {
            return new Response(null, {
              status: 303,
              headers: { Location: STATUS_PATH, "Retry-After": "1" },
            });
          }
          return see(RECEIPT_PATH);
        }
        if (method === "GET" && url.pathname === RECEIPT_PATH) {
          receiptGets++;
          if (receiptGets === 1) return new Response(null, { status: 404 });
          return new Response(RECEIPT, { status: 200 });
        }
        return undefined;
      }),
      ...clock,
    });
    expect(result.receipt).toEqual(RECEIPT);
    expect(clock.waits).toEqual([1000, 1000, 100]);
  });

  test("non-303 register response surfaces CBOR problem details (stage register)", async () => {
    const err = await runRegisterGrantFlow(flowParams, {
      fetchImpl: fakeFetch(({ method }) =>
        method === "POST"
          ? new Response(
              cborProblem({
                title: "Conflict",
                detail: "creation grant already sequenced",
                status: 409,
              }),
              { status: 409, headers: { "Content-Type": "application/cbor" } },
            )
          : undefined,
      ),
      ...fakeClock(),
    }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(RegisterFlowError);
    const flowErr = err as RegisterFlowError;
    expect(flowErr.stage).toBe("register");
    expect(flowErr.httpStatus).toBe(409);
    expect(flowErr.detail).toBe("creation grant already sequenced");
    expect(flowErr.problem).toEqual({
      title: "Conflict",
      detail: "creation grant already sequenced",
      status: 409,
    });
  });

  test("times out while pending without sleeping past the deadline", async () => {
    const clock = fakeClock();
    const err = await runRegisterGrantFlow(
      { ...flowParams, timeoutMs: 450, pollIntervalMs: 100 },
      {
        fetchImpl: fakeFetch(({ method, url }) => {
          if (method === "POST") return see(STATUS_PATH);
          if (method === "GET" && url.pathname === STATUS_PATH) {
            return see(STATUS_PATH); // forever pending
          }
          return undefined;
        }),
        ...clock,
      },
    ).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(RegisterFlowError);
    expect((err as RegisterFlowError).stage).toBe("timeout");
    expect(clock.waits).toEqual([100, 100, 100, 100]);
  });

  test("connection-refused fetch failure maps to stage network", async () => {
    const err = await runRegisterGrantFlow(flowParams, {
      fetchImpl: (async () => {
        throw Object.assign(
          new TypeError("Unable to connect. Is the computer able to access the url?"),
          { code: "ConnectionRefused" },
        );
      }) as unknown as typeof fetch,
      ...fakeClock(),
    }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(RegisterFlowError);
    const flowErr = err as RegisterFlowError;
    expect(flowErr.stage).toBe("network");
    expect(flowErr.message).toContain(`/register/${BOOT_LOG}/grants`);
    expect(flowErr.detail).toContain("Unable to connect");
  });
});

// --- main runner ----------------------------------------------------------

const tmp = mkdtempSync(path.join(os.tmpdir(), "forestrie-register-grant-"));
const OWNER_PEM_PATH = path.join(tmp, "owner.es256.pem");
const SIGNER_PEM_PATH = path.join(tmp, "signer.es256.pem");
writeFileSync(OWNER_PEM_PATH, OWNER_PRIV_PEM);
writeFileSync(SIGNER_PEM_PATH, SIGNER_PUB_PEM);

describe("runRegisterGrant (main)", () => {
  const baseOptions: RegisterGrantOptions = {
    json: true,
    verbosity: 0,
    baseUrl: BASE,
    ownerLog: OWNER_LOG,
    dataLog: DATA_LOG,
    signWith: OWNER_PEM_PATH,
    signerPem: SIGNER_PEM_PATH,
    selfReferential: false,
    authLog: false,
    parentGrantB64: PARENT_B64,
    outB64: undefined,
    bootstrapLog: BOOT_LOG,
    timeoutMs: 5_000,
    pollIntervalMs: 100,
  };

  const happyFetch = () =>
    fakeFetch(({ method, url }) => {
      if (method === "POST" && url.pathname === `/register/${BOOT_LOG}/grants`) {
        return see(STATUS_PATH);
      }
      if (url.pathname === STATUS_PATH) return see(RECEIPT_PATH);
      if (url.pathname === RECEIPT_PATH) return new Response(RECEIPT, { status: 200 });
      return undefined;
    });

  test("--json success without --out-b64 embeds the COMPLETED grant", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    await runRegisterGrant(out, baseOptions, {
      fetchImpl: happyFetch(),
      ...fakeClock(),
    });
    expect(process.exitCode).toBe(0);
    const report = JSON.parse(
      out.lines.filter((l) => l.stream === "stdout").map((l) => l.text).join("\n"),
    ) as Record<string, unknown>;
    expect(report["command"]).toBe("register-grant");
    expect(report["status"]).toBe("receipt");
    expect(report["entryId"]).toBe(ENTRY_ID);
    expect(report["ownerLog"]).toBe(OWNER_LOG);
    expect(report["dataLog"]).toBe(DATA_LOG);
    expect(report["grantDataHex"]).toBe(SIGNER_XY_HEX);
    expect(report["receiptBytes"]).toBe(RECEIPT.length);
    // The emitted grant is COMPLETED: receipt + idtimestamp attached, and
    // it still verifies against the granting authority key.
    const completed = base64ToBytes(String(report["grantB64"]));
    const unprotected = coseUnprotectedToMap(decodeCoseSign1(completed)!.unprotected);
    expect(hex(unprotected.get(HEADER_RECEIPT) as Uint8Array)).toBe(hex(RECEIPT));
    expect(hex(unprotected.get(HEADER_IDTIMESTAMP) as Uint8Array)).toBe(
      "0123456789abcdef",
    );
    expect(
      await verifyCoseSign1WithParsedKey(completed, xyKey(OWNER_PRIV_PEM)),
    ).toBe(true);
  });

  test("--out-b64 writes the completed grant and omits it from the report", async () => {
    const outPath = path.join(tmp, "grant-alice.b64");
    const out = createCaptureOut();
    process.exitCode = 0;
    await runRegisterGrant(
      out,
      { ...baseOptions, outB64: outPath },
      { fetchImpl: happyFetch(), ...fakeClock() },
    );
    expect(process.exitCode).toBe(0);
    const report = JSON.parse(
      out.lines.filter((l) => l.stream === "stdout").map((l) => l.text).join("\n"),
    ) as Record<string, unknown>;
    expect(report["outB64"]).toBe(outPath);
    expect(report["grantB64"]).toBeUndefined();
    const written = await Bun.file(outPath).text();
    const unprotected = coseUnprotectedToMap(
      decodeCoseSign1(base64ToBytes(written))!.unprotected,
    );
    expect(hex(unprotected.get(HEADER_RECEIPT) as Uint8Array)).toBe(hex(RECEIPT));
  });

  test("missing key file is a structured key_read_failed error", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    await runRegisterGrant(out, {
      ...baseOptions,
      signWith: "/nonexistent/bootstrap.es256.pem",
    });
    expect(process.exitCode).toBe(1);
    process.exitCode = 0;
    const report = JSON.parse(
      out.lines.filter((l) => l.stream === "stdout").map((l) => l.text).join("\n"),
    ) as Record<string, unknown>;
    expect(report["error"]).toBe("key_read_failed");
    expect(String(report["message"])).toContain("--sign-with");
  });

  test("bad grant shape is a structured grant_build_failed error", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    await runRegisterGrant(out, {
      ...baseOptions,
      dataLog: "not-a-uuid",
    });
    expect(process.exitCode).toBe(1);
    process.exitCode = 0;
    const report = JSON.parse(
      out.lines.filter((l) => l.stream === "stdout").map((l) => l.text).join("\n"),
    ) as Record<string, unknown>;
    expect(report["error"]).toBe("grant_build_failed");
    expect(String(report["message"])).toContain("--data-log");
  });

  test("--json flow error carries the problem-details passthrough", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    await runRegisterGrant(out, baseOptions, {
      fetchImpl: fakeFetch(() =>
        new Response(cborProblem({ detail: "grant rejected", status: 403 }), {
          status: 403,
        }),
      ),
      ...fakeClock(),
    });
    expect(process.exitCode).toBe(1);
    process.exitCode = 0;
    const report = JSON.parse(
      out.lines.filter((l) => l.stream === "stdout").map((l) => l.text).join("\n"),
    ) as Record<string, unknown>;
    expect(report["error"]).toBe("registration_failed");
    expect(report["httpStatus"]).toBe(403);
    expect(report["problem"]).toEqual({ detail: "grant rejected", status: 403 });
  });
});

// --- binary smoke (mock SCRAPI server) ------------------------------------

/**
 * Async CLI spawn: the mock SCRAPI server runs on this test process's
 * event loop, so the sync `runCli` helper would deadlock.
 */
async function runCliAsync(args: string[]): Promise<CliResult> {
  const env: Record<string, string | undefined> = { ...process.env };
  for (const name of ["FORESTRIE_BASE_URL", "FORESTRIE_CONFIG", "GRANT_B64"]) {
    delete env[name];
  }
  const proc = Bun.spawn({
    cmd: ["bun", path.join(ROOT, "src/cli.ts"), ...args],
    cwd: ROOT,
    env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}

describe("forestrie register-grant (binary smoke, mock SCRAPI server)", () => {
  let sawParentEvidence = false;
  const server = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url);
      if (req.method === "POST" && url.pathname === `/register/${BOOT_LOG}/grants`) {
        const auth = req.headers.get("authorization") ?? "";
        if (!auth.startsWith("Forestrie-Grant ")) {
          return new Response(cborProblem({ detail: "no grant", status: 401 }), {
            status: 401,
            headers: { "Content-Type": "application/cbor" },
          });
        }
        if (req.headers.get("content-type") === "application/cbor") {
          const body = new Uint8Array(await req.arrayBuffer());
          const evidence = decodeCbor(body) as { parentGrant?: Uint8Array };
          sawParentEvidence = evidence.parentGrant !== undefined;
        }
        return new Response(null, {
          status: 303,
          headers: { Location: STATUS_PATH },
        });
      }
      if (req.method === "GET" && url.pathname === STATUS_PATH) {
        return new Response(null, {
          status: 303,
          headers: { Location: RECEIPT_PATH },
        });
      }
      if (req.method === "GET" && url.pathname === RECEIPT_PATH) {
        return new Response(RECEIPT, {
          status: 200,
          headers: { "Content-Type": "application/cbor" },
        });
      }
      return new Response("unexpected", { status: 500 });
    },
  });
  const baseUrl = `http://localhost:${server.port}`;
  afterAll(() => server.stop(true));

  test("registers a signer grant end-to-end and writes the completed grant", async () => {
    const outPath = path.join(tmp, "grant-smoke.b64");
    const result = await runCliAsync([
      "register-grant",
      "--json",
      "--base-url",
      baseUrl,
      "--owner-log",
      OWNER_LOG,
      "--data-log",
      DATA_LOG,
      "--bootstrap-log",
      BOOT_LOG,
      "--sign-with",
      OWNER_PEM_PATH,
      "--signer-pem",
      SIGNER_PEM_PATH,
      "--parent-grant-b64",
      PARENT_B64,
      "--out-b64",
      outPath,
      "--timeout",
      "10",
      "--poll-interval",
      "0.05",
    ]);
    expect(result.stderr).toContain("grant registered; status:");
    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.stdout) as Record<string, unknown>;
    expect(report["status"]).toBe("receipt");
    expect(report["entryId"]).toBe(ENTRY_ID);
    expect(report["grantDataHex"]).toBe(SIGNER_XY_HEX);
    expect(report["outB64"]).toBe(outPath);
    expect(sawParentEvidence).toBe(true);
    const written = await Bun.file(outPath).text();
    assertRootGrantTransparentStatement(written);
  });

  test("human mode without --out-b64 pipes the completed grant on stdout", async () => {
    const result = await runCliAsync([
      "register-grant",
      "--base-url",
      baseUrl,
      "--owner-log",
      BOOT_LOG,
      "--data-log",
      BOOT_LOG,
      "--self-referential",
      "--sign-with",
      OWNER_PEM_PATH,
      "--timeout",
      "10",
      "--poll-interval",
      "0.05",
    ]);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toContain(`entryId: ${ENTRY_ID}`);
    const grantB64 = result.stdout.trim();
    assertRootGrantTransparentStatement(grantB64);
    expect(
      await verifyCoseSign1WithParsedKey(
        base64ToBytes(grantB64),
        xyKey(OWNER_PRIV_PEM),
      ),
    ).toBe(true);
  });

  test("self-referential shape violation exits 1 with grant_build_failed", async () => {
    const result = await runCliAsync([
      "register-grant",
      "--json",
      "--base-url",
      baseUrl,
      "--owner-log",
      OWNER_LOG,
      "--data-log",
      DATA_LOG,
      "--self-referential",
      "--sign-with",
      OWNER_PEM_PATH,
    ]);
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout) as Record<string, unknown>;
    expect(report["error"]).toBe("grant_build_failed");
    expect(String(report["message"])).toContain("logId == ownerLogId");
  });
});
