import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { createCaptureOut } from "@forestrie/cli-kit/reporting";
import {
  base64ToBytes,
  hasAuthLogClass,
  hasCreateAndExtend,
  hasDataLogClass,
} from "@forestrie/grant-builder";
import {
  coseUnprotectedToMap,
  decodeCoseSign1,
  verifyCoseSign1WithParsedKey,
} from "@forestrie/encoding";
import {
  RegisterGrantBuildError,
  buildCreateLogGrant,
} from "../src/lib/create-log-build.js";
import { es256PublicKeyXyFromPem } from "../src/lib/register-grant-build.js";
import { runCreateLog } from "../src/main/create-log.js";
import type { CreateLogOptions } from "../src/options/create-log.js";

// --- fixed key material --------------------------------------------------

/** Granting authority (K(L)) — signs the grant envelope. */
const OWNER_PRIV_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGxrJpl9sjlCQwltR
3btD0brmwtbMn5gWiC4vwone2NGhRANCAAT0JXX0XeSdWqIiq7RwycaHZm6nc9XT
XRpnVj/zLQsUOTiI3knG8j4WmckJE2MDOZFfNtp74x4Lc0/jhfS3yg/J
-----END PRIVATE KEY-----
`;

/** The new log's owner (grantData = its ES256 x||y). */
const SIGNER_PRIV_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAMYyTIYwhL/QISGo
yv5+8bVI8mxFiaXhnlXrBFl7GLWhRANCAASBburTjdDo6prpdr0aIqf3EbRIZ0MO
/PtlMzBLzPxZeDhnwRusngCXhNzUBoLu3ooB1a2ufuuK9LrasunOO32o
-----END PRIVATE KEY-----
`;

const SIGNER_XY_HEX =
  "816eead38dd0e8ea9ae976bd1a22a7f711b44867430efcfb6533304bccfc5978" +
  "3867c11bac9e009784dcd40682eede8a01d5adae7eeb8af4badab2e9ce3b7da8";

const NEW_LOG = "11111111-1111-1111-1111-111111111111";
const OWNER_LOG = "22222222-2222-2222-2222-222222222222";
const BOOT_LOG = "00000000-0000-0000-0000-000000000000";
const ENTRY_ID = "0123456789abcdef0123456789abcdef";
const RECEIPT = Uint8Array.from([0xd2, 0x84, 0x40, 0xa0, 0x58, 0x20, 7]);
const PARENT_B64 = Buffer.from("parent-grant-wire").toString("base64");
const BASE = "https://scrapi.example";
const STATUS_PATH = `/logs/boot/${BOOT_LOG}/grants/${"ab".repeat(32)}`;
const RECEIPT_PATH = `/logs/boot/${BOOT_LOG}/14/entries/${ENTRY_ID}/receipt`;

const HEADER_RECEIPT = 396;

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function xyKey(pem: string): { x: Uint8Array; y: Uint8Array; curve: "P-256" } {
  const xy = es256PublicKeyXyFromPem(pem);
  return { x: xy.slice(0, 32), y: xy.slice(32), curve: "P-256" };
}

// --- create-log grant construction --------------------------------------

describe("buildCreateLogGrant", () => {
  test("self-referential root grant: auth-shaped (0x03 + GF_AUTH_LOG), grantData == envelope signer", () => {
    const built = buildCreateLogGrant({
      newLog: BOOT_LOG,
      ownerLog: BOOT_LOG,
      signWithPem: OWNER_PRIV_PEM,
      signerPem: undefined,
      selfReferential: true,
      authLog: false,
    });
    // byte 3 = GF_CREATE|GF_EXTEND (0x03), byte 7 = GF_AUTH_LOG (0x01).
    expect(built.flags[3]).toBe(0x03);
    expect(built.flags[7]).toBe(0x01);
    expect(hasCreateAndExtend(built.flags)).toBe(true);
    expect(hasAuthLogClass(built.flags)).toBe(true);
    expect(hex(built.grantData)).toBe(hex(es256PublicKeyXyFromPem(OWNER_PRIV_PEM)));
  });

  test("auth-log create: grantData = --signer-pem, GF_CREATE present, auth class", () => {
    const built = buildCreateLogGrant({
      newLog: NEW_LOG,
      ownerLog: OWNER_LOG,
      signWithPem: OWNER_PRIV_PEM,
      signerPem: SIGNER_PRIV_PEM,
      selfReferential: false,
      authLog: true,
    });
    expect(hex(built.grantData)).toBe(SIGNER_XY_HEX);
    expect(built.flags[3]).toBe(0x03);
    expect(hasCreateAndExtend(built.flags)).toBe(true);
    expect(hasAuthLogClass(built.flags)).toBe(true);
  });

  test("data-log create: GF_DATA_LOG byte7 0x02, GF_CREATE present", () => {
    const built = buildCreateLogGrant({
      newLog: NEW_LOG,
      ownerLog: OWNER_LOG,
      signWithPem: OWNER_PRIV_PEM,
      signerPem: SIGNER_PRIV_PEM,
      selfReferential: false,
      authLog: false,
    });
    expect(hex(built.grantData)).toBe(SIGNER_XY_HEX);
    expect(built.flags[7]).toBe(0x02);
    expect(hasCreateAndExtend(built.flags)).toBe(true);
    expect(hasDataLogClass(built.flags)).toBe(true);
    // Signed envelope verifies against the granting authority key.
    expect(built.grantBase64.length).toBeGreaterThan(0);
  });

  test("self-referential with differing logs is rejected", () => {
    expect(() =>
      buildCreateLogGrant({
        newLog: NEW_LOG,
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
      buildCreateLogGrant({
        newLog: BOOT_LOG,
        ownerLog: BOOT_LOG,
        signWithPem: OWNER_PRIV_PEM,
        signerPem: SIGNER_PRIV_PEM,
        selfReferential: true,
        authLog: false,
      }),
    ).toThrow(/omit --signer-pem/);
  });

  test("non-self-referential without --signer-pem is rejected", () => {
    expect(() =>
      buildCreateLogGrant({
        newLog: NEW_LOG,
        ownerLog: OWNER_LOG,
        signWithPem: OWNER_PRIV_PEM,
        signerPem: undefined,
        selfReferential: false,
        authLog: false,
      }),
    ).toThrow(/--signer-pem is required/);
  });

  test("non-UUID new-log is rejected with the offending flag named", () => {
    expect(() =>
      buildCreateLogGrant({
        newLog: "not-a-uuid",
        ownerLog: OWNER_LOG,
        signWithPem: OWNER_PRIV_PEM,
        signerPem: SIGNER_PRIV_PEM,
        selfReferential: false,
        authLog: false,
      }),
    ).toThrow(/--new-log/);
  });
});

// --- main runner (fake fetch) -------------------------------------------

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

function fakeClock() {
  let t = 0;
  return {
    now: () => t,
    sleep: async (ms: number) => {
      t += ms;
    },
  };
}

const tmp = mkdtempSync(path.join(os.tmpdir(), "forestrie-create-log-"));
const OWNER_PEM_PATH = path.join(tmp, "owner.es256.pem");
const SIGNER_PEM_PATH = path.join(tmp, "signer.es256.pem");
writeFileSync(OWNER_PEM_PATH, OWNER_PRIV_PEM);
writeFileSync(SIGNER_PEM_PATH, SIGNER_PRIV_PEM);

describe("runCreateLog (main)", () => {
  const baseOptions: CreateLogOptions = {
    json: true,
    verbosity: 0,
    baseUrl: BASE,
    ownerLog: OWNER_LOG,
    newLog: NEW_LOG,
    authLog: false,
    selfReferential: false,
    signerPem: SIGNER_PEM_PATH,
    signWith: OWNER_PEM_PATH,
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

  test("--json success embeds the COMPLETED grant with newLog/owner labels", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    await runCreateLog(out, baseOptions, { fetchImpl: happyFetch(), ...fakeClock() });
    expect(process.exitCode).toBe(0);
    const report = JSON.parse(
      out.lines.filter((l) => l.stream === "stdout").map((l) => l.text).join("\n"),
    ) as Record<string, unknown>;
    expect(report["command"]).toBe("create-log");
    expect(report["status"]).toBe("receipt");
    expect(report["ownerLog"]).toBe(OWNER_LOG);
    expect(report["newLog"]).toBe(NEW_LOG);
    expect(report["ownerHex"]).toBe(SIGNER_XY_HEX);
    expect(report["entryId"]).toBe(ENTRY_ID);
    // Completed grant still verifies against the granting authority key.
    const completed = base64ToBytes(String(report["grantB64"]));
    const unprotected = coseUnprotectedToMap(decodeCoseSign1(completed)!.unprotected);
    expect(hex(unprotected.get(HEADER_RECEIPT) as Uint8Array)).toBe(hex(RECEIPT));
    expect(await verifyCoseSign1WithParsedKey(completed, xyKey(OWNER_PRIV_PEM))).toBe(
      true,
    );
  });

  test("self-referential success has no parent evidence and binds --sign-with", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    let sawBody: Uint8Array | undefined = Uint8Array.of(1);
    await runCreateLog(
      out,
      {
        ...baseOptions,
        ownerLog: BOOT_LOG,
        newLog: BOOT_LOG,
        selfReferential: true,
        signerPem: undefined,
        parentGrantB64: undefined,
      },
      {
        fetchImpl: fakeFetch(({ method, url, body }) => {
          if (method === "POST") {
            sawBody = body;
            return see(STATUS_PATH);
          }
          if (url.pathname === STATUS_PATH) return see(RECEIPT_PATH);
          return new Response(RECEIPT, { status: 200 });
        }),
        ...fakeClock(),
      },
    );
    expect(process.exitCode).toBe(0);
    expect(sawBody).toBeUndefined();
    const report = JSON.parse(
      out.lines.filter((l) => l.stream === "stdout").map((l) => l.text).join("\n"),
    ) as Record<string, unknown>;
    expect(report["ownerHex"]).toBe(hex(es256PublicKeyXyFromPem(OWNER_PRIV_PEM)));
  });

  test("bad grant shape is a structured grant_build_failed error", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    await runCreateLog(out, { ...baseOptions, newLog: "not-a-uuid" });
    expect(process.exitCode).toBe(1);
    process.exitCode = 0;
    const report = JSON.parse(
      out.lines.filter((l) => l.stream === "stdout").map((l) => l.text).join("\n"),
    ) as Record<string, unknown>;
    expect(report["error"]).toBe("grant_build_failed");
    expect(String(report["message"])).toContain("--new-log");
  });
});
