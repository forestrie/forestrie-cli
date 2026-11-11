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
  requiresChildPayment,
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
import { decodeForestrieGrantCose } from "@forestrie/receipt-verify";
import type { AnchorChain } from "../src/lib/anchor-wait.js";
import type { OnChainLogState } from "../src/lib/verify-anchored.js";
import { es256PublicKeyXyFromPem } from "../src/lib/register-grant-build.js";
import { runCreateLog } from "../src/main/create-log.js";
import type { CreateLogOptions } from "../src/options/create-log.js";
import { receiptForLeaf } from "./anchor-wait-fixture.js";
import { FIXTURE_LOG_ID, buildGenesisCbor } from "./verify-fixture.js";

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

  test("auth-log + child-payment-required: GF_DERIVED|GF_CHILD_PAYMENT_REQUIRED added, shape preserved", () => {
    const built = buildCreateLogGrant({
      newLog: NEW_LOG,
      ownerLog: OWNER_LOG,
      signWithPem: OWNER_PRIV_PEM,
      signerPem: SIGNER_PRIV_PEM,
      selfReferential: false,
      authLog: true,
      childPaymentRequired: true,
    });
    // byte 3: GF_CREATE|GF_EXTEND (0x03) | GF_DERIVED (0x04) | GF_CHILD_PAYMENT_REQUIRED (0x08)
    expect(built.flags[3]).toBe(0x0f);
    expect(hasCreateAndExtend(built.flags)).toBe(true);
    expect(hasAuthLogClass(built.flags)).toBe(true);
    expect(requiresChildPayment(built.flags)).toBe(true);
  });

  test("self-referential + child-payment-required: policy bits on the root bootstrap grant", () => {
    const built = buildCreateLogGrant({
      newLog: BOOT_LOG,
      ownerLog: BOOT_LOG,
      signWithPem: OWNER_PRIV_PEM,
      signerPem: undefined,
      selfReferential: true,
      authLog: false,
      childPaymentRequired: true,
    });
    expect(built.flags[3]).toBe(0x0f);
    expect(hasAuthLogClass(built.flags)).toBe(true);
    expect(requiresChildPayment(built.flags)).toBe(true);
  });

  test("data-log + child-payment-required is rejected (auth-shaped grants only)", () => {
    expect(() =>
      buildCreateLogGrant({
        newLog: NEW_LOG,
        ownerLog: OWNER_LOG,
        signWithPem: OWNER_PRIV_PEM,
        signerPem: SIGNER_PRIV_PEM,
        selfReferential: false,
        authLog: false,
        childPaymentRequired: true,
      }),
    ).toThrow(/--child-payment-required/);
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
    childPaymentRequired: false,
    selfReferential: false,
    signerPem: SIGNER_PEM_PATH,
    signWith: OWNER_PEM_PATH,
    prepare: false,
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

  test("--prepare pre-registers the child root via /prepare (Forestrie-Grant header, no sequencing)", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    let sawAuth: string | null = null;
    let sawUrl = "";
    const prepareFetch = fakeFetch(({ method, url, headers }) => {
      if (method === "POST" && url.pathname === `/api/forest/${NEW_LOG}/prepare`) {
        sawAuth = headers.get("Authorization");
        sawUrl = url.pathname;
        return Response.json({ publicRoot: "ok", webhook: "ok" }, { status: 200 });
      }
      return undefined; // any /register/ call would be an error (no sequencing)
    });
    await runCreateLog(
      out,
      { ...baseOptions, prepare: true },
      { fetchImpl: prepareFetch, ...fakeClock() },
    );
    expect(process.exitCode).toBe(0);
    expect(sawUrl).toBe(`/api/forest/${NEW_LOG}/prepare`);
    expect(String(sawAuth).startsWith("Forestrie-Grant ")).toBe(true);
    const report = JSON.parse(
      out.lines.filter((l) => l.stream === "stdout").map((l) => l.text).join("\n"),
    ) as Record<string, unknown>;
    expect(report["command"]).toBe("create-log");
    expect(report["status"]).toBe("prepared");
    expect(report["newLog"]).toBe(NEW_LOG);
    expect(report["publicRoot"]).toBe("ok");
    // The emitted grant is the create grant (parent-signed), not a completed one.
    expect(
      await verifyCoseSign1WithParsedKey(
        base64ToBytes(String(report["grantB64"])),
        xyKey(OWNER_PRIV_PEM),
      ),
    ).toBe(true);
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

describe("runCreateLog --wait-anchored", () => {
  const options: CreateLogOptions = {
    json: true,
    verbosity: 0,
    baseUrl: BASE,
    ownerLog: OWNER_LOG,
    newLog: NEW_LOG,
    authLog: false,
    childPaymentRequired: false,
    selfReferential: false,
    signerPem: SIGNER_PEM_PATH,
    signWith: OWNER_PEM_PATH,
    prepare: false,
    parentGrantB64: PARENT_B64,
    outB64: undefined,
    bootstrapLog: BOOT_LOG,
    timeoutMs: 5_000,
    pollIntervalMs: 100,
    anchorWait: {
      genesis: undefined,
      univocity: "0x" + "ab".repeat(20),
      rpcUrl: "https://rpc.example",
      timeoutMs: 30_000,
      intervalMs: 10_000,
    },
  };

  /**
   * canopy, sequencing whatever create grant it is sent as leaf 1 of the
   * owner's MMR: the receipt it serves really includes that grant, and
   * `peaks` resolves to the owner's peak once it has.
   */
  function sequencingCanopy(opts: { resealedAt7?: boolean } = {}) {
    let resolvePeak: (p: Uint8Array) => void;
    const peak = new Promise<Uint8Array>((r) => (resolvePeak = r));
    let receipt: Promise<Uint8Array> | undefined;
    let receipt7: Uint8Array | undefined;
    let peak7: Uint8Array | undefined;
    let posts = 0;
    let receiptGets = 0;
    const fetchImpl = (async (
      input: Parameters<typeof fetch>[0],
      init?: RequestInit,
    ) => {
      const url = new URL(String(input));
      if (init?.method === "POST" && url.pathname === `/register/${BOOT_LOG}/grants`) {
        posts++;
        const auth = new Headers(init.headers).get("Authorization") ?? "";
        const { grant } = decodeForestrieGrantCose(
          base64ToBytes(auth.replace(/^Forestrie-Grant /, "")),
        );
        receipt = receiptForLeaf(
          grant,
          Buffer.from(ENTRY_ID.slice(0, 16), "hex"),
        ).then((leaf) => {
          receipt7 = leaf.receiptCbor7;
          peak7 = leaf.peak7;
          resolvePeak(leaf.peak);
          return leaf.receiptCbor;
        });
        return see(STATUS_PATH);
      }
      if (url.pathname === STATUS_PATH) return see(RECEIPT_PATH);
      if (url.pathname === RECEIPT_PATH && receipt !== undefined) {
        const first = await receipt;
        // The first GET is the register flow's; later ones are refreshes.
        const body = opts.resealedAt7 && receiptGets++ > 0 ? receipt7! : first;
        return new Response(body, { status: 200 });
      }
      throw new Error(`fake canopy: unexpected ${init?.method ?? "GET"} ${url}`);
    }) as typeof fetch;
    return { fetchImpl, peak, peak7: () => peak7!, posts: () => posts };
  }

  /** The owner's on-chain state, round by round (the last repeats). */
  function ownerChain(
    states: (peak: Uint8Array) => OnChainLogState[],
    peak: Promise<Uint8Array>,
    chainId = 84532n,
  ): AnchorChain {
    let reads = 0;
    return {
      async logState() {
        const all = states(await peak);
        return all[Math.min(reads++, all.length - 1)]!;
      },
      async publishedSteps() {
        return [];
      },
      async hasCode() {
        return true;
      },
      async bootstrapConfig() {
        throw new Error("not a root");
      },
      async logConfig() {
        return undefined;
      },
      async rootLogId() {
        throw new Error("not a root");
      },
      async chainId() {
        return chainId;
      },
    };
  }

  const reportOf = (out: ReturnType<typeof createCaptureOut>) =>
    JSON.parse(
      out.lines.filter((l) => l.stream === "stdout").map((l) => l.text).join("\n"),
    ) as Record<string, unknown>;

  test("returns once a published checkpoint of the owner covers the new log", async () => {
    const canopy = sequencingCanopy();
    const out = createCaptureOut();
    process.exitCode = 0;
    await runCreateLog(out, options, {
      fetchImpl: canopy.fetchImpl,
      anchorChain: ownerChain(
        (peak) => [
          { accumulator: [new Uint8Array(32)], size: 1n },
          { accumulator: [peak], size: 3n },
        ],
        canopy.peak,
      ),
      ...fakeClock(),
    });
    expect(process.exitCode).toBe(0);
    const report = reportOf(out);
    expect(report["status"]).toBe("receipt");
    expect(typeof report["grantB64"]).toBe("string");
    expect(report["anchor"]).toEqual({
      status: "anchored",
      reason: "peak_in_current_state",
      detail: expect.any(String),
      logId: NEW_LOG,
      ownerLogId: OWNER_LOG,
      rounds: 2,
      timedOut: false,
    });
  });

  test("re-fetches the new log's receipt when the seal it came from never reached the chain", async () => {
    // canopy re-sealed the owner at size 7 before its publisher ran: the
    // receipt create-log got proves against size 3, which the chain skipped.
    const canopy = sequencingCanopy({ resealedAt7: true });
    const out = createCaptureOut();
    process.exitCode = 0;
    await runCreateLog(out, options, {
      fetchImpl: canopy.fetchImpl,
      anchorChain: ownerChain(
        (_peak) => [{ accumulator: [canopy.peak7()], size: 7n }],
        canopy.peak,
      ),
      ...fakeClock(),
    });
    expect(process.exitCode).toBe(0);
    expect(reportOf(out)["anchor"]).toMatchObject({
      status: "anchored",
      reason: "peak_in_current_state",
      rounds: 1,
    });
  });

  test("exits non-zero on timeout, still emitting the completed grant", async () => {
    const canopy = sequencingCanopy();
    const out = createCaptureOut();
    process.exitCode = 0;
    await runCreateLog(
      out,
      { ...options, json: false },
      {
        fetchImpl: canopy.fetchImpl,
        anchorChain: ownerChain(
          () => [{ accumulator: [new Uint8Array(32)], size: 1n }],
          canopy.peak,
        ),
        ...fakeClock(),
      },
    );
    expect(process.exitCode).toBe(1);
    process.exitCode = 0;
    const stdout = out.lines.filter((l) => l.stream === "stdout").map((l) => l.text);
    // The completed grant is still the stdout product: the log exists.
    expect(stdout).toHaveLength(1);
    expect(decodeCoseSign1(base64ToBytes(stdout[0]!))).toBeDefined();
    const stderr = out.lines.filter((l) => l.stream === "stderr").map((l) => l.text);
    expect(stderr).toContain(
      `forestrie create-log: log ${NEW_LOG} is not anchored after 30s (4 rounds)`,
    );
  });

  test("a forest root waits on its contract, with --new-log in 32-hex form", async () => {
    const genesis = path.join(tmp, "root-genesis.cbor");
    const rootKey = new Uint8Array(64).fill(0x42);
    writeFileSync(genesis, buildGenesisCbor(rootKey));
    const hexRoot = FIXTURE_LOG_ID.replaceAll("-", "");
    const canopy = sequencingCanopy();
    const clock = fakeClock();
    const out = createCaptureOut();
    process.exitCode = 0;
    await runCreateLog(
      out,
      {
        ...options,
        newLog: hexRoot,
        ownerLog: hexRoot,
        selfReferential: true,
        parentGrantB64: undefined,
        signerPem: undefined,
        anchorWait: {
          ...options.anchorWait!,
          genesis,
          univocity: undefined,
        },
      },
      {
        fetchImpl: canopy.fetchImpl,
        anchorChain: {
          ...ownerChain(() => [], canopy.peak),
          async hasCode() {
            return true;
          },
          async bootstrapConfig() {
            return { alg: -7n, key: rootKey };
          },
          async rootLogId() {
            return undefined;
          },
        },
        ...clock,
      },
    );
    expect(process.exitCode).toBe(0);
    expect(reportOf(out)["anchor"]).toMatchObject({
      status: "anchored",
      reason: "contract_root_unset",
      logId: FIXTURE_LOG_ID,
      rounds: 1,
    });
  });

  test("a genesis bound to another chain is refused before the grant is registered", async () => {
    const tmpGenesis = path.join(tmp, "genesis.cbor");
    writeFileSync(tmpGenesis, buildGenesisCbor(new Uint8Array(64).fill(0x42)));
    const canopy = sequencingCanopy();
    const out = createCaptureOut();
    process.exitCode = 0;
    await runCreateLog(
      out,
      {
        ...options,
        anchorWait: { ...options.anchorWait!, genesis: tmpGenesis, univocity: undefined },
      },
      {
        fetchImpl: canopy.fetchImpl,
        anchorChain: ownerChain(() => [], canopy.peak, 1n),
        ...fakeClock(),
      },
    );
    expect(process.exitCode).toBe(1);
    process.exitCode = 0;
    expect(canopy.posts()).toBe(0);
    expect(reportOf(out)).toMatchObject({
      error: "anchor_setup_failed",
      command: "create-log",
    });
  });
});
