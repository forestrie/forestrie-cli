import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { createCaptureOut } from "@forestrie/cli-kit/reporting";
import type { AnchorChain } from "../src/lib/anchor-wait.js";
import type { OnChainLogState } from "../src/lib/verify-anchored.js";
import { runLogWaitAnchored } from "../src/main/log-wait-anchored.js";
import {
  parseLogWaitAnchoredOptions,
  type LogWaitAnchoredOptions,
} from "../src/options/log-wait-anchored.js";
import {
  CHILD_LOG,
  OWNER_LOG,
  buildChildAnchorFixture,
  type ChildAnchorFixture,
} from "./anchor-wait-fixture.js";
import "./reset-exit-code.js";
import { FIXTURE_LOG_ID, buildGenesisCbor } from "./verify-fixture.js";

const ROOT_KEY = new Uint8Array(64).fill(0x42);
const OTHER_ROOT = "0badbeef-0000-4000-8000-000000000009";

/** Every read answers from `opts`; the owner's state is the same each round. */
function chain(opts: {
  state?: OnChainLogState;
  rootLogId?: string;
  chainId?: bigint;
}): AnchorChain {
  return {
    async logState() {
      return opts.state ?? { accumulator: [], size: 0n };
    },
    async publishedSteps() {
      return [];
    },
    async hasCode() {
      return true;
    },
    async bootstrapConfig() {
      return { alg: -7n, key: ROOT_KEY };
    },
    async rootLogId() {
      return opts.rootLogId;
    },
    async chainId() {
      return opts.chainId ?? 84532n;
    },
  };
}

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

function stdoutJson(out: ReturnType<typeof createCaptureOut>) {
  return JSON.parse(
    out.lines
      .filter((l) => l.stream === "stdout")
      .map((l) => l.text)
      .join("\n"),
  ) as Record<string, unknown>;
}

let fx: ChildAnchorFixture;
let tmp: string;
let grantPath: string;
let genesisPath: string;

beforeAll(async () => {
  fx = await buildChildAnchorFixture();
  tmp = mkdtempSync(path.join(os.tmpdir(), "forestrie-wait-anchored-"));
  grantPath = path.join(tmp, "create-grant.b64");
  writeFileSync(grantPath, fx.completedGrantB64 + "\n");
  genesisPath = path.join(tmp, "genesis.cbor");
  writeFileSync(genesisPath, buildGenesisCbor(ROOT_KEY));
});

afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const base = (): LogWaitAnchoredOptions => ({
  json: true,
  verbosity: 0,
  createGrant: grantPath,
  receiptUrl: undefined,
  genesis: undefined,
  univocity: "0x" + "ab".repeat(20),
  rpcUrl: "https://rpc.example",
  timeoutMs: 60_000,
  intervalMs: 5_000,
});

describe("runLogWaitAnchored (main)", () => {
  test("exits 0 and reports the child anchored once its owner covers the grant", async () => {
    const out = createCaptureOut();
    await runLogWaitAnchored(out, base(), {
      chain: chain({ state: { accumulator: [fx.peak], size: 3n } }),
      ...fakeClock(),
    });
    expect(process.exitCode ?? 0).toBe(0);
    expect(stdoutJson(out)).toMatchObject({
      command: "log wait-anchored",
      status: "anchored",
      reason: "peak_in_current_state",
      logId: CHILD_LOG,
      ownerLogId: OWNER_LOG,
      rounds: 1,
      timedOut: false,
    });
  });

  test("re-fetches the receipt from --receipt-url when the grant's seal never reached the chain", async () => {
    const receiptUrl = "https://scrapi.example/logs/boot/x/14/entries/e/receipt";
    const fetched: string[] = [];
    const out = createCaptureOut();
    await runLogWaitAnchored(
      out,
      { ...base(), receiptUrl },
      {
        chain: chain({ state: { accumulator: [fx.peak7], size: 7n } }),
        fetchImpl: (async (input: Parameters<typeof fetch>[0]) => {
          fetched.push(String(input));
          return new Response(fx.receiptCbor7, { status: 200 });
        }) as typeof fetch,
        ...fakeClock(),
      },
    );
    expect(process.exitCode ?? 0).toBe(0);
    expect(fetched).toEqual([receiptUrl]);
    expect(stdoutJson(out)).toMatchObject({
      status: "anchored",
      reason: "peak_in_current_state",
    });
  });

  test("exits non-zero on timeout, printing the last result", async () => {
    const out = createCaptureOut();
    await runLogWaitAnchored(
      out,
      { ...base(), json: false, timeoutMs: 10_000 },
      {
        chain: chain({ state: { accumulator: [new Uint8Array(32)], size: 1n } }),
        ...fakeClock(),
      },
    );
    expect(process.exitCode).toBe(1);
    const stdout = out.lines.filter((l) => l.stream === "stdout").map((l) => l.text);
    expect(stdout).toEqual([
      `pending (receipt_newer_than_anchored_state): owner ${OWNER_LOG} has published up to size 1; the create grant is leaf 1`,
    ]);
    const stderr = out.lines.filter((l) => l.stream === "stderr").map((l) => l.text);
    expect(stderr).toContain(
      `forestrie log wait-anchored: log ${CHILD_LOG} is not anchored after 10s (3 rounds)`,
    );
  });

  test("a forest root whose contract records another root exits non-zero at once, as conflicted", async () => {
    const out = createCaptureOut();
    const clock = fakeClock();
    await runLogWaitAnchored(
      out,
      { ...base(), createGrant: undefined, genesis: genesisPath, univocity: undefined },
      { chain: chain({ rootLogId: OTHER_ROOT }), ...clock },
    );
    expect(process.exitCode).toBe(1);
    expect(clock.waits).toEqual([]);
    expect(stdoutJson(out)).toMatchObject({
      status: "conflicted",
      reason: "contract_rooted_elsewhere",
      logId: FIXTURE_LOG_ID,
      rounds: 1,
      timedOut: false,
    });
  });

  test("refuses a genesis whose chain is not the RPC's", async () => {
    const out = createCaptureOut();
    await runLogWaitAnchored(
      out,
      { ...base(), createGrant: undefined, genesis: genesisPath, univocity: undefined },
      { chain: chain({ chainId: 1n }), ...fakeClock() },
    );
    expect(process.exitCode).toBe(1);
    expect(stdoutJson(out)).toMatchObject({
      error: "forest_mismatch",
      command: "log wait-anchored",
    });
  });

  test("refuses a grant that does not create a log", async () => {
    const writer = path.join(tmp, "writer.b64");
    // The verify fixture's grant flags are create+extend; flip GF_CREATE off
    // by building a writer grant from the register-grant builder instead.
    const { buildGrantStatement } = await import(
      "../src/lib/register-grant-build.js"
    );
    writeFileSync(
      writer,
      buildGrantStatement({
        targetLog: CHILD_LOG,
        ownerLog: OWNER_LOG,
        signWithPem: SIGN_PEM,
        signerPem: SIGN_PEM,
      }).grantBase64,
    );
    const out = createCaptureOut();
    await runLogWaitAnchored(out, { ...base(), createGrant: writer }, {
      chain: chain({}),
      ...fakeClock(),
    });
    expect(process.exitCode).toBe(1);
    expect(stdoutJson(out)).toMatchObject({ error: "input_invalid" });
    expect(String(stdoutJson(out)["message"])).toContain("not a create grant");
  });
});

describe("parseLogWaitAnchoredOptions", () => {
  test("needs a create grant or a genesis", () => {
    expect(() =>
      parseLogWaitAnchoredOptions({ "rpc-url": "https://rpc.example", _: [] }),
    ).toThrow("--create-grant");
  });

  test("--receipt-url refreshes a child's receipt, so it needs --create-grant", () => {
    expect(() =>
      parseLogWaitAnchoredOptions({
        "rpc-url": "https://rpc.example",
        genesis: "g.cbor",
        "receipt-url": "https://scrapi.example/r",
        _: [],
      }),
    ).toThrow("--receipt-url needs --create-grant");
  });

  test("defaults: 600 s budget, 10 s interval", () => {
    const o = parseLogWaitAnchoredOptions({
      "rpc-url": "https://rpc.example",
      genesis: "g.cbor",
      _: [],
    });
    expect(o.timeoutMs).toBe(600_000);
    expect(o.intervalMs).toBe(10_000);
  });
});

/** A P-256 key for the writer grant (the register-grant test's owner key). */
const SIGN_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGxrJpl9sjlCQwltR
3btD0brmwtbMn5gWiC4vwone2NGhRANCAAT0JXX0XeSdWqIiq7RwycaHZm6nc9XT
XRpnVj/zLQsUOTiI3knG8j4WmckJE2MDOZFfNtp74x4Lc0/jhfS3yg/J
-----END PRIVATE KEY-----
`;
