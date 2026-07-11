import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { createCaptureOut } from "@forestrie/cli-kit/reporting";
import {
  RegisterFlowError,
  runRegisterFlow,
  type RegisterProgress,
} from "../src/lib/register-flow.js";
import { runRegister } from "../src/main/register.js";
import type { RegisterOptions } from "../src/options/register.js";
import { ROOT, type CliResult } from "./support.js";

const LOG_ID = "00000000-0000-0000-0000-000000000000";
const GRANT_B64 = "Z3JhbnQ=";
const ENTRY_ID = "0123456789abcdef0123456789abcdef";
const STATUS_PATH = `/logs/boot/${LOG_ID}/entries/${"ab".repeat(32)}`;
const RECEIPT_PATH = `/logs/boot/${LOG_ID}/14/entries/${ENTRY_ID}/receipt`;
const STATEMENT = Uint8Array.from([0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26]);
const RECEIPT = Uint8Array.from([0xd2, 0x84, 0x40, 0xa0, 0x58, 0x20, 7]);

// --- minimal CBOR (text keys, text/uint values) for problem details ---

function cborText(value: string): number[] {
  const bytes = [...new TextEncoder().encode(value)];
  if (bytes.length > 23) throw new Error("test cbor: text too long");
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
  if (entries.length > 23) throw new Error("test cbor: map too large");
  const out = [0xa0 + entries.length];
  for (const [key, value] of entries) {
    out.push(...cborText(key));
    out.push(...(typeof value === "string" ? cborText(value) : cborUint(value)));
  }
  return Uint8Array.from(out);
}

// --- fake fetch -------------------------------------------------------

type FakeRoute = (req: { method: string; url: URL; headers: Headers }) =>
  | Response
  | undefined;

function fakeFetch(route: FakeRoute): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    const response = route({
      method,
      url,
      headers: new Headers(init?.headers),
    });
    if (!response) {
      throw new Error(`fake fetch: unexpected ${method} ${url}`);
    }
    return response;
  }) as typeof fetch;
}

const see = (location: string): Response =>
  new Response(null, { status: 303, headers: { Location: location } });

const BASE = "https://scrapi.example";

const flowParams = {
  baseUrl: BASE,
  logId: LOG_ID,
  grantB64: GRANT_B64,
  statement: STATEMENT,
  timeoutMs: 5_000,
  pollIntervalMs: 100,
};

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

describe("runRegisterFlow", () => {
  test("follows the 303 redirect chain straight to the receipt", async () => {
    const phases: RegisterProgress["phase"][] = [];
    const result = await runRegisterFlow(flowParams, {
      fetchImpl: fakeFetch(({ method, url, headers }) => {
        if (method === "POST" && url.pathname === `/register/${LOG_ID}/entries`) {
          expect(headers.get("authorization")).toBe(
            `Forestrie-Grant ${GRANT_B64}`,
          );
          expect(headers.get("content-type")).toBe(
            'application/cose; cose-type="cose-sign1"',
          );
          return see(STATUS_PATH);
        }
        if (method === "GET" && url.pathname === STATUS_PATH) {
          return see(RECEIPT_PATH);
        }
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
    expect(result.contentType).toBe("application/cbor");
    expect(phases).toEqual(["registered", "receipt-located"]);
  });

  test("polls pending status (Retry-After paced) and pending receipt", async () => {
    const clock = fakeClock();
    let statusGets = 0;
    let receiptGets = 0;
    const result = await runRegisterFlow(flowParams, {
      fetchImpl: fakeFetch(({ method, url }) => {
        if (method === "POST") return see(STATUS_PATH);
        if (method === "GET" && url.pathname === STATUS_PATH) {
          statusGets++;
          if (statusGets < 3) {
            // pending: 303 back to the status URL, worker-paced.
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
    expect(statusGets).toBe(3);
    expect(receiptGets).toBe(2);
    // Retry-After (1s) wins over --poll-interval (100ms) for status polls;
    // the receipt 404 retry uses the plain interval.
    expect(clock.waits).toEqual([1000, 1000, 100]);
  });

  test("non-303 register response surfaces CBOR problem details", async () => {
    const err = await runRegisterFlow(flowParams, {
      fetchImpl: fakeFetch(({ method }) =>
        method === "POST"
          ? new Response(
              cborProblem({
                title: "Unauthorized",
                detail: "grant rejected",
                status: 401,
              }),
              { status: 401, headers: { "Content-Type": "application/cbor" } },
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
    expect(flowErr.httpStatus).toBe(401);
    expect(flowErr.detail).toBe("grant rejected");
    expect(flowErr.problem).toEqual({
      title: "Unauthorized",
      detail: "grant rejected",
      status: 401,
    });
  });

  test("times out while pending without sleeping past the deadline", async () => {
    const clock = fakeClock();
    const err = await runRegisterFlow(
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
    const flowErr = err as RegisterFlowError;
    expect(flowErr.stage).toBe("timeout");
    expect(flowErr.statusUrl).toBe(`${BASE}${STATUS_PATH}`);
    expect(clock.waits).toEqual([100, 100, 100, 100]); // stops at 400 < 450
  });
});

describe("runRegister (main)", () => {
  const baseOptions: RegisterOptions = {
    json: true,
    verbosity: 0,
    baseUrl: BASE,
    logId: LOG_ID,
    statement: undefined,
    grantB64: GRANT_B64,
    out: undefined,
    timeoutMs: 5_000,
    pollIntervalMs: 100,
  };

  test("--json success without --out embeds the receipt as base64", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    await runRegister(out, baseOptions, {
      readStdin: async () => STATEMENT,
      fetchImpl: fakeFetch(({ method, url }) => {
        if (method === "POST") return see(STATUS_PATH);
        if (url.pathname === STATUS_PATH) return see(RECEIPT_PATH);
        if (url.pathname === RECEIPT_PATH) {
          return new Response(RECEIPT, { status: 200 });
        }
        return undefined;
      }),
      ...fakeClock(),
    });
    expect(process.exitCode).toBe(0);
    const stdout = out.lines.filter((l) => l.stream === "stdout");
    const report = JSON.parse(stdout.map((l) => l.text).join("\n")) as Record<
      string,
      unknown
    >;
    expect(report["status"]).toBe("receipt");
    expect(report["entryId"]).toBe(ENTRY_ID);
    expect(report["statusUrl"]).toBe(`${BASE}${STATUS_PATH}`);
    expect(report["receiptUrl"]).toBe(`${BASE}${RECEIPT_PATH}`);
    expect(report["receiptB64"]).toBe(Buffer.from(RECEIPT).toString("base64"));
  });

  test("--json error carries the problem-details passthrough", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    await runRegister(out, baseOptions, {
      readStdin: async () => STATEMENT,
      fetchImpl: fakeFetch(() =>
        new Response(cborProblem({ detail: "log unknown", status: 404 }), {
          status: 404,
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
    expect(report["httpStatus"]).toBe(404);
    expect(report["problem"]).toEqual({ detail: "log unknown", status: 404 });
  });

  test("missing statement file is a structured error", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    await runRegister(out, {
      ...baseOptions,
      json: false,
      statement: "/nonexistent/statement.cose",
    });
    expect(process.exitCode).toBe(1);
    process.exitCode = 0;
    const warned = out.lines.filter((l) => l.channel === "warn");
    expect(warned.some((l) => l.text.includes("statement file not found"))).toBe(
      true,
    );
  });
});

/**
 * Async CLI spawn for the smoke tests: the mock SCRAPI server runs on this
 * test process's event loop, so the sync `runCli` helper would deadlock
 * (`Bun.spawnSync` blocks the loop and the server never answers).
 */
async function runCliAsync(
  args: string[],
  stdin?: Uint8Array,
): Promise<CliResult> {
  const env: Record<string, string | undefined> = { ...process.env };
  for (const name of ["FORESTRIE_BASE_URL", "FORESTRIE_CONFIG", "GRANT_B64"]) {
    delete env[name];
  }
  const proc = Bun.spawn({
    cmd: ["bun", path.join(ROOT, "src/cli.ts"), ...args],
    cwd: ROOT,
    env,
    stdin: stdin ?? "ignore",
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

describe("forestrie register (binary smoke, mock SCRAPI server)", () => {
  let statusGets = 0;
  let receiptGets = 0;
  const server = Bun.serve({
    port: 0,
    fetch(req) {
      const url = new URL(req.url);
      if (
        req.method === "POST" &&
        url.pathname === `/register/${LOG_ID}/entries`
      ) {
        if (
          req.headers.get("authorization") !== `Forestrie-Grant ${GRANT_B64}`
        ) {
          return new Response(
            cborProblem({ detail: "grant rejected", status: 401 }),
            { status: 401, headers: { "Content-Type": "application/cbor" } },
          );
        }
        return new Response(null, {
          status: 303,
          headers: { Location: STATUS_PATH },
        });
      }
      if (req.method === "GET" && url.pathname === STATUS_PATH) {
        statusGets++;
        return new Response(null, {
          status: 303,
          headers: {
            Location: statusGets < 2 ? STATUS_PATH : RECEIPT_PATH,
          },
        });
      }
      if (req.method === "GET" && url.pathname === RECEIPT_PATH) {
        receiptGets++;
        if (receiptGets < 2) return new Response(null, { status: 404 });
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

  const tmp = mkdtempSync(path.join(os.tmpdir(), "forestrie-register-"));
  const statementPath = path.join(tmp, "statement.cose");
  writeFileSync(statementPath, STATEMENT);

  test("registers a statement file and writes the receipt to --out", async () => {
    const receiptPath = path.join(tmp, "receipt.cbor");
    const result = await runCliAsync([
      "register",
      "--json",
      "--base-url",
      baseUrl,
      "--log-id",
      LOG_ID,
      "--statement",
      statementPath,
      "--grant-b64",
      GRANT_B64,
      "--out",
      receiptPath,
      "--timeout",
      "10",
      "--poll-interval",
      "0.05",
    ]);
    // Progress narration goes to stderr; stdout carries only the JSON.
    expect(result.stderr).toContain("registered; status:");
    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.stdout) as Record<string, unknown>;
    expect(report["status"]).toBe("receipt");
    expect(report["entryId"]).toBe(ENTRY_ID);
    expect(report["statusUrl"]).toBe(`${baseUrl}${STATUS_PATH}`);
    expect(report["receiptUrl"]).toBe(`${baseUrl}${RECEIPT_PATH}`);
    expect(report["out"]).toBe(receiptPath);
    expect(report["receiptB64"]).toBeUndefined();
    const written = new Uint8Array(await Bun.file(receiptPath).arrayBuffer());
    expect(written).toEqual(RECEIPT);
  });

  test("reads the statement from stdin and prints a human summary", async () => {
    const result = await runCliAsync(
      [
        "register",
        "--base-url",
        baseUrl,
        "--log-id",
        LOG_ID,
        "--grant-b64",
        GRANT_B64,
        "--timeout",
        "10",
        "--poll-interval",
        "0.05",
      ],
      STATEMENT,
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain(`entryId: ${ENTRY_ID}`);
    expect(result.stdout).toContain(`receiptUrl: ${baseUrl}${RECEIPT_PATH}`);
    expect(result.stdout).toContain("--out");
  });

  test("rejected grant exits 1 with the problem-details JSON", async () => {
    const result = await runCliAsync([
      "register",
      "--json",
      "--base-url",
      baseUrl,
      "--log-id",
      LOG_ID,
      "--statement",
      statementPath,
      "--grant-b64",
      "d3Jvbmc=",
      "--timeout",
      "10",
    ]);
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout) as Record<string, unknown>;
    expect(report["error"]).toBe("registration_failed");
    expect(report["httpStatus"]).toBe(401);
    expect(report["problem"]).toEqual({ detail: "grant rejected", status: 401 });
  });
});
