import { beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createCaptureOut } from "@forestrie/cli-kit/reporting";
import {
  decodeLogStateResult,
  toContractLogId,
} from "../src/lib/verify-anchored.js";
import type { VerifyReport } from "../src/lib/verify-report.js";
import { runVerify } from "../src/main/verify.js";
import { parseVerifyOptions } from "../src/options/verify.js";
import { runCli } from "./support.js";
import {
  buildVerifyFixture,
  bytesToHex,
  encodeLogStateResult,
  FIXTURE_LOG_ID,
  tamperSignature,
  type VerifyFixture,
} from "./verify-fixture.js";

const UNIVOCITY = "0x" + "ab".repeat(20);

let fx: VerifyFixture;
let dir: string;
const file = (name: string) => path.join(dir, name);

beforeAll(async () => {
  // Hermetic: the CLI reads these implicitly (see test/support.ts).
  delete process.env["GRANT_B64"];
  delete process.env["RPC_URL"];
  fx = await buildVerifyFixture();
  dir = mkdtempSync(path.join(tmpdir(), "forestrie-verify-"));
  writeFileSync(file("genesis.cbor"), fx.genesisCbor);
  writeFileSync(file("ks256-genesis.cbor"), fx.ks256GenesisCbor);
  writeFileSync(file("receipt.cbor"), fx.receiptCbor);
  writeFileSync(file("receipt-attached.cbor"), fx.attachedPeakReceiptCbor);
  writeFileSync(file("receipt-bad-path.cbor"), fx.tamperedPathReceiptCbor);
  writeFileSync(file("receipt-bad-sig.cbor"), tamperSignature(fx.receiptCbor));
  writeFileSync(file("receipt-garbage.cbor"), new Uint8Array([1, 2, 3]));
  writeFileSync(file("grant.cbor"), fx.grantPayloadCbor);
});

/** Throws if the offline path ever touches the network. */
const forbiddenFetch = (() => {
  throw new Error("network forbidden during offline verify");
}) as unknown as typeof fetch;

type LooseArgs = Parameters<typeof parseVerifyOptions>[0];

async function verifyInProcess(
  args: LooseArgs,
  fetchImpl: typeof fetch = forbiddenFetch,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const out = createCaptureOut(0);
  const options = parseVerifyOptions(args);
  const realFetch = globalThis.fetch;
  const savedExitCode = process.exitCode;
  process.exitCode = 0;
  globalThis.fetch = fetchImpl;
  try {
    await runVerify(out, options);
  } finally {
    globalThis.fetch = realFetch;
  }
  const exitCode = Number(process.exitCode ?? 0);
  process.exitCode = savedExitCode;
  const text = (stream: "stdout" | "stderr") =>
    out.lines
      .filter((l) => l.stream === stream)
      .map((l) => l.text)
      .join("\n");
  return { exitCode, stdout: text("stdout"), stderr: text("stderr") };
}

function baseArgs(overrides: LooseArgs = {}) {
  return {
    genesis: file("genesis.cbor"),
    receipt: file("receipt.cbor"),
    "grant-b64": fx.grantCoseB64,
    ...overrides,
  };
}

function jsonReport(stdout: string): VerifyReport {
  return JSON.parse(stdout) as VerifyReport;
}

describe("forestrie verify — offline (no network)", () => {
  test("golden pass with --grant-b64 (Forestrie-Grant COSE); fetch is never touched", async () => {
    const r = await verifyInProcess(baseArgs());
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("PASS: receipt verified offline");
    for (const stage of ["parse", "signature", "inclusion", "binding"]) {
      expect(r.stderr).toContain(`verify: ${stage}`);
    }
    expect(r.stderr).not.toContain("failed");
  });

  test("golden pass with --grant CBOR + --entry-id", async () => {
    const r = await verifyInProcess(
      baseArgs({
        "grant-b64": undefined,
        grant: file("grant.cbor"),
        "entry-id": fx.entryIdHex,
      }),
    );
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("PASS");
  });

  test("golden pass with --grant-b64 raw payload + --entry-id", async () => {
    const r = await verifyInProcess(
      baseArgs({
        "grant-b64": Buffer.from(fx.grantPayloadCbor).toString("base64"),
        "entry-id": fx.entryIdHex,
      }),
    );
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("PASS");
  });

  test("golden pass with an attached-peak receipt", async () => {
    const r = await verifyInProcess(
      baseArgs({ receipt: file("receipt-attached.cbor") }),
    );
    expect(r.exitCode).toBe(0);
  });

  test("raw payload --grant-b64 without --entry-id is a usage error", async () => {
    await expect(
      verifyInProcess(
        baseArgs({
          "grant-b64": Buffer.from(fx.grantPayloadCbor).toString("base64"),
        }),
      ),
    ).rejects.toThrow(/--entry-id/);
  });

  test("missing genesis file is a clear error", async () => {
    await expect(
      verifyInProcess(baseArgs({ genesis: file("nope.cbor") })),
    ).rejects.toThrow(/--genesis/);
  });

  test("tampered signature fails at stage=signature, exit 1", async () => {
    const r = await verifyInProcess(
      baseArgs({ receipt: file("receipt-bad-sig.cbor"), json: true }),
    );
    expect(r.exitCode).toBe(1);
    const report = jsonReport(r.stdout);
    expect(report.ok).toBe(false);
    expect(report.stage).toBe("signature");
    expect(report.reason).toBe("signature_invalid");
  });

  test("tampered proof path fails at stage=inclusion, exit 1", async () => {
    const r = await verifyInProcess(
      baseArgs({ receipt: file("receipt-bad-path.cbor"), json: true }),
    );
    expect(r.exitCode).toBe(1);
    const report = jsonReport(r.stdout);
    expect(report.stage).toBe("inclusion");
    expect(report.reason).toBe("inclusion_failed");
    expect(report.stages).toEqual([
      { stage: "parse", status: "ok" },
      { stage: "signature", status: "ok" },
      { stage: "inclusion", status: "failed", reason: "inclusion_failed" },
      { stage: "binding", status: "skipped" },
    ]);
  });

  test("garbage receipt fails at stage=parse, exit 1", async () => {
    const r = await verifyInProcess(
      baseArgs({ receipt: file("receipt-garbage.cbor"), json: true }),
    );
    expect(r.exitCode).toBe(1);
    expect(jsonReport(r.stdout).stage).toBe("parse");
    expect(jsonReport(r.stdout).reason).toBe("receipt_malformed");
  });

  test("wrong grant fails verification, exit 1", async () => {
    const other = Buffer.from(fx.grantPayloadCbor).toString("base64");
    // Same grant bytes but a different idtimestamp — leaf no longer matches.
    const r = await verifyInProcess(
      baseArgs({
        "grant-b64": other,
        "entry-id": "0f0f0f0f0f0f0f0f0000000000000001",
        json: true,
      }),
    );
    expect(r.exitCode).toBe(1);
    expect(jsonReport(r.stdout).ok).toBe(false);
  });

  test("KS256 genesis surfaces no_es256_trust_key (ES256-only verify)", async () => {
    const r = await verifyInProcess(
      baseArgs({ genesis: file("ks256-genesis.cbor"), json: true }),
    );
    expect(r.exitCode).toBe(1);
    const report = jsonReport(r.stdout);
    expect(report.stage).toBe("signature");
    expect(report.reason).toBe("no_es256_trust_key");
  });

  test("--json emits the structured contract on success", async () => {
    const r = await verifyInProcess(baseArgs({ json: true }));
    expect(r.exitCode).toBe(0);
    const report = jsonReport(r.stdout);
    expect(report.command).toBe("verify");
    expect(report.mode).toBe("offline");
    expect(report.ok).toBe(true);
    expect(report.stage).toBe("binding");
    expect(report.stages).toHaveLength(4);
    expect(report.stages.every((s) => s.status === "ok")).toBe(true);
    expect(report.anchor).toBeUndefined();
  });
});

describe("forestrie verify — chain-anchored mode", () => {
  function rpcFetch(resultHex: string, calls: unknown[] = []): typeof fetch {
    return (async (_url: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as {
        method: string;
        params: unknown[];
      };
      calls.push(body);
      expect(body.method).toBe("eth_call");
      return new Response(
        JSON.stringify({ jsonrpc: "2.0", id: 1, result: resultHex }),
        { headers: { "Content-Type": "application/json" } },
      );
    }) as unknown as typeof fetch;
  }

  const chainArgs = (overrides: LooseArgs = {}) =>
    baseArgs({
      univocity: UNIVOCITY,
      "log-id": FIXTURE_LOG_ID,
      "rpc-url": "http://rpc.mock",
      json: true,
      ...overrides,
    });

  test("anchored: receipt peak found in the on-chain accumulator (detached receipt)", async () => {
    const otherPeak = new Uint8Array(32).fill(0x11);
    const calls: { params: [{ data: string }, string] }[] = [];
    const r = await verifyInProcess(
      chainArgs(),
      rpcFetch(encodeLogStateResult([otherPeak, fx.peak], 3n), calls),
    );
    expect(r.exitCode).toBe(0);
    const report = jsonReport(r.stdout);
    expect(report.mode).toBe("chain-anchored");
    expect(report.ok).toBe(true);
    expect(report.anchor).toEqual({
      univocity: UNIVOCITY,
      logId: FIXTURE_LOG_ID,
      anchored: true,
      anchoredSize: "3",
      peakCount: 2,
      matchedPeak: 1,
    });
    // logState(bytes32) selector + zero-padded contract log id
    expect(calls[0]!.params[0].data).toBe(
      "0xeecac1b7" + toContractLogId(FIXTURE_LOG_ID).slice(2),
    );
  });

  test("anchored: explicit-peak receipt is byte-compared", async () => {
    const r = await verifyInProcess(
      chainArgs({ receipt: file("receipt-attached.cbor") }),
      rpcFetch(encodeLogStateResult([fx.peak], 3n)),
    );
    expect(r.exitCode).toBe(0);
    expect(jsonReport(r.stdout).anchor?.matchedPeak).toBe(0);
  });

  test("not anchored: peak absent from the accumulator, exit 1", async () => {
    const otherPeak = new Uint8Array(32).fill(0x11);
    const r = await verifyInProcess(
      chainArgs(),
      rpcFetch(encodeLogStateResult([otherPeak], 5n)),
    );
    expect(r.exitCode).toBe(1);
    const report = jsonReport(r.stdout);
    expect(report.ok).toBe(false);
    expect(report.anchor?.anchored).toBe(false);
    expect(report.anchor?.reason).toBe("peak_not_in_onchain_accumulator");
    expect(report.anchor?.anchoredSize).toBe("5");
  });

  test("offline failure skips the network entirely in chain mode", async () => {
    const r = await verifyInProcess(
      chainArgs({ receipt: file("receipt-bad-sig.cbor") }),
      forbiddenFetch,
    );
    expect(r.exitCode).toBe(1);
    expect(jsonReport(r.stdout).stage).toBe("signature");
  });
});

describe("verify-anchored helpers", () => {
  test("toContractLogId accepts UUID, 32-hex and 64-hex forms", () => {
    const expected =
      "0x" + "0".repeat(32) + FIXTURE_LOG_ID.replaceAll("-", "");
    expect(toContractLogId(FIXTURE_LOG_ID)).toBe(expected);
    expect(toContractLogId(FIXTURE_LOG_ID.replaceAll("-", ""))).toBe(expected);
    expect(toContractLogId(expected)).toBe(expected);
    expect(() => toContractLogId("not-a-log-id")).toThrow(/--log-id/);
  });

  test("decodeLogStateResult round-trips encodeLogStateResult", () => {
    const peaks = [
      new Uint8Array(32).fill(0x01),
      new Uint8Array(32).fill(0x02),
    ];
    const state = decodeLogStateResult(encodeLogStateResult(peaks, 42n));
    expect(state.size).toBe(42n);
    expect(state.accumulator.map(bytesToHex)).toEqual(peaks.map(bytesToHex));
    expect(() => decodeLogStateResult("0x")).toThrow(/empty/);
  });
});

describe("forestrie verify — CLI surface", () => {
  test("binary-equivalent CLI run: golden pass exits 0", () => {
    const result = runCli([
      "verify",
      "--genesis",
      file("genesis.cbor"),
      "--receipt",
      file("receipt.cbor"),
      "--grant-b64",
      fx.grantCoseB64,
    ]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("PASS");
  });

  test("CLI run: tampered receipt exits non-zero with --json report", () => {
    const result = runCli([
      "verify",
      "--json",
      "--genesis",
      file("genesis.cbor"),
      "--receipt",
      file("receipt-bad-sig.cbor"),
      "--grant-b64",
      fx.grantCoseB64,
    ]);
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout) as VerifyReport;
    expect(report.ok).toBe(false);
    expect(report.stage).toBe("signature");
  });

  test("CLI run: GRANT_B64 env fallback works", () => {
    const result = runCli(
      [
        "verify",
        "--genesis",
        file("genesis.cbor"),
        "--receipt",
        file("receipt.cbor"),
      ],
      { GRANT_B64: fx.grantCoseB64 },
    );
    expect(result.exitCode).toBe(0);
  });
});
