import { beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createCaptureOut } from "@forestrie/cli-kit/reporting";
import {
  decodeLogStateResult,
  toContractLogId,
} from "../src/lib/verify-anchored.js";
import {
  stageRows,
  type StageRow,
  type VerifyReport,
} from "../src/lib/verify-report.js";
import { readFileSync } from "node:fs";
import { runVerifyGrant, type VerifyErrorReport } from "../src/main/verify.js";
import { runFetchAccumulator } from "../src/main/fetch-accumulator.js";
import { parseVerifyGrantOptions } from "../src/options/verify.js";
import { parseFetchAccumulatorOptions } from "../src/options/fetch-accumulator.js";
import {
  decodeKnownAccumulator,
  encodeKnownAccumulator,
  type KnownAccumulator,
} from "../src/lib/verify-known-accumulator.js";
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
  delete process.env["KNOWN_LOG_KEY"];
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
  writeFileSync(file("receipt-child.cbor"), fx.delegatedChildReceiptCbor);
  writeFileSync(
    file("receipt-child-bad-path.cbor"),
    fx.tamperedPathChildReceiptCbor,
  );
});

/** Throws if the offline path ever touches the network. */
const forbiddenFetch = (() => {
  throw new Error("network forbidden during offline verify");
}) as unknown as typeof fetch;

type LooseArgs = Parameters<typeof parseVerifyGrantOptions>[0];

async function verifyInProcess(
  args: LooseArgs,
  fetchImpl: typeof fetch = forbiddenFetch,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const out = createCaptureOut(0);
  const options = parseVerifyGrantOptions(args);
  const realFetch = globalThis.fetch;
  const savedExitCode = process.exitCode;
  process.exitCode = 0;
  globalThis.fetch = fetchImpl;
  try {
    await runVerifyGrant(out, options);
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
    "committed-grant": fx.grantCoseB64,
    ...overrides,
  };
}

function jsonReport(stdout: string): VerifyReport {
  return JSON.parse(stdout) as VerifyReport;
}

describe("forestrie verify — offline (no network)", () => {
  test("golden pass with --committed-grant (Forestrie-Grant COSE); fetch is never touched", async () => {
    const r = await verifyInProcess(baseArgs());
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("PASS: receipt verified offline");
    for (const stage of ["parse", "signature", "inclusion", "binding"]) {
      expect(r.stderr).toContain(`verify: ${stage}`);
    }
    expect(r.stderr).not.toContain("failed");
  });

  test("golden pass with --committed-grant-file CBOR + --entry-id", async () => {
    const r = await verifyInProcess(
      baseArgs({
        "committed-grant": undefined,
        "committed-grant-file": file("grant.cbor"),
        "entry-id": fx.entryIdHex,
      }),
    );
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("PASS");
  });

  test("golden pass with --committed-grant raw payload + --entry-id", async () => {
    const r = await verifyInProcess(
      baseArgs({
        "committed-grant": Buffer.from(fx.grantPayloadCbor).toString("base64"),
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

  test("raw payload --committed-grant without --entry-id is a structured input error (F3)", async () => {
    const r = await verifyInProcess(
      baseArgs({
        "committed-grant": Buffer.from(fx.grantPayloadCbor).toString(
          "base64",
        ),
        json: true,
      }),
    );
    expect(r.exitCode).toBe(1);
    const report = JSON.parse(r.stdout) as VerifyErrorReport;
    expect(report.error).toBe("verify_input_failed");
    expect(report.command).toBe("verify");
    expect(report.stage).toBe("input");
    expect(report.message).toMatch(/--entry-id/);
  });

  test("missing genesis file: --json owns stdout with the error envelope (F3)", async () => {
    const r = await verifyInProcess(
      baseArgs({ genesis: file("nope.cbor"), json: true }),
    );
    expect(r.exitCode).toBe(1);
    const report = JSON.parse(r.stdout) as VerifyErrorReport;
    expect(report.error).toBe("verify_input_failed");
    expect(report.stage).toBe("input");
    expect(report.message).toMatch(/--genesis/);
  });

  test("missing genesis file, human mode: clean stderr line, empty stdout, no stack", async () => {
    const r = await verifyInProcess(baseArgs({ genesis: file("nope.cbor") }));
    expect(r.exitCode).toBe(1);
    expect(r.stdout).toBe("");
    expect(r.stderr).toContain("forestrie verify: input:");
    expect(r.stderr).toContain("--genesis");
    expect(r.stderr).not.toMatch(/\n\s+at /);
  });

  test("garbage --committed-grant is a structured input error, not a crash (F3)", async () => {
    const r = await verifyInProcess(
      baseArgs({ "committed-grant": "AAAA", json: true }),
    );
    expect(r.exitCode).toBe(1);
    const report = JSON.parse(r.stdout) as VerifyErrorReport;
    expect(report.error).toBe("verify_input_failed");
    expect(report.stage).toBe("input");
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
        "committed-grant": other,
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

  test("RPC transport failure: --json owns stdout with anchor_check_failed (F3)", async () => {
    const refusedFetch = (async () => {
      throw new TypeError("fetch failed: connect ECONNREFUSED 127.0.0.1:8545");
    }) as unknown as typeof fetch;
    const r = await verifyInProcess(chainArgs(), refusedFetch);
    expect(r.exitCode).toBe(1);
    const report = JSON.parse(r.stdout) as VerifyErrorReport;
    expect(report.error).toBe("anchor_check_failed");
    expect(report.command).toBe("verify");
    expect(report.stage).toBe("anchor");
    expect(report.message).toContain("ECONNREFUSED");
  });

  test("RPC garbage result: structured anchor error, human mode stays clean", async () => {
    const badRpc = rpcFetch("0x01"); // too short to decode
    const r = await verifyInProcess(chainArgs({ json: undefined }), badRpc);
    expect(r.exitCode).toBe(1);
    expect(r.stdout).toBe("");
    expect(r.stderr).toContain("forestrie verify: anchor:");
    expect(r.stderr).not.toMatch(/\n\s+at /);
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

describe("verify-report stageRows", () => {
  test("unknown future stage renders explicitly as the failed row (F3)", () => {
    // A stage this CLI predates must NOT degrade to four silent
    // "skipped" rows with the failure dropped.
    const rows = stageRows({
      ok: false,
      stage: "consistency" as never,
      reason: "consistency_failed",
    });
    expect(rows).toHaveLength(5);
    const failed = rows.filter((r: StageRow) => r.status === "failed");
    expect(failed).toEqual([
      {
        stage: "consistency" as never,
        status: "failed",
        reason: "consistency_failed",
      },
    ]);
    for (const known of [
      "parse",
      "signature",
      "inclusion",
      "binding",
    ] as const) {
      expect(rows).toContainEqual({ stage: known, status: "skipped" });
    }
  });
});

describe("forestrie verify — CLI surface", () => {
  test("binary-equivalent CLI run: golden pass exits 0", () => {
    const result = runCli([
      "verify-grant",
      "--genesis",
      file("genesis.cbor"),
      "--receipt",
      file("receipt.cbor"),
      "--committed-grant",
      fx.grantCoseB64,
    ]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("PASS");
  });

  test("CLI run: tampered receipt exits non-zero with --json report", () => {
    const result = runCli([
      "verify-grant",
      "--json",
      "--genesis",
      file("genesis.cbor"),
      "--receipt",
      file("receipt-bad-sig.cbor"),
      "--committed-grant",
      fx.grantCoseB64,
    ]);
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout) as VerifyReport;
    expect(report.ok).toBe(false);
    expect(report.stage).toBe("signature");
  });

  test("CLI run: bogus input under --json emits parseable JSON, exit non-zero, no stack (F3)", () => {
    // The CI implemented-smoke jq assertion mirrors this exact shape.
    const result = runCli([
      "verify-grant",
      "--json",
      "--genesis",
      "missing.cbor",
      "--receipt",
      "missing.cbor",
      "--committed-grant",
      "AAAA",
    ]);
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout) as VerifyErrorReport;
    expect(report.error).toBe("verify_input_failed");
    expect(report.command).toBe("verify");
    expect(report.stage).toBe("input");
    expect(report.message).toContain("--genesis");
    expect(result.stderr).not.toMatch(/\n\s+at /);
  });

  test("CLI run: GRANT_B64 env fallback works", () => {
    const result = runCli(
      [
        "verify-grant",
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

describe("forestrie verify — anchor-only child-log fallback (FOR-297 approach C)", () => {
  function rpcFetch(resultHex: string): typeof fetch {
    return (async (_url: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { method: string };
      expect(body.method).toBe("eth_call");
      return new Response(
        JSON.stringify({ jsonrpc: "2.0", id: 1, result: resultHex }),
        { headers: { "Content-Type": "application/json" } },
      );
    }) as unknown as typeof fetch;
  }

  const childChainArgs = (overrides: LooseArgs = {}) =>
    baseArgs({
      receipt: file("receipt-child.cbor"),
      univocity: UNIVOCITY,
      "log-id": FIXTURE_LOG_ID,
      "rpc-url": "http://rpc.mock",
      json: true,
      ...overrides,
    });

  test("offline mode still hard-fails delegation_invalid (unchanged)", async () => {
    const r = await verifyInProcess(
      baseArgs({ receipt: file("receipt-child.cbor"), json: true }),
    );
    expect(r.exitCode).toBe(1);
    const report = jsonReport(r.stdout);
    expect(report.stage).toBe("signature");
    expect(report.reason).toBe("delegation_invalid");
  });

  test("chain mode: recomputed peak anchored on-chain → PASS, signature ok via the anchor", async () => {
    const otherPeak = new Uint8Array(32).fill(0x77);
    const r = await verifyInProcess(
      childChainArgs(),
      rpcFetch(encodeLogStateResult([otherPeak, fx.peak], 2n)),
    );
    expect(r.exitCode).toBe(0);
    const report = jsonReport(r.stdout);
    expect(report.ok).toBe(true);
    expect(report.mode).toBe("chain-anchored");
    const sig = report.stages.find((s: StageRow) => s.stage === "signature");
    expect(sig?.status).toBe("ok");
    expect(sig?.reason).toContain("verified against accumulator from chain");
    expect(report.stages.find((s: StageRow) => s.stage === "inclusion")?.status).toBe("ok");
    expect(report.stages.find((s: StageRow) => s.stage === "binding")?.status).toBe("ok");
    expect(report.anchor).toMatchObject({
      anchored: true,
      matchedPeak: 1,
      anchoredSize: "2",
    });
  });

  test("chain mode, human narration: PASS names the on-chain accumulator", async () => {
    const r = await verifyInProcess(
      childChainArgs({ json: undefined }),
      rpcFetch(encodeLogStateResult([fx.peak], 2n)),
    );
    expect(r.exitCode).toBe(0);
    expect(r.stderr).toContain("verified against accumulator from chain");
    expect(r.stdout).toContain(
      "PASS: receipt verified against the on-chain accumulator",
    );
    expect(r.stdout).toContain("signature enforced by univocity at publish");
  });

  test("chain mode: peak NOT anchored → original delegation_invalid failure stands", async () => {
    const otherPeak = new Uint8Array(32).fill(0x77);
    const r = await verifyInProcess(
      childChainArgs(),
      rpcFetch(encodeLogStateResult([otherPeak], 2n)),
    );
    expect(r.exitCode).toBe(1);
    const report = jsonReport(r.stdout);
    expect(report.ok).toBe(false);
    expect(report.stage).toBe("signature");
    expect(report.reason).toBe("delegation_invalid");
  });

  test("chain mode: wrong grant (leaf mismatch) cannot anchor — fails", async () => {
    const wrongGrantB64 = Buffer.from(fx.grantPayloadCbor.slice())
      .toString("base64");
    // raw payload grant with a tampered byte → different commitment → different
    // recomputed peak → no accumulator match even when the true peak is on-chain.
    const tampered = new Uint8Array(fx.grantPayloadCbor);
    tampered[tampered.length - 1]! ^= 0xff;
    const r = await verifyInProcess(
      childChainArgs({
        "committed-grant": Buffer.from(tampered).toString("base64"),
        "entry-id": fx.entryIdHex,
      }),
      rpcFetch(encodeLogStateResult([fx.peak], 2n)),
    );
    expect(r.exitCode).toBe(1);
    void wrongGrantB64;
  });

  test("chain mode: RPC failure during fallback is a structured anchor error", async () => {
    const refusedFetch = (async () => {
      throw new TypeError("fetch failed: connect ECONNREFUSED");
    }) as unknown as typeof fetch;
    const r = await verifyInProcess(childChainArgs(), refusedFetch);
    expect(r.exitCode).toBe(1);
    const report = JSON.parse(r.stdout) as VerifyErrorReport;
    expect(report.error).toBe("anchor_check_failed");
    expect(report.stage).toBe("anchor");
  });
});

describe("forestrie verify-grant — caller-known log key (FOR-297 D1)", () => {
  const knownKeyArgs = (overrides: LooseArgs = {}) =>
    baseArgs({
      genesis: undefined,
      receipt: file("receipt-child.cbor"),
      "known-log-key": fx.childOwnerKeyXyB64,
      json: true,
      ...overrides,
    });

  test("golden: child receipt verifies offline under the known owner key, no genesis", async () => {
    const r = await verifyInProcess(knownKeyArgs());
    expect(r.exitCode).toBe(0);
    const report = jsonReport(r.stdout);
    expect(report.ok).toBe(true);
    expect(report.mode).toBe("offline");
    const sig = report.stages.find((s: StageRow) => s.stage === "signature");
    expect(sig?.status).toBe("ok");
    expect(sig?.reason).toContain("caller-known log key");
    const parse = report.stages.find((s: StageRow) => s.stage === "parse");
    expect(parse?.reason).toContain("caller-known log key");
  });

  test("human narration names the anchor: not genesis-derived", async () => {
    const r = await verifyInProcess(knownKeyArgs({ json: undefined }));
    expect(r.exitCode).toBe(0);
    expect(r.stderr).toContain("caller-known log key (not genesis-derived)");
    expect(r.stdout).toContain(
      "PASS: receipt verified offline under the caller-known log key (not genesis-derived)",
    );
  });

  test("wrong known key → known_key_mismatch (distinct from delegation_invalid)", async () => {
    const rootRaw = new Uint8Array(
      (await crypto.subtle.exportKey(
        "raw",
        fx.rootKeyPair.publicKey,
      )) as ArrayBuffer,
    );
    const wrongKeyB64 = Buffer.from(rootRaw.slice(1)).toString("base64");
    const r = await verifyInProcess(
      knownKeyArgs({ "known-log-key": wrongKeyB64 }),
    );
    expect(r.exitCode).toBe(1);
    const report = jsonReport(r.stdout);
    expect(report.ok).toBe(false);
    expect(report.stage).toBe("signature");
    expect(report.reason).toBe("known_key_mismatch");
  });

  test("correct known key + tampered proof path → inclusion fails", async () => {
    const r = await verifyInProcess(
      knownKeyArgs({ receipt: file("receipt-child-bad-path.cbor") }),
    );
    expect(r.exitCode).toBe(1);
    const report = jsonReport(r.stdout);
    expect(report.ok).toBe(false);
    expect(report.stage).toBe("inclusion");
  });

  test("known key also verifies the ROOT-log receipt (cert chained to the owner)", async () => {
    // The root receipt has no delegation cert; the known key is then the
    // direct signer key — standard SCITT RP posture on a root log.
    const rootRaw = new Uint8Array(
      (await crypto.subtle.exportKey(
        "raw",
        fx.rootKeyPair.publicKey,
      )) as ArrayBuffer,
    );
    const rootKeyB64 = Buffer.from(rootRaw.slice(1)).toString("base64");
    const r = await verifyInProcess(
      knownKeyArgs({
        receipt: file("receipt.cbor"),
        "known-log-key": rootKeyB64,
      }),
    );
    expect(r.exitCode).toBe(0);
  });

  test("neither --genesis nor --known-log-key is a usage error", () => {
    expect(() =>
      parseVerifyGrantOptions(
        baseArgs({ genesis: undefined }) as LooseArgs,
      ),
    ).toThrow(/trust anchor/);
  });

  test("malformed --known-log-key (not 64 bytes) is a structured error", async () => {
    const r = await verifyInProcess(knownKeyArgs({ "known-log-key": "AAAA" }));
    expect(r.exitCode).toBe(1);
    const report = JSON.parse(r.stdout) as VerifyErrorReport;
    expect(report.error).toBe("verify_failed");
    expect(report.message).toContain("64 bytes");
  });
});

describe("forestrie verify-grant — known accumulator snapshot (FOR-297 D5)", () => {
  const contractLogIdBytes = (logId: string): Uint8Array => {
    const hex = toContractLogId(logId).slice(2);
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  };

  const snapshotBytes = (over: Partial<KnownAccumulator> = {}): Uint8Array =>
    encodeKnownAccumulator({
      version: 1,
      chainId: 84532n,
      univocity: new Uint8Array(20).fill(0xab),
      logId: contractLogIdBytes(FIXTURE_LOG_ID),
      size: 3n,
      accumulator: [fx.peak],
      blockNumber: 123n,
      blockHash: new Uint8Array(32).fill(0xbb),
      ...over,
    });

  const snapshotFile = (name: string, bytes: Uint8Array): string => {
    writeFileSync(file(name), bytes);
    return file(name);
  };

  test("golden: child receipt anchors to the snapshot fully offline (fetch forbidden)", async () => {
    const snap = snapshotFile("acc-golden.cbor", snapshotBytes());
    const r = await verifyInProcess(
      baseArgs({
        receipt: file("receipt-child.cbor"),
        "known-accumulator": snap,
        json: true,
      }),
    );
    expect(r.exitCode).toBe(0);
    const report = jsonReport(r.stdout);
    expect(report.ok).toBe(true);
    expect(report.mode).toBe("accumulator-anchored");
    const sig = report.stages.find((s: StageRow) => s.stage === "signature");
    expect(sig?.status).toBe("ok");
    expect(report.anchor).toMatchObject({
      anchored: true,
      matchedPeak: 0,
      anchoredSize: "3",
      blockNumber: "123",
      extended: false,
    });
  });

  test("human narration names the known accumulator and the block", async () => {
    const snap = snapshotFile("acc-golden.cbor", snapshotBytes());
    const r = await verifyInProcess(
      baseArgs({
        receipt: file("receipt-child.cbor"),
        "known-accumulator": snap,
      }),
    );
    expect(r.exitCode).toBe(0);
    expect(r.stderr).toContain("known accumulator");
    expect(r.stderr).toContain("block 123");
    expect(r.stdout).toContain(
      "PASS: receipt verified against the known accumulator",
    );
  });

  test("ok-path: root receipt (genesis trust) also anchors to the snapshot", async () => {
    const snap = snapshotFile("acc-golden.cbor", snapshotBytes());
    const r = await verifyInProcess(
      baseArgs({ "known-accumulator": snap, json: true }),
    );
    expect(r.exitCode).toBe(0);
    const report = jsonReport(r.stdout);
    expect(report.ok).toBe(true);
    expect(report.mode).toBe("accumulator-anchored");
    expect(report.anchor?.anchored).toBe(true);
  });

  test("stale snapshot: old receipt extends to the grown peak via --massif", async () => {
    const snap = snapshotFile(
      "acc-grown.cbor",
      snapshotBytes({ size: 7n, accumulator: [fx.peak7] }),
    );
    writeFileSync(file("massif7.bin"), fx.massif7Bytes);
    const r = await verifyInProcess(
      baseArgs({
        receipt: file("receipt-child.cbor"),
        "known-accumulator": snap,
        massif: file("massif7.bin"),
        json: true,
      }),
    );
    expect(r.exitCode).toBe(0);
    const report = jsonReport(r.stdout);
    expect(report.ok).toBe(true);
    expect(report.anchor).toMatchObject({
      anchored: true,
      extended: true,
      anchoredSize: "7",
    });
  });

  test("stale snapshot without --massif cannot extend — fails closed", async () => {
    const snap = snapshotFile(
      "acc-grown.cbor",
      snapshotBytes({ size: 7n, accumulator: [fx.peak7] }),
    );
    const r = await verifyInProcess(
      baseArgs({
        receipt: file("receipt-child.cbor"),
        "known-accumulator": snap,
        json: true,
      }),
    );
    expect(r.exitCode).toBe(1);
  });

  test("receipt newer than the snapshot fails closed with a refresh hint", async () => {
    const snap = snapshotFile(
      "acc-old.cbor",
      snapshotBytes({ size: 1n, accumulator: [fx.peak] }),
    );
    const r = await verifyInProcess(
      baseArgs({
        receipt: file("receipt-child.cbor"),
        "known-accumulator": snap,
      }),
    );
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain("receipt_newer_than_known_accumulator");
    expect(r.stderr).toContain("refresh the accumulator");
  });

  test("forged snapshot (wrong peaks) does not anchor", async () => {
    const snap = snapshotFile(
      "acc-forged.cbor",
      snapshotBytes({ accumulator: [new Uint8Array(32).fill(0x77)] }),
    );
    const r = await verifyInProcess(
      baseArgs({
        receipt: file("receipt-child.cbor"),
        "known-accumulator": snap,
        json: true,
      }),
    );
    expect(r.exitCode).toBe(1);
    const report = jsonReport(r.stdout);
    expect(report.ok).toBe(false);
  });

  test("snapshot bound to a different log is rejected before any peak math", async () => {
    const snap = snapshotFile(
      "acc-wrong-log.cbor",
      snapshotBytes({
        logId: contractLogIdBytes("00000000-0000-4000-8000-000000000009"),
      }),
    );
    const r = await verifyInProcess(
      baseArgs({
        receipt: file("receipt-child.cbor"),
        "known-accumulator": snap,
        "log-id": FIXTURE_LOG_ID,
        json: true,
      }),
    );
    expect(r.exitCode).toBe(1);
    const report = JSON.parse(r.stdout) as VerifyErrorReport;
    expect(report.error).toBe("anchor_check_failed");
    expect(report.message).toContain("bound to log");
  });

  test("--known-accumulator conflicts with a live chain read", () => {
    expect(() =>
      parseVerifyGrantOptions(
        baseArgs({
          "known-accumulator": file("acc-golden.cbor"),
          univocity: UNIVOCITY,
          "log-id": FIXTURE_LOG_ID,
          "rpc-url": "http://rpc.mock",
        }) as LooseArgs,
      ),
    ).toThrow(/choose one chain anchor/);
  });

  test("--massif without --known-accumulator is a usage error", () => {
    expect(() =>
      parseVerifyGrantOptions(
        baseArgs({ massif: file("massif7.bin") }) as LooseArgs,
      ),
    ).toThrow(/--massif only applies/);
  });
});

describe("forestrie fetch-accumulator (FOR-297 D5 producer)", () => {
  async function fetchAccumulatorInProcess(
    args: Record<string, unknown>,
    fetchImpl: typeof fetch,
  ): Promise<{ exitCode: number; stdout: string; stderr: string }> {
    const out = createCaptureOut(0);
    const options = parseFetchAccumulatorOptions(args as LooseArgs);
    const realFetch = globalThis.fetch;
    const savedExitCode = process.exitCode;
    process.exitCode = 0;
    globalThis.fetch = fetchImpl;
    try {
      await runFetchAccumulator(out, options);
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

  const rpcRouter = (): typeof fetch =>
    (async (_url: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { method: string };
      const results: Record<string, unknown> = {
        eth_chainId: "0x14a34",
        eth_getBlockByNumber: {
          number: "0x7b",
          hash: "0x" + "bb".repeat(32),
        },
        eth_call: encodeLogStateResult([fx.peak], 3n),
      };
      if (!(body.method in results)) {
        throw new Error(`unexpected RPC method ${body.method}`);
      }
      return new Response(
        JSON.stringify({ jsonrpc: "2.0", id: 1, result: results[body.method] }),
        { headers: { "Content-Type": "application/json" } },
      );
    }) as unknown as typeof fetch;

  test("writes a canonical snapshot that verify accepts as --known-accumulator", async () => {
    const outPath = file("acc-fetched.cbor");
    const r = await fetchAccumulatorInProcess(
      {
        univocity: UNIVOCITY,
        "log-id": FIXTURE_LOG_ID,
        "rpc-url": "http://rpc.mock",
        out: outPath,
        json: true,
      },
      rpcRouter(),
    );
    expect(r.exitCode).toBe(0);
    const report = JSON.parse(r.stdout) as Record<string, unknown>;
    expect(report.command).toBe("fetch-accumulator");
    expect(report.chainId).toBe("84532");
    expect(report.anchoredSize).toBe("3");
    expect(report.blockNumber).toBe("123");

    const snapshot = decodeKnownAccumulator(
      new Uint8Array(readFileSync(outPath)),
    );
    expect(snapshot.size).toBe(3n);
    expect(snapshot.chainId).toBe(84532n);
    expect(snapshot.blockNumber).toBe(123n);
    expect(bytesToHex(snapshot.accumulator[0]!)).toBe(bytesToHex(fx.peak));

    // Round-trip: the fetched snapshot anchors the child receipt offline.
    const v = await verifyInProcess(
      baseArgs({
        receipt: file("receipt-child.cbor"),
        "known-accumulator": outPath,
        json: true,
      }),
    );
    expect(v.exitCode).toBe(0);
  });

  test("RPC failure is a structured error", async () => {
    const refusedFetch = (async () => {
      throw new TypeError("fetch failed: connect ECONNREFUSED");
    }) as unknown as typeof fetch;
    const r = await fetchAccumulatorInProcess(
      {
        univocity: UNIVOCITY,
        "log-id": FIXTURE_LOG_ID,
        "rpc-url": "http://rpc.mock",
        out: file("acc-never.cbor"),
        json: true,
      },
      refusedFetch,
    );
    expect(r.exitCode).toBe(1);
    const report = JSON.parse(r.stdout) as Record<string, unknown>;
    expect(report.error).toBe("fetch_accumulator_failed");
  });
});
