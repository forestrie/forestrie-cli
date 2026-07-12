import { beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createCaptureOut } from "@forestrie/cli-kit/reporting";
import { encodeGrantPayload } from "@forestrie/encoding";
import { verifyGrantReceiptOffline } from "@forestrie/receipt-verify";
import type {
  CreateReceiptErrorReport,
  CreateReceiptNotImplementedReport,
  CreateReceiptReport,
} from "../src/main/create-receipt.js";
import { runCreateReceipt } from "../src/main/create-receipt.js";
import { parseCreateReceiptOptions } from "../src/options/create-receipt.js";
import {
  buildCreateReceiptFixture,
  buildV2CheckpointBytes,
  tamperMassifSibling,
  type CreateReceiptFixture,
} from "./create-receipt-fixture.js";
import { runCli } from "./support.js";

let fx: CreateReceiptFixture;
let dir: string;
const file = (name: string) => path.join(dir, name);

beforeAll(async () => {
  delete process.env["RPC_URL"];
  fx = await buildCreateReceiptFixture();
  dir = mkdtempSync(path.join(tmpdir(), "forestrie-create-receipt-"));
  writeFileSync(file("massif.log"), fx.massifBytes);
  writeFileSync(file("massif-tampered.log"), tamperMassifSibling(fx.massifBytes));
  writeFileSync(file("checkpoint3.sth"), fx.checkpointSize3);
  writeFileSync(file("checkpoint4.sth"), fx.checkpointSize4);
  writeFileSync(file("checkpoint-cert.sth"), fx.checkpointWithCert);
  // Checkpoint whose sealed size outruns the local massif blob (coverage
  // passes; the leaf-range check must fire).
  writeFileSync(
    file("checkpoint8.sth"),
    buildV2CheckpointBytes({ mmrSize: 8n, peakReceipts: [] }),
  );
  writeFileSync(file("checkpoint-garbage.sth"), new Uint8Array([1, 2, 3]));
  writeFileSync(file("genesis.cbor"), fx.genesisCbor);
  writeFileSync(file("grant1.cbor"), encodeGrantPayload(fx.leaf1.grant));
});

type LooseArgs = Parameters<typeof parseCreateReceiptOptions>[0];

/** Throws if checkpoint-mode derivation ever touches the network. */
const forbiddenFetch = (() => {
  throw new Error("network forbidden during offline create-receipt");
}) as unknown as typeof fetch;

async function createReceiptInProcess(
  args: LooseArgs,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const out = createCaptureOut(0);
  const options = parseCreateReceiptOptions(args);
  const realFetch = globalThis.fetch;
  const savedExitCode = process.exitCode;
  process.exitCode = 0;
  globalThis.fetch = forbiddenFetch;
  try {
    await runCreateReceipt(out, options);
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

const baseArgs = (checkpoint = "checkpoint3.sth"): Record<string, string> => ({
  massif: file("massif.log"),
  checkpoint: file(checkpoint),
});

describe("create-receipt (checkpoint mode)", () => {
  test("derives a receipt that passes verifyGrantReceiptOffline (AC: verify-equivalence)", async () => {
    const outPath = file("receipt-mmr.cbor");
    const result = await createReceiptInProcess({
      ...baseArgs(),
      "mmr-index": "1",
      out: outPath,
    });
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toContain("mmrIndex 1");

    const receiptCbor = new Uint8Array(readFileSync(outPath));
    const verified = await verifyGrantReceiptOffline({
      genesisCbor: fx.genesisCbor,
      receiptCbor,
      grant: fx.leaf1.grant,
      idtimestampBe8: fx.leaf1.idtimestampBe8,
    });
    expect(verified).toEqual({ ok: true, stage: "binding" });
  });

  test("--entry-id addresses the leaf without any index lookup", async () => {
    const outPath = file("receipt-entry-id.cbor");
    const result = await createReceiptInProcess({
      ...baseArgs(),
      "entry-id": fx.leaf1.entryIdHex,
      json: true,
      out: outPath,
    });
    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.stdout) as CreateReceiptReport;
    // The permanent entry id IS idtimestamp_be8 || mmrIndex_be8 — the
    // mmrIndex decodes straight out of it (no urkle/index region).
    expect(report.leaf).toEqual({
      mmrIndex: "1",
      source: "entry-id",
      entryId: fx.leaf1.entryIdHex,
      // idtimestamp 0x0202020202020202 as decimal.
      idtimestamp: "144680345676153346",
    });

    const receiptCbor = new Uint8Array(readFileSync(outPath));
    const verified = await verifyGrantReceiptOffline({
      genesisCbor: fx.genesisCbor,
      receiptCbor,
      grant: fx.leaf1.grant,
      idtimestampBe8: fx.leaf1.idtimestampBe8,
    });
    expect(verified).toEqual({ ok: true, stage: "binding" });
  });

  test("--json report narrates massif, proof, peak and cert copy", async () => {
    const result = await createReceiptInProcess({
      ...baseArgs(),
      "mmr-index": "1",
      json: true,
    });
    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.stdout) as CreateReceiptReport;
    expect(report.command).toBe("create-receipt");
    expect(report.anchor).toBe("checkpoint");
    expect(report.massif).toEqual({
      massifIndex: "0",
      massifHeight: 3,
      firstIndex: "0",
      lastIndex: "3",
    });
    expect(report.checkpoint).toEqual({ sealedSize: "3", peakCount: 1 });
    expect(report.proof).toEqual({
      length: 1,
      peakIndex: 0,
      peakMMRIndex: "2",
    });
    expect(report.certCopied).toBe(false);
    // No --out: the receipt rides base64 inside the report (JSON owns
    // stdout) and still verifies.
    expect(report.out).toBeUndefined();
    const receiptCbor = new Uint8Array(
      Buffer.from(report.receiptB64!, "base64"),
    );
    expect(receiptCbor.length).toBe(report.receiptBytes);
    const verified = await verifyGrantReceiptOffline({
      genesisCbor: fx.genesisCbor,
      receiptCbor,
      grant: fx.leaf1.grant,
      idtimestampBe8: fx.leaf1.idtimestampBe8,
    });
    expect(verified).toEqual({ ok: true, stage: "binding" });
  });

  test("copies the delegation cert (label 1000) when the checkpoint carries one", async () => {
    const result = await createReceiptInProcess({
      massif: file("massif.log"),
      checkpoint: file("checkpoint-cert.sth"),
      "mmr-index": "1",
      json: true,
    });
    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.stdout) as CreateReceiptReport;
    expect(report.certCopied).toBe(true);
    const receiptCbor = new Uint8Array(
      Buffer.from(report.receiptB64!, "base64"),
    );
    const verified = await verifyGrantReceiptOffline({
      genesisCbor: fx.genesisCbor,
      receiptCbor,
      grant: fx.leaf1.grant,
      idtimestampBe8: fx.leaf1.idtimestampBe8,
    });
    expect(verified).toEqual({ ok: true, stage: "binding" });
  });

  test("selects the right pre-signed peak in a multi-peak accumulator", async () => {
    // leaf2 (mmrIndex 3) is its own peak at size 4: empty path, slot 1.
    const result = await createReceiptInProcess({
      massif: file("massif.log"),
      checkpoint: file("checkpoint4.sth"),
      "mmr-index": "3",
      json: true,
    });
    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.stdout) as CreateReceiptReport;
    expect(report.checkpoint).toEqual({ sealedSize: "4", peakCount: 2 });
    expect(report.proof).toEqual({
      length: 0,
      peakIndex: 1,
      peakMMRIndex: "3",
    });
    const receiptCbor = new Uint8Array(
      Buffer.from(report.receiptB64!, "base64"),
    );
    const verified = await verifyGrantReceiptOffline({
      genesisCbor: fx.genesisCbor,
      receiptCbor,
      grant: fx.leaf2.grant,
      idtimestampBe8: fx.leaf2.idtimestampBe8,
    });
    expect(verified).toEqual({ ok: true, stage: "binding" });
  });

  test("tampered massif content still derives, but fails verify at stage=signature", async () => {
    // Derivation is honest arithmetic over whatever bytes it is given; the
    // checkpoint signature is what catches the tamper, downstream.
    const result = await createReceiptInProcess({
      massif: file("massif-tampered.log"),
      checkpoint: file("checkpoint3.sth"),
      "mmr-index": "1",
      json: true,
    });
    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.stdout) as CreateReceiptReport;
    const receiptCbor = new Uint8Array(
      Buffer.from(report.receiptB64!, "base64"),
    );
    const verified = await verifyGrantReceiptOffline({
      genesisCbor: fx.genesisCbor,
      receiptCbor,
      grant: fx.leaf1.grant,
      idtimestampBe8: fx.leaf1.idtimestampBe8,
    });
    expect(verified.ok).toBe(false);
    expect(verified.stage).toBe("signature");
  });
});

describe("create-receipt error taxonomy", () => {
  test("checkpoint does not cover the leaf: stage=derive, structured reason", async () => {
    const result = await createReceiptInProcess({
      ...baseArgs(),
      "mmr-index": "3",
      json: true,
    });
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout) as CreateReceiptErrorReport;
    expect(report.error).toBe("create_receipt_derive_failed");
    expect(report.stage).toBe("derive");
    expect(report.reason).toBe("checkpoint_does_not_cover_leaf");
  });

  test("leaf not in this massif blob: stage=derive, structured reason", async () => {
    const result = await createReceiptInProcess({
      massif: file("massif.log"),
      checkpoint: file("checkpoint8.sth"),
      "mmr-index": "5",
      json: true,
    });
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout) as CreateReceiptErrorReport;
    expect(report.error).toBe("create_receipt_derive_failed");
    expect(report.stage).toBe("derive");
    expect(report.reason).toBe("leaf_not_in_massif");
  });

  test("garbage checkpoint: stage=parse", async () => {
    const result = await createReceiptInProcess({
      massif: file("massif.log"),
      checkpoint: file("checkpoint-garbage.sth"),
      "mmr-index": "1",
      json: true,
    });
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout) as CreateReceiptErrorReport;
    expect(report.error).toBe("create_receipt_parse_failed");
    expect(report.stage).toBe("parse");
  });

  test("unreadable massif: stage=input", async () => {
    const result = await createReceiptInProcess({
      massif: file("no-such-massif.log"),
      checkpoint: file("checkpoint3.sth"),
      "mmr-index": "1",
      json: true,
    });
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout) as CreateReceiptErrorReport;
    expect(report.error).toBe("create_receipt_input_failed");
    expect(report.stage).toBe("input");
  });

  test("malformed --entry-id: stage=input", async () => {
    const result = await createReceiptInProcess({
      ...baseArgs(),
      "entry-id": "not-hex",
      json: true,
    });
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout) as CreateReceiptErrorReport;
    expect(report.error).toBe("create_receipt_input_failed");
    expect(report.message).toContain("--entry-id");
  });

  test("human mode: one clean stderr line, nothing on stdout", async () => {
    const result = await createReceiptInProcess({
      ...baseArgs(),
      "mmr-index": "3",
    });
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("forestrie create-receipt: derive:");
  });
});

describe("create-receipt chain mode (plan-2607-15 phase 2 stub)", () => {
  const chainArgs = {
    massif: "massif.log",
    "mmr-index": "0",
    univocity: "0x" + "ab".repeat(20),
    "log-id": "660e8400-e29b-41d4-a716-446655440001",
    "rpc-url": "http://localhost:8545",
  };

  test("--json: structured not_implemented citing phase 2", async () => {
    const result = await createReceiptInProcess({ ...chainArgs, json: true });
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(
      result.stdout,
    ) as CreateReceiptNotImplementedReport;
    expect(report.error).toBe("not_implemented");
    expect(report.command).toBe("create-receipt");
    expect(report.mode).toBe("chain");
    expect(report.issue).toBe("FOR-345");
    expect(report.message).toContain("plan-2607-15 phase 2");
  });

  test("human mode: warning on stderr", async () => {
    const result = await createReceiptInProcess({ ...chainArgs });
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("plan-2607-15 phase 2");
  });
});

describe("create-receipt | verify (CLI end-to-end)", () => {
  test("the self-derived receipt passes `forestrie verify` — same tool, both ends", () => {
    const receiptPath = file("receipt-cli.cbor");
    const created = runCli([
      "create-receipt",
      "--massif",
      file("massif.log"),
      "--checkpoint",
      file("checkpoint3.sth"),
      "--entry-id",
      fx.leaf1.entryIdHex,
      "--out",
      receiptPath,
    ]);
    expect(created.exitCode).toBe(0);
    expect(created.stderr).toContain("create-receipt: receipt");

    const verified = runCli([
      "verify",
      "--genesis",
      file("genesis.cbor"),
      "--receipt",
      receiptPath,
      "--grant",
      file("grant1.cbor"),
      "--entry-id",
      fx.leaf1.entryIdHex,
    ]);
    expect(verified.exitCode).toBe(0);
    expect(verified.stdout).toContain("PASS");
  });

  test("a receipt derived from tampered log data FAILS `forestrie verify`", () => {
    const receiptPath = file("receipt-cli-tampered.cbor");
    const created = runCli([
      "create-receipt",
      "--massif",
      file("massif-tampered.log"),
      "--checkpoint",
      file("checkpoint3.sth"),
      "--entry-id",
      fx.leaf1.entryIdHex,
      "--out",
      receiptPath,
    ]);
    expect(created.exitCode).toBe(0);

    const verified = runCli([
      "verify",
      "--genesis",
      file("genesis.cbor"),
      "--receipt",
      receiptPath,
      "--grant",
      file("grant1.cbor"),
      "--entry-id",
      fx.leaf1.entryIdHex,
    ]);
    expect(verified.exitCode).toBe(1);
    expect(verified.stdout).toContain("FAIL");
    expect(verified.stdout).toContain("stage=signature");
  });
});
