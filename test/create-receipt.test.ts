import { beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { decode as decodeCbor } from "cbor-x";
import { createCaptureOut } from "@forestrie/cli-kit/reporting";
import { encodeGrantPayload } from "@forestrie/encoding";
import { verifyGrantReceiptOffline } from "@forestrie/receipt-verify";
import type {
  CreateReceiptChainErrorReport,
  CreateReceiptChainReport,
  CreateReceiptErrorReport,
  CreateReceiptReport,
} from "../src/main/create-receipt.js";
import { runCreateReceipt } from "../src/main/create-receipt.js";
import { deriveCheckpointReceipt } from "../src/lib/create-receipt-derive.js";
import { parseCreateReceiptOptions } from "../src/options/create-receipt.js";
import {
  buildCreateReceiptFixture,
  buildMultiPeakFixture,
  buildV2CheckpointBytes,
  buildV2MassifBytes,
  tamperMassifSibling,
  type CreateReceiptFixture,
  type MultiPeakFixture,
} from "./create-receipt-fixture.js";
import { encodeLogStateResult } from "./verify-fixture.js";
import { toContractLogId } from "../src/lib/verify-anchored.js";
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
  // A massif blob for a DIFFERENT massif than leaf 1: massifIndex 1 holds mmr
  // indexes 7..10, so a request for leaf mmrIndex 1 falls below firstIndex —
  // the chain-mode wrong_massif pre-check (plan-2607-18 W3, V2/V3).
  writeFileSync(
    file("massif-other.log"),
    buildV2MassifBytes({
      massifHeight: 3,
      massifIndex: 1,
      logHashes: Array.from({ length: 4 }, () => new Uint8Array(32)),
    }),
  );
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
  fetchImpl: typeof fetch = forbiddenFetch,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const out = createCaptureOut(0);
  const options = parseCreateReceiptOptions(args);
  const realFetch = globalThis.fetch;
  const savedExitCode = process.exitCode;
  process.exitCode = 0;
  globalThis.fetch = fetchImpl;
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

describe("create-receipt peak narration pins to the attached receipt (R1, plan-2607-16 W1)", () => {
  let mp: MultiPeakFixture;

  beforeAll(async () => {
    mp = await buildMultiPeakFixture();
  });

  /** Detached signature (COSE Sign1 element 3) of a receipt or peak receipt. */
  const sigOf = (cbor: Uint8Array): Uint8Array => {
    const sign1 = decodeCbor(cbor) as unknown[];
    return sign1[3] as Uint8Array;
  };

  /**
   * The invariant: the narrated peak identifies the SAME peak whose
   * pre-signed receipt buildReceiptOffline actually attached. We prove it by
   * matching the derived receipt's detached signature against the -65931
   * entry at the reported peakIndex, and asserting the reported peakMMRIndex
   * is that entry's peak. Peaks are ordered ascending by mmr index (the
   * sealer's descending-height order), so peakIndex must NOT be inverted.
   */
  const assertPinned = async (mmrIndex: bigint, expectedPeakMMRIndex: bigint) => {
    const derived = await deriveCheckpointReceipt({
      massifBytes: mp.massifBytes,
      checkpointBytes: mp.checkpoint,
      mmrIndex,
    });
    expect(derived.details.peakCount).toBe(3);
    // The narrated peak is the peak the builder actually signed over.
    expect(derived.details.peakMMRIndex).toBe(expectedPeakMMRIndex);
    expect(mp.peakMMRIndexes[derived.details.peakIndex]).toBe(
      expectedPeakMMRIndex,
    );
    // Cross-check against the crypto: the derived receipt carries the exact
    // signature of the -65931 entry at the reported peakIndex.
    const peakReceipts = (decodeCbor(mp.checkpoint) as unknown[])[1] as Map<
      number,
      unknown
    >;
    const presigned = peakReceipts.get(-65931) as Uint8Array[];
    const attached = presigned[derived.details.peakIndex]!;
    expect(Buffer.from(sigOf(derived.receiptCbor))).toEqual(
      Buffer.from(sigOf(attached)),
    );
  };

  test("size-11 leaf 0 (under the leftmost, non-top peak) narrates mmr index 6, not 10", async () => {
    // Regression for the inversion R1 warned about: pre-fix reasoning would
    // report the top peak (10); the peak actually signed is n6 (mmr 6).
    await assertPinned(0n, 6n);
  });

  test("size-11 leaf 7 (mmr) under the middle peak narrates mmr index 9", async () => {
    // Asymmetric second case: a leaf under the interior peak n9.
    await assertPinned(7n, 9n);
  });

  test("size-11 leaf 10 (mmr) is its own top peak — narrates mmr index 10", async () => {
    await assertPinned(10n, 10n);
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

describe("create-receipt chain mode (report-only; plan-2607-15 §3, FOR-345)", () => {
  const UNIVOCITY = "0x" + "ab".repeat(20);
  const LOG_ID = "660e8400-e29b-41d4-a716-446655440001";

  const chainArgs = (overrides: Record<string, unknown> = {}) => ({
    massif: file("massif.log"),
    "mmr-index": "1",
    univocity: UNIVOCITY,
    "log-id": LOG_ID,
    "rpc-url": "http://rpc.mock",
    ...overrides,
  });

  /** Mock `logState` returning `accumulator` / `size`; records the calldata. */
  function rpcFetch(
    accumulator: Uint8Array[],
    size: bigint,
    calls: unknown[] = [],
  ): typeof fetch {
    return (async (_url: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as {
        method: string;
        params: unknown[];
      };
      calls.push(body);
      expect(body.method).toBe("eth_call");
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: encodeLogStateResult(accumulator, size),
        }),
        { headers: { "Content-Type": "application/json" } },
      );
    }) as unknown as typeof fetch;
  }

  test("verified: computed peak matches the on-chain accumulator (exit 0)", async () => {
    // Size-3 accumulator = [n2]; leaf 1 proves into n2 via sibling n0.
    const calls: { params: [{ data: string }, string] }[] = [];
    const result = await createReceiptInProcess(
      chainArgs({ json: true }),
      rpcFetch([fx.n2], 3n, calls),
    );
    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.stdout) as CreateReceiptChainReport;
    expect(report.command).toBe("create-receipt");
    expect(report.anchor).toBe("chain");
    expect(report.ok).toBe(true);
    expect(report.outcome).toBe("verified");
    expect(report.onchain).toEqual({ size: "3", peakCount: 1 });
    expect(report.peakCheck).toMatchObject({
      proofLength: 1,
      peakIndex: 0,
      peakMMRIndex: "2",
      matched: true,
    });
    // computed peak equals the on-chain peak at the selected slot.
    expect(report.peakCheck!.computedPeakHex).toBe(
      report.peakCheck!.onchainPeakHex,
    );
    // logState(bytes32) selector + zero-padded contract log id.
    expect(calls[0]!.params[0].data).toBe(
      "0xeecac1b7" + toContractLogId(LOG_ID).slice(2),
    );
  });

  test("verified: works at a LARGER on-chain size (no exact-size constraint)", async () => {
    // Size-4 accumulator = [n2, n3]; leaf 1 still lives under n2 (slot 0).
    const result = await createReceiptInProcess(
      chainArgs({ json: true }),
      rpcFetch([fx.n2, fx.n3], 4n),
    );
    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.stdout) as CreateReceiptChainReport;
    expect(report.outcome).toBe("verified");
    expect(report.onchain).toEqual({ size: "4", peakCount: 2 });
    expect(report.peakCheck).toMatchObject({ peakIndex: 0, matched: true });
  });

  test("not_yet_anchored: leaf postdates the anchor (mmrIndex >= size), exit 2", async () => {
    // Leaf at mmrIndex 3 with an on-chain size of 3 → not yet anchored.
    const result = await createReceiptInProcess(
      chainArgs({ "mmr-index": "3", json: true }),
      rpcFetch([fx.n2], 3n),
    );
    expect(result.exitCode).toBe(2);
    const report = JSON.parse(result.stdout) as CreateReceiptChainReport;
    expect(report.ok).toBe(false);
    expect(report.outcome).toBe("not_yet_anchored");
    expect(report.onchain.size).toBe("3");
    // No peak was computed for an un-anchored leaf.
    expect(report.peakCheck).toBeUndefined();
  });

  test("coverage: local blob short of the on-chain size, exit 3", async () => {
    // On-chain size 8 needs nodes up to mmr index 7; this blob holds 0..3.
    const result = await createReceiptInProcess(
      chainArgs({ json: true }),
      rpcFetch([new Uint8Array(32).fill(0x11)], 8n),
    );
    expect(result.exitCode).toBe(3);
    const report = JSON.parse(result.stdout) as CreateReceiptChainReport;
    expect(report.ok).toBe(false);
    expect(report.outcome).toBe("coverage");
    expect(report.onchain.size).toBe("8");
    expect(report.peakCheck).toBeUndefined();
  });

  test("wrong_massif: blob is for a different massif than the leaf, exit 5", async () => {
    // plan-2607-18 W3 (V2/V3): massif-other.log is massifIndex 1 (holds mmr
    // indexes 7..10); leaf 1 falls below its firstIndex, so the leaf's path
    // cannot be built from this blob. Previously misreported as `coverage`
    // ("fetch the covering massif") — a misleading remedy; the fix is a
    // DIFFERENT massif, not a later one. On-chain size 8 keeps the leaf
    // anchored (mmrIndex 1 < 8) so the wrong_massif pre-check (not
    // not_yet_anchored) is what fires.
    const result = await createReceiptInProcess(
      chainArgs({ massif: file("massif-other.log"), json: true }),
      rpcFetch([fx.n2], 8n),
    );
    expect(result.exitCode).toBe(5);
    const report = JSON.parse(result.stdout) as CreateReceiptChainReport;
    expect(report.ok).toBe(false);
    expect(report.outcome).toBe("wrong_massif");
    // The blob's own window is reported; the leaf sits outside it.
    expect(report.massif).toEqual({
      massifIndex: "1",
      massifHeight: 3,
      firstIndex: "7",
      lastIndex: "10",
    });
    expect(report.leaf.mmrIndex).toBe("1");
    // No peak was computed — the pre-check short-circuits before it.
    expect(report.peakCheck).toBeUndefined();
  });

  test("wrong_massif (human mode): FAIL names the mmrIndex to supply", async () => {
    const result = await createReceiptInProcess(
      chainArgs({ massif: file("massif-other.log") }),
      rpcFetch([fx.n2], 8n),
    );
    expect(result.exitCode).toBe(5);
    expect(result.stdout).toContain("FAIL: wrong_massif");
    expect(result.stdout).toContain("mmrIndex 1");
  });

  test("accumulator_short: on-chain accumulator has fewer peaks than the slot, exit 6", async () => {
    // plan-2607-18 W3 (V4): leaf 3 at size 4 is its own peak — slot 1. Supply
    // an accumulator with a single element, so slot 1 is absent: a shape
    // disagreement (chain behind/truncated), distinct from a byte-level
    // peak_mismatch. The blob DOES cover size 4 (lastIndex 3), so this is not
    // coverage, and the leaf IS in-massif, so not wrong_massif.
    const result = await createReceiptInProcess(
      chainArgs({ "mmr-index": "3", json: true }),
      rpcFetch([fx.n2], 4n),
    );
    expect(result.exitCode).toBe(6);
    const report = JSON.parse(result.stdout) as CreateReceiptChainReport;
    expect(report.ok).toBe(false);
    expect(report.outcome).toBe("accumulator_short");
    expect(report.onchain).toEqual({ size: "4", peakCount: 1 });
    // The peak WAS computed (blob is fine); there is just no on-chain slot.
    expect(report.peakCheck).toMatchObject({
      peakIndex: 1,
      matched: false,
      onchainPeakHex: "",
    });
    expect(report.peakCheck!.computedPeakHex).not.toBe("");
  });

  // Cross-massif proof note (plan-2607-18 W3, V1): a leaf's OWN inclusion path
  // is always built from the leaf's own massif blob — the leaf node must be
  // present locally (which is exactly what wrong_massif guards). Proof
  // siblings from earlier massifs resolve through the in-blob ancestor peak
  // stack, and the "verified at a LARGER on-chain size" test above already
  // exercises a peak selected against a multi-peak accumulator spanning beyond
  // the leaf. A genuine 2-massif on-disk fixture adds no distinct leaf-path
  // code path (the leaf is still in one blob) and is heavy to build, so it is
  // documented rather than materialised here.

  test("peak_mismatch: tampered node data, exit 4", async () => {
    // Correct size/shape, but the anchored peak is NOT n2 → tamper-shaped.
    const wrongPeak = new Uint8Array(32).fill(0x99);
    const result = await createReceiptInProcess(
      chainArgs({ json: true }),
      rpcFetch([wrongPeak], 3n),
    );
    expect(result.exitCode).toBe(4);
    const report = JSON.parse(result.stdout) as CreateReceiptChainReport;
    expect(report.ok).toBe(false);
    expect(report.outcome).toBe("peak_mismatch");
    expect(report.peakCheck!.matched).toBe(false);
    expect(report.peakCheck!.computedPeakHex).not.toBe(
      report.peakCheck!.onchainPeakHex,
    );
  });

  test("peak_mismatch: a tampered massif blob computes the wrong peak, exit 4", async () => {
    // Honest on-chain accumulator [n2]; the LOCAL blob's sibling is flipped,
    // so the computed peak diverges from the anchored one.
    const result = await createReceiptInProcess(
      chainArgs({ massif: file("massif-tampered.log"), json: true }),
      rpcFetch([fx.n2], 3n),
    );
    expect(result.exitCode).toBe(4);
    const report = JSON.parse(result.stdout) as CreateReceiptChainReport;
    expect(report.outcome).toBe("peak_mismatch");
    expect(report.peakCheck!.matched).toBe(false);
  });

  test("human mode: narrates on-chain size, computed peak and PASS", async () => {
    const result = await createReceiptInProcess(
      chainArgs(),
      rpcFetch([fx.n2], 3n),
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("PASS");
    expect(result.stdout).toContain("no receipt needed");
    expect(result.stderr).toContain("size 3");
    expect(result.stderr).toContain("on-chain");
    // No .cbor receipt is emitted in report-only mode.
  });

  test("human mode: non-verified outcome prints FAIL with the reason", async () => {
    const result = await createReceiptInProcess(
      chainArgs({ "mmr-index": "3" }),
      rpcFetch([fx.n2], 3n),
    );
    expect(result.exitCode).toBe(2);
    expect(result.stdout).toContain("FAIL: not_yet_anchored");
  });

  test("RPC transport failure: structured chain error, exit 1", async () => {
    const refusedFetch = (async () => {
      throw new TypeError("fetch failed: connect ECONNREFUSED 127.0.0.1:8545");
    }) as unknown as typeof fetch;
    const result = await createReceiptInProcess(
      chainArgs({ json: true }),
      refusedFetch,
    );
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(
      result.stdout,
    ) as CreateReceiptChainErrorReport;
    expect(report.error).toBe("create_receipt_chain_failed");
    expect(report.stage).toBe("chain");
    expect(report.message).toContain("ECONNREFUSED");
  });

  test("garbage massif: parse-stage chain error, exit 1", async () => {
    writeFileSync(file("chain-garbage.log"), new Uint8Array([1, 2, 3]));
    const result = await createReceiptInProcess(
      chainArgs({ massif: file("chain-garbage.log"), json: true }),
      // fetch is never reached — the massif fails to open first.
      forbiddenFetch,
    );
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(
      result.stdout,
    ) as CreateReceiptChainErrorReport;
    expect(report.error).toBe("create_receipt_chain_failed");
    expect(report.stage).toBe("parse");
    expect(report.reason).toBe("massif_parse_failed");
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
