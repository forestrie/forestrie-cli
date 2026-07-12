import { beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { decodeCborDeterministic } from "@forestrie/encoding";
import { verifyGrantReceiptOffline } from "@forestrie/receipt-verify";
import type { CompleteGrantReport } from "../src/main/complete-grant.js";
import {
  buildCompleteGrantFixture,
  type CompleteGrantFixture,
} from "./complete-grant-fixture.js";
import { buildV2MassifBytes } from "./create-receipt-fixture.js";
import { runCli } from "./support.js";

const HEADER_RECEIPT = 396;
const HEADER_IDTIMESTAMP = -65537;

let fx: CompleteGrantFixture;
let dir: string;
const file = (name: string) => path.join(dir, name);

/** Pull the merged receipt (396) + idtimestamp (−65537) out of a completed grant. */
function unpackCompletedGrant(b64: string): {
  receiptCbor: Uint8Array;
  idtimestampBe8: Uint8Array;
} {
  const arr = decodeCborDeterministic(
    new Uint8Array(Buffer.from(b64, "base64")),
  ) as unknown[];
  const unprot = arr[1] as Map<number, unknown>;
  const receiptCbor = unprot.get(HEADER_RECEIPT) as Uint8Array;
  const idtimestampBe8 = unprot.get(HEADER_IDTIMESTAMP) as Uint8Array;
  return { receiptCbor, idtimestampBe8 };
}

beforeAll(async () => {
  fx = await buildCompleteGrantFixture();
  dir = mkdtempSync(path.join(tmpdir(), "forestrie-complete-grant-"));
  writeFileSync(file("grant.b64"), fx.grantB64);
  writeFileSync(file("massif.log"), fx.massifBytes);
  writeFileSync(file("checkpoint.sth"), fx.checkpointBytes);
  writeFileSync(file("genesis.cbor"), fx.genesisCbor);
  // A full-length massif whose index region is empty (grant not present).
  writeFileSync(
    file("massif-empty.log"),
    buildV2MassifBytes({
      massifHeight: 3,
      massifIndex: 0,
      logHashes: Array.from({ length: 4 }, () => new Uint8Array(32)),
    }),
  );
});

describe("forestrie complete-grant (FOR-344)", () => {
  test("completes offline: leaf + idtimestamp recovered from the massif", () => {
    const result = runCli([
      "complete-grant",
      "--grant",
      file("grant.b64"),
      "--checkpoint",
      file("checkpoint.sth"),
      "--massif",
      file("massif.log"),
      "--json",
    ]);
    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.stdout) as CompleteGrantReport;
    expect(report.command).toBe("complete-grant");
    expect(report.status).toBe("completed");
    expect(report.mmrIndex).toBe("0");
    expect(report.idtimestampSource).toBe("massif");
    expect(report.entryId).toBe(fx.entryIdHex);
    expect(report.idtimestamp).toBe(Buffer.from(fx.idtimestampBe8).toString("hex"));
    expect(report.proof.length).toBe(1);
    expect(report.certCopied).toBe(false);
    expect(report.receiptBytes).toBeGreaterThan(0);
    expect(typeof report.grantB64).toBe("string");
  });

  test("the offline-completed grant verifies (receipt + idtimestamp bind the leaf)", async () => {
    const result = runCli([
      "complete-grant",
      "--grant",
      file("grant.b64"),
      "--checkpoint",
      file("checkpoint.sth"),
      "--massif",
      file("massif.log"),
      "--json",
    ]);
    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.stdout) as CompleteGrantReport;
    const { receiptCbor, idtimestampBe8 } = unpackCompletedGrant(report.grantB64!);
    // The idtimestamp the CLI attached is exactly the sequenced one.
    expect([...idtimestampBe8]).toEqual([...fx.idtimestampBe8]);

    const verdict = await verifyGrantReceiptOffline({
      genesisCbor: fx.genesisCbor,
      receiptCbor,
      grant: fx.grant,
      idtimestampBe8,
    });
    expect(verdict.ok).toBe(true);
    expect(verdict.stage).toBe("binding");
  });

  test("--out-b64 writes the completed grant; the summary narrates on stderr", () => {
    const out = file("grant.completed.b64");
    const result = runCli([
      "complete-grant",
      "--grant",
      file("grant.b64"),
      "--checkpoint",
      file("checkpoint.sth"),
      "--massif",
      file("massif.log"),
      "--out-b64",
      out,
    ]);
    expect(result.exitCode).toBe(0);
    const written = readFileSync(out, "utf8").trim();
    expect(written.length).toBeGreaterThan(0);
    // Same entry id lands in the human summary.
    expect(result.stdout).toContain(fx.entryIdHex);
    const { idtimestampBe8 } = unpackCompletedGrant(written);
    expect([...idtimestampBe8]).toEqual([...fx.idtimestampBe8]);
  });

  test("--massif is required", () => {
    const result = runCli([
      "complete-grant",
      "--grant",
      file("grant.b64"),
      "--checkpoint",
      file("checkpoint.sth"),
      "--json",
    ]);
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout) as {
      error: string;
      stage: string;
    };
    expect(report.error).toBe("complete_grant_input_failed");
    expect(report.stage).toBe("input");
  });

  test("errors when the grant's leaf is not in the massif", () => {
    const result = runCli([
      "complete-grant",
      "--grant",
      file("grant.b64"),
      "--checkpoint",
      file("checkpoint.sth"),
      "--massif",
      file("massif-empty.log"),
      "--json",
    ]);
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout) as {
      error: string;
      stage: string;
      reason: string;
    };
    expect(report.error).toBe("complete_grant_locate_failed");
    expect(report.reason).toBe("grant_leaf_not_found");
  });
});
