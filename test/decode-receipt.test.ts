import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";

import {
  DecodeReceiptError,
  decodeReceipt,
} from "../src/lib/decode-receipt-decode.js";
import { renderReceipt } from "../src/lib/decode-receipt-render.js";
import {
  FIXTURE,
  buildReceiptFixture,
  buildSign1WithBadProtected,
  buildSign1WithoutProof,
  cbor,
} from "./decode-receipt-fixture.js";
import { runCli } from "./support.js";

describe("decodeReceipt (golden fixture)", () => {
  const decoded = decodeReceipt(buildReceiptFixture());

  test("sees the COSE_Sign1 tag and envelope", () => {
    expect(decoded.tag).toBe(18);
    expect(decoded.byteLength).toBeGreaterThan(0);
  });

  test("protected header: alg, kid, vds named", () => {
    expect(decoded.protected.alg).toEqual({
      value: -7,
      name: "ES256 (ECDSA P-256 + SHA-256)",
    });
    expect(decoded.protected.kid).toEqual({
      hex: "6c".repeat(12),
      byteLength: 12,
    });
    expect(decoded.protected.vds?.value).toBe(3);
    // F7: 3 is the draft's UNREGISTERED codepoint (draft-bryce requests
    // TBD_1) — rendered as such, never asserted as registry fact.
    expect(decoded.protected.vds?.name).toContain("codepoint TBD");
    expect(decoded.protected.vds?.name).not.toContain("MMRIVER");
  });

  test("inclusion proof summary: index, path length, detached peak", () => {
    expect(decoded.inclusion.mmrIndex).toBe("5");
    expect(decoded.inclusion.pathLength).toBe(3);
    expect(decoded.inclusion.path[0]).toBe("11".repeat(32));
    expect(decoded.inclusion.peakHex).toBeNull();
    expect(decoded.payload).toEqual({ detached: true });
  });

  test("attached payload surfaces the peak hash", () => {
    const attached = decodeReceipt(
      buildReceiptFixture({ attachedPayload: true }),
    );
    expect(attached.payload).toEqual({
      detached: false,
      byteLength: 32,
      hex: "44".repeat(32),
    });
    expect(attached.inclusion.peakHex).toBe("44".repeat(32));
    expect(attached.inclusion.peakSource).toBe("payload");
  });

  test("delegation certificate is summarised as nested COSE_Sign1", () => {
    expect(decoded.unprotected.delegation?.nestedCoseSign1).toBe(true);
    expect(decoded.unprotected.delegation?.byteLength).toBeGreaterThan(0);
  });

  test("unknown labels are shown raw, never dropped", () => {
    const unknown = decoded.unprotected.entries.find(
      (entry) => entry.label === FIXTURE.unknownLabel,
    );
    expect(unknown).toBeDefined();
    expect(unknown?.name).toBeNull();
    expect(unknown?.value).toBe(FIXTURE.unknownValue);
  });

  test("tag tolerance: untagged receipt decodes identically", () => {
    const untagged = decodeReceipt(buildReceiptFixture({ tagged: false }));
    expect(untagged.tag).toBeNull();
    expect(untagged.protected).toEqual(decoded.protected);
    expect(untagged.inclusion).toEqual(decoded.inclusion);
  });
});

describe("renderReceipt (human tree)", () => {
  const text = renderReceipt(decodeReceipt(buildReceiptFixture()));

  test("annotates the COSE structure for the audience", () => {
    expect(text).toContain("COSE_Sign1 — tagged 18");
    expect(text).toContain("1 (alg): -7 — ES256");
    expect(text).toContain("4 (kid): 6c6c6c6c6c6c6c6c6c6c6c6c (12 bytes)");
    expect(text).toContain(
      "395 (verifiable data structure): 3 — MMR profile (draft-bryce, codepoint TBD)",
    );
    expect(text).toContain("396 (verifiable proofs)");
    expect(text).toContain("-1 (inclusion proofs)");
    expect(text).toContain("1 (mmr index): 5");
    expect(text).toContain("2 (path): 3 × 32-byte hashes");
    expect(text).toContain("1000 (delegation certificate)");
    expect(text).toContain("payload: detached (nil)");
    expect(text).toContain("signature: 64 bytes");
  });

  test("MMR inclusion summary block", () => {
    expect(text).toContain("MMR inclusion");
    expect(text).toContain("mmr index:    5");
    expect(text).toContain("path length:  3");
    expect(text).toContain("derived at verify time (detached payload)");
  });

  test("unknown labels appear in the tree", () => {
    expect(text).toContain('-70000 (unknown label): "mystery"');
  });
});

describe("decodeReceipt (malformed input names the parse stage)", () => {
  function stageOf(bytes: Uint8Array): string {
    try {
      decodeReceipt(bytes);
    } catch (error) {
      expect(error).toBeInstanceOf(DecodeReceiptError);
      return (error as DecodeReceiptError).stage;
    }
    throw new Error("expected decodeReceipt to throw");
  }

  test("empty input → input", () => {
    expect(stageOf(new Uint8Array(0))).toBe("input");
  });

  test("truncated CBOR → envelope", () => {
    expect(stageOf(new Uint8Array([0x58, 0x20, 0x01]))).toBe("envelope");
  });

  test("valid CBOR, not a Sign1 array → cose-sign1", () => {
    expect(stageOf(cbor.uint(42))).toBe("cose-sign1");
  });

  test("payload that is neither nil nor 32 bytes → payload", () => {
    const bad = cbor.tag(
      18,
      cbor.array(
        cbor.bstr(cbor.map([cbor.uint(1), cbor.nint(7)])),
        cbor.map(),
        cbor.bstr(new Uint8Array(4)),
        cbor.bstr(new Uint8Array(64)),
      ),
    );
    expect(stageOf(bad)).toBe("payload");
  });

  test("missing header 396 inclusion proof → inclusion-proof", () => {
    expect(stageOf(buildSign1WithoutProof())).toBe("inclusion-proof");
  });

  test("garbage protected header bstr → protected-header", () => {
    expect(stageOf(buildSign1WithBadProtected())).toBe("protected-header");
  });
});

describe("forestrie decode-receipt (CLI)", () => {
  let dir: string;
  let goldenPath: string;

  beforeAll(() => {
    dir = mkdtempSync(path.join(tmpdir(), "forestrie-decode-receipt-"));
    goldenPath = path.join(dir, "receipt.cbor");
    writeFileSync(goldenPath, buildReceiptFixture());
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  test("human mode prints the annotated tree on stdout", () => {
    const result = runCli(["decode-receipt", goldenPath]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("COSE_Sign1 — tagged 18");
    expect(result.stdout).toContain("MMR inclusion");
  });

  test("--json emits the full structured decode", () => {
    const result = runCli(["decode-receipt", "--json", goldenPath]);
    expect(result.exitCode).toBe(0);
    const decoded = JSON.parse(result.stdout) as {
      tag: number;
      protected: { alg: { value: number } };
      inclusion: { mmrIndex: string; pathLength: number; path: string[] };
      unprotected: { entries: Array<{ label: number | string }> };
      signature: { byteLength: number };
    };
    expect(decoded.tag).toBe(18);
    expect(decoded.protected.alg.value).toBe(-7);
    expect(decoded.inclusion.mmrIndex).toBe("5");
    expect(decoded.inclusion.pathLength).toBe(3);
    expect(decoded.inclusion.path).toHaveLength(3);
    expect(decoded.signature.byteLength).toBe(64);
    expect(
      decoded.unprotected.entries.some(
        (entry) => entry.label === FIXTURE.unknownLabel,
      ),
    ).toBe(true);
  });

  test("--json output is stable (snapshot)", () => {
    const result = runCli(["decode-receipt", "--json", goldenPath]);
    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchSnapshot();
  });

  test("reads the receipt from stdin when the positional is omitted", () => {
    const proc = Bun.spawnSync({
      cmd: ["bun", path.join(import.meta.dir, "..", "src/cli.ts"), "decode-receipt"],
      stdin: buildReceiptFixture(),
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(proc.exitCode).toBe(0);
    expect(proc.stdout.toString()).toContain("COSE_Sign1 — tagged 18");
  });

  test("malformed file: structured --json error names the stage", () => {
    const badPath = path.join(dir, "bad.cbor");
    writeFileSync(badPath, cbor.uint(42));
    const result = runCli(["decode-receipt", "--json", badPath]);
    expect(result.exitCode).toBe(1);
    expect(JSON.parse(result.stdout)).toEqual({
      error: "decode_failed",
      command: "decode-receipt",
      stage: "cose-sign1",
      message: "Receipt is not a COSE Sign1 array",
    });
  });

  test("missing file: input stage on stderr, non-zero exit", () => {
    const result = runCli(["decode-receipt", path.join(dir, "nope.cbor")]);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("forestrie decode-receipt: input:");
  });
});
