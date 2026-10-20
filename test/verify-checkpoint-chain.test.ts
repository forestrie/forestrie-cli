import { beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { loadCheckpointChainFiles } from "../src/lib/verify-checkpoint-chain.js";

let dir: string;
const file = (name: string) => path.join(dir, name);

beforeAll(() => {
  dir = mkdtempSync(path.join(tmpdir(), "forestrie-chain-"));
});

describe("loadCheckpointChainFiles", () => {
  test("directory: .sth files sort into chain order; other files ignored", () => {
    const d = mkdtempSync(path.join(tmpdir(), "forestrie-sth-"));
    writeFileSync(path.join(d, "0000000000000001.sth"), new Uint8Array([2]));
    writeFileSync(path.join(d, "0000000000000000.sth"), new Uint8Array([1]));
    writeFileSync(path.join(d, "notes.txt"), new Uint8Array([9]));
    const { files, checkpoints } = loadCheckpointChainFiles(d);
    expect(files.map((f) => path.basename(f))).toEqual([
      "0000000000000000.sth",
      "0000000000000001.sth",
    ]);
    expect(Array.from(checkpoints[0]!)).toEqual([1]);
    expect(Array.from(checkpoints[1]!)).toEqual([2]);
  });

  test("comma list preserves the caller's order", () => {
    writeFileSync(file("b.sth"), new Uint8Array([2]));
    writeFileSync(file("a.sth"), new Uint8Array([1]));
    const { checkpoints } = loadCheckpointChainFiles(
      `${file("b.sth")}, ${file("a.sth")}`,
    );
    expect(Array.from(checkpoints[0]!)).toEqual([2]);
    expect(Array.from(checkpoints[1]!)).toEqual([1]);
  });

  test("directory with no .sth objects is an error", () => {
    const d = mkdtempSync(path.join(tmpdir(), "forestrie-empty-"));
    expect(() => loadCheckpointChainFiles(d)).toThrow(/no \.sth/);
  });
});
