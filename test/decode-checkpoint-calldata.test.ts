import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { encodeFunctionData, toFunctionSelector } from "viem";
import {
  PUBLISH_CHECKPOINT_ABI,
  decodePublishCheckpointCalldata,
  fetchTransactionInput,
  type CalldataCheckpoint,
} from "../src/lib/decode-checkpoint-calldata.js";

/**
 * FOR-418 Phase 1 (plan-2607-32): the `publishCheckpoint` calldata reader.
 * A FROZEN golden vector from a REAL Base-Sepolia `publishCheckpoint` tx proves
 * interop with on-chain data; a synthetic round-trip exercises the multi-link /
 * multi-path shapes the single real tx does not.
 */

const dir = path.join(
  import.meta.dir,
  "fixtures",
  "golden",
  "checkpoint-calldata",
);
const manifest = JSON.parse(
  readFileSync(path.join(dir, "manifest.json"), "utf8"),
) as {
  txHash: string;
  calldataSha256: string;
  protectedHeaderHex: string;
  signatureHex: string;
  consistencyProofs: {
    treeSize1: string;
    treeSize2: string;
    paths: string[][];
    rightPeaks: string[];
  }[];
  delegation: {
    protectedHeaderHex: string;
    delegationKeyHex: string;
    mmrStart: string;
    mmrEnd: string;
    signatureHex: string;
  };
};
const calldataHex = readFileSync(
  path.join(dir, "publish-checkpoint.calldata.hex"),
  "utf8",
).trim();

const toHex = (b: Uint8Array) =>
  `0x${Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")}`;

describe("publishCheckpoint calldata golden vector (FOR-418 — frozen real tx)", () => {
  test("the ABI selector matches the foundry-generated 0x87ce4c61", () => {
    const fn = PUBLISH_CHECKPOINT_ABI.find(
      (f): f is typeof f & { type: "function" } => f.type === "function",
    );
    expect(fn && toFunctionSelector(fn)).toBe("0x87ce4c61");
  });

  test("the frozen calldata matches its recorded digest (no accidental edits)", () => {
    const bytes = Buffer.from(calldataHex.replace(/^0x/, ""), "hex");
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(
      manifest.calldataSha256,
    );
  });

  test("decodes the real tx to its recorded ConsistencyReceipt", () => {
    const cp = decodePublishCheckpointCalldata(calldataHex);
    expect(toHex(cp.protectedHeader)).toBe(manifest.protectedHeaderHex);
    expect(toHex(cp.signature)).toBe(manifest.signatureHex);
    expect(cp.signature.length).toBe(64); // ES256 r‖s

    expect(cp.consistencyProofs.length).toBe(manifest.consistencyProofs.length);
    cp.consistencyProofs.forEach((p, i) => {
      const m = manifest.consistencyProofs[i]!;
      expect(p.treeSize1.toString()).toBe(m.treeSize1);
      expect(p.treeSize2.toString()).toBe(m.treeSize2);
      expect(p.paths.map((path) => path.map(toHex))).toEqual(m.paths);
      expect(p.rightPeaks.map(toHex)).toEqual(m.rightPeaks);
    });

    expect(toHex(cp.delegation.delegationKey)).toBe(
      manifest.delegation.delegationKeyHex,
    );
    expect(cp.delegation.delegationKey.length).toBe(64); // P-256 x‖y
    expect(cp.delegation.mmrStart.toString()).toBe(manifest.delegation.mmrStart);
    expect(cp.delegation.mmrEnd.toString()).toBe(manifest.delegation.mmrEnd);
    expect(toHex(cp.delegation.signature)).toBe(manifest.delegation.signatureHex);
  });

  test("the real vector exercises the empty-path case (sth 7→8)", () => {
    const cp = decodePublishCheckpointCalldata(calldataHex);
    expect(cp.consistencyProofs[0]!.paths[0]).toEqual([]);
    expect(cp.consistencyProofs[0]!.rightPeaks.length).toBe(1);
  });
});

// --- synthetic round-trip: shapes the single real tx does not have ---

const b32 = (fill: number) => new Uint8Array(32).fill(fill);
const b32hex = (fill: number) => toHex(b32(fill)) as `0x${string}`;

/** Encode a ConsistencyReceipt as publishCheckpoint calldata via viem. */
function encodeSynthetic(proofs: {
  treeSize1: bigint;
  treeSize2: bigint;
  paths: `0x${string}`[][];
  rightPeaks: `0x${string}`[];
}[]): `0x${string}` {
  const zero32 = b32hex(0);
  return encodeFunctionData({
    abi: PUBLISH_CHECKPOINT_ABI,
    functionName: "publishCheckpoint",
    args: [
      {
        protectedHeader: "0xa20126" as `0x${string}`,
        signature: `0x${"ab".repeat(64)}` as `0x${string}`,
        consistencyProofs: proofs,
        delegationProof: {
          protectedHeader: "0xa20126" as `0x${string}`,
          delegationKey: `0x${"cd".repeat(64)}` as `0x${string}`,
          mmrStart: 0n,
          mmrEnd: 42n,
          signature: `0x${"ef".repeat(64)}` as `0x${string}`,
        },
      },
      { index: 3n, path: [b32hex(9)] },
      "0x0102030405060708" as `0x${string}`,
      {
        logId: zero32,
        grant: 0n,
        request: 0n,
        maxHeight: 14n,
        minGrowth: 0n,
        ownerLogId: zero32,
        grantData: "0x" as `0x${string}`,
      },
    ],
  });
}

describe("publishCheckpoint calldata — synthetic round-trip", () => {
  test("multi-link chain with multi-node paths round-trips exactly", () => {
    const data = encodeSynthetic([
      { treeSize1: 0n, treeSize2: 3n, paths: [], rightPeaks: [b32hex(1)] },
      {
        treeSize1: 3n,
        treeSize2: 10n,
        paths: [[b32hex(2), b32hex(3)]],
        rightPeaks: [b32hex(4)],
      },
    ]);
    const cp = decodePublishCheckpointCalldata(data);
    expect(cp.consistencyProofs.length).toBe(2);
    expect(cp.consistencyProofs[0]!.treeSize1).toBe(0n);
    expect(cp.consistencyProofs[0]!.paths).toEqual([]);
    expect(cp.consistencyProofs[1]!.treeSize2).toBe(10n);
    expect(cp.consistencyProofs[1]!.paths[0]!.map(toHex)).toEqual([
      b32hex(2),
      b32hex(3),
    ]);
    expect(cp.consistencyProofs[1]!.rightPeaks.map(toHex)).toEqual([b32hex(4)]);
    expect(cp.delegation.mmrEnd).toBe(42n);
    expect(cp.signature.length).toBe(64);
  });

  test("rejects non-publishCheckpoint calldata (wrong selector)", () => {
    expect(() => decodePublishCheckpointCalldata("0xdeadbeef")).toThrow();
  });

  test("rejects a non-growing link (hostile calldata)", () => {
    const data = encodeSynthetic([
      { treeSize1: 5n, treeSize2: 5n, paths: [[]], rightPeaks: [] },
    ]);
    expect(() => decodePublishCheckpointCalldata(data)).toThrow(/grow the tree/);
  });

  test("rejects an empty proof chain", () => {
    const data = encodeSynthetic([]);
    expect(() => decodePublishCheckpointCalldata(data)).toThrow(
      /no consistency proofs/,
    );
  });
});

describe("fetchTransactionInput", () => {
  test("returns the tx input via eth_getTransactionByHash", async () => {
    const mockFetch = (async () =>
      new Response(
        JSON.stringify({ jsonrpc: "2.0", id: 1, result: { input: calldataHex } }),
        { status: 200 },
      )) as unknown as typeof fetch;
    const input = await fetchTransactionInput({
      rpcUrl: "http://rpc.mock",
      txHash: manifest.txHash,
      fetchImpl: mockFetch,
    });
    expect(input).toBe(calldataHex);
    // and it decodes
    const cp: CalldataCheckpoint = decodePublishCheckpointCalldata(input);
    expect(cp.consistencyProofs.length).toBe(1);
  });

  test("throws when the tx has no input", async () => {
    const mockFetch = (async () =>
      new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: null }), {
        status: 200,
      })) as unknown as typeof fetch;
    await expect(
      fetchTransactionInput({
        rpcUrl: "http://rpc.mock",
        txHash: "0xabc",
        fetchImpl: mockFetch,
      }),
    ).rejects.toThrow(/no input calldata/);
  });
});
