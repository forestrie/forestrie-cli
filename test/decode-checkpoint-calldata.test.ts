import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import {
  decodeFunctionData,
  encodeFunctionData,
  parseAbi,
  toFunctionSelector,
} from "viem";
import {
  encodeCborDeterministic,
  verifyCoseSign1WithParsedKey,
} from "@forestrie/encoding";
import {
  accumulatorPayload,
  checkpointConsistencyProof,
  computeCheckpointAccumulator,
} from "@forestrie/receipt-verify";
import {
  PUBLISH_CHECKPOINT_ABI,
  decodePublishCheckpointCalldata,
  fetchTransactionInput,
  type CalldataCheckpoint,
} from "../src/lib/decode-checkpoint-calldata.js";

/**
 * FOR-418 Phase 1 (plan-2607-32): the `publishCheckpoint` calldata reader.
 * Two FROZEN golden vectors from REAL Base-Sepolia `publishCheckpoint` txs
 * prove interop with on-chain data; a synthetic round-trip exercises the
 * multi-link / multi-path shapes the real txs do not.
 *
 * - `checkpoint-calldata/`: a pre-ADR-0008 / pre-ADR-0066 tx (five-field
 *   delegation, no signed tree size). It is NOT decodable by the current
 *   ABI — the contract's `publishCheckpoint` selector changed when
 *   `DelegationProof.algData` was added (univocity #36) — so it is kept as
 *   the wrong-selector vector, and decoded here with the legacy ABI only to
 *   show that a checkpoint without the signed size fails verification.
 * - `checkpoint-calldata-v0.3.0/`: a post-reset tx on the univocity v0.3.0
 *   demo instance (plan-2609-10 slice 06, step A8): the root log's 1→3 link
 *   with protected header `{1: -7, 395: 3, -65933: 3}`. It must decode,
 *   fold from the trusted size-1 accumulator to the accumulator the
 *   `CheckpointPublished` event recorded, and its signature must verify
 *   under the sealer key carried in the delegation proof.
 */

type GoldenManifest = {
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
    algData?: string[];
  };
};

function loadGolden(name: string): { manifest: GoldenManifest; calldataHex: string } {
  const dir = path.join(import.meta.dir, "fixtures", "golden", name);
  return {
    manifest: JSON.parse(
      readFileSync(path.join(dir, "manifest.json"), "utf8"),
    ) as GoldenManifest,
    calldataHex: readFileSync(
      path.join(dir, "publish-checkpoint.calldata.hex"),
      "utf8",
    ).trim(),
  };
}

const legacy = loadGolden("checkpoint-calldata");
const manifest = legacy.manifest;
const calldataHex = legacy.calldataHex;

const v030 = loadGolden("checkpoint-calldata-v0.3.0") as {
  manifest: GoldenManifest & {
    univocityRelease: string;
    signedTreeSize2: string;
    baseAccumulator: string[];
    eventAccumulator: string[];
  };
  calldataHex: string;
};

const toHex = (b: Uint8Array) =>
  `0x${Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")}`;
const fromHex = (h: string) => new Uint8Array(Buffer.from(h.replace(/^0x/, ""), "hex"));

/**
 * The pre-ADR-0008 `publishCheckpoint` ABI (five-field `DelegationProof`,
 * selector 0x87ce4c61). Test-only: the production decoder targets v0.3.0.
 */
const LEGACY_PUBLISH_CHECKPOINT_ABI = parseAbi([
  "struct ConsistencyProof { uint64 treeSize1; uint64 treeSize2; bytes32[][] paths; bytes32[] rightPeaks; }",
  "struct DelegationProof { bytes protectedHeader; bytes delegationKey; uint64 mmrStart; uint64 mmrEnd; bytes signature; }",
  "struct ConsistencyReceipt { bytes protectedHeader; bytes signature; ConsistencyProof[] consistencyProofs; DelegationProof delegationProof; }",
  "struct InclusionProof { uint64 index; bytes32[] path; }",
  "struct PublishGrant { bytes32 logId; uint256 grant; uint256 request; uint64 maxHeight; uint64 minGrowth; bytes32 ownerLogId; bytes grantData; }",
  "function publishCheckpoint(ConsistencyReceipt consistencyParts, InclusionProof grantInclusionProof, bytes8 grantIDTimestampBe, PublishGrant publishGrant)",
]);

/** Rebuild the COSE Sign1 the `.sth` store would hold for a calldata checkpoint. */
function checkpointSign1(cp: CalldataCheckpoint): Uint8Array {
  const proofs = cp.consistencyProofs.map((proof) =>
    encodeCborDeterministic([
      proof.treeSize1,
      proof.treeSize2,
      proof.paths,
      proof.rightPeaks,
    ]),
  );
  // Only the last link is directly signed; a single-link tx has exactly one.
  const unprotected = new Map<number, unknown>([
    [396, new Map<number, unknown>([[-2, proofs[proofs.length - 1]!]])],
  ]);
  return encodeCborDeterministic([
    cp.protectedHeader,
    unprotected,
    null,
    cp.signature,
  ]);
}

describe("publishCheckpoint ABI (univocity v0.3.0)", () => {
  test("the selector matches the foundry-generated 0x295e6ade", () => {
    const fn = PUBLISH_CHECKPOINT_ABI.find(
      (f): f is typeof f & { type: "function" } => f.type === "function",
    );
    expect(fn && toFunctionSelector(fn)).toBe("0x295e6ade");
  });

  test("the pre-ADR-0008 selector 0x87ce4c61 is not publishCheckpoint on this ABI", () => {
    const fn = LEGACY_PUBLISH_CHECKPOINT_ABI.find(
      (f): f is typeof f & { type: "function" } => f.type === "function",
    );
    expect(fn && toFunctionSelector(fn)).toBe("0x87ce4c61");
    expect(() => decodePublishCheckpointCalldata(calldataHex)).toThrow();
  });
});

describe("publishCheckpoint calldata golden vector — pre-ADR-0066 tx (frozen; legacy ABI)", () => {
  test("the frozen calldata matches its recorded digest (no accidental edits)", () => {
    const bytes = Buffer.from(calldataHex.replace(/^0x/, ""), "hex");
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(
      manifest.calldataSha256,
    );
  });

  /** Decode with the legacy ABI into the production `CalldataCheckpoint` shape. */
  function decodeLegacy(): CalldataCheckpoint {
    const { args } = decodeFunctionData({
      abi: LEGACY_PUBLISH_CHECKPOINT_ABI,
      data: calldataHex as `0x${string}`,
    });
    const r = args[0];
    return {
      protectedHeader: fromHex(r.protectedHeader),
      signature: fromHex(r.signature),
      consistencyProofs: r.consistencyProofs.map((p) => ({
        treeSize1: p.treeSize1,
        treeSize2: p.treeSize2,
        paths: p.paths.map((path) => path.map(fromHex)),
        rightPeaks: p.rightPeaks.map(fromHex),
      })),
      delegation: {
        protectedHeader: fromHex(r.delegationProof.protectedHeader),
        delegationKey: fromHex(r.delegationProof.delegationKey),
        mmrStart: r.delegationProof.mmrStart,
        mmrEnd: r.delegationProof.mmrEnd,
        signature: fromHex(r.delegationProof.signature),
        algData: [],
      },
    };
  }

  test("decodes under the legacy ABI to its recorded ConsistencyReceipt", () => {
    const cp = decodeLegacy();
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
    // the empty-path case (sth 7→8)
    expect(cp.consistencyProofs[0]!.paths[0]).toEqual([]);
    expect(cp.consistencyProofs[0]!.rightPeaks.length).toBe(1);
  });

  test("verification fails with the missing-signed-size reason (FOR-568, pre-ADR-0066 tx)", () => {
    // This tx predates ADR-0066 D1 (amended 2026-09-20): its protected
    // header is `{1: -7, 395: 3}` — no `-65933` (tree-size-2) label. The
    // manifest's `protectedHeaderHex` 0xa2012619018b03 has no size label
    // (2-entry map: alg, vds). Reconstructing the checkpoint COSE Sign1 the
    // `.sth` store would have held and handing it to
    // `checkpointConsistencyProof` must fail closed — a pre-signed-size
    // checkpoint is not verifiable under the current protocol.
    expect(() => checkpointConsistencyProof(checkpointSign1(decodeLegacy()))).toThrow(
      /no signed tree-size-2/,
    );
  });
});

describe("publishCheckpoint calldata golden vector — univocity v0.3.0 tx (frozen; signed size)", () => {
  const m = v030.manifest;
  const hex = v030.calldataHex;

  test("the frozen calldata matches its recorded digest (no accidental edits)", () => {
    const bytes = Buffer.from(hex.replace(/^0x/, ""), "hex");
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(m.calldataSha256);
    expect(m.univocityRelease).toBe("v0.3.0");
  });

  test("decodes the real tx to its recorded ConsistencyReceipt", () => {
    const cp = decodePublishCheckpointCalldata(hex);
    expect(toHex(cp.protectedHeader)).toBe(m.protectedHeaderHex);
    expect(toHex(cp.signature)).toBe(m.signatureHex);
    expect(cp.signature.length).toBe(64);
    expect(cp.consistencyProofs.length).toBe(1);
    const p = cp.consistencyProofs[0]!;
    expect(p.treeSize1.toString()).toBe(m.consistencyProofs[0]!.treeSize1);
    expect(p.treeSize2.toString()).toBe(m.consistencyProofs[0]!.treeSize2);
    expect(p.paths.map((path) => path.map(toHex))).toEqual(m.consistencyProofs[0]!.paths);
    expect(p.rightPeaks.map(toHex)).toEqual(m.consistencyProofs[0]!.rightPeaks);
    // 1→3: one peak at size 1, climbing one node to the single peak at size 3
    expect(p.paths.length).toBe(1);
    expect(p.paths[0]!.length).toBe(1);
    expect(p.rightPeaks).toEqual([]);
    expect(toHex(cp.delegation.protectedHeader)).toBe(m.delegation.protectedHeaderHex);
    expect(toHex(cp.delegation.delegationKey)).toBe(m.delegation.delegationKeyHex);
    expect(cp.delegation.mmrStart.toString()).toBe(m.delegation.mmrStart);
    expect(cp.delegation.mmrEnd.toString()).toBe(m.delegation.mmrEnd);
    expect(toHex(cp.delegation.signature)).toBe(m.delegation.signatureHex);
    expect(cp.delegation.algData).toEqual([]); // ES256: no alg-specific material
  });

  test("the protected header carries the signed tree-size-2 (ADR-0066 D1) equal to the proof's", () => {
    // {1: -7, 395: 3, -65933: 3} in canonical (length-first) key order
    expect(m.protectedHeaderHex).toBe("0xa3012619018b033a0001018c03");
    const proof = checkpointConsistencyProof(
      checkpointSign1(decodePublishCheckpointCalldata(hex)),
    );
    expect(proof.signedTreeSize2.toString()).toBe(m.signedTreeSize2);
    expect(proof.signedTreeSize2).toBe(proof.treeSize2);
  });

  test("folds from the trusted size-1 accumulator to the CheckpointPublished accumulator, and the seal verifies under the delegation key", async () => {
    const cp = decodePublishCheckpointCalldata(hex);
    const sign1 = checkpointSign1(cp);
    const proof = checkpointConsistencyProof(sign1);
    const accumulator = await computeCheckpointAccumulator(
      proof,
      m.baseAccumulator.map(fromHex),
      1n,
    );
    expect(accumulator.map(toHex)).toEqual(m.eventAccumulator);

    // ADR-0046: the signature covers the accumulator as a detached payload.
    const key = cp.delegation.delegationKey;
    const ok = await verifyCoseSign1WithParsedKey(
      sign1,
      { x: key.slice(0, 32), y: key.slice(32, 64), curve: "P-256" },
      { detachedPayload: accumulatorPayload(accumulator) },
    );
    expect(ok).toBe(true);

    // and a different payload does not verify (the check is not vacuous)
    const other = await verifyCoseSign1WithParsedKey(
      sign1,
      { x: key.slice(0, 32), y: key.slice(32, 64), curve: "P-256" },
      { detachedPayload: accumulatorPayload(m.baseAccumulator.map(fromHex)) },
    );
    expect(other).toBe(false);
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
          algData: [],
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
        JSON.stringify({ jsonrpc: "2.0", id: 1, result: { input: v030.calldataHex } }),
        { status: 200 },
      )) as unknown as typeof fetch;
    const input = await fetchTransactionInput({
      rpcUrl: "http://rpc.mock",
      txHash: v030.manifest.txHash,
      fetchImpl: mockFetch,
    });
    expect(input).toBe(v030.calldataHex);
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
