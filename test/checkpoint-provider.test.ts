import { beforeAll, describe, expect, test } from "bun:test";
import { encodeAbiParameters, encodeFunctionData } from "viem";
import { PUBLISH_CHECKPOINT_ABI } from "../src/lib/decode-checkpoint-calldata.js";
import {
  calldataCheckpointChain,
  findPeakInChain,
  foldProofChain,
  sthCheckpointChain,
  type CheckpointLink,
  type FoldableConsistencyProof,
} from "../src/lib/checkpoint-provider.js";
import { buildCheckpoint, buildVerifyFixture, type VerifyFixture } from "./verify-fixture.js";

/**
 * FOR-418 Phase 2 (plan-2607-32), updated for receipt-verify 3.0.0
 * (`CheckpointConsistencyProof.proofs`, ADR-0066 D2): the checkpoint-chain
 * providers. The headline claim is PARITY — the same log's chain read from
 * retained `.sth` and from `publishCheckpoint` calldata folds to the
 * identical authenticated accumulators. Uses the real MMR nodes from the
 * verify fixture: a 2-link chain sth(0→3)=[peak] then sth(3→7)=[peak7] (the
 * buried peak climbs via node5).
 */

let fx: VerifyFixture;

const toHex = (b: Uint8Array): `0x${string}` =>
  `0x${Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")}`;

type RawStep = { treeSize1: bigint; treeSize2: bigint; paths: Uint8Array[][]; rightPeaks: Uint8Array[] };

/** The two-step proof chain, in the raw shape both encoders take (one entry
 * per relayed consistency proof, ADR-0066 D2). */
function chainProofs(fx: VerifyFixture): RawStep[] {
  return [
    { treeSize1: 0n, treeSize2: 3n, paths: [] as Uint8Array[][], rightPeaks: [fx.peak] },
    { treeSize1: 3n, treeSize2: 7n, paths: [[fx.node5]], rightPeaks: [] as Uint8Array[] },
  ];
}

/** Wrap a single raw step as the one-step chain `foldProofChain` takes
 * (receipt-verify 3.0.0's `CheckpointConsistencyProof` shape). */
function asChain(step: RawStep): FoldableConsistencyProof {
  return { proofs: [step], treeSize1: step.treeSize1, treeSize2: step.treeSize2 };
}

/** Encode one `publishCheckpoint` calldata carrying `proofs` (viem). */
function encodeCalldata(proofs: RawStep[]): `0x${string}` {
  const zero32 = toHex(new Uint8Array(32));
  return encodeFunctionData({
    abi: PUBLISH_CHECKPOINT_ABI,
    functionName: "publishCheckpoint",
    args: [
      {
        protectedHeader: "0xa20126",
        signature: `0x${"ab".repeat(64)}`,
        consistencyProofs: proofs.map((p) => ({
          treeSize1: p.treeSize1,
          treeSize2: p.treeSize2,
          paths: p.paths.map((path) => path.map(toHex)),
          rightPeaks: p.rightPeaks.map(toHex),
        })),
        delegationProof: {
          protectedHeader: "0xa20126",
          delegationKey: `0x${"cd".repeat(64)}`,
          mmrStart: 0n,
          mmrEnd: 7n,
          signature: `0x${"ef".repeat(64)}`,
          algData: [],
        },
      },
      { index: 0n, path: [] },
      "0x0000000000000000",
      { logId: zero32, grant: 0n, request: 0n, maxHeight: 14n, minGrowth: 0n, ownerLogId: zero32, grantData: "0x" },
    ],
  });
}

/** Encode a CheckpointPublished event's non-indexed data (size + accumulator). */
function encodeEventData(size: bigint, accumulator: Uint8Array[]): `0x${string}` {
  return encodeAbiParameters(
    [
      { type: "address" }, // sender
      { type: "bytes8" }, // grantIDTimestampBe
      { type: "uint8" }, // logKind
      { type: "uint64" }, // size
      { type: "bytes32[]" }, // accumulator
      { type: "uint64" }, // grantIndex
      { type: "bytes32[]" }, // grantPath
    ],
    ["0x".padEnd(42, "0") as `0x${string}`, "0x0000000000000000", 0, size, accumulator.map(toHex), 0n, []],
  );
}

const accHex = (link: CheckpointLink) => link.accumulator.map(toHex);

beforeAll(async () => {
  fx = await buildVerifyFixture();
});

describe("foldProofChain + provider parity (FOR-418)", () => {
  test("the fold produces the real accumulators [peak] then [peak7]", async () => {
    const links = await foldProofChain(chainProofs(fx).map(asChain));
    expect(links.length).toBe(2);
    expect(accHex(links[0]!)).toEqual([toHex(fx.peak)]);
    expect(accHex(links[1]!)).toEqual([toHex(fx.peak7)]);
  });

  test("each link carries its raw proof chain — freshen's climb material, one pass", async () => {
    const chain = chainProofs(fx).map(asChain);
    const links = await foldProofChain(chain);
    // `links.map((l) => l.proof)` IS freshen's ordered `consistencyProofs`.
    expect(links.map((l) => l.proof)).toEqual(chain);
    expect(links.map((l) => l.proof.treeSize2)).toEqual([3n, 7n]);
    expect(
      links[1]!.proof.proofs.flatMap((p) => p.paths.map((path) => path.map(toHex))),
    ).toEqual([[toHex(fx.node5)]]);
  });

  test("PARITY: `.sth` and calldata read the SAME chain to identical accumulators", async () => {
    const proofs = chainProofs(fx);
    // .sth source: one signed checkpoint per link
    const sth1 = await buildCheckpoint({ signer: fx.rootKeyPair, treeSize1: 0n, treeSize2: 3n, paths: [], rightPeaks: [fx.peak], accumulator: [fx.peak] });
    const sth2 = await buildCheckpoint({ signer: fx.rootKeyPair, treeSize1: 3n, treeSize2: 7n, paths: [[fx.node5]], rightPeaks: [], accumulator: [fx.peak7] });
    const sthLinks = await sthCheckpointChain([sth1, sth2]);

    // calldata source: two publishCheckpoint txs, one proof each
    const calldata1 = encodeCalldata([proofs[0]!]);
    const calldata2 = encodeCalldata([proofs[1]!]);
    const mockFetch = makeMockChain([
      { size: 3n, accumulator: [fx.peak], txHash: "0x" + "11".repeat(32), calldata: calldata1 },
      { size: 7n, accumulator: [fx.peak7], txHash: "0x" + "22".repeat(32), calldata: calldata2 },
    ]);
    const calldataLinks = await calldataCheckpointChain({
      univocity: "0x" + "ab".repeat(20),
      logId: "660e8400-e29b-41d4-a716-446655440001",
      rpcUrl: "http://rpc.mock",
      fetchImpl: mockFetch,
    });

    expect(calldataLinks.map(accHex)).toEqual(sthLinks.map(accHex));
    expect(calldataLinks.map(accHex)).toEqual([[toHex(fx.peak)], [toHex(fx.peak7)]]);
    // PARITY extends to the raw climb paths (what freshen consumes), not just
    // the folded accumulators.
    const pathsHex = (links: CheckpointLink[]) =>
      links.map((l) => l.proof.proofs.flatMap((p) => p.paths.map((path) => path.map(toHex))));
    expect(pathsHex(calldataLinks)).toEqual(pathsHex(sthLinks));
    expect(pathsHex(sthLinks)).toEqual([[], [[toHex(fx.node5)]]]);
    // sourceRef carried from the tx hash on the calldata path
    expect(calldataLinks[1]!.sourceRef).toBe("0x" + "22".repeat(32));
  });

  test("a relayed (multi-proof) calldata tx produces ONE link with N proofs, folding to the same final accumulator as N single-proof txs", async () => {
    const both = encodeCalldata(chainProofs(fx));
    const mockFetchRelayed = makeMockChain([
      { size: 7n, accumulator: [fx.peak7], txHash: "0x" + "33".repeat(32), calldata: both },
    ]);
    const relayedLinks = await calldataCheckpointChain({
      univocity: "0x" + "ab".repeat(20),
      logId: "660e8400-e29b-41d4-a716-446655440001",
      rpcUrl: "http://rpc.mock",
      fetchImpl: mockFetchRelayed,
    });
    // One transaction relaying two consistency proofs is ONE link, not two —
    // only the last relayed step is directly signed (ADR-0066 D2).
    expect(relayedLinks.length).toBe(1);
    expect(relayedLinks[0]!.proof.proofs.length).toBe(2);
    expect(relayedLinks[0]!.treeSize1).toBe(0n);
    expect(relayedLinks[0]!.treeSize2).toBe(7n);
    expect(accHex(relayedLinks[0]!)).toEqual([toHex(fx.peak7)]);

    // Same log, read as two single-proof txs instead: two links, same final
    // accumulator — the relay framing does not change what state is proven.
    const proofs = chainProofs(fx);
    const calldata1 = encodeCalldata([proofs[0]!]);
    const calldata2 = encodeCalldata([proofs[1]!]);
    const mockFetchSplit = makeMockChain([
      { size: 3n, accumulator: [fx.peak], txHash: "0x" + "11".repeat(32), calldata: calldata1 },
      { size: 7n, accumulator: [fx.peak7], txHash: "0x" + "22".repeat(32), calldata: calldata2 },
    ]);
    const splitLinks = await calldataCheckpointChain({
      univocity: "0x" + "ab".repeat(20),
      logId: "660e8400-e29b-41d4-a716-446655440001",
      rpcUrl: "http://rpc.mock",
      fetchImpl: mockFetchSplit,
    });
    expect(splitLinks.length).toBe(2);
    expect(accHex(relayedLinks[relayedLinks.length - 1]!)).toEqual(
      accHex(splitLinks[splitLinks.length - 1]!),
    );
  });
});

describe("foldProofChain — contiguity + suffix", () => {
  test("a non-contiguous chain throws (legacy / gap)", async () => {
    const chain = [
      { treeSize1: 0n, treeSize2: 3n, paths: [] as Uint8Array[][], rightPeaks: [fx.peak] },
      { treeSize1: 5n, treeSize2: 7n, paths: [[fx.node5]], rightPeaks: [] as Uint8Array[] },
    ].map(asChain);
    await expect(foldProofChain(chain)).rejects.toThrow(/not contiguous/);
  });

  test("a suffix chain seeds from a trusted accumulatorFrom + size (R2)", async () => {
    const links = await foldProofChain([asChain(chainProofs(fx)[1]!)], {
      accumulatorFrom: [fx.peak],
      accumulatorFromSize: 3n,
    });
    expect(accHex(links[0]!)).toEqual([toHex(fx.peak7)]);
  });

  test("accumulatorFrom without a size is rejected (R2)", async () => {
    await expect(
      foldProofChain([asChain(chainProofs(fx)[1]!)], { accumulatorFrom: [fx.peak] }),
    ).rejects.toThrow(/requires accumulatorFromSize/);
  });

  test("a seed whose size mismatches the first link's base throws (R2)", async () => {
    await expect(
      foldProofChain([asChain(chainProofs(fx)[1]!)], {
        accumulatorFrom: [fx.peak],
        accumulatorFromSize: 5n, // first proof's treeSize1 is 3
      }),
    ).rejects.toThrow(/not contiguous at link 0/);
  });
});

describe("seal retention (R1) + event cross-check (R3) + from-block (R2)", () => {
  test("calldata links each carry the tx's seal, whether relaying one step or several", async () => {
    const both = encodeCalldata(chainProofs(fx));
    const mockFetch = makeMockChain([
      { size: 7n, accumulator: [fx.peak7], txHash: "0x" + "44".repeat(32), calldata: both },
    ]);
    const links = await calldataCheckpointChain({
      univocity: "0x" + "ab".repeat(20),
      logId: "660e8400-e29b-41d4-a716-446655440001",
      rpcUrl: "http://rpc.mock",
      fetchImpl: mockFetch,
    });
    // one tx relaying two proofs -> one link, sealed
    expect(links.length).toBe(1);
    expect(links[0]!.seal?.kind).toBe("calldata");
    if (links[0]!.seal?.kind === "calldata") {
      expect(links[0]!.seal.signature.length).toBe(64);
      expect(links[0]!.seal.delegation.delegationKey.length).toBe(64);
    }
  });

  test(".sth links each retain the checkpoint bytes as their seal", async () => {
    const sth1 = await buildCheckpoint({ signer: fx.rootKeyPair, treeSize1: 0n, treeSize2: 3n, paths: [], rightPeaks: [fx.peak], accumulator: [fx.peak] });
    const links = await sthCheckpointChain([sth1], { sourceRefs: ["0000.sth"] });
    expect(links[0]!.seal?.kind).toBe("sth");
    if (links[0]!.seal?.kind === "sth") {
      expect(links[0]!.seal.checkpointBytes).toEqual(sth1);
    }
    expect(links[0]!.sourceRef).toBe("0000.sth"); // R6
  });

  test("R3: a calldata fold that disagrees with the event accumulator throws", async () => {
    const both = encodeCalldata(chainProofs(fx));
    // event claims a WRONG accumulator at size 7
    const mockFetch = makeMockChain([
      { size: 7n, accumulator: [new Uint8Array(32).fill(0x99)], txHash: "0x" + "55".repeat(32), calldata: both },
    ]);
    await expect(
      calldataCheckpointChain({
        univocity: "0x" + "ab".repeat(20),
        logId: "660e8400-e29b-41d4-a716-446655440001",
        rpcUrl: "http://rpc.mock",
        fetchImpl: mockFetch,
      }),
    ).rejects.toThrow(/disagrees with the CheckpointPublished event/);
  });

  test("R2: --from-block without a trusted seed is rejected", async () => {
    const mockFetch = makeMockChain([]);
    await expect(
      calldataCheckpointChain({
        univocity: "0x" + "ab".repeat(20),
        logId: "660e8400-e29b-41d4-a716-446655440001",
        rpcUrl: "http://rpc.mock",
        fromBlock: 100n,
        fetchImpl: mockFetch,
      }),
    ).rejects.toThrow(/must be paired with a trusted seed/);
  });
});

describe("findPeakInChain", () => {
  test("finds a buried peak in the older link (newest-first)", async () => {
    const links = await foldProofChain(chainProofs(fx).map(asChain));
    // fx.peak is buried by size 7 (climbed into peak7) — it lives only in link 0
    const hit = findPeakInChain(links, fx.peak);
    expect(hit?.link.treeSize2).toBe(3n);
    expect(hit?.matchedPeak).toBe(0);
    // the current peak matches the newest link
    expect(findPeakInChain(links, fx.peak7)?.link.treeSize2).toBe(7n);
    // an absent peak
    expect(findPeakInChain(links, new Uint8Array(32).fill(0xee))).toBeNull();
  });
});

/**
 * Mock `fetch` for the calldata provider: dispatches `eth_getLogs` to the
 * CheckpointPublished logs and `eth_getTransactionByHash` to each tx's input.
 */
function makeMockChain(
  entries: { size: bigint; accumulator: Uint8Array[]; txHash: string; calldata: `0x${string}` }[],
): typeof fetch {
  const byTx = new Map(entries.map((e) => [e.txHash, e.calldata]));
  return (async (_url: string, init: { body: string }) => {
    const req = JSON.parse(init.body) as { method: string; params: unknown[] };
    let result: unknown;
    if (req.method === "eth_getLogs") {
      result = entries.map((e, i) => ({
        address: "0x" + "ab".repeat(20),
        data: encodeEventData(e.size, e.accumulator),
        blockNumber: `0x${(i + 1).toString(16)}`,
        transactionHash: e.txHash,
        blockHash: "0x" + "bb".repeat(32),
      }));
    } else if (req.method === "eth_getTransactionByHash") {
      result = { input: byTx.get(req.params[0] as string) };
    } else {
      throw new Error(`unexpected rpc method ${req.method}`);
    }
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), {
      status: 200,
    });
  }) as unknown as typeof fetch;
}
