import { describe, expect, test } from "bun:test";
import { encodeAbiParameters, encodeFunctionData } from "viem";
import { encodeCborDeterministic } from "@forestrie/encoding";
import { verifyGrantReceiptOffline } from "@forestrie/receipt-verify";
import { PUBLISH_CHECKPOINT_ABI } from "../src/lib/decode-checkpoint-calldata.js";
import { parseCreateReceiptOptions } from "../src/options/create-receipt.js";
import {
  freshenFromCalldataChain,
  freshenFromSthChain,
} from "../src/lib/resolve-receipt-freshen.js";
import { buildVerifyFixture, grantWithData } from "./verify-fixture.js";
import { signDetachedPeakReceipt } from "./create-receipt-fixture.js";

/**
 * FOR-418 Phase 3c: `resolve-receipt` freshen over a retained `.sth` chain.
 *
 * The verify fixture gives a stale receipt for leaf1 (grant commits the
 * bootstrap key) whose peak is node2 at size 3. We build a genesis-rooted
 * `.sth` chain `0 -> 3 -> 7` (the base-0 first link is the real shape), freshen
 * tile-free, and the re-emitted receipt verifies against genesis at the current
 * sealed size.
 */

/**
 * A format-v3 `.sth`: the embedded consistency proof at vdp 396 key -2 and, when
 * this is the latest checkpoint to emit under, the pre-signed peak receipts at
 * label -65931. (Freshen does not use the checkpoint's own outer signature.)
 */
function buildSth(opts: {
  consistency: [bigint, bigint, Uint8Array[][], Uint8Array[]];
  peakReceipts?: Uint8Array[];
}): Uint8Array {
  const proofBstr = encodeCborDeterministic(opts.consistency);
  const unprot = new Map<number, unknown>([
    [396, new Map<number, unknown>([[-2, proofBstr]])],
  ]);
  if (opts.peakReceipts !== undefined) {
    unprot.set(-65931, opts.peakReceipts);
  }
  return encodeCborDeterministic([
    new Uint8Array(),
    unprot,
    null,
    new Uint8Array(64),
  ]);
}

describe("resolve-receipt freshen via .sth chain (FOR-418)", () => {
  test("freshens a stale receipt over a genesis-rooted 0 -> 3 -> 7 chain and it verifies", async () => {
    const fx = await buildVerifyFixture();

    // sth0: base-0 link (paths [], the size-3 accumulator is its right-peaks).
    const sth0 = buildSth({ consistency: [0n, 3n, [], [fx.peak]] });
    // sth1: 3 -> 7, buries node2 via node5; carries the peak receipt to emit under.
    const sth1 = buildSth({
      consistency: [3n, 7n, [[fx.node5]], []],
      peakReceipts: [await signDetachedPeakReceipt(fx.rootKeyPair, fx.peak7)],
    });

    const result = await freshenFromSthChain({
      oldReceiptBytes: fx.receiptCbor,
      grant: fx.grant,
      idtimestampBe8: fx.idtimestampBe8,
      checkpoints: [sth0, sth1],
      sourceRefs: ["0000.sth", "0001.sth"],
    });

    expect(result.details.sealedSize).toBe(7n);
    expect(result.details.chainLinks).toBe(2);
    expect(result.details.leafMmrIndex).toBe(1n);
    expect(result.details.sourceRefs).toEqual(["0000.sth", "0001.sth"]);

    const verified = await verifyGrantReceiptOffline({
      genesisCbor: fx.genesisCbor,
      receiptCbor: result.receiptCbor,
      grant: fx.grant,
      idtimestampBe8: fx.idtimestampBe8,
    });
    expect(verified).toEqual({ ok: true, stage: "binding" });
  });

  test("fails closed when the grant does not match the receipt's leaf", async () => {
    const fx = await buildVerifyFixture();
    const sth0 = buildSth({ consistency: [0n, 3n, [], [fx.peak]] });
    const sth1 = buildSth({
      consistency: [3n, 7n, [[fx.node5]], []],
      peakReceipts: [await signDetachedPeakReceipt(fx.rootKeyPair, fx.peak7)],
    });
    // A different grant → different leaf value → self-check must reject.
    const wrongGrant = grantWithData(
      "660e8400-e29b-41d4-a716-446655440001",
      new Uint8Array(64).fill(0x7e),
    );
    await expect(
      freshenFromSthChain({
        oldReceiptBytes: fx.receiptCbor,
        grant: wrongGrant,
        idtimestampBe8: fx.idtimestampBe8,
        checkpoints: [sth0, sth1],
      }),
    ).rejects.toThrow(/does not recompute the latest accumulator peak/);
  });
});

const toHex = (b: Uint8Array): `0x${string}` =>
  `0x${Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")}`;

/** Encode one `publishCheckpoint` calldata carrying `proofs` (viem). */
function encodeCalldata(
  proofs: {
    treeSize1: bigint;
    treeSize2: bigint;
    paths: Uint8Array[][];
    rightPeaks: Uint8Array[];
  }[],
): `0x${string}` {
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
        },
      },
      { index: 0n, path: [] },
      "0x0000000000000000",
      {
        logId: zero32,
        grant: 0n,
        request: 0n,
        maxHeight: 14n,
        minGrowth: 0n,
        ownerLogId: zero32,
        grantData: "0x",
      },
    ],
  });
}

/** CheckpointPublished event data (size + accumulator). */
function encodeEventData(size: bigint, accumulator: Uint8Array[]): `0x${string}` {
  return encodeAbiParameters(
    [
      { type: "address" },
      { type: "bytes8" },
      { type: "uint8" },
      { type: "uint64" },
      { type: "bytes32[]" },
      { type: "uint64" },
      { type: "bytes32[]" },
    ],
    [
      "0x".padEnd(42, "0") as `0x${string}`,
      "0x0000000000000000",
      0,
      size,
      accumulator.map(toHex),
      0n,
      [],
    ],
  );
}

/** Mock JSON-RPC serving the CheckpointPublished logs + each tx's calldata. */
function makeMockChain(
  entries: {
    size: bigint;
    accumulator: Uint8Array[];
    txHash: string;
    calldata: `0x${string}`;
  }[],
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

describe("resolve-receipt freshen via calldata (FOR-418)", () => {
  test("freshens a stale receipt from on-chain publish calldata and it verifies", async () => {
    const fx = await buildVerifyFixture();

    // The on-chain publish history: 0 -> 3 then 3 -> 7 (one tx each).
    const calldata03 = encodeCalldata([
      { treeSize1: 0n, treeSize2: 3n, paths: [], rightPeaks: [fx.peak] },
    ]);
    const calldata37 = encodeCalldata([
      { treeSize1: 3n, treeSize2: 7n, paths: [[fx.node5]], rightPeaks: [] },
    ]);
    const mockFetch = makeMockChain([
      {
        size: 3n,
        accumulator: [fx.peak],
        txHash: "0x" + "11".repeat(32),
        calldata: calldata03,
      },
      {
        size: 7n,
        accumulator: [fx.peak7],
        txHash: "0x" + "22".repeat(32),
        calldata: calldata37,
      },
    ]);

    // Calldata carries no peak receipts — the latest .sth is supplied for emission.
    const latestSth = buildSth({
      consistency: [3n, 7n, [[fx.node5]], []],
      peakReceipts: [await signDetachedPeakReceipt(fx.rootKeyPair, fx.peak7)],
    });

    const result = await freshenFromCalldataChain({
      oldReceiptBytes: fx.receiptCbor,
      grant: fx.grant,
      idtimestampBe8: fx.idtimestampBe8,
      univocity: "0x" + "ab".repeat(20),
      logId: "660e8400-e29b-41d4-a716-446655440001",
      rpcUrl: "http://rpc.mock",
      latestCheckpointBytes: latestSth,
      fetchImpl: mockFetch,
    });

    expect(result.details.sealedSize).toBe(7n);
    expect(result.details.chainLinks).toBe(2);
    // sources are the publishing tx hashes
    expect(result.details.sourceRefs).toEqual([
      "0x" + "11".repeat(32),
      "0x" + "22".repeat(32),
    ]);

    const verified = await verifyGrantReceiptOffline({
      genesisCbor: fx.genesisCbor,
      receiptCbor: result.receiptCbor,
      grant: fx.grant,
      idtimestampBe8: fx.idtimestampBe8,
    });
    expect(verified).toEqual({ ok: true, stage: "binding" });
  });
});

type LooseArgs = Parameters<typeof parseCreateReceiptOptions>[0];
const parse = (args: Record<string, unknown>) =>
  parseCreateReceiptOptions(args as LooseArgs);

describe("resolve-receipt freshen source dispatch (D3)", () => {
  test("--massif + --receipt is a source conflict", () => {
    expect(() =>
      parse({ massif: "m.log", receipt: "r.cbor", "entry-id": "ab" }),
    ).toThrow(/choose one source/);
  });

  test("--receipt with no tile-free source errors", () => {
    expect(() =>
      parse({ receipt: "r.cbor", "committed-grant-file": "g.cbor", "entry-id": "ab" }),
    ).toThrow(/needs a tile-free source/);
  });

  test("freshen without a grant errors", () => {
    expect(() =>
      parse({ receipt: "r.cbor", "checkpoint-chain": "chain/" }),
    ).toThrow(/needs the committed grant/);
  });

  test("--checkpoint-chain resolves to freshen-sth", () => {
    const o = parse({
      receipt: "r.cbor",
      "checkpoint-chain": "chain/",
      "committed-grant-file": "g.cbor",
      "entry-id": "ab",
    });
    expect(o.anchor).toBe("freshen-sth");
  });

  test("both freshen sources is a conflict", () => {
    expect(() =>
      parse({
        receipt: "r.cbor",
        "checkpoint-chain": "chain/",
        "rpc-url": "http://rpc",
        "committed-grant-file": "g.cbor",
        "entry-id": "ab",
      }),
    ).toThrow(/choose one freshen source/);
  });

  test("calldata freshen without --checkpoint errors (no emission artifact)", () => {
    expect(() =>
      parse({
        receipt: "r.cbor",
        univocity: "0xabc",
        "log-id": "log",
        "rpc-url": "http://rpc",
        "committed-grant-file": "g.cbor",
        "entry-id": "ab",
      }),
    ).toThrow(/requires --checkpoint .* for emission/);
  });

  test("full calldata + --checkpoint resolves to freshen-calldata", () => {
    const o = parse({
      receipt: "r.cbor",
      univocity: "0xabc",
      "log-id": "log",
      "rpc-url": "http://rpc",
      checkpoint: "latest.sth",
      "committed-grant-file": "g.cbor",
      "entry-id": "ab",
    });
    expect(o.anchor).toBe("freshen-calldata");
  });
});
