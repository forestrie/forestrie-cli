import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { encodeAbiParameters, encodeFunctionData } from "viem";
import { createCaptureOut } from "@forestrie/cli-kit/reporting";
import { encodeCborDeterministic, encodeGrantPayload } from "@forestrie/encoding";
import { verifyGrantReceiptOffline } from "@forestrie/receipt-verify";
import { PUBLISH_CHECKPOINT_ABI } from "../src/lib/decode-checkpoint-calldata.js";
import { runCli } from "./support.js";
import { parseCreateReceiptOptions } from "../src/options/create-receipt.js";
import { runCreateReceipt } from "../src/main/create-receipt.js";
import type { KnownAccumulator } from "../src/lib/verify-known-accumulator.js";
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

  test("fails closed when --checkpoint size disagrees with the calldata chain", async () => {
    const fx = await buildVerifyFixture();
    const calldata03 = encodeCalldata([
      { treeSize1: 0n, treeSize2: 3n, paths: [], rightPeaks: [fx.peak] },
    ]);
    const calldata37 = encodeCalldata([
      { treeSize1: 3n, treeSize2: 7n, paths: [[fx.node5]], rightPeaks: [] },
    ]);
    const mockFetch = makeMockChain([
      { size: 3n, accumulator: [fx.peak], txHash: "0x" + "11".repeat(32), calldata: calldata03 },
      { size: 7n, accumulator: [fx.peak7], txHash: "0x" + "22".repeat(32), calldata: calldata37 },
    ]);
    // Emission checkpoint sealed size 4 — does not match the size-7 chain.
    const wrongSth = buildSth({ consistency: [0n, 4n, [], []] });
    await expect(
      freshenFromCalldataChain({
        oldReceiptBytes: fx.receiptCbor,
        grant: fx.grant,
        idtimestampBe8: fx.idtimestampBe8,
        univocity: "0x" + "ab".repeat(20),
        logId: "660e8400-e29b-41d4-a716-446655440001",
        rpcUrl: "http://rpc.mock",
        latestCheckpointBytes: wrongSth,
        fetchImpl: mockFetch,
      }),
    ).rejects.toThrow(/ends at size 7 but the checkpoint sealed size 4/);
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

  test("--in-place + --out is rejected", () => {
    expect(() =>
      parse({
        receipt: "r.cbor",
        "checkpoint-chain": "chain/",
        "committed-grant-file": "g.cbor",
        "entry-id": "ab",
        "in-place": true,
        out: "o.cbor",
      }),
    ).toThrow(/--out or --in-place, not both/);
  });

  test("--in-place without --receipt (tiles) is rejected", () => {
    expect(() =>
      parse({ massif: "m.log", checkpoint: "c.sth", "entry-id": "ab", "in-place": true }),
    ).toThrow(/--in-place only applies to freshen/);
  });

  test("--known-accumulator without --receipt (tiles) is rejected", () => {
    expect(() =>
      parse({
        massif: "m.log",
        checkpoint: "c.sth",
        "entry-id": "ab",
        "known-accumulator": "acc.cbor",
      }),
    ).toThrow(/--known-accumulator only applies to freshen/);
  });
});

/** A minimal known-accumulator snapshot at `size` with `accumulator`. */
const snap = (size: bigint, accumulator: Uint8Array[]): KnownAccumulator => ({
  version: 1,
  chainId: 84532n,
  univocity: new Uint8Array(20).fill(0xab),
  logId: new Uint8Array(32).fill(0x11),
  size,
  accumulator,
  blockNumber: 1n,
  blockHash: new Uint8Array(32).fill(0xbb),
});

describe("resolve-receipt freshen --known-accumulator (C1)", () => {
  async function sthSetup() {
    const fx = await buildVerifyFixture();
    const sth0 = buildSth({ consistency: [0n, 3n, [], [fx.peak]] });
    const sth1 = buildSth({
      consistency: [3n, 7n, [[fx.node5]], []],
      peakReceipts: [await signDetachedPeakReceipt(fx.rootKeyPair, fx.peak7)],
    });
    return { fx, checkpoints: [sth0, sth1] };
  }

  test("binds the freshened state to a matching snapshot", async () => {
    const { fx, checkpoints } = await sthSetup();
    const result = await freshenFromSthChain({
      oldReceiptBytes: fx.receiptCbor,
      grant: fx.grant,
      idtimestampBe8: fx.idtimestampBe8,
      checkpoints,
      knownAccumulator: snap(7n, [fx.peak7]),
    });
    expect(result.details.knownAccumulatorMatched).toBe(true);
  });

  test("fails closed when the snapshot accumulator disagrees", async () => {
    const { fx, checkpoints } = await sthSetup();
    await expect(
      freshenFromSthChain({
        oldReceiptBytes: fx.receiptCbor,
        grant: fx.grant,
        idtimestampBe8: fx.idtimestampBe8,
        checkpoints,
        knownAccumulator: snap(7n, [new Uint8Array(32).fill(0x99)]),
      }),
    ).rejects.toThrow(/does not match --known-accumulator/);
  });

  test("fails closed when the snapshot is a different size", async () => {
    const { fx, checkpoints } = await sthSetup();
    await expect(
      freshenFromSthChain({
        oldReceiptBytes: fx.receiptCbor,
        grant: fx.grant,
        idtimestampBe8: fx.idtimestampBe8,
        checkpoints,
        knownAccumulator: snap(3n, [fx.peak]),
      }),
    ).rejects.toThrow(/is size 3 but the freshened state is size 7/);
  });
});

describe("resolve-receipt freshen --in-place (FOR-418)", () => {
  test("rewrites the stale --receipt file with the freshened receipt", async () => {
    const fx = await buildVerifyFixture();
    const sth0 = buildSth({ consistency: [0n, 3n, [], [fx.peak]] });
    const sth1 = buildSth({
      consistency: [3n, 7n, [[fx.node5]], []],
      peakReceipts: [await signDetachedPeakReceipt(fx.rootKeyPair, fx.peak7)],
    });

    const dir = mkdtempSync(path.join(tmpdir(), "forestrie-freshen-inplace-"));
    const receiptPath = path.join(dir, "receipt.cbor");
    writeFileSync(receiptPath, fx.receiptCbor);
    writeFileSync(path.join(dir, "0000.sth"), sth0);
    writeFileSync(path.join(dir, "0001.sth"), sth1);

    const options = parseCreateReceiptOptions({
      receipt: receiptPath,
      "checkpoint-chain": dir,
      "committed-grant": fx.grantCoseB64,
      "entry-id": fx.entryIdHex,
      "in-place": true,
    } as Parameters<typeof parseCreateReceiptOptions>[0]);
    await runCreateReceipt(createCaptureOut(0), options);

    const rewritten = new Uint8Array(readFileSync(receiptPath));
    // The file was replaced by the (larger) freshened receipt, not the stale one.
    expect(rewritten).not.toEqual(new Uint8Array(fx.receiptCbor));
    const verified = await verifyGrantReceiptOffline({
      genesisCbor: fx.genesisCbor,
      receiptCbor: rewritten,
      grant: fx.grant,
      idtimestampBe8: fx.idtimestampBe8,
    });
    expect(verified).toEqual({ ok: true, stage: "binding" });
  });
});

describe("resolve-receipt freshen | verify (CLI end-to-end, FOR-418)", () => {
  /** Write a stale receipt + a genesis-rooted 0->3->7 `.sth` chain + grant +
   * genesis to disk; return the paths for a real `forestrie` invocation. */
  async function writeFreshenArtifacts() {
    const fx = await buildVerifyFixture();
    const dir = mkdtempSync(path.join(tmpdir(), "forestrie-freshen-e2e-"));
    // .sth chain in its own directory so --checkpoint-chain sees only checkpoints.
    const chain = path.join(dir, "chain");
    mkdirSync(chain);
    const stale = path.join(dir, "stale.cbor");
    const grant = path.join(dir, "grant.cbor");
    const genesis = path.join(dir, "genesis.cbor");
    writeFileSync(stale, fx.receiptCbor);
    writeFileSync(grant, encodeGrantPayload(fx.grant));
    writeFileSync(genesis, fx.genesisCbor);
    writeFileSync(
      path.join(chain, "0000.sth"),
      buildSth({ consistency: [0n, 3n, [], [fx.peak]] }),
    );
    writeFileSync(
      path.join(chain, "0001.sth"),
      buildSth({
        consistency: [3n, 7n, [[fx.node5]], []],
        peakReceipts: [await signDetachedPeakReceipt(fx.rootKeyPair, fx.peak7)],
      }),
    );
    return { fx, dir, chain, stale, grant, genesis };
  }

  test("`resolve-receipt --receipt --checkpoint-chain` freshens and the result passes `forestrie verify-grant`", async () => {
    const { fx, dir, chain, stale, grant, genesis } =
      await writeFreshenArtifacts();
    const fresh = path.join(dir, "fresh.cbor");

    const created = runCli([
      "resolve-receipt",
      "--receipt",
      stale,
      "--checkpoint-chain",
      chain,
      "--committed-grant-file",
      grant,
      "--entry-id",
      fx.entryIdHex,
      "--out",
      fresh,
    ]);
    expect(created.exitCode).toBe(0);
    expect(created.stderr).toContain("resolve-receipt: freshen");

    const verified = runCli([
      "verify-grant",
      "--genesis",
      genesis,
      "--receipt",
      fresh,
      "--committed-grant-file",
      grant,
      "--entry-id",
      fx.entryIdHex,
    ]);
    expect(verified.exitCode).toBe(0);
    expect(verified.stdout).toContain("PASS");
  });

  test("the `create-receipt` alias routes to the same freshen path", async () => {
    const { fx, dir, chain, stale, grant } = await writeFreshenArtifacts();
    const fresh = path.join(dir, "fresh-alias.cbor");
    const created = runCli([
      "create-receipt",
      "--receipt",
      stale,
      "--checkpoint-chain",
      chain,
      "--committed-grant-file",
      grant,
      "--entry-id",
      fx.entryIdHex,
      "--out",
      fresh,
    ]);
    expect(created.exitCode).toBe(0);
    expect(new Uint8Array(readFileSync(fresh)).length).toBeGreaterThan(0);
  });
});
