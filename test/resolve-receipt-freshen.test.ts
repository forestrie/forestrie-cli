import { describe, expect, test } from "bun:test";
import { encodeCborDeterministic } from "@forestrie/encoding";
import { verifyGrantReceiptOffline } from "@forestrie/receipt-verify";
import { freshenFromSthChain } from "../src/lib/resolve-receipt-freshen.js";
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
