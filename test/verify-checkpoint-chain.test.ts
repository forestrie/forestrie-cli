import { beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { verifyCheckpointChain } from "@forestrie/receipt-verify";
import type { CheckpointChainLink } from "@forestrie/receipt-verify";
import {
  checkReceiptAnchoredToCheckpointChain,
  loadCheckpointChainFiles,
  makeCheckpointSignatureVerifier,
} from "../src/lib/verify-checkpoint-chain.js";
import {
  buildCheckpoint,
  buildDelegationCert,
  buildVerifyFixture,
  generateP256KeyPair,
  type VerifyFixture,
} from "./verify-fixture.js";

/**
 * FOR-368 Phase 3 (plan-2607-29): the retained `.sth` chain rung. The
 * fixture MMR grows 3 -> 7 nodes, burying the original peak (node 2) as an
 * interior node — the exact honest-receipt-turns-tamper-shaped scenario.
 * The chain is two checkpoints: sth(0->3) then sth(3->7) (ADR-0056
 * entry-boundary bases).
 */

let fx: VerifyFixture;
let dir: string;
const file = (name: string) => path.join(dir, name);

/** cp1 sth(0->3): base 0, no paths, the single peak arrives as a right-peak. */
async function buildChain(fx: VerifyFixture): Promise<Uint8Array[]> {
  const cp1 = await buildCheckpoint({
    signer: fx.rootKeyPair,
    treeSize1: 0n,
    treeSize2: 3n,
    paths: [],
    rightPeaks: [fx.peak],
    accumulator: [fx.peak],
  });
  // cp2 sth(3->7): old peak (node 2) climbs to peak7 via node5; no right-peaks.
  const cp2 = await buildCheckpoint({
    signer: fx.rootKeyPair,
    treeSize1: 3n,
    treeSize2: 7n,
    paths: [[fx.node5]],
    rightPeaks: [],
    accumulator: [fx.peak7],
  });
  return [cp1, cp2];
}

beforeAll(async () => {
  fx = await buildVerifyFixture();
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

describe("verifyCheckpointChain + CLI trust wiring", () => {
  test("golden: two-link chain folds under the root key; buried peak matches the OLDER link", async () => {
    const checkpoints = await buildChain(fx);
    const chain = await verifyCheckpointChain({
      checkpoints,
      verifySignature: makeCheckpointSignatureVerifier([
        fx.rootKeyPair.publicKey,
      ]),
    });
    expect(chain.ok).toBe(true);
    if (!chain.ok) return;
    expect(chain.links.length).toBe(2);
    expect(chain.accumulator.length).toBe(1);
    expect(Array.from(chain.accumulator[0]!)).toEqual(Array.from(fx.peak7));

    // The receipt's peak (node 2) is buried at size 7 — it must match the
    // older link, never the final accumulator.
    const anchor = checkReceiptAnchoredToCheckpointChain({
      links: chain.links,
      recomputedPeak: fx.peak,
      leafMmrIndex: 1n,
    });
    expect(anchor.anchored).toBe(true);
    expect(anchor.matchedLinkSize).toBe(3n);
    expect(anchor.linkCount).toBe(2);
  });

  test("delegated sealer resolves via the label-1000 cert under the root", async () => {
    const sealer = await generateP256KeyPair();
    const cert = await buildDelegationCert(fx.rootKeyPair, sealer.publicKey);
    const cp1 = await buildCheckpoint({
      signer: sealer,
      treeSize1: 0n,
      treeSize2: 3n,
      paths: [],
      rightPeaks: [fx.peak],
      accumulator: [fx.peak],
      delegationCert: cert,
    });
    const chain = await verifyCheckpointChain({
      checkpoints: [cp1],
      verifySignature: makeCheckpointSignatureVerifier([
        fx.rootKeyPair.publicKey,
      ]),
    });
    expect(chain.ok).toBe(true);
  });

  test("a signer outside the trust root fails the fold with reason signature", async () => {
    const rogue = await generateP256KeyPair();
    const cp1 = await buildCheckpoint({
      signer: rogue,
      treeSize1: 0n,
      treeSize2: 3n,
      paths: [],
      rightPeaks: [fx.peak],
      accumulator: [fx.peak],
    });
    const chain = await verifyCheckpointChain({
      checkpoints: [cp1],
      verifySignature: makeCheckpointSignatureVerifier([
        fx.rootKeyPair.publicKey,
      ]),
    });
    expect(chain.ok).toBe(false);
    if (chain.ok) return;
    expect(chain.reason).toBe("signature");
  });

  test("suffix chain without a trusted base is the legacy break", async () => {
    const checkpoints = await buildChain(fx);
    const chain = await verifyCheckpointChain({
      checkpoints: [checkpoints[1]!],
      verifySignature: makeCheckpointSignatureVerifier([
        fx.rootKeyPair.publicKey,
      ]),
    });
    expect(chain.ok).toBe(false);
    if (chain.ok) return;
    expect(chain.reason).toBe("legacy_chain_break");
  });
});

describe("checkReceiptAnchoredToCheckpointChain (pure)", () => {
  const A = new Uint8Array(32).fill(0xa1);
  const B = new Uint8Array(32).fill(0xb2);
  const C = new Uint8Array(32).fill(0xc3);
  const links: CheckpointChainLink[] = [
    { treeSize1: 0n, treeSize2: 4n, accumulator: [A, B], signatureOk: true },
    { treeSize1: 4n, treeSize2: 10n, accumulator: [C, B], signatureOk: true },
  ];

  test("newest link wins when the peak appears in both", () => {
    const anchor = checkReceiptAnchoredToCheckpointChain({
      links,
      recomputedPeak: B,
      leafMmrIndex: 1n,
    });
    expect(anchor.anchored).toBe(true);
    expect(anchor.matchedLinkSize).toBe(10n);
    expect(anchor.matchedPeak).toBe(1);
  });

  test("newer-than-chain fails closed with the refresh reason", () => {
    const anchor = checkReceiptAnchoredToCheckpointChain({
      links,
      recomputedPeak: A,
      leafMmrIndex: 10n,
    });
    expect(anchor.anchored).toBe(false);
    expect(anchor.reason).toBe("receipt_newer_than_checkpoint_chain");
  });

  test("absent peak reports peak_not_in_checkpoint_chain", () => {
    const anchor = checkReceiptAnchoredToCheckpointChain({
      links,
      recomputedPeak: new Uint8Array(32).fill(0xee),
      leafMmrIndex: 1n,
    });
    expect(anchor.anchored).toBe(false);
    expect(anchor.reason).toBe("peak_not_in_checkpoint_chain");
  });
});
