import { beforeAll, describe, expect, test } from "bun:test";
import {
  buildConsistencyProofArtifact,
  checkReceiptAnchoredViaConsistencyProof,
  decodeConsistencyProofArtifact,
  encodeConsistencyProofArtifact,
  multiMassifNodeGetter,
  type ConsistencyProofArtifact,
} from "../src/lib/consistency-proof.js";
import { buildVerifyFixture, type VerifyFixture } from "./verify-fixture.js";

/**
 * FOR-368 Phase 3 (plan-2607-29): the portable top-up artifact. Built from
 * the fixture's 7-node massif; the receipt-era peak (node 2, size 3) is
 * buried at size 7 — the artifact extends it tile-free into the trusted
 * accumulator [peak7].
 */

let fx: VerifyFixture;
let artifact: ConsistencyProofArtifact;

beforeAll(async () => {
  fx = await buildVerifyFixture();
  artifact = await buildConsistencyProofArtifact({
    get: multiMassifNodeGetter([fx.massif7Bytes]),
    fromSize: 3n,
    toSize: 7n,
  });
});

describe("buildConsistencyProofArtifact", () => {
  test("derives the base accumulator and per-peak paths from massif nodes", () => {
    expect(artifact.fromSize).toBe(3n);
    expect(artifact.toSize).toBe(7n);
    expect(artifact.accumulatorFrom.length).toBe(1);
    expect(Array.from(artifact.accumulatorFrom[0]!)).toEqual(
      Array.from(fx.peak),
    );
    expect(artifact.paths.length).toBe(1);
    expect(Array.from(artifact.paths[0]![0]!)).toEqual(Array.from(fx.node5));
  });

  test("a range the massifs cannot cover fails at build time (self-check)", async () => {
    await expect(
      buildConsistencyProofArtifact({
        get: multiMassifNodeGetter([fx.massif7Bytes]),
        fromSize: 3n,
        toSize: 15n,
      }),
    ).rejects.toThrow(/not covered/);
  });

  test("degenerate ranges are rejected", async () => {
    await expect(
      buildConsistencyProofArtifact({
        get: multiMassifNodeGetter([fx.massif7Bytes]),
        fromSize: 7n,
        toSize: 3n,
      }),
    ).rejects.toThrow(/--from-size/);
  });
});

describe("artifact codec (strict deterministic CBOR)", () => {
  test("roundtrip", () => {
    const decoded = decodeConsistencyProofArtifact(
      encodeConsistencyProofArtifact(artifact),
    );
    expect(decoded.fromSize).toBe(3n);
    expect(decoded.toSize).toBe(7n);
    expect(Array.from(decoded.accumulatorFrom[0]!)).toEqual(
      Array.from(fx.peak),
    );
  });

  test("wrong base peak count is rejected structurally", () => {
    const bad = encodeConsistencyProofArtifact({
      ...artifact,
      accumulatorFrom: [
        ...artifact.accumulatorFrom,
        new Uint8Array(32).fill(1),
      ],
    });
    expect(() => decodeConsistencyProofArtifact(bad)).toThrow(/peaks/);
  });

  test("unknown version is rejected", () => {
    const bad = encodeConsistencyProofArtifact({ ...artifact, version: 9 });
    expect(() => decodeConsistencyProofArtifact(bad)).toThrow(
      /version 9 not supported/,
    );
  });
});

describe("checkReceiptAnchoredViaConsistencyProof", () => {
  test("golden: buried receipt peak extends into the trusted accumulator", async () => {
    const check = await checkReceiptAnchoredViaConsistencyProof({
      artifact,
      recomputedPeak: fx.peak,
      leafMmrIndex: 1n,
      trustedSize: 7n,
      trustedAccumulator: [fx.peak7],
    });
    expect(check.anchored).toBe(true);
    expect(check.matchedPeak).toBe(0);
  });

  test("artifact for a different target size never applies", async () => {
    const check = await checkReceiptAnchoredViaConsistencyProof({
      artifact,
      recomputedPeak: fx.peak,
      leafMmrIndex: 1n,
      trustedSize: 15n,
      trustedAccumulator: [fx.peak7],
    });
    expect(check.anchored).toBe(false);
    expect(check.reason).toBe("consistency_proof_target_mismatch");
  });

  test("receipt newer than the artifact base fails closed", async () => {
    const check = await checkReceiptAnchoredViaConsistencyProof({
      artifact,
      recomputedPeak: fx.peak,
      leafMmrIndex: 5n,
      trustedSize: 7n,
      trustedAccumulator: [fx.peak7],
    });
    expect(check.anchored).toBe(false);
    expect(check.reason).toBe("receipt_newer_than_consistency_proof_base");
  });

  test("a peak outside the artifact base cannot anchor", async () => {
    const check = await checkReceiptAnchoredViaConsistencyProof({
      artifact,
      recomputedPeak: new Uint8Array(32).fill(0xee),
      leafMmrIndex: 1n,
      trustedSize: 7n,
      trustedAccumulator: [fx.peak7],
    });
    expect(check.anchored).toBe(false);
    expect(check.reason).toBe("peak_not_in_consistency_proof_base");
  });

  test("a tampered path can only FAIL against the trusted state", async () => {
    const forgedPath = artifact.paths.map((p) =>
      p.map((n) => new Uint8Array(n)),
    );
    forgedPath[0]![0]![0]! ^= 0xff;
    const check = await checkReceiptAnchoredViaConsistencyProof({
      artifact: { ...artifact, paths: forgedPath },
      recomputedPeak: fx.peak,
      leafMmrIndex: 1n,
      trustedSize: 7n,
      trustedAccumulator: [fx.peak7],
    });
    expect(check.anchored).toBe(false);
    expect(check.reason).toBe("consistency_proof_invalid");
  });
});
