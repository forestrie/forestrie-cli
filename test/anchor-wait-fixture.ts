/**
 * Fixture for `forestrie log wait-anchored`: a child log's create grant,
 * sequenced as leaf 1 of its owner log, and the owner's MMR at the receipt's
 * size (3 nodes) and after growth (7 nodes), where the receipt's peak is
 * buried under node 6.
 *
 *            6
 *          /   \
 *         2     5
 *        / \   / \
 *       0   1 3   4      leaf 1 is the create grant
 *
 * Test-only; the hashing is the verify fixture's.
 */
import {
  encodeGrantPayload,
  uuidToBytes,
  type Grant,
} from "@forestrie/encoding";
import {
  calculateRoot,
  createSyncHasher,
  type Proof,
} from "@forestrie/merklelog";
import { completeGrantBase64 } from "../src/lib/register-grant-complete.js";
import {
  buildGrantCose,
  buildPeakReceipt,
  entryIdHexFor,
  generateP256KeyPair,
  grantCommitmentHash,
  inclusionProofForIndex,
  univocityLeafHash,
} from "./verify-fixture.js";

export const OWNER_LOG = "7a6b5c4d-0000-4000-8000-000000000001";
export const CHILD_LOG = "7a6b5c4d-0000-4000-8000-000000000002";

export type ChildAnchorFixture = {
  /** Completed create grant (receipt and idtimestamp attached), base64. */
  completedGrantB64: string;
  receiptCbor: Uint8Array;
  idtimestampBe8: Uint8Array;
  /** The grant commitment hash: the leaf's inner value. */
  inner: Uint8Array;
  /** The grant's MMR index in the owner log. */
  leafMmrIndex: bigint;
  /** The receipt's peak: node 2, the owner's only peak at size 3. */
  peak: Uint8Array;
  /** The owner's only peak at size 7: node 6, which buries node 2. */
  peak7: Uint8Array;
  /** The receipt canopy serves once the owner is sealed at size 7. */
  receiptCbor7: Uint8Array;
};

/**
 * A child create grant owned by {@link OWNER_LOG}, at leaf 1 of its MMR.
 * `grantDataFill` varies the grant (and so the leaf) for a foreign one.
 */
export async function buildChildAnchorFixture(
  opts: { grantDataFill?: number } = {},
): Promise<ChildAnchorFixture> {
  const grant: Grant = {
    logId: uuidToBytes(CHILD_LOG),
    ownerLogId: uuidToBytes(OWNER_LOG),
    grant: Uint8Array.from([0, 0, 0, 0x03, 0, 0, 0, 0x01]),
    maxHeight: 0,
    minGrowth: 0,
    grantData: new Uint8Array(64).fill(opts.grantDataFill ?? 0x5c),
  };
  const idtimestampBe8 = new Uint8Array(8).fill(0x02);
  const leaf = await receiptForLeaf(grant, idtimestampBe8);
  const grantCose = await buildGrantCose(
    encodeGrantPayload(grant),
    idtimestampBe8,
  );
  const completedGrantB64 = completeGrantBase64(
    Buffer.from(grantCose).toString("base64"),
    leaf.receiptCbor,
    entryIdHexFor(idtimestampBe8, leaf.leafMmrIndex),
  );
  return { completedGrantB64, idtimestampBe8, ...leaf };
}

/**
 * The receipt for `grant` sequenced at `idtimestampBe8` as leaf 1 of the
 * owner's MMR (the tree above), and the owner's peaks at sizes 3 and 7.
 */
export async function receiptForLeaf(
  grant: Grant,
  idtimestampBe8: Uint8Array,
): Promise<{
  receiptCbor: Uint8Array;
  inner: Uint8Array;
  leafMmrIndex: bigint;
  peak: Uint8Array;
  peak7: Uint8Array;
  receiptCbor7: Uint8Array;
}> {
  const leafMmrIndex = 1n;
  const inner = await grantCommitmentHash(grant);
  const leaf0 = await univocityLeafHash(
    new Uint8Array(8).fill(0x01),
    new Uint8Array(32).fill(0xaa),
  );
  const leaf1 = await univocityLeafHash(idtimestampBe8, inner);
  const leaf3 = await univocityLeafHash(
    new Uint8Array(8).fill(0x03),
    new Uint8Array(32).fill(0xd3),
  );
  const leaf4 = await univocityLeafHash(
    new Uint8Array(8).fill(0x04),
    new Uint8Array(32).fill(0xd4),
  );

  const hasher = await createSyncHasher();
  const proof: Proof = {
    path: inclusionProofForIndex(
      (i) => (i === 0n ? leaf0 : leaf1),
      1n,
      leafMmrIndex,
    ),
    mmrIndex: leafMmrIndex,
  };
  const peak = await calculateRoot(hasher, leaf1, proof, leafMmrIndex);
  const node5 = await calculateRoot(
    hasher,
    leaf3,
    { path: [leaf4], mmrIndex: 3n },
    3n,
  );
  const proof7: Proof = { path: [leaf0, node5], mmrIndex: leafMmrIndex };
  const peak7 = await calculateRoot(hasher, leaf1, proof7, leafMmrIndex);
  const signer = await generateP256KeyPair();
  const receiptCbor = await buildPeakReceipt({ signer, peak, proof });
  const receiptCbor7 = await buildPeakReceipt({
    signer,
    peak: peak7,
    proof: proof7,
  });
  return { receiptCbor, inner, leafMmrIndex, peak, peak7, receiptCbor7 };
}
