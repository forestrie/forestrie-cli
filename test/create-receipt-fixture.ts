/**
 * Fixture massif (`.log`) + checkpoint (`.sth`) blobs for
 * `forestrie create-receipt` tests — a self-contained port of canopy
 * `packages/libs/receipt-verify/test/helpers/massif-checkpoint-fixture.ts`
 * (the package's own test vectors are not published). Test-only: the CLI
 * never imports from here; the load-bearing derivation stays in
 * `@forestrie/receipt-verify`.
 *
 * Fixture MMR (3 leaves, size 4):
 *   nodes: 0=leaf0, 1=leaf1, 2=H(3||n0||n1), 3=leaf2
 *   peaks at size 3: [n2]; peaks at size 4: [n2, n3]
 */
import { encode as encodeCbor } from "cbor-x";
import { encodeSigStructure, type Grant } from "@forestrie/encoding";
import {
  buildGenesisCbor,
  entryIdHexFor,
  FIXTURE_LOG_ID,
  generateP256KeyPair,
  grantCommitmentHash,
  grantWithData,
  univocityLeafHash,
} from "./verify-fixture.js";

const SEAL_PEAK_RECEIPTS_LABEL = -65931;
const DELEGATION_CERT_LABEL = 1000;

const VALUE_BYTES = 32;
const RESERVED_HEADER_SLOTS = 7;
const INDEX_HEADER_BYTES = 32;
const MAX_MMR_HEIGHT = 64;
const BLOOM_BITS_PER_ELEMENT_V1 = 10;
const BLOOM_FILTERS = 4;
const BLOOM_HEADER_BYTES_V1 = 32;
const URKLE_FRONTIER_STATE_V1_BYTES = 544;
const URKLE_LEAF_RECORD_BYTES = 128;
const URKLE_NODE_RECORD_BYTES = 64;

function cborBytes(value: unknown): Uint8Array {
  const encoded = encodeCbor(value);
  return encoded instanceof Uint8Array
    ? encoded
    : new Uint8Array(encoded as ArrayLike<number>);
}

/** Build v2 massif bytes with `logHashes[i]` at MMR log index i. */
export function buildV2MassifBytes(opts: {
  massifHeight: number;
  massifIndex: number;
  logHashes: Uint8Array[];
}): Uint8Array {
  const { massifHeight, massifIndex, logHashes } = opts;
  const leafCount = 1 << (massifHeight - 1);
  const mBits = BLOOM_BITS_PER_ELEMENT_V1 * leafCount;
  const bitsetBytes = Math.ceil(mBits / 8);
  const bloomRegionBytes = BLOOM_HEADER_BYTES_V1 + BLOOM_FILTERS * bitsetBytes;
  const bloomBitsetsBytes = bloomRegionBytes - BLOOM_HEADER_BYTES_V1;
  const leafTableBytes = leafCount * URKLE_LEAF_RECORD_BYTES;
  const nodeStoreBytes = (2 * leafCount - 1) * URKLE_NODE_RECORD_BYTES;
  const indexDataBytes =
    bloomBitsetsBytes +
    URKLE_FRONTIER_STATE_V1_BYTES +
    leafTableBytes +
    nodeStoreBytes;

  const fixedHeaderEnd = VALUE_BYTES + VALUE_BYTES * RESERVED_HEADER_SLOTS;
  const trieHeaderEnd = fixedHeaderEnd + INDEX_HEADER_BYTES;
  const peakStackStart = trieHeaderEnd + indexDataBytes;
  const logStart = peakStackStart + MAX_MMR_HEIGHT * VALUE_BYTES;

  const massifBytes = new Uint8Array(logStart + logHashes.length * VALUE_BYTES);
  const view = new DataView(massifBytes.buffer);

  view.setBigUint64(8, 0n, false);
  view.setUint16(21, 2, false); // format version 2
  view.setUint32(23, 1, false); // commitment epoch
  massifBytes[27] = massifHeight;
  view.setUint32(28, massifIndex, false);

  for (let i = 0; i < logHashes.length; i++) {
    const h = logHashes[i]!;
    if (h.length !== 32) {
      throw new Error(`logHashes[${i}] must be 32 bytes`);
    }
    massifBytes.set(h, logStart + i * VALUE_BYTES);
  }

  return massifBytes;
}

/**
 * Format-v3 checkpoint (ADR-0046): detached (null) payload; the sealed
 * size travels as tree-size-2 of the consistency proof under the
 * verifiable-proofs unprotected header (label 396, key -2); pre-signed
 * peak receipts under label -65931; optional delegation cert at 1000.
 */
export function buildV2CheckpointBytes(opts: {
  mmrSize: bigint;
  peakReceipts: Uint8Array[];
  delegationCert?: Uint8Array;
}): Uint8Array {
  const consistencyProof = cborBytes([0n, opts.mmrSize, [], []]);
  const verifiableProofs = new Map<number, unknown>([[-2, consistencyProof]]);
  const checkpointUnprotected = new Map<number, unknown>([
    [396, verifiableProofs],
    [SEAL_PEAK_RECEIPTS_LABEL, opts.peakReceipts],
  ]);
  if (opts.delegationCert?.length) {
    checkpointUnprotected.set(DELEGATION_CERT_LABEL, opts.delegationCert);
  }
  return cborBytes([
    new Uint8Array(),
    checkpointUnprotected,
    null,
    new Uint8Array(),
  ]);
}

/** 8-byte big-endian, matching go `HashWriteUint64`. */
function u64BigEndian(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let v = value & 0xffffffffffffffffn;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * Interior MMR node hash the go-merklelog / spec way:
 * `H(pos_BE8 || left || right)` where `pos` is the 1-based node position.
 * Built directly via crypto.subtle so fixtures are independent of the
 * implementation under test.
 */
export async function positionCommittedInteriorHash(
  pos: bigint,
  left: Uint8Array,
  right: Uint8Array,
): Promise<Uint8Array> {
  const combined = new Uint8Array(8 + left.length + right.length);
  combined.set(u64BigEndian(pos), 0);
  combined.set(left, 8);
  combined.set(right, 8 + left.length);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", combined));
}

/**
 * Raw pre-signed peak receipt as the sealer emits into the checkpoint:
 * detached (nil) payload, NO header 396 — the inclusion proof is attached
 * by the receipt builder.
 */
export async function signDetachedPeakReceipt(
  signer: CryptoKeyPair,
  peak: Uint8Array,
): Promise<Uint8Array> {
  const protectedInner = cborBytes(new Map<number, unknown>([[1, -7]]));
  const sigStructure = encodeSigStructure(
    protectedInner,
    new Uint8Array(0),
    peak,
  );
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      signer.privateKey,
      sigStructure.buffer.slice(
        sigStructure.byteOffset,
        sigStructure.byteOffset + sigStructure.byteLength,
      ) as ArrayBuffer,
    ),
  );
  return cborBytes([protectedInner, new Map<number, unknown>(), null, sig]);
}

export type FixtureLeaf = {
  grant: Grant;
  idtimestampBe8: Uint8Array;
  leafHash: Uint8Array;
  mmrIndex: bigint;
  entryIdHex: string;
};

export type CreateReceiptFixture = {
  rootKeyPair: CryptoKeyPair;
  genesisCbor: Uint8Array;
  massifBytes: Uint8Array;
  /** Sealed size 3 — single peak (n2). */
  checkpointSize3: Uint8Array;
  /** Sealed size 4 — two peaks (n2, n3). */
  checkpointSize4: Uint8Array;
  /** Sealed size 3, with a delegation cert (label 1000) to copy. */
  checkpointWithCert: Uint8Array;
  delegationCert: Uint8Array;
  leaf0: FixtureLeaf;
  leaf1: FixtureLeaf;
  leaf2: FixtureLeaf;
  n0: Uint8Array;
  n1: Uint8Array;
  n2: Uint8Array;
  n3: Uint8Array;
};

async function fixtureLeaf(
  grantData: Uint8Array,
  idFill: number,
  mmrIndex: bigint,
): Promise<FixtureLeaf> {
  const grant = grantWithData(FIXTURE_LOG_ID, grantData);
  const idtimestampBe8 = new Uint8Array(8).fill(idFill);
  const inner = await grantCommitmentHash(grant);
  const leafHash = await univocityLeafHash(idtimestampBe8, inner);
  return {
    grant,
    idtimestampBe8,
    leafHash,
    mmrIndex,
    entryIdHex: entryIdHexFor(idtimestampBe8, mmrIndex),
  };
}

export async function buildCreateReceiptFixture(): Promise<CreateReceiptFixture> {
  const rootKeyPair = await generateP256KeyPair();
  const rootRaw = new Uint8Array(
    (await crypto.subtle.exportKey(
      "raw",
      rootKeyPair.publicKey,
    )) as ArrayBuffer,
  );
  const bootstrapKey = rootRaw.slice(1); // x||y (64 bytes)
  const genesisCbor = buildGenesisCbor(bootstrapKey);

  const leaf0 = await fixtureLeaf(new Uint8Array(64).fill(0xaa), 0x01, 0n);
  const leaf1 = await fixtureLeaf(bootstrapKey, 0x02, 1n);
  const leaf2 = await fixtureLeaf(new Uint8Array(64).fill(0xbb), 0x03, 3n);

  const n0 = leaf0.leafHash;
  const n1 = leaf1.leafHash;
  const n2 = await positionCommittedInteriorHash(3n, n0, n1);
  const n3 = leaf2.leafHash;

  const massifBytes = buildV2MassifBytes({
    massifHeight: 3,
    massifIndex: 0,
    logHashes: [n0, n1, n2, n3],
  });

  const peakReceiptN2 = await signDetachedPeakReceipt(rootKeyPair, n2);
  const peakReceiptN3 = await signDetachedPeakReceipt(rootKeyPair, n3);
  // Stand-in cert bstr: create-receipt copies label 1000 verbatim; the
  // offline verify trust root still resolves from genesis (FOR-297 wires
  // cert consumption later).
  const delegationCert = new Uint8Array(48).fill(0xcd);

  return {
    rootKeyPair,
    genesisCbor,
    massifBytes,
    checkpointSize3: buildV2CheckpointBytes({
      mmrSize: 3n,
      peakReceipts: [peakReceiptN2],
    }),
    checkpointSize4: buildV2CheckpointBytes({
      mmrSize: 4n,
      peakReceipts: [peakReceiptN2, peakReceiptN3],
    }),
    checkpointWithCert: buildV2CheckpointBytes({
      mmrSize: 3n,
      peakReceipts: [peakReceiptN2],
      delegationCert,
    }),
    delegationCert,
    leaf0,
    leaf1,
    leaf2,
    n0,
    n1,
    n2,
    n3,
  };
}

export type MultiPeakLeaf = {
  grant: Grant;
  idtimestampBe8: Uint8Array;
  mmrIndex: bigint;
  entryIdHex: string;
};

export type MultiPeakFixture = {
  rootKeyPair: CryptoKeyPair;
  genesisCbor: Uint8Array;
  massifBytes: Uint8Array;
  /** Sealed size 11 — three peaks at mmr indexes 6, 9, 10. */
  checkpoint: Uint8Array;
  /** Peak mmr indexes in the checkpoint's -65931 order (ascending). */
  peakMMRIndexes: bigint[];
  leaves: MultiPeakLeaf[];
};

/**
 * A size-11 (7-leaf, height-4) multi-peak fixture: the case that pins
 * create-receipt's peak narration for a leaf under a *non-top* peak.
 *
 * MMR layout (index = content):
 *   0=leaf0 1=leaf1 2=H(0,1) 3=leaf2 4=leaf3 5=H(3,4) 6=H(2,5)
 *   7=leaf4 8=leaf5 9=H(7,8) 10=leaf6
 * Peaks at size 11: [6, 9, 10] — descending height / ascending mmr index,
 * the order the sealer (go-merklelog PeakHashes) writes the -65931 array in.
 * leaf 0 lives under the leftmost, tallest peak (n6), so its correctly
 * narrated peak is mmr index 6, NOT the top peak 10.
 */
export async function buildMultiPeakFixture(): Promise<MultiPeakFixture> {
  const rootKeyPair = await generateP256KeyPair();
  const rootRaw = new Uint8Array(
    (await crypto.subtle.exportKey(
      "raw",
      rootKeyPair.publicKey,
    )) as ArrayBuffer,
  );
  const bootstrapKey = rootRaw.slice(1);
  const genesisCbor = buildGenesisCbor(bootstrapKey);

  // 7 leaves at mmr indexes 0, 1, 3, 4, 7, 8, 10.
  const leafMMRIndexes = [0n, 1n, 3n, 4n, 7n, 8n, 10n];
  const leaves: MultiPeakLeaf[] = [];
  const leafHashes: Uint8Array[] = [];
  for (let i = 0; i < leafMMRIndexes.length; i++) {
    const idFill = 0x10 + i;
    const leaf = await fixtureLeaf(
      new Uint8Array(64).fill(idFill),
      idFill,
      leafMMRIndexes[i]!,
    );
    leaves.push({
      grant: leaf.grant,
      idtimestampBe8: leaf.idtimestampBe8,
      mmrIndex: leaf.mmrIndex,
      entryIdHex: leaf.entryIdHex,
    });
    leafHashes.push(leaf.leafHash);
  }
  const [n0, n1, n3, n4, n7, n8, n10] = leafHashes as [
    Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array,
    Uint8Array,
  ];
  // Interior nodes keyed by 1-based position (index + 1).
  const n2 = await positionCommittedInteriorHash(3n, n0, n1);
  const n5 = await positionCommittedInteriorHash(6n, n3, n4);
  const n6 = await positionCommittedInteriorHash(7n, n2, n5);
  const n9 = await positionCommittedInteriorHash(10n, n7, n8);

  const massifBytes = buildV2MassifBytes({
    massifHeight: 4,
    massifIndex: 0,
    logHashes: [n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10],
  });

  // Peak receipts in the sealer's order: peaks 6, 9, 10 (ascending mmr index).
  const peakReceipts = [
    await signDetachedPeakReceipt(rootKeyPair, n6),
    await signDetachedPeakReceipt(rootKeyPair, n9),
    await signDetachedPeakReceipt(rootKeyPair, n10),
  ];

  return {
    rootKeyPair,
    genesisCbor,
    massifBytes,
    checkpoint: buildV2CheckpointBytes({ mmrSize: 11n, peakReceipts }),
    peakMMRIndexes: [6n, 9n, 10n],
    leaves,
  };
}

/** Flip a bit in the sibling node (n0) log data — last 4 fields are nodes. */
export function tamperMassifSibling(massifBytes: Uint8Array): Uint8Array {
  const tampered = massifBytes.slice();
  tampered[tampered.length - 4 * 32]! ^= 0x01;
  return tampered;
}
