/**
 * Golden fixture builder for `forestrie verify` tests — a self-contained
 * port of canopy `packages/libs/receipt-verify/test/helpers/*` (the
 * package's own test vectors are not published). Test-only: the CLI never
 * imports from here; the load-bearing verification stays in
 * `@forestrie/receipt-verify`.
 *
 * `cbor-x` is imported as a transitive dependency of
 * `@forestrie/receipt-verify` (test-only convenience; not a package dep).
 */
import { encode as encodeCbor } from "cbor-x";
import {
  encodeGrantPayload,
  encodeSigStructure,
  grantDataToBytes,
  toPaddedWire32,
  uuidToBytes,
  type Grant,
} from "@forestrie/encoding";
import {
  calculateRoot,
  createSyncHasher,
  type Proof,
} from "@forestrie/merklelog";

/** Forest genesis wire labels (stable; see receipt-verify forest-genesis-labels). */
const LABEL_GENESIS_VERSION = -68009;
const LABEL_UNIVOCITY_ADDR = -68011;
const LABEL_CHAIN_ID = -68013;
const LABEL_GENESIS_ALG = -68014;
const LABEL_BOOTSTRAP_KEY = -68015;
const LABEL_LOG_ID = -68010;
const GENESIS_SCHEMA_V2 = 2;
const COSE_ALG_ES256 = -7;
const COSE_ALG_KS256 = -65799;

/** Forestrie-Grant COSE unprotected header labels. */
const HEADER_IDTIMESTAMP = -65537;
const HEADER_FORESTRIE_GRANT_V0 = -65538;

const VDS_COSE_RECEIPT_PROOFS_TAG = 396;

export const FIXTURE_LOG_ID = "660e8400-e29b-41d4-a716-446655440001";

function cborBytes(value: unknown): Uint8Array {
  const encoded = encodeCbor(value);
  return encoded instanceof Uint8Array
    ? encoded
    : new Uint8Array(encoded as ArrayLike<number>);
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      bytes.buffer.slice(
        bytes.byteOffset,
        bytes.byteOffset + bytes.byteLength,
      ) as ArrayBuffer,
    ),
  );
}

function u64Be(n: number | bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n) & 0xffffffffffffffffn);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// --- grant commitment + univocity leaf hash (mirror of receipt-verify
// internals, which are not exported; the golden test proves parity because
// verifyGrantReceiptOffline accepts receipts built from these). ---

function grantFlags32(flags: Uint8Array): Uint8Array {
  const out = new Uint8Array(32);
  if (flags.length >= 8) {
    out.set(flags.slice(-8), 24);
  } else if (flags.length > 0) {
    out.set(flags, 32 - flags.length);
  }
  return out;
}

export async function grantCommitmentHash(grant: Grant): Promise<Uint8Array> {
  const logId = toPaddedWire32(grant.logId);
  const flags32 = grantFlags32(grant.grant);
  const ownerLogId = toPaddedWire32(grant.ownerLogId);
  const grantData = grantDataToBytes(grant.grantData ?? new Uint8Array(0));
  const preimage = new Uint8Array(
    logId.length + 32 + 16 + ownerLogId.length + grantData.length,
  );
  let off = 0;
  preimage.set(logId, off);
  off += logId.length;
  preimage.set(flags32, off);
  off += 32;
  preimage.set(u64Be(grant.maxHeight ?? 0), off);
  off += 8;
  preimage.set(u64Be(grant.minGrowth ?? 0), off);
  off += 8;
  preimage.set(ownerLogId, off);
  off += ownerLogId.length;
  preimage.set(grantData, off);
  return sha256(preimage);
}

export async function univocityLeafHash(
  idtimestampBe8: Uint8Array,
  grantCommitment: Uint8Array,
): Promise<Uint8Array> {
  const preimage = new Uint8Array(8 + grantCommitment.length);
  preimage.set(idtimestampBe8.slice(-8));
  preimage.set(grantCommitment, 8);
  return sha256(preimage);
}

// --- minimal MMR inclusion proof (port of canopy test helper) ---

function allOnes(num: bigint): boolean {
  return num > 0n && (num & (num + 1n)) === 0n;
}

function bitLength(num: bigint): number {
  return num === 0n ? 0 : num.toString(2).length;
}

function indexHeight(i: bigint): number {
  let current = i + 1n;
  while (!allOnes(current)) {
    const msb = 1n << BigInt(bitLength(current) - 1);
    current = current - (msb - 1n);
  }
  return bitLength(current) - 1;
}

export function inclusionProofForIndex(
  getHash: (mmrIndex: bigint) => Uint8Array,
  mmrLastIndex: bigint,
  targetIndex: bigint,
): Uint8Array[] {
  if (targetIndex > mmrLastIndex) throw new Error("index out of range");
  let i = targetIndex;
  let g = BigInt(indexHeight(i));
  const proof: Uint8Array[] = [];
  for (;;) {
    const siblingOffset = 2n << g;
    let iSibling: bigint;
    if (BigInt(indexHeight(i + 1n)) > g) {
      iSibling = i - siblingOffset + 1n;
      i += 1n;
    } else {
      iSibling = i + siblingOffset - 1n;
      i += siblingOffset;
    }
    if (iSibling > mmrLastIndex) return proof;
    proof.push(getHash(iSibling));
    g += 1n;
  }
}

// --- COSE receipt / grant builders ---

export async function generateP256KeyPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
}

async function signPeak(
  signer: CryptoKeyPair,
  protectedInner: Uint8Array,
  peak: Uint8Array,
): Promise<Uint8Array> {
  const sigStructure = encodeSigStructure(
    protectedInner,
    new Uint8Array(0),
    peak,
  );
  return new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      signer.privateKey,
      sigStructure.buffer.slice(
        sigStructure.byteOffset,
        sigStructure.byteOffset + sigStructure.byteLength,
      ) as ArrayBuffer,
    ),
  );
}

/**
 * Build a checkpoint peak receipt: COSE Sign1 with the MMR inclusion proof
 * in unprotected header 396 and the peak either detached (payload nil) or
 * attached (payload = peak).
 */
export async function buildPeakReceipt(opts: {
  signer: CryptoKeyPair;
  peak: Uint8Array;
  proof: Proof;
  attachPeak?: boolean;
  proofPathOverride?: Uint8Array[];
}): Promise<Uint8Array> {
  const protectedInner = cborBytes(new Map<number, unknown>([[1, -7]]));
  const sig = await signPeak(opts.signer, protectedInner, opts.peak);
  const mmrIndex = opts.proof.mmrIndex ?? opts.proof.leafIndex ?? 0n;
  const inclusionProofEntry = new Map<number, unknown>([
    [1, mmrIndex],
    [2, opts.proofPathOverride ?? opts.proof.path],
  ]);
  const unprot = new Map<number, unknown>([
    [VDS_COSE_RECEIPT_PROOFS_TAG, new Map<number, unknown>([[-1, [inclusionProofEntry]]])],
  ]);
  const payload = opts.attachPeak ? opts.peak : null;
  return cborBytes([protectedInner, unprot, payload, sig]);
}

export function grantWithData(logId: string, grantData: Uint8Array): Grant {
  const owner = uuidToBytes(logId);
  const g = new Uint8Array(8);
  g[3] = 0x03;
  g[7] = 0x01;
  return {
    logId: owner,
    ownerLogId: owner,
    grant: g,
    maxHeight: 0,
    minGrowth: 0,
    grantData,
  };
}

/** Forestrie-Grant COSE Sign1 (transparent statement profile) for --committed-grant. */
export async function buildGrantCose(
  grantPayloadCbor: Uint8Array,
  idtimestampBe8: Uint8Array,
): Promise<Uint8Array> {
  const protectedInner = cborBytes(new Map<number, unknown>([[1, -7]]));
  const unprot = new Map<number, unknown>([
    [HEADER_FORESTRIE_GRANT_V0, grantPayloadCbor],
    [HEADER_IDTIMESTAMP, idtimestampBe8],
  ]);
  return cborBytes([
    protectedInner,
    unprot,
    await sha256(grantPayloadCbor),
    new Uint8Array(64), // signature is not checked by decodeForestrieGrantCose
  ]);
}

export type VerifyFixture = {
  genesisCbor: Uint8Array;
  ks256GenesisCbor: Uint8Array;
  receiptCbor: Uint8Array;
  attachedPeakReceiptCbor: Uint8Array;
  tamperedPathReceiptCbor: Uint8Array;
  grant: Grant;
  grantPayloadCbor: Uint8Array;
  grantCoseCbor: Uint8Array;
  grantCoseB64: string;
  idtimestampBe8: Uint8Array;
  entryIdHex: string;
  peak: Uint8Array;
  rootKeyPair: CryptoKeyPair;
};

/** Forest genesis CBOR with `bootstrapKey` (ES256 x||y) as the trust root. */
export function buildGenesisCbor(bootstrapKey: Uint8Array): Uint8Array {
  return cborBytes(
    new Map<number, unknown>([
      [LABEL_GENESIS_VERSION, GENESIS_SCHEMA_V2],
      [LABEL_GENESIS_ALG, COSE_ALG_ES256],
      [LABEL_BOOTSTRAP_KEY, bootstrapKey],
      [LABEL_UNIVOCITY_ADDR, new Uint8Array(20).fill(0xab)],
      [LABEL_CHAIN_ID, "84532"],
      [LABEL_LOG_ID, toPaddedWire32(uuidToBytes(FIXTURE_LOG_ID))],
    ]),
  );
}

/** Permanent SCRAPI entry id: idtimestamp_be8 || mmrIndex_be8, hex. */
export function entryIdHexFor(
  idtimestampBe8: Uint8Array,
  mmrIndex: bigint,
): string {
  return bytesToHex(idtimestampBe8) + bytesToHex(u64Be(mmrIndex));
}

/**
 * Two-leaf MMR: leaf 0 is an unrelated grant, leaf 1 (mmrIndex 1) is the
 * grant under test. The checkpoint peak is their parent; the genesis trust
 * root is the checkpoint signer's ES256 key.
 */
export async function buildVerifyFixture(): Promise<VerifyFixture> {
  const rootKeyPair = await generateP256KeyPair();
  const rootRaw = new Uint8Array(
    (await crypto.subtle.exportKey("raw", rootKeyPair.publicKey)) as ArrayBuffer,
  );
  const bootstrapKey = rootRaw.slice(1); // x||y (64 bytes)

  const grant = grantWithData(FIXTURE_LOG_ID, bootstrapKey);
  const idtimestampBe8 = new Uint8Array(8).fill(0x02);
  const mmrIndex = 1n;
  const entryIdHex = entryIdHexFor(idtimestampBe8, mmrIndex);

  const inner0 = await grantCommitmentHash(
    grantWithData(FIXTURE_LOG_ID, new Uint8Array(64).fill(0xaa)),
  );
  const inner1 = await grantCommitmentHash(grant);
  const leaf0Hash = await univocityLeafHash(new Uint8Array(8).fill(0x01), inner0);
  const leaf1Hash = await univocityLeafHash(idtimestampBe8, inner1);

  const getHash = (i: bigint) => (i === 0n ? leaf0Hash : leaf1Hash);
  const proof: Proof = {
    path: inclusionProofForIndex(getHash, 1n, mmrIndex),
    mmrIndex,
  };
  const hasher = await createSyncHasher();
  const peak = await calculateRoot(hasher, leaf1Hash, proof, mmrIndex);

  const receiptCbor = await buildPeakReceipt({
    signer: rootKeyPair,
    peak,
    proof,
  });
  const attachedPeakReceiptCbor = await buildPeakReceipt({
    signer: rootKeyPair,
    peak,
    proof,
    attachPeak: true,
  });
  const badPath = proof.path.map((p) => new Uint8Array(p));
  badPath[0]![0]! ^= 0xff;
  const tamperedPathReceiptCbor = await buildPeakReceipt({
    signer: rootKeyPair,
    peak,
    proof,
    attachPeak: true,
    proofPathOverride: badPath,
  });

  const genesisCbor = buildGenesisCbor(bootstrapKey);
  const ks256GenesisCbor = cborBytes(
    new Map<number, unknown>([
      [LABEL_GENESIS_VERSION, GENESIS_SCHEMA_V2],
      [LABEL_GENESIS_ALG, COSE_ALG_KS256],
      [LABEL_BOOTSTRAP_KEY, new Uint8Array(20).fill(0xab)],
      [LABEL_UNIVOCITY_ADDR, new Uint8Array(20).fill(0xab)],
      [LABEL_CHAIN_ID, "84532"],
    ]),
  );

  const grantPayloadCbor = encodeGrantPayload(grant);
  const grantCoseCbor = await buildGrantCose(grantPayloadCbor, idtimestampBe8);
  const grantCoseB64 = Buffer.from(grantCoseCbor).toString("base64");

  return {
    genesisCbor,
    ks256GenesisCbor,
    receiptCbor,
    attachedPeakReceiptCbor,
    tamperedPathReceiptCbor,
    grant,
    grantPayloadCbor,
    grantCoseCbor,
    grantCoseB64,
    idtimestampBe8,
    entryIdHex,
    peak,
    rootKeyPair,
  };
}

/** Flip the last byte (inside the COSE signature bstr): stage=signature. */
export function tamperSignature(receiptCbor: Uint8Array): Uint8Array {
  const out = new Uint8Array(receiptCbor);
  out[out.length - 1]! ^= 0xff;
  return out;
}

/** ABI-encode a `logState(bytes32)` result: tuple (bytes32[] accumulator, uint64 size). */
export function encodeLogStateResult(
  accumulator: Uint8Array[],
  size: bigint,
): string {
  const word = (v: bigint) => v.toString(16).padStart(64, "0");
  let hex = word(0x20n); // offset to the tuple
  hex += word(0x40n); // offset to the accumulator array (relative to tuple)
  hex += word(size);
  hex += word(BigInt(accumulator.length));
  for (const peak of accumulator) {
    hex += bytesToHex(peak).padStart(64, "0");
  }
  return "0x" + hex;
}
