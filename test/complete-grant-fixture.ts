/**
 * Fixture for `forestrie complete-grant` (FOR-344): a signed (uncompleted)
 * Forestrie-Grant statement, plus the owner-log massif (`.log`) and checkpoint
 * (`.sth`) a client would fetch. The massif's urkle index region is populated
 * so the grant's leaf is locatable by its commitment hash offline — the whole
 * point of complete-grant.
 *
 * MMR (3 leaves, size 4): 0=grant leaf, 1=filler, 2=H(3||n0||n1), 3=filler.
 * The grant under test sits at mmrIndex 0 (proof: 1 node → peak n2).
 */
import { encodeGrantPayload, type Grant } from "@forestrie/encoding";
import { grantCommitmentHashFromGrant } from "@forestrie/receipt-verify";
import {
  FIXTURE_LOG_ID,
  buildGenesisCbor,
  buildGrantCose,
  entryIdHexFor,
  generateP256KeyPair,
  grantWithData,
  univocityLeafHash,
} from "./verify-fixture.js";
import {
  buildV2CheckpointBytes,
  buildV2MassifBytes,
  positionCommittedInteriorHash,
  signDetachedPeakReceipt,
} from "./create-receipt-fixture.js";

export type CompleteGrantFixture = {
  genesisCbor: Uint8Array;
  massifBytes: Uint8Array;
  checkpointBytes: Uint8Array;
  /** Uncompleted grant statement (no receipt / idtimestamp yet), base64. */
  grantB64: string;
  grant: Grant;
  /** Sequenced idtimestamp the massif index records for the grant leaf. */
  idtimestampBe8: Uint8Array;
  mmrIndex: bigint;
  entryIdHex: string;
  rootKeyPair: CryptoKeyPair;
};

async function leaf(
  grantData: Uint8Array,
  idFill: number,
): Promise<{ grant: Grant; inner: Uint8Array; id: Uint8Array; hash: Uint8Array }> {
  const grant = grantWithData(FIXTURE_LOG_ID, grantData);
  const inner = await grantCommitmentHashFromGrant(grant);
  const id = new Uint8Array(8).fill(idFill);
  const hash = await univocityLeafHash(id, inner);
  return { grant, inner, id, hash };
}

export async function buildCompleteGrantFixture(): Promise<CompleteGrantFixture> {
  const rootKeyPair = await generateP256KeyPair();
  const rootRaw = new Uint8Array(
    (await crypto.subtle.exportKey("raw", rootKeyPair.publicKey)) as ArrayBuffer,
  );
  const bootstrapKey = rootRaw.slice(1); // x||y (64 bytes)

  // leaf 0 is the grant under test; leaves 1,2 are fillers.
  const l0 = await leaf(new Uint8Array(64).fill(0x77), 0x01);
  const l1 = await leaf(new Uint8Array(64).fill(0xaa), 0x02);
  const l2 = await leaf(new Uint8Array(64).fill(0xbb), 0x03);

  const n0 = l0.hash;
  const n1 = l1.hash;
  const n2 = await positionCommittedInteriorHash(3n, n0, n1);
  const n3 = l2.hash;

  const massifBytes = buildV2MassifBytes({
    massifHeight: 3,
    massifIndex: 0,
    logHashes: [n0, n1, n2, n3],
    leafRecords: [
      { idtimestampBe8: l0.id, valueBytes: l0.inner },
      { idtimestampBe8: l1.id, valueBytes: l1.inner },
      { idtimestampBe8: l2.id, valueBytes: l2.inner },
    ],
  });

  const checkpointBytes = buildV2CheckpointBytes({
    mmrSize: 4n,
    peakReceipts: [
      await signDetachedPeakReceipt(rootKeyPair, n2),
      await signDetachedPeakReceipt(rootKeyPair, n3),
    ],
  });

  // The UNcompleted grant carries no idtimestamp (zeros = absent); complete-grant
  // recovers it from the massif leaf key.
  const grantPayloadCbor = encodeGrantPayload(l0.grant);
  const grantCose = await buildGrantCose(grantPayloadCbor, new Uint8Array(8));

  return {
    genesisCbor: buildGenesisCbor(bootstrapKey),
    massifBytes,
    checkpointBytes,
    grantB64: Buffer.from(grantCose).toString("base64"),
    grant: l0.grant,
    idtimestampBe8: l0.id,
    mmrIndex: 0n,
    entryIdHex: entryIdHexFor(l0.id, 0n),
    rootKeyPair,
  };
}
