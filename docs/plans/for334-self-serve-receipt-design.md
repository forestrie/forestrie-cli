# FOR-334 — self-serve receipt derivation design

Design spike for [FOR-334](https://linear.app/forestrie/issue/FOR-334)
(self-created receipts). This is the design that unblocks
`forestrie create-receipt` ([FOR-345](https://linear.app/forestrie/issue/FOR-345)),
shapes `forestrie complete-grant`
([FOR-344](https://linear.app/forestrie/issue/FOR-344)), and couples to
[FOR-368](https://linear.app/forestrie/issue/FOR-368) (buried peaks) and
[FOR-323](https://linear.app/forestrie/issue/FOR-323) (ephemeral keys in
receipts).

**Thesis (the product claim being engineered):** receipts are derivable from
the log data; the operator's receipt endpoint is a convenience, not an
authority. This capability is a locked product differentiator — the format-v3
cutover explicitly preserved it (pre-signed peak receipts under label
`-65931`; devdocs
[plan-0033 format-v3 cutover status](https://github.com/forestrie/devdocs/blob/905485bcf48b/plans/plan-0033-format-v3-cutover-status.md)),
and any future format migration must carry it forward.

**Soundness anchor:** the checkpoint signature covers *only the accumulator*
— `SignCheckpointReceipt` signs `DetachedPayload(accumulator)` =
`concat(peaks)`, and each pre-signed peak receipt signs a single peak hash
([go-merklelog `massifs/checkpointsign.go:104`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/checkpointsign.go#L104),
[`:163`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/checkpointsign.go#L163);
[ADR-0046](https://github.com/forestrie/devdocs/blob/905485bcf48b/adr/adr-0046-checkpoint-is-consistency-receipt.md)).
Inclusion paths are unsigned and freely recomputable by anyone holding the
node data — the same property that made the publisher's lagging-anchor rebuild
sound (arbor
[PR #38](https://github.com/forestrie/arbor/pull/38),
`services/pkgs/publishproof/assemble.go`).

---

## 1. Ground truth — what a client holds and what it means

### 1.1 The massif `.log` blob

Fixed, offset-computable v2 layout
([go-merklelog `massifs/logformat.go`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/logformat.go)):

| Region | Offset | Size | Content |
|---|---|---|---|
| Start header | 0 | 256 B (`StartHeaderSize`, [`logformat.go:24`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/logformat.go#L24)) | version (bytes 21–22), commitment epoch, `massifHeight` (byte 27), `massifIndex` (bytes 28–31) ([`massifstart.go:60-83`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/massifstart.go#L60-L83)) |
| Index (Bloom + Urkle) | 256 | `32 + indexDataBytesV2(leafCount)` ([`indexformat_v2.go:22-50`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/indexformat_v2.go#L22-L50)) | duplicate-detection / exclusion index — **not needed for inclusion paths** |
| Ancestor peak stack | `PeakStackStart(h)` ([`logformat.go:74-82`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/logformat.go#L74-L82)) | fixed 64×32 = 2048 B, `PeakStackLen×32` populated | roots of prior massifs needed to complete this one's peaks |
| MMR node data | `LogStart()` | 32 B per node | nodes in MMR order from `FirstIndex` |

Node lookup is pure arithmetic: `offset = LogStart + (mmrIndex − FirstIndex)·32`
([`massifcontext.go:246-254`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/massifcontext.go#L246-L254));
nodes below `FirstIndex` resolve through the peak stack via
`PeakStackMap`. `FirstIndex` and `PeakStackLen` are derived from the header
fields, not stored ([`massifstart.go:153,198`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/massifstart.go#L153)).

So a single massif blob is **self-sufficient** for any leaf→peak inclusion
path whose leaf lives in that massif: local nodes give the in-massif siblings,
the ancestor peak stack gives everything older. No trie/index parsing is
required.

### 1.2 The format-v3 checkpoint `.sth`

One COSE Sign1 (tag 18) per sealed massif state
([go-merklelog `massifs/checkpointreceipt.go`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/checkpointreceipt.go)):

| Part | Content |
|---|---|
| protected | `{1: alg, 395: vds=3}` — canonical CBOR, int labels only ([`checkpointsign.go:93-96`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/checkpointsign.go#L93-L96)) |
| unprotected `396` | verifiable-proofs map; key `-2` = consistency proof `bstr .cbor [tree-size-1, tree-size-2, paths, right-peaks]` ([`checkpointreceipt.go:35-40,240-246`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/checkpointreceipt.go#L35-L40)) — **`tree-size-2` is the sealed MMR size** |
| unprotected `-65931` | `SealPeakReceiptsLabel = COSEPrivateStart(-65535) − 396` ([`checkpointreceipt.go:44-55`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/checkpointreceipt.go#L44-L55)): array of pre-signed peak receipts, one per accumulator peak, descending height order |
| unprotected `1000` | delegation cert (raw COSE Sign1) carrying the ephemeral sealer public key, embedded once by the sealer ([arbor `services/sealer/src/sealer.go:24-28,217-223`](https://github.com/forestrie/arbor/blob/e59b41b61fa5/services/sealer/src/sealer.go#L24-L28); cert format: [arc-0010](https://github.com/forestrie/devdocs/blob/905485bcf48b/arc/arc-0010-delegation-signer-cose-cbor-scitt.md)) |
| unprotected `-66535` | `SealDelegationProofLabel` — on-chain delegation proof, distinct from label 1000 ([`checkpointreceipt.go:57-65`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/checkpointreceipt.go#L57-L65)) |
| payload | `null` (detached) — real payload is `concat(accumulator peaks)` ([`checkpointreceipt.go:121-136`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/checkpointreceipt.go#L121-L136)) |

Each **pre-signed peak receipt** is itself a detached-payload COSE Sign1
`[protected, {}, nil, signature]` with slim protected `{1: alg, 395: 3, 4: kid?}`
and signature over a single 32-byte peak hash
([`checkpointsign.go:132-175`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/checkpointsign.go#L132-L175)).
By locked decision (plan-0033) they carry **no key material** — the verifier
resolves the same trust root as for the checkpoint.

### 1.3 What is downloadable, by whom

Storage keys: `v2/merklelog/massifs/{h}/{logId}/{index:016d}.log` and
`v2/merklelog/checkpoints/{h}/{logId}/{index:016d}.sth`
([go-merklelog `massifs/storage/const.go`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/massifs/storage/const.go);
same paths consumed server-side in
[canopy `resolve-receipt.ts:119-120`](https://github.com/forestrie/canopy/blob/86d55d4b3c54/packages/apps/canopy-api/src/scrapi/resolve-receipt.ts#L119-L120)).

Per [ADR-0047](https://github.com/forestrie/devdocs/blob/905485bcf48b/adr/adr-0047-publisher-resolves-contract-from-public-r2-genesis.md)
and [ADR-0034](https://github.com/forestrie/devdocs/blob/905485bcf48b/adr/adr-0034-forest-genesis-chain-binding-required.md),
what a participant can GET **without auth** is the forest genesis
(`forests/forest/{R}/genesis.cbor`) and grant objects on the public R2
domain. The massif/checkpoint blobs are **internal R2** — FOR-334 explicitly
scopes a public download endpoint out ("organizers distribute"). Both
derivation options therefore take the `.log` / `.sth` bytes as **local files**;
distribution is out of band.

---

## 2. Option A — attach the rebuilt path to a pre-signed peak receipt

**Data dependencies (exhaustive):**

1. the massif `.log` blob containing the leaf (self-sufficient per §1.1);
2. the covering checkpoint `.sth`, from which three fields are consumed:
   the peak-receipts array (label `-65931`), the sealed size
   (`tree-size-2` of the label-396/-2 consistency proof), and the
   delegation cert (label 1000, when present);
3. the leaf's `mmrIndex` (derivable from an entryId —
   `decodeEntryIdHex` already ships in `@forestrie/receipt-verify@0.3.0`).

No key, no network, no operator.

**Assembly (mirrors the server exactly).** The API path in
[canopy `resolve-receipt.ts`](https://github.com/forestrie/canopy/blob/86d55d4b3c54/packages/apps/canopy-api/src/scrapi/resolve-receipt.ts)
does: read massif start header (L196), build the ancestor peak-stack map
(L210-212), wrap a node getter over log region + peak stack (L216-235), build
the inclusion proof (L237, inline port of
[go-merklelog `mmr/proof.go:89`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/mmr/proof.go#L89)),
select the peak receipt by proof length via `peakIndexForLeafProof`
(L238-245, L735-747), copy the label-1000 cert (L253-269), splice the proof
into unprotected 396 as `{-1: [{1: mmrIndex, 2: [path…]}]}` (L271-280 — the
[draft-bryce](https://github.com/robinbryce/draft-bryce-cose-receipts-mmr-profile/blob/f392d571171a/draft-bryce-cose-receipts-mmr-profile.md)
Receipt-of-Inclusion encoding), and emit `[protected, unprotected, null, sig]`
(L284-291).

**Byte-compatibility — every field of the emitted receipt:**

| Field | Source | Mutated? |
|---|---|---|
| protected header bstr | copied verbatim from the pre-signed peak receipt | never (signature covers it) |
| unprotected `1000` | copied verbatim from checkpoint unprotected | added if present |
| unprotected `396` | `{-1: [{1: mmrIndex, 2: [32B bstr × n]}]}` built locally | the only computed field |
| payload | `null` (detached; verify derives the peak from the proof) | fixed |
| signature | copied verbatim from the pre-signed peak receipt | never |

Residual byte-equality risks (all encoder-side, none cryptographic): CBOR map
insertion order for the unprotected header (cbor-x encodes JS `Map`s in
insertion order — client must insert cert-then-396 to match the server's
L253→L271 order), bigint-vs-number encoding of `mmrIndex`, and tag-18
presence. These should be pinned by a golden byte-equality test against an
API-issued receipt (see open question 1).

**Status: option A is already implemented as WIP.** The canopy worktree
branch `robin/for-334-create-receipt` (local:
`~/Dev/personal/forestrie/.worktrees/canopy-create-receipt`, uncommitted)
contains `packages/libs/receipt-verify/src/build-receipt-offline.ts`
implementing exactly the FOR-334 library AC —
`buildReceiptOffline` (L148), `computeAccumulatorPeak` (L243),
`openMassifNodeStore` (L54), `parseCheckpoint` (L113) — plus
`scripts/create-receipt.ts` and in-process round-trip tests. This design is
validated by that code; the remaining work is landing/publishing it and
wiring the CLI.

## 3. Option B — verify the computed peak against the on-chain accumulator

**Data dependencies:** the massif `.log` blob (must cover nodes up to the
on-chain size), the leaf `mmrIndex`, and one `eth_call`:
`logState(bytes32) → LogState { bytes32[] accumulator; uint64 size }`
([univocity `src/interfaces/IUnivocity.sol:27`](https://github.com/forestrie/univocity/blob/ea410d5a90e4/src/interfaces/IUnivocity.sol#L27),
[`src/interfaces/types.sol:20-23`](https://github.com/forestrie/univocity/blob/ea410d5a90e4/src/interfaces/types.sol#L20-L23),
selector `0xeecac1b7`). The checkpoint signature is enforced at
`publishCheckpoint` time and **not stored**
([`_Univocity.sol:112-114, 155-230`](https://github.com/forestrie/univocity/blob/ea410d5a90e4/src/contracts/_Univocity.sol#L112-L114))
— what the chain attests is the accumulator itself.

**Semantics:** build the inclusion path *at the on-chain size*
(`mmrLastIndex = size − 1`), compute the peak, and compare it with
`accumulator[peakIndexForLeafProof(size, |path|)]` — the same
proof-length→peak selection the contract's own verifier uses
([univocity `algorithms/includedRoot.sol:27-40`](https://github.com/forestrie/univocity/blob/ea410d5a90e4/src/algorithms/includedRoot.sol#L27-L40)).
Because the path is built at the *current* size, the target peak is by
construction a member of the current accumulator — **burial cannot occur at
creation time**. The two failure modes are:

- **lag** — the leaf postdates the last anchor (`mmrIndex ≥ size`): report
  `not_yet_anchored`, non-zero exit ("anchor lag",
  [devdocs glossary](https://github.com/forestrie/devdocs/blob/905485bcf48b/glossary.md));
- **coverage** — the local blob doesn't hold nodes up to the on-chain size
  (on-chain size in a later massif): needs the later blob.

**What option B emits:** a match/mismatch attestation, not a signed receipt —
there is no signature over an arbitrary on-chain-size peak unless that size
coincides with a sealed checkpoint. It is the "trust the chain, not the
operator" complement to A, and the CLI treats it as a check with structured
output (`forestrie-cli` scaffold already declares both anchor modes:
[`src/options/create-receipt.ts`](../../src/options/create-receipt.ts)). ABI
plumbing already exists in the CLI's chain-anchored verify
([`src/lib/verify-anchored.ts`](../../src/lib/verify-anchored.ts), FOR-347)
and in
[system-testing `src/onchain-logstate.ts:36-72`](https://github.com/forestrie/system-testing/blob/19da83c005a6/src/onchain-logstate.ts#L36-L72).

---

## 4. What `@forestrie/merklelog` must gain

Published `@forestrie/merklelog@0.0.3` today exports the massif *reader*
(`Massif`, layout math `peakStackEnd`/`massifLogEntries`/…), index math
(`mmrIndex`, `massifFirstLeaf`, `leafMinusSpurSum`, `heightIndex`, …), and the
*verify-side* algorithms `calculateRoot` / `verifyInclusion`
(source: [canopy `packages/merklelog/src/index.ts`](https://github.com/forestrie/canopy/blob/86d55d4b3c54/packages/merklelog/src/index.ts)).
It has **no proof builder**: `inclusionProof`, `peaks`/`peaksBitmap`,
`peakIndexForLeafProof`, `peakStackMap`, and `massifIndexFromMMRIndex` exist
only as private inline ports — once in
[`resolve-receipt.ts:641-747`](https://github.com/forestrie/canopy/blob/86d55d4b3c54/packages/apps/canopy-api/src/scrapi/resolve-receipt.ts#L641-L747)
and now a second time in the WIP `build-receipt-offline.ts:315-475`. Its
`verifyConsistency` is an explicit always-true stub
([`algorithms.ts:183-194`](https://github.com/forestrie/canopy/blob/86d55d4b3c54/packages/merklelog/src/mmr/algorithms.ts#L183-L194)).

Proposed additions (hoist the WIP helpers; names mirror
[go-merklelog `mmr/`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/mmr/proof.go)):

```ts
// --- mmr proof building (pure; store-agnostic) ---
type NodeGetter = (i: bigint) => Uint8Array;
/** Witness path for node i in the MMR ending at mmrLastIndex. (go: mmr.InclusionProof, proof.go:89) */
function inclusionProof(get: NodeGetter, mmrLastIndex: bigint, i: bigint): Uint8Array[];
/** Peak MMR indices for the tree ending at mmrIndex, ascending. (go: mmr.Peaks, peaks.go:24) */
function peakMMRIndexes(mmrIndex: bigint): bigint[];
function peaksBitmap(mmrSize: bigint): bigint;               // (go: mmr.PeaksBitmap, peaks.go:206)
/** Accumulator slot committed by a proof of this length. (server resolve-receipt.ts:735) */
function peakIndexForLeafProof(mmrSize: bigint, proofLen: number): number;
function indexHeight(i: bigint): number;                     // (go: mmr.IndexHeight)
function firstMMRSize(mmrIndex: bigint): bigint;
function massifIndexFromMMRIndex(massifHeight: number, i: bigint): bigint;

// --- massif blob node access ---
interface MassifNodeStore {
  get(i: bigint): Uint8Array;   // log region ≥ firstIndex; ancestor peak stack below
  massifHeight: number; massifIndex: bigint; firstIndex: bigint; lastIndex: bigint;
}
function openMassifNodeStore(blob: Uint8Array): MassifNodeStore;
function peakStackMap(massifHeight: number, firstIndex: bigint): Map<bigint, number>;

// --- later, FOR-368 (go: mmr.IndexConsistencyProof / ConsistentRoots / VerifyConsistency) ---
function consistencyProof(get: NodeGetter, sizeA: bigint, sizeB: bigint): ConsistencyProof;
function consistentRoots(hasher, sizeA, peaksA, proofs): Promise<Uint8Array[]>;
// and replace the always-true verifyConsistency stub with the real check
```

`@forestrie/receipt-verify` keeps the COSE-shaped layer
(`parseCheckpoint`, `buildReceiptOffline`, `computeAccumulatorPeak`) and
consumes the above — receipt-verify should not own MMR math long-term.

---

## 5. Dependency verdicts

### FOR-323 (ephemeral key in receipt claims) — **not a hard prerequisite; optional interop follow-up**

The peak receipts are signed by the (possibly delegated/ephemeral) sealer
key, and verification needs that public key — but the delegation cert
carrying it is **already in the checkpoint** (label 1000,
[sealer.go:217-223](https://github.com/forestrie/arbor/blob/e59b41b61fa5/services/sealer/src/sealer.go#L217-L223)),
which option A's inputs necessarily include, and `buildReceiptOffline`
copies it onto the receipt exactly as the API does
(WIP `build-receipt-offline.ts:203-205` ↔ `resolve-receipt.ts:253-269`).
The cert is root-signed and verifiable against the genesis trust root with
no network ([arc-0010](https://github.com/forestrie/devdocs/blob/905485bcf48b/arc/arc-0010-delegation-signer-cose-cbor-scitt.md);
[ADR-0032](https://github.com/forestrie/devdocs/blob/905485bcf48b/adr/adr-0032-delegated-checkpoint-signature-verification.md)).
So **option A works today**: creation needs no key at all, and offline verify
resolves the key from artifacts the client already holds. Caveats:

- `verifyGrantReceiptOffline` currently resolves keys from genesis only
  ([`verify-grant-receipt-offline.ts:96-141`](https://github.com/forestrie/canopy/blob/86d55d4b3c54/packages/libs/receipt-verify/src/verify-grant-receipt-offline.ts#L96-L141));
  consuming the label-1000 cert offline is FOR-297 (the
  `delegationCertCbor` input is contracted in
  [ADR-0045](https://github.com/forestrie/devdocs/blob/905485bcf48b/adr/adr-0045-receipt-verify-offline-contract.md)
  but not yet wired). On the current paved path (sealer key resolvable from
  genesis) the round trip closes without it.
- FOR-323 proper is the *standards-compliance* re-scope: label 1000 is
  application-private, so a generic SCITT/COSE verifier can't discover the
  key. Needed for the "verifiable by any conformant tool" story, not for
  FOR-345.
- **Migration constraint (load-bearing):** peak receipts stay slim and
  key-free by locked decision; the key travels by cert-copy at
  attach/issuance time. Whatever placement FOR-323 chooses (CWT `cnf` etc.)
  must keep the self-serve attach flow producing self-contained receipts —
  capabilities must survive mechanism migrations.

### FOR-368 (buried peaks / grow-proofs) — **not a prerequisite for creation; the coupled fix for long-lived verification**

A peak stops being an accumulator member once the MMR grows enough to merge
it ("buried",
[draft-bryce](https://github.com/robinbryce/draft-bryce-cose-receipts-mmr-profile/blob/f392d571171a/draft-bryce-cose-receipts-mmr-profile.md)
§Receipt of Inclusion). Impact by mode:

- **Option B, creation time: burial is a non-issue.** The path is built at
  the current on-chain size, so the computed peak is definitionally in the
  current accumulator. Only lag and blob-coverage can fail (§3).
- **Option A receipts age like any API-issued receipt.** The peak-receipt
  signature is valid forever, but `forestrie verify --univocity` checks the
  receipt's peak against the *current* accumulator, so an honest old receipt
  eventually fails tamper-shaped — exactly FOR-368. Fixes, in order: (1)
  distinguishable `peak_not_current` error (cheap, no new crypto); (2) the
  real fix — accept old checkpoint + consistency path per draft-bryce
  Receipt-of-Consistency / `consistent_roots`
  ([go: `mmr/consistentroots.go:30-52`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/mmr/consistentroots.go#L30-L52),
  [`verifyconsistency.go:57`](https://github.com/forestrie/go-merklelog/blob/ad41dc055b2c/mmr/verifyconsistency.go#L57)),
  which proves each old peak into the new accumulator.
- **Shared machinery:** a client holding the massif data can always
  *re-derive* a fresh receipt at the current size (the degenerate
  grow-proof), using exactly this design's node store + path builder; true
  grow-proofs without full massif data need the §4 consistency functions.
  FOR-368's real fix should be built on the `@forestrie/merklelog` additions
  above, not another inline port.

---

## 6. Recommended phasing for FOR-345

1. **Phase 1 — option A end-to-end with local artifacts (unblocks the demo).**
   Land the canopy WIP (`build-receipt-offline.ts`, tests, demo script);
   publish `@forestrie/receipt-verify@0.4.0` exporting
   `buildReceiptOffline` / `computeAccumulatorPeak` / `openMassifNodeStore` /
   `parseCheckpoint` (inline MMR math tolerated for one release); implement
   [`src/main/create-receipt.ts`](../../src/main/create-receipt.ts)
   `anchor: "checkpoint"` mode over it. AC: emitted receipt passes
   `verifyGrantReceiptOffline` unchanged; golden byte-comparison against an
   API-issued receipt.
2. **Phase 2 — chain-anchored mode + hoist.** Wire `anchor: "chain"` using
   `computeAccumulatorPeak` + the existing `verify-anchored.ts` logState
   plumbing (full accumulator decode, `not_yet_anchored` / mismatch exit
   codes). Hoist the proof-building/massif-store API into
   `@forestrie/merklelog@0.1.x` (§4) and delete both inline copies
   (resolve-receipt.ts and build-receipt-offline.ts) — the server then
   provably shares the client's path code.
3. **Phase 3 — couplings.** FOR-344 `complete-grant` on the same primitives
   (checkpoint parse + leaf pre-image reconstruction + attach via
   `attachReceiptAndIdtimestampToTransparentStatement`, already published in
   receipt-verify 0.3.0); FOR-368 distinguishable error, then consistency
   functions; FOR-297 delegated-cert offline verify; FOR-323 standards
   placement.

## 7. Open questions for Robin

1. **Byte-equality vs verify-equivalence** as the option-A AC: is bit-for-bit
   identity with the API receipt required (then pin cbor-x map insertion
   order, `mmrIndex` bigint-vs-number encoding, and tag-18 presence with a
   golden vector), or is "verifies identically" sufficient?
2. **Home for proof-building code:** hoist into `@forestrie/merklelog` in
   phase 2 as proposed, or keep it in `receipt-verify` (accepting a third
   inline copy pattern)?
3. **Artifact distribution:** keep massif/checkpoint blobs strictly
   out-of-band files for FOR-345 (per FOR-334 out-of-scope), or schedule the
   public download endpoint as its own issue now?
4. **Option B output shape:** report-only (current WIP), or additionally
   emit a signed receipt when the on-chain size coincides with a held
   checkpoint's sealed size?
5. **CLI leaf addressing:** `--mmr-index` only, or also accept
   `--entry-id` / idtimestamp (via `decodeEntryIdHex`) so participants can
   use what registration handed them?
6. **FOR-323 interaction:** confirm the locked slim-peak-receipt decision
   stands (key travels by cert-copy at attach time), so FOR-323 relocates
   *where the copy lands on the receipt* (e.g. CWT `cnf`) without touching
   the checkpoint format.
