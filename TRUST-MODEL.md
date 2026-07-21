# Forestrie receipt trust model

What a forestrie receipt proves, and how the `verify` / `resolve-receipt` trust
anchors map onto it. This is the conceptual reference; the per-command sections
in the [README](./README.md) are the operational recipes and link back here.

A receipt is a COSE proof that **a leaf is included in a transparency log's
sealed state**. A relying party may care about up to three *independent*
questions about that state. Keeping them apart is the whole model — most
confusion comes from collapsing them into one "the receipt is valid".

## The three questions

### 1. Split-view consistency — *is this a single, un-forked history?*

Answered by the **accumulator** (the log's peak set). Recompute the leaf's
inclusion path to a peak and match it against a *trusted* accumulator. Because
every published accumulator is consistency-gated forward (each is a committed
prefix of every later one — ADR-0056), matching one proves the log has not
forked or rewritten history under you.

This property is **independent of currency.** Any accumulator is a genuine,
non-equivocal commitment up to its own tree size, so an older one is not "less
valid" — staleness only limits *coverage* (whether the snapshot reaches the leaf,
and how much newer history it attests), never the validity of what it does cover.
"Freshness" — *is this the latest accumulator* — is therefore a weaker, separate
axis that bears only on coverage; do not collapse it into split-view. Split-view
is the load-bearing property here; currency is at most the `--rpc-url` "as of
now" delta below.

Trusted-accumulator sources, in ascending currency:

- `--known-accumulator` — a cached, auditable chain read (`fetch-accumulator`).
- `--rpc-url` — a live read; same guarantee plus "as of now".

Never source the accumulator unauthenticated from the log operator's own tile
store — that re-internalises the operator trust this anchor exists to remove.

### 2. Sealing attestation — *who sealed this state?*

The checkpoint signer's signature over the accumulator: the `.sth`'s pre-signed
peak receipts (COSE label `-65931`) and its owner→sealer delegation cert (label
`1000`). It identifies **the individual log checkpoint signer**, and nothing
finer — the log authorises a *set* of sealers (see §3), it does not rank them.

This signature is **load-bearing only when you do not already hold the
accumulator from a trusted source.** At the accumulator rung (§1) you have
explicitly chosen to trust the chain-read state over any signature, so *which*
authorised sealer signed is, by your own choice, irrelevant — the signature is
**vestigial there.** It still matters at the signature rungs below, where verify
checks it chains to the owner.

### 3. Authority — *is this log authorised, back to the genesis / bootstrap key?*

Answered by **the grants and their inclusion proofs** — the grant hierarchy, in
which each log's authority *is* a receipted, provable inclusion in its parent
log — **not** by the checkpoint signature, and **not** by a per-log genesis
document.

> **`genesis.cbor` is not a per-log artifact.** It is the **univocity-instance
> registration document**: it records the instance's bootstrap/root owner key —
> the key bound into the `ImmutableUnivocity` contract at deploy. There is **one
> per instance (the root log)**, not one per log. So `--genesis` directly roots a
> receipt whose signer chains to that root owner (the root log, or a delegation
> *directly* under it); it does **not**, by itself, root an arbitrary child log.
> Reaching genesis from a child log means walking the grant hierarchy (below).

To establish a child log's authority you follow its grant to its parent, that
grant's inclusion proof, and so on up to the bootstrap key — the "grant-chain
walk". Three ways to obtain that, strongest first:

- **On-chain (chain trust) — the strong, available path.** The contract already
  did the walk at publish, so reading the accumulator from chain
  (`--known-accumulator` / `--rpc-url`) inherits it (see below). No off-chain
  walk needed.
- **Off-chain grant-chain walk** from the grant records + their inclusion proofs
  (rooted at `genesis.cbor`). This is a genuine tile-/receipt-level proof — but
  it is **not yet implemented** (the open verify rung); do not assume it today.
- **Operator storage / APIs surfacing the chain — forestrie-operator trust.**
  Convenient, but re-internalises the very operator trust the log system exists
  to remove; not a trust source.

Crucially, **the contract discharges this at publish.** `publishCheckpoint`
verifies, on-chain:

- the checkpoint is signed by the log's root key **or a valid delegation** of it
  (sealing authority, §2), and
- the publisher presented a grant whose **inclusion** in the parent log the
  contract re-checks against the parent's on-chain accumulator, within the
  grant's size bounds — link by link, transitively to the bootstrap key bound
  into the contract at deploy.

So **any state read from the chain** (an accumulator snapshot, `publishCheckpoint`
calldata, a `CheckpointPublished` event) inherits the contract's sealing *and*
authority checks for free. That is *why* the accumulator rung needs no genesis
walk: the authority question was already answered, on-chain, when the state was
published.

## The verify trust ladder, mapped onto the questions

`verify` offers four named anchors (FOR-297 / plan-2607-24). They are not a
single "more vs less trust" line — each answers a different subset:

| Anchor | Split-view (§1) | Sealing (§2) | Authority (§3) |
|---|---|---|---|
| `--known-log-key` | — | signature under a caller-known owner key | key→log binding **asserted** (out-of-band), not proven |
| `--genesis` | — | signature chains to the **root** owner (root log / direct delegation) | root only; a child log needs the grant-chain walk (still open) |
| `--known-accumulator` | covered entries root into a trusted chain read | (not checked — subsumed by the chain) | (not checked — discharged by the contract at publish) |
| `--rpc-url` | as `--known-accumulator`, live | (subsumed) | (discharged at publish) |

The signature rungs (`--known-log-key`, `--genesis`) answer §2 offline by
checking the signature — and §3 only as far as the cert reaches (`--genesis`
covers the root log / a direct delegation; a deeper child's §3 is the grant-chain
walk, still open). The accumulator rungs (`--known-accumulator`, `--rpc-url`)
answer §1 and let the contract's publish-time checks stand in for §2/§3 for *any*
log — which is why, in practice, the on-chain path is the strong authority anchor
for an arbitrary log, not `genesis.cbor`. A receipt never expires and the anchor
never needs to be current — only trusted.

## Freshen and the attestor

Freshen (`resolve-receipt --receipt <stale> + a tile-free source`) re-anchors a
stale receipt to the current sealed state without tiles. A receipt goes stale
when log growth *buries* the peak it commits to; freshen extends the leaf's
inclusion path from its old peak up to the current accumulator.

```
 original receipt, log size 3 (2 leaves)        grown log, size 7 (4 leaves)
                                                 the size-3 peak (node 2) is buried

         2   <- peak;  accumulator = [2]                    6   <- peak;  accumulator = [6]
        / \                                               / \
       0   1                                             2   5   <- climb node, from the
           ^                                            / \ / \      3->7 consistency proof
           leaf, mmrIndex 1                            0  1 3  4     (or the retained chain)
       old path = [0]                                     ^
       root = H(0,1) = node 2                             leaf, mmrIndex 1  (same leaf)
                                                       fresh path = [0, 5]
                                                       root = H( H(0,1), 5 ) = node 6
```

`old path [0]` is a **prefix** of `fresh path [0,5]` (MMR prefix-composability),
so freshen only appends the climb node. It then attaches `(leaf@1, [0,5])` at
COSE header `396` to the **latest checkpoint's** pre-signed peak receipt for
node 6. The three questions attach to that one re-emitted receipt like this:

```
freshened receipt, leaf@1 @ size 7
├─ inclusion path [0,5] --recompute--> node 6
│    SPLIT-VIEW (§1): node 6 == trusted size-7 accumulator[0]
│                     (freshen self-check vs the .sth; bound by --known-accumulator / --rpc-url)
│
├─ peak receipt over node 6, signed by the size-7 sealer
│    SEALING   (§2) : "an authorised sealer sealed size 7"
│                     CHECKED at verify's signature rung (--genesis / --known-log-key)
│                     IGNORED at the accumulator rung        <- vestigial here only
│
└─ label-1000 delegation cert  (owner --> sealer)
     AUTHORITY (§3) : owner/grant chain to the bootstrap key
                      enforced by the contract at publishCheckpoint;
                      re-provable via grants + their inclusion proofs
```

### Why the `.sth` is still required — and why the signer is not a choice

Freshen produces a **new attestation of the current accumulator**, so the only
signature it can legitimately carry is one over a checkpoint at the current size
— i.e. the latest checkpoint's signer. Attaching any other signer's signature
would be forgery. Hence the `.sth` is **load-bearing for emission**: it supplies
the pre-signed peak receipts and the delegation cert that make the freshened
receipt a native, signature-rung-verifiable receipt. "Vestigial" (§2) describes
the signature *at accumulator-rung verification*, never the freshen build step.

(For the calldata source the `.sth` must be supplied separately: calldata
carries a *checkpoint-level* COSE signature over the whole accumulator, not the
per-peak receipts label `-65931` that the emission format needs.)

### Attestor rotation is not a downgrade

If the sealer rotated (`K1 → K2`) between the original receipt's checkpoint and
the fresh `.sth`, the freshened receipt is sealed under `K2`. This is **not** a
downgrade attack, even though `K2` may be a less-trusted operational identity
than `K1`:

- The log authorises a *set* of sealers (root + its delegations) and the
  contract enforces **membership** at publish. It does not **rank** members —
  `K1` and `K2` are equally authorised. Any preference between them is
  out-of-band relying-party policy, which the log system never promised to
  uphold.
- A relying party who cares about the specific signer is, by definition, at a
  **signature rung**, where verify checks it: an *unauthorised* signer fails
  closed; a *rotated-but-authorised* one (the routine case) passes — correctly.
- A relying party at the **accumulator rung** has chosen not to check the
  signature at all, so the signer identity cannot matter to them.

There is no coherent configuration where the identity distinction both matters
and is not already handled. The mirror case (an *upgrade* to a more-trusted
signer) is symmetric and equally a non-issue. Freshen therefore emits under the
latest checkpoint's signer and does nothing further — there is **no
signer-change gate** (an earlier `--allow-new-signer` sketch was removed for
exactly this reason).

## "Known-accumulator-verifiable but not genesis-verifiable" is not a gap

A receipt anchored purely at the accumulator rung authenticates the **state**
(the leaf roots into the genuine canonical accumulator) but says nothing, by
itself, about **signer provenance** (that the sealer chains to genesis). These
are the two *different* questions §1 and §2/§3 — not a strong check and a weak
one. The state question is answered by the accumulator; the provenance question,
if you want it, is answered at a signature rung or was already discharged by the
contract at publish. Separating them is the design, not a shortfall.

---

*See also: [`plan-2607-24`](../../devdocs/plans/plan-2607-24-for297-verify-trust-anchors.md)
(verify trust anchors), ADR-0046 (detached checkpoint payload), ADR-0056
(consistency proof spans the massif entry boundary).*
