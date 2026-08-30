# Forestrie receipt trust model — moved

This document has moved to devdocs, which is now its canonical home:

**→ [devdocs `protocol/receipt-trust-model.md`](https://github.com/forestrie/devdocs/blob/main/protocol/receipt-trust-model.md)**

It was written here (plan-2607-33) as a repo-local, user-facing companion to
`verify` and `resolve-receipt`. It is now cited from three rules-of-the-road
files and two product decks, which makes it a platform document rather than a
CLI one — and devdocs' ownership rules put cross-repo architecture there, with
a stub redirect in the implementing repo.

The promoted version is the same document, extended with a **fourth trust
question — attribution**: *who was authorised to sign this leaf?* That question
is independent of split-view, sealing and authority, and it is what the
passkey/WebAuthn work added.

Section anchors are preserved, so deep links still resolve against the new
location — including
[`#freshen-and-the-attestor`](https://github.com/forestrie/devdocs/blob/main/protocol/receipt-trust-model.md#freshen-and-the-attestor).

## Related

- [devdocs `protocol/`](https://github.com/forestrie/devdocs/blob/main/protocol/README.md)
  — the full protocol document set: wire formats, key custody, and what the
  operator can and cannot do.
- [README.md](./README.md) — the per-command operational recipes, which remain
  here.
