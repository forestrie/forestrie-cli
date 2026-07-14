# forestrie-cli — domain context

Terms and the authority model behind the `forestrie` subcommands. Read this
before adding or changing a command; the verb you reach for is determined by
*which authority* the caller is exercising, not by convenience flags. The
platform decision is [devdocs ADR-0052](https://github.com/forestrie/devdocs/blob/main/adr/adr-0052-cli-authority-taxonomy.md);
the delegation model is [ADR-0050](https://github.com/forestrie/devdocs/blob/main/adr/adr-0050-delegation-in-advance.md).

## The four authorities → four verbs

Each subcommand exercises exactly one authority. The authorities differ by who
signs, what grant flags go on the wire, and which layer enforces them.

| Verb | Authority | Signer | Grant flags / material | Enforced by |
|------|-----------|--------|------------------------|-------------|
| `deploy` | stand up the forest root | deployer (gas) + bootstrap key | on-chain `bootstrapConfig` | univocity constructor |
| `create-log` | create a log, become its `K(L)` | parent-log authority | `GF_CREATE\|GF_EXTEND` + `GF_AUTH_LOG`\|`GF_DATA_LOG`; `grantData` = new owner | univocity first checkpoint (`GF_CREATE`) |
| `register-grant` | authorize a statement **writer** | log owner `K(L)` | `GF_EXTEND\|GF_DATA_LOG` (no `GF_CREATE`); `grantData` = writer | canopy `isStatementRegistrationGrant` |
| `delegate` | authorize **sealing** on your behalf | log owner `K(L)` | delegation cert + compact on-chain sig | univocity delegation verifier |

The offline verbs (`sign-statement`, `register`, `verify`, `create-receipt`,
`complete-grant`, `decode-receipt`) exercise no authority — they build, submit,
or verify COSE artefacts.

## Key terms

- **`K(L)` (log root key)** — the key univocity binds as a log's root at its
  first checkpoint (`grantData` of the `GF_CREATE` grant). Holding `K(L)` is
  what lets you publish checkpoints, authorize writers, and delegate sealing for
  log `L`. It is **not** related to a writer's key.
- **Grant** — a COSE-signed statement authorizing an action, recorded and
  receipted in an **auth log** (never a side channel). One grant binds exactly
  one signer (`grantData` = that signer's ES256 `x||y`). Carried on the wire in
  the `Authorization: Forestrie-Grant` header.
- **Owner log / auth log** — the parent log a grant leaf is sequenced into
  (`ownerLogId`). A grant that authorizes a data-log writer is recorded in that
  data log's **parent auth log**.
- **Create vs. write** — a **create** grant (`GF_CREATE`) names the log's new
  owner (`grantData` = the party who will hold `K(L)`). A **writer** grant
  (`GF_EXTEND`, no `GF_CREATE`) names a party who may only append statements —
  never create or re-root. Different noun (owner vs. writer) ⇒ different verb
  (`create-log` vs. `register-grant`).
- **Delegation-in-advance (standing key)** — the custodian derives a standing
  sealer key and vouches for it (COSE voucher signed by the registrar voucher
  key). The coordinator advertises it at
  `GET /api/logs/{logId}/pending-delegation`. The `K(L)` holder verifies the
  voucher against a **pinned registrar key**, then signs a wide-horizon
  delegation authorizing that sealer to publish checkpoints. See ADR-0050.
- **Voucher / pinned registrar key** — the voucher is the custodian's
  attestation `(sealerId, epoch, delegatePublicKey)`. `delegate` verifies it
  against a caller-supplied pinned registrar key and **fails closed** if it is
  absent or invalid — so *"I authorized my custodian-vouched sealer"* is a true
  statement, not blind trust in the coordinator.
- **Horizon** — the MMR range a delegation authorizes (`mmrStart..mmrEnd`).
  On-chain this is effectively permanent within its range (ADR-0050 V4), so
  `delegate` grants a **wide** horizon by default — one-shot authorization, not
  a renewable lease.

## Grant-flag shapes (`@forestrie/grant-builder`)

8-byte wire bitmap; byte 3 holds create/extend/derived, byte 7 holds the log
kind. See `grant-flags.ts`.

- `create-log` (data): byte3 `0x03` (`GF_CREATE|GF_EXTEND`), byte7 `0x02`
  (`GF_DATA_LOG`) — `dataLogCreateExtendFlags()`.
- `create-log --auth-log` / root bootstrap: byte3 `0x03`, byte7 `0x01`
  (`GF_AUTH_LOG`) — `authLogBootstrapShapedFlags()`.
- `register-grant` (writer): byte3 `0x02` (`GF_EXTEND` only), byte7 `0x02` —
  `dataLogExtendFlags()` **(to add — ADR-0052/plan-2607-21)**.
- Endorsement (not a CLI verb): byte3 `0x06` (`GF_EXTEND|GF_DERIVED`), byte7
  `0x01` — `derivedEndorsementGrantFlags()`.

`GF_EXTEND` is currently overloaded (publish authority *and* writer authority);
[ADR-0051](https://github.com/forestrie/devdocs/blob/main/adr/adr-0051-gf-extend-overloaded-publish-vs-write.md)
is the deferred cleanup to move writers to `GF_DERIVED`. Until it lands, writer
grants use `GF_EXTEND` — but only `create-log` sets `GF_CREATE`.

## Personas (demo + trust story)

- **Robert** — holds `K(root)`. `deploy`; `create-log --self-referential`
  (root grant); `create-log --auth-log` for David's auth log; `delegate` the
  root log.
- **David** — holds `K(David-auth)` + `K(David-data)`. `create-log` his data
  log; `register-grant` Alice and Bob as writers; `delegate` his auth log and
  his data log.
- **Alice / Bob** — writers. `sign-statement` + `register` only.

Hierarchy: root → David-auth → David-data. That is **three** `delegate` beats
(root, David-auth, David-data) — the minimal accurate representation of the
authority hierarchy, kept deliberately.
