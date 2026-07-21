# forestrie-cli

`forestrie` — the single-binary **participant CLI** for forestrie
transparency logs (SCITT / COSE receipts). One static Bun binary hosts the
subcommands a participant needs to deploy, sign, register, and verify
against a forestrie log:

| Subcommand | What it does |
|---|---|
| `deploy` | Deploy a univocity instance (ES256 bootstrap is the paved path) |
| `sign-statement` | Produce a SCITT signed statement (plain COSE Sign1 with CWT claims) |
| `register` | Register a signed statement via SCRAPI, download the receipt |
| `register-grant` | Authorize a signer for a child/data log (one grant per signer) |
| `complete-grant` | Self-create the `Forestrie-Grant` header from a checkpoint |
| `resolve-receipt` | Produce or freshen a COSE receipt — from tiles, or tile-free from a `.sth`/calldata chain (alias: `create-receipt`) |
| `decode-receipt` | Decode a COSE receipt — it is just COSE: Sign1 + MMR inclusion |
| `verify` | Verify a receipt offline — the same closer for every other subcommand |
| `fetch-accumulator` | Cache the on-chain accumulator as a `--known-accumulator` snapshot |

**Status:** subcommands not yet implemented declare their real argument
surface and parse it, then exit non-zero with a structured `not_implemented`
error. `--json` emits that report as JSON on stdout. Implementations land
per-subcommand.

## Install from a release

Every [GitHub release](https://github.com/forestrie/forestrie-cli/releases)
attaches prebuilt static binaries — `forestrie-darwin-arm64` and
`forestrie-linux-x64` — each with a `.sha256` sidecar. No runtime is
needed; just download, verify, and run:

```bash
target=darwin-arm64   # or: linux-x64
base=https://github.com/forestrie/forestrie-cli/releases/latest/download
curl -fsSLO "${base}/forestrie-${target}"
curl -fsSLO "${base}/forestrie-${target}.sha256"
shasum -a 256 -c "forestrie-${target}.sha256"
chmod +x "forestrie-${target}"
./forestrie-${target} --help
```

Releases are cut by pushing a `v*` tag; the workflow fails closed unless
the tag matches the `package.json` version
([.github/workflows/release.yml](./.github/workflows/release.yml)).

## Install from source

Requires [Bun](https://bun.sh) (pinned in `mise.toml`; `mise install`
works). All dependencies install **tokenless** from public npmjs — no
registry auth, no `.npmrc`:

```bash
bun install
bun run typecheck && bun test
bun run dev -- --help          # run from source
```

## Build the static binary

```bash
bun run build:binary            # host platform → dist/forestrie
bun run build:binary:linux-x64  # → dist/forestrie-linux-x64
bun run build:binary:darwin-arm64
./dist/forestrie --help
```

## Conventions

- Human output by default; `--json` for machine-readable output on stdout.
- `-v` / `--verbosity` per `@forestrie/cli-kit` reporting (`-1` silences
  stderr feedback; stdout stays pipeable).
- Env fallbacks: `FORESTRIE_BASE_URL`, `RPC_URL`, `GRANT_B64`,
  `OWNER_ADDRESS`, `DEPLOYER_KEY`, `FORESTRIE_CONFIG`; any string flag also
  accepts `${env:VAR}` / `${env}` whole-value templates.
- **ES256 is the paved path end-to-end**; KS256 appears only in the
  Safe / ERC-1271 aside.

## Usage

Minimal example per subcommand. `$FORESTRIE_BASE_URL`, `$RPC_URL`, and
`$GRANT_B64` are the env fallbacks from [Conventions](#conventions).

### `deploy`

```bash
forestrie deploy \
  --bootstrap-alg es256 \
  --bootstrap-es256-generate --bootstrap-es256-pem-out bootstrap.es256.pem \
  --owner-address 0xYourDeployer \
  --rpc-url "$RPC_URL" \
  --out deployment.json
```

```
ImutableUnivocity deployed at: 0xAbC…123
genesisLogId: 0f9a1c7e-…-…
chainId: 84532  txHash: 0x9f…21
wrote deployment record to deployment.json
```

### `sign-statement`

```bash
forestrie sign-statement \
  --key alice.es256.pem \
  --payload statement.json --content-type application/json \
  --out statement.cose
```

```
signed statement: plain COSE Sign1 (ES256)
  kid:       241115ab754013fcbf2e88544a369009d5d7de7f54497ad640ef28ad6237392c
  iss:       241115ab754013fcbf2e88544a369009d5d7de7f54497ad640ef28ad6237392c
  sub:       sha-256:9c3f8a5d0e6b17c4a2f1d8e05b6c93a7714f2e8d90ab35c6e1d47f80b92c5a13
  payload:   45 bytes (application/json)
  statement: 253 bytes -> statement.cose
```

Statements carry SCITT CWT claims (protected COSE header label 15,
covered by the signature). Defaults keep signing zero-config and
deterministic; every claim is settable:

- `--iss <string-or-uri>` — issuer (CWT claim 1). Default: the
  lowercase hex kid. The keyword `ckt` derives the RFC 9679 COSE Key
  Thumbprint URI (`urn:ietf:params:oauth:ckt:sha-256:…`) from the
  signing key — which also means a literal issuer named `ckt` is not
  expressible.
- `--sub <string-or-uri>` — subject the statement speaks about (CWT
  claim 2). Default: `sha-256:<hex>` of the payload bytes.
- `--iat now|<unix-seconds>` — issued-at (CWT claim 6). Omitted by
  default so repeated signing of the same payload is byte-identical.

Empty `--iss`/`--sub` values are rejected rather than silently
replaced with the defaults.

### `register`

```bash
forestrie register \
  --base-url "$FORESTRIE_BASE_URL" \
  --log-id "$LOG_ID" \
  --statement statement.cose \
  --grant-b64 "$GRANT_B64" \
  --out receipt.cbor
```

```
entryId: 0202020202020202…0001
statusUrl: https://.../register/.../entries/…
receiptUrl: …/receipt
wrote receipt (612 bytes) to receipt.cbor
```

### `register-grant`

```bash
forestrie register-grant \
  --base-url "$FORESTRIE_BASE_URL" \
  --owner-log "$OWNER_LOG_ID" --data-log "$DATA_LOG_ID" \
  --sign-with bootstrap.es256.pem \
  --out-b64 grant.b64
```

```
ownerLog: 0f9a1c7e-…-… (grant leaf)
dataLog: 8c2e4b…-… (authorized)
signer: 04a91f…
entryId: …
wrote completed grant base64 to grant.b64
```

### `complete-grant`

```bash
forestrie complete-grant \
  --grant grant.b64 \
  --checkpoint checkpoint.sth --massif massif.log \
  --out-b64 grant.completed.b64
```

```
complete-grant: leaf       — mmrIndex 0 (recovered from massif)
complete-grant: entry id   — 01010101010101010000000000000000 (idtimestamp from massif)
complete-grant: proof      — 1 node(s) to peak 1/2
complete-grant: checkpoint — sealed size 4, delegation cert copied: no
complete-grant: receipt    — 118 bytes attached (header 396)
```

Self-creates the `Forestrie-Grant` header from a checkpoint, without an
operator round-trip: it locates the grant's leaf in the local `--massif` blob
by its commitment hash (recovering the `mmrIndex` and the sequenced
idtimestamp), rebuilds the inclusion receipt against the checkpoint's pre-signed
peak, and attaches the receipt + idtimestamp — the same completed bearer
`register-grant` produces online. `--massif` is required (it carries the leaf);
`--idtimestamp <hex|path>` is a fallback for the rare massif with no index
region.

### `resolve-receipt`

One receipt producer (SCRAPI §2.4 "Resolve Receipt"; `create-receipt` is a
kept alias). The **source is chosen by the flags present**, not a `--mode`;
passing more than one source, or an under-specified one, errors with guidance.

```bash
# from tiles: rebuild the leaf→peak path from a massif and a checkpoint
forestrie resolve-receipt \
  --massif massif.log --checkpoint checkpoint.sth \
  --mmr-index 0 \
  --out receipt.cbor
```

```
resolve-receipt: massif     — index 0 (height 3, mmr indexes 0..3)
resolve-receipt: leaf       — mmrIndex 0 (from --mmr-index)
resolve-receipt: checkpoint — sealed size 4, 2 peak(s)
resolve-receipt: proof      — 1 node(s) to peak 1/2 (mmrIndex 2)
resolve-receipt: receipt    — 144 bytes -> receipt.cbor
```

Add `--univocity <address> --log-id <id> --rpc-url $RPC_URL` for a
chain-anchored (report-only) verification instead of a checkpoint-based
receipt.

#### Freshen a stale receipt (tile-free)

When log growth buries the peak a receipt commits to, **freshen** re-anchors
it to the current sealed state without tiles. `resolve-receipt --receipt
<stale>` plus a tile-free source extends the receipt's old inclusion path to
the latest peak and re-emits it. The leaf value is recomputed exactly as
`verify` does, from the same leaf inputs: `--payload <statement>` for statement
receipts, or `--committed-grant`/`--committed-grant-file` for grant receipts
(both with `--entry-id`).

```bash
# a STATEMENT receipt from a retained .sth chain (genesis-verifiable)
forestrie resolve-receipt \
  --receipt stale.cbor --checkpoint-chain ./checkpoints/ \
  --payload statement.cose --entry-id <hex> \
  --in-place

# a GRANT receipt, same chain source
forestrie resolve-receipt \
  --receipt stale.cbor --checkpoint-chain ./checkpoints/ \
  --committed-grant-file grant.cbor --entry-id <hex> \
  --in-place

# from on-chain publishCheckpoint calldata (known-key rung); calldata carries
# no peak receipts, so the latest .sth is supplied for emission, and
# --known-accumulator binds the folded state to a trusted snapshot
forestrie resolve-receipt \
  --receipt stale.cbor \
  --rpc-url $RPC_URL --univocity <address> --log-id <id> \
  --checkpoint latest.sth --known-accumulator accumulator.cbor \
  --committed-grant-file grant.cbor --entry-id <hex> \
  --out fresh.cbor
```

`--in-place` rewrites the `--receipt` file (mutually exclusive with `--out`;
crash-safe — written to a sibling temp then atomically renamed). The freshened
receipt is a native receipt that verifies with plain `verify` against the
current state, and freshen fails closed (it never emits a receipt whose
recomputed peak does not match the folded latest accumulator).

#### Bind the freshened state (`--known-accumulator`)

Both sources fold a consistency-proof chain to the latest accumulator, but the
**source authenticates that state differently**, and the emission checkpoint's
role differs:

- **`--checkpoint-chain` (retained `.sth`)** is the safer source because the
  checkpoint the receipt is emitted under **is the chain's own tail** — there is
  no separate artifact to mismatch, and the sealer-signed, genesis-rooted `.sth`
  makes the freshened receipt **genesis-verifiable** offline. Reach for this by
  default.
- **calldata (`--rpc-url`/`--univocity`/`--log-id` + `--checkpoint`)** reads the
  climb material trustlessly from the `publishCheckpoint` transactions (the fold
  is cross-checked against the on-chain `CheckpointPublished` accumulator), but
  emission borrows a **separately-supplied** latest `.sth` for its signature.
  This is the **known-key rung**.

Because the calldata `--checkpoint` is a separate input, pass
**`--known-accumulator <snapshot>`** (a `fetch-accumulator` capture) to bind the
freshened state to a trusted accumulator: freshen asserts the folded latest
accumulator **equals your snapshot at the same size**, failing closed on any
disagreement. This is the accumulator trust rung — a chain-captured `logState`
is a direct, falsifiable attestation of the current state, stronger than a
genesis walk for "is this the real log," and it needs no genesis (non-root logs
would otherwise have to walk the grant hierarchy to find it). It also catches a
lying/stale RPC on the calldata path, since the snapshot is an independent
read. `--known-accumulator` works with either source.

### `decode-receipt`

```bash
forestrie decode-receipt receipt.cbor
```

```
COSE_Sign1 — tagged 18 (COSE_Sign1) — 304 bytes
├─ protected: 1 (alg): -7 — ES256   4 (kid): 6c6c6c6c…
├─ unprotected: inclusion proof — mmr index 5, path length 3
├─ payload: detached — recomputed from the inclusion path at verify time
└─ signature: 64 bytes
```

### `verify`

```bash
forestrie verify \
  --genesis genesis.cbor --receipt receipt.cbor --committed-grant "$GRANT_B64"
```

```
verify: parse     ok      — receipt COSE decodes; genesis trust root loads (ES256)
verify: signature ok      — checkpoint signature verifies under the genesis trust key
verify: inclusion ok      — proof path recomputes the checkpoint peak
verify: binding   ok      — leaf binds the grant commitment at the receipt idtimestamp
PASS: receipt verified offline against the cached checkpoint
```

Add `--univocity <address> --log-id <id> --rpc-url $RPC_URL` to check the
receipt's peak against the on-chain accumulator instead of the checkpoint
signature — no operator trust required.

#### Trust anchors (FOR-297)

`verify` supports four explicitly-named trust anchors; each rung of the
ladder needs strictly less trust than the one before it:

1. **`--known-log-key`** — a caller-known log OWNER key (base64 `x||y`,
   env `KNOWN_LOG_KEY`), obtained out of band: the standard SCITT
   relying-party posture and the SSH known-hosts model. Fully offline, no
   genesis; but the "key K owns log L" binding is *asserted* by the key's
   provenance, not proven, and there is no grant-lifecycle visibility and
   no split-view protection.
2. **`--genesis`** — genesis-derived roots; the planned grant-chain walk
   (approach A) will *derive* per-log bindings from `genesis.cbor` +
   public tiles, adding lifecycle visibility with no key distribution.
3. **`--known-accumulator`** — a cached, auditable chain read of the log's
   on-chain `logState` (produced by `forestrie fetch-accumulator`):
   contract-enforced state — signature, grant chain AND split-view for
   covered entries — fully offline. Older receipts extend to a newer
   snapshot via `--massif` proof-path extension; newer receipts fail
   closed. Never source the snapshot unauthenticated from the log
   operator's tile store — that re-internalises the operator trust this
   anchor removes.
4. **`--rpc-url`** (live chain read) — same as 3 plus freshness; the RPC
   provider is itself a trusted chain reader, a trust the snapshot merely
   makes explicit and portable.

The receipt never expires, and the anchor never needs to be current —
only trusted.

### `fetch-accumulator`

```bash
forestrie fetch-accumulator \
  --univocity "$UNIVOCITY" --log-id "$LOG_ID" --rpc-url "$RPC_URL" \
  --out accumulator.cbor
```

Reads `logState(logId)` pinned to a block and writes the
`--known-accumulator` snapshot: canonical CBOR binding
`(chainId, univocity, logId, size, blockNumber, blockHash)` — anyone with
RPC can re-run the read at that block and confirm or disprove it.

## Built on (published packages)

The binary is buildable from **published packages only** (plan-2607-12) —
all public on npmjs under the `@forestrie` scope, MIT licensed per-package,
installable without auth:

`@forestrie/cli-kit` · `@forestrie/deploy-core` · `@forestrie/encoding` ·
`@forestrie/grant-builder` · `@forestrie/scrapi-client` ·
`@forestrie/receipt-verify` · `@forestrie/merklelog` ·
`@forestrie/delegation-cose` · `viem` (deploy tx signing/submission)

## License

MIT — see [LICENSE](./LICENSE).
