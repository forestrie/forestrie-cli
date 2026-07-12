# forestrie-cli

`forestrie` — the single-binary **participant CLI** for forestrie
transparency logs (SCITT / COSE receipts). One static Bun binary hosts the
subcommands a participant needs to deploy, sign, register, and verify
against a forestrie log:

| Subcommand | What it does |
|---|---|
| `deploy` | Deploy a univocity instance (ES256 bootstrap is the paved path) |
| `sign-statement` | Produce a plain COSE Sign1 signed statement |
| `register` | Register a signed statement via SCRAPI, download the receipt |
| `register-grant` | Authorize a signer for a child/data log (one grant per signer) |
| `complete-grant` | Self-create the `Forestrie-Grant` header from a checkpoint |
| `create-receipt` | Self-serve COSE receipt from log data + checkpoint (or chain-anchored) |
| `decode-receipt` | Decode a COSE receipt — it is just COSE: Sign1 + MMR inclusion |
| `verify` | Verify a receipt offline — the same closer for every other subcommand |

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
  payload:   45 bytes (application/json)
  statement: 173 bytes -> statement.cose
```

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

### `create-receipt`

```bash
forestrie create-receipt \
  --massif massif.log --checkpoint checkpoint.sth \
  --mmr-index 0 \
  --out receipt.cbor
```

```
create-receipt: massif     — index 0 (height 3, mmr indexes 0..3)
create-receipt: leaf       — mmrIndex 0 (from --mmr-index)
create-receipt: checkpoint — sealed size 4, 2 peak(s)
create-receipt: proof      — 1 node(s) to peak 1/2 (mmrIndex 2)
create-receipt: receipt    — 144 bytes -> receipt.cbor
```

Add `--univocity <address> --log-id <id> --rpc-url $RPC_URL` for a
chain-anchored (report-only) receipt instead of a checkpoint-based one.

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
