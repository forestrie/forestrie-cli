# forestrie-cli

`forestrie` — the single-binary **participant CLI** for forestrie
transparency logs (SCITT / COSE receipts). One static Bun binary hosts the
Zero-to-Hero demo subcommands; each subcommand is a demo step:

| Subcommand | What it does | Linear |
|---|---|---|
| `deploy` | Deploy a univocity instance (ES256 bootstrap is the paved path) | FOR-340 |
| `sign-statement` | Produce a plain COSE Sign1 signed statement | FOR-341 |
| `register` | Register a signed statement via SCRAPI, download the receipt | FOR-342 |
| `register-grant` | Authorize a signer for a child/data log (one grant per signer) | FOR-343 |
| `complete-grant` | Self-create the `Forestrie-Grant` header from a checkpoint | FOR-344 |
| `create-receipt` | Self-serve COSE receipt from log data + checkpoint (or chain-anchored) | FOR-345 |
| `decode-receipt` | Decode a COSE receipt — it is just COSE: Sign1 + MMR inclusion | FOR-346 |
| `verify` | Verify a receipt offline — the same closer for every demo step | FOR-347 |

**Status:** scaffold (FOR-339). Every subcommand declares its real argument
surface and parses it, then exits non-zero with a structured
`not_implemented` error naming its issue. `--json` emits that report as
JSON on stdout. Implementations land per-subcommand.

The demo the subcommands serve:
`canopy/docs/demo/forestrie-demo-01.md` (Zero to Hero — MMR Profile
Adoption Call, initiative
[MMR Profile Adoption Call Demo](https://linear.app/forestrie/initiative/mmr-profile-adoption-call-demo-3822bf4c5af7)).

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
  `OWNER_ADDRESS`, `FORESTRIE_CONFIG`; any string flag also accepts
  `${env:VAR}` / `${env}` whole-value templates.
- **ES256 is the paved path end-to-end**; KS256 appears only in the
  Safe / ERC-1271 aside.

## Built on (published packages)

The binary is buildable from **published packages only** (plan-2607-12) —
all public on npmjs under the `@forestrie` scope, MIT licensed per-package,
installable without auth:

`@forestrie/cli-kit` · `@forestrie/deploy-core` · `@forestrie/encoding` ·
`@forestrie/grant-builder` · `@forestrie/scrapi-client` ·
`@forestrie/receipt-verify` · `@forestrie/merklelog` ·
`@forestrie/delegation-cose`

## License

No repository license yet — whether this repo goes public (and MIT) is an
open decision. The packages it builds on are MIT regardless.
