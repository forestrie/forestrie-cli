# forestrie-cli — agent guidance

Shared Forestrie team conventions:
[forestrie-agents](https://github.com/forestrie/forestrie-agents).

## This repo

Single-binary participant CLI (`forestrie`), Bun + TypeScript + citty.
Pattern source: univocity-tools `docs/agents/cli.md` — **parse/execute
split**, enforced by layout:

| Path | Role | Must not |
|---|---|---|
| `src/cli.ts` | `runMain(command)` entry | anything else |
| `src/command.ts` | root citty command, lazy `subCommands` | business logic |
| `src/commands/*.ts` | citty `args` schema + `defineCommandRunner(parse, run)` wiring | heavy I/O, business logic |
| `src/options/*.ts` | `*Options` types + `parse*Options(args)` | side effects |
| `src/main/*.ts` | `run*(out, options)` behaviour | citty imports, `process.argv` |

- Use `defineForestrieCommand` (merges tool-wide `commonArgs` — citty does
  not inherit parent flags) and `defineCommandRunner` from
  `src/commoncli.ts` (re-exported from `@forestrie/cli-kit`).
- Output goes through cli-kit's `Out` (`out.out` = stdout/pipeable,
  `out.print`/`warn`/`log` = stderr by verbosity). No raw `console.*` in
  `src/main/`.
- Dependencies are **published `@forestrie/*` packages only** — no
  workspace/repo-internal deps, no copied package code (plan-2607-12).
- Implementing a subcommand (FOR-340..347): replace its `src/main/<cmd>.ts`
  stub, extend its `src/options/<cmd>.ts` as needed, keep the
  `not_implemented` JSON contract out of the way, and land it as its own PR.
- One command per file; keep each PR to one subcommand.
