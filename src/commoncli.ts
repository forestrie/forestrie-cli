/**
 * Tool-wide CLI flags and command wiring for the `forestrie` binary.
 *
 * citty does not pass parent flags into subcommand `run({ args })`, so
 * `commonArgs` is merged into every command via `defineForestrieCommand`
 * (see univocity-tools docs/agents/cli.md — the pattern source).
 */
import type { ArgsDef, CommandDef } from "citty";
import { defineAppCommand, verbosityArgs } from "@forestrie/cli-kit";

export { defineCommandRunner } from "@forestrie/cli-kit";

/** Flags shared by every `forestrie` command. */
export const commonArgs = {
  ...verbosityArgs,
  json: {
    type: "boolean",
    description: "Machine-readable JSON output on stdout",
    default: false,
  },
  config: {
    type: "string",
    description:
      "Config file path (default: ${env} → FORESTRIE_CONFIG). Stub — config loading lands with the subcommand implementations.",
    valueHint: "path",
  },
} as const satisfies ArgsDef;

/** Wrap `defineCommand` so every node in the tree gets `commonArgs`. */
export function defineForestrieCommand<T extends ArgsDef>(
  def: CommandDef<T>,
): CommandDef<T> {
  return defineAppCommand(commonArgs, def);
}
