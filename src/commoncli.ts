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

/**
 * citty keeps only the last occurrence of a repeated string flag. Wrap a
 * runner so the named repeatable flags reach the option parser as arrays of
 * every occurrence (`--flag a --flag b` and `--flag=a`).
 */
export function withRepeatedFlags<
  C extends { args: unknown; rawArgs: string[] },
>(
  names: readonly string[],
  runner: (context: C) => Promise<void>,
): (context: C) => Promise<void> {
  return (context) => {
    const args = { ...(context.args as Record<string, unknown>) };
    for (const name of names) {
      const values: string[] = [];
      const raw = context.rawArgs;
      const camel = name.replace(/-([a-z0-9])/g, (_, c: string) =>
        c.toUpperCase(),
      );
      for (let i = 0; i < raw.length; i++) {
        const a = raw[i]!;
        if (a === "--") break;
        if (a === `--${name}` || a === `--${camel}`) {
          const next = raw[i + 1];
          if (next !== undefined && !next.startsWith("--")) {
            values.push(next);
            i++;
          }
        } else if (a.startsWith(`--${name}=`)) {
          values.push(a.slice(name.length + 3));
        } else if (a.startsWith(`--${camel}=`)) {
          values.push(a.slice(camel.length + 3));
        }
      }
      if (values.length > 1) args[name] = values;
    }
    return runner({ ...context, args });
  };
}
