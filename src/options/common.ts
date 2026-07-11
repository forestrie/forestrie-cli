import {
  readEvaluatedStringOption,
  resolveVerbosity,
  type LooseParsedArgs,
} from "@forestrie/cli-kit";

/** Options shared by every `forestrie` command (after parsing). */
export type ForestrieCommonOptions = {
  /** Emit machine-readable JSON on stdout instead of human output. */
  json: boolean;
  /**
   * Config file path, if provided (`--config` / `FORESTRIE_CONFIG`).
   * Stub: recorded at parse time; loading lands with the implementations.
   */
  config?: string;
  /** Resolved output verbosity. */
  verbosity: number;
};

/** Resolve the tool-wide common options at parse time. */
export function parseForestrieCommonOptions(
  args: LooseParsedArgs,
): ForestrieCommonOptions {
  const config =
    readEvaluatedStringOption(args, "config") ??
    process.env["FORESTRIE_CONFIG"] ??
    undefined;
  const options: ForestrieCommonOptions = {
    json: args["json"] === true,
    verbosity: resolveVerbosity(args),
  };
  if (config !== undefined && config !== "") {
    options.config = config;
  }
  return options;
}

/**
 * Read a string option (kebab or camelCase, `${env:…}` templates
 * evaluated), falling back to `envVar` when the flag is absent.
 */
export function optionalStringOption(
  args: LooseParsedArgs,
  name: string,
  envVar?: string,
): string | undefined {
  const value =
    readEvaluatedStringOption(args, name) ??
    (envVar ? process.env[envVar] : undefined);
  return value === "" ? undefined : value;
}

/**
 * As `optionalStringOption`, but a missing value is a usage error.
 * Options with an env fallback are enforced here rather than with
 * citty `required: true` (which cannot see the environment).
 */
export function requiredStringOption(
  args: LooseParsedArgs,
  name: string,
  envVar?: string,
): string {
  const value = optionalStringOption(args, name, envVar);
  if (value === undefined) {
    const hint = envVar ? ` (or set ${envVar})` : "";
    throw new Error(`missing required option --${name}${hint}`);
  }
  return value;
}
