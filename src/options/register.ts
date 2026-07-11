import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/** Default overall receipt wait (`--timeout`), seconds. */
export const DEFAULT_TIMEOUT_SECONDS = 60;
/** Default poll pacing (`--poll-interval`), seconds. */
export const DEFAULT_POLL_INTERVAL_SECONDS = 1;

/** `forestrie register` — FOR-342. */
export type RegisterOptions = ForestrieCommonOptions & {
  /** SCRAPI origin, no trailing slash (`FORESTRIE_BASE_URL`). */
  baseUrl: string;
  /** Target log id (UUID). */
  logId: string;
  /**
   * COSE Sign1 signed statement file to register; `-` or absent reads
   * the statement bytes from stdin.
   */
  statement: string | undefined;
  /** `Authorization: Forestrie-Grant` bearer credential (`GRANT_B64`). */
  grantB64: string;
  /** Receipt output path (default: human/JSON summary only). */
  out: string | undefined;
  /** Overall receipt wait budget, milliseconds (`--timeout` seconds). */
  timeoutMs: number;
  /** Poll pacing, milliseconds (`--poll-interval` seconds). */
  pollIntervalMs: number;
};

/**
 * Read `--<name>` as a positive (fractional allowed) number of seconds,
 * returning milliseconds; a missing flag yields the default.
 */
function durationOptionMs(
  args: LooseParsedArgs,
  name: string,
  defaultSeconds: number,
): number {
  const raw = optionalStringOption(args, name);
  if (raw === undefined) {
    return Math.round(defaultSeconds * 1000);
  }
  const seconds = Number(raw);
  if (!Number.isFinite(seconds) || seconds <= 0) {
    throw new Error(`--${name} must be a positive number of seconds`);
  }
  return Math.round(seconds * 1000);
}

export function parseRegisterOptions(args: LooseParsedArgs): RegisterOptions {
  return {
    ...parseForestrieCommonOptions(args),
    baseUrl: requiredStringOption(args, "base-url", "FORESTRIE_BASE_URL"),
    logId: requiredStringOption(args, "log-id"),
    statement: optionalStringOption(args, "statement"),
    grantB64: requiredStringOption(args, "grant-b64", "GRANT_B64"),
    out: optionalStringOption(args, "out"),
    timeoutMs: durationOptionMs(args, "timeout", DEFAULT_TIMEOUT_SECONDS),
    pollIntervalMs: durationOptionMs(
      args,
      "poll-interval",
      DEFAULT_POLL_INTERVAL_SECONDS,
    ),
  };
}
