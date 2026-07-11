import type { Out } from "@forestrie/cli-kit/reporting";
import type { ForestrieCommonOptions } from "../options/common.js";

/** Structured not-implemented report — the `--json` shape is a contract. */
export type NotImplementedReport = {
  error: "not_implemented";
  command: string;
  issue: string;
  message: string;
  options: Record<string, unknown>;
};

/**
 * Every subcommand stub terminates here: parsing succeeded (the arg
 * surface is real), the behaviour ships under the referenced FOR-34x
 * issue. Exits non-zero via `process.exitCode` so citty does not wrap
 * the message in its own error formatting.
 *
 * Human mode: one line on stderr. `--json`: the report on stdout.
 */
export function reportNotImplemented(
  out: Out,
  common: ForestrieCommonOptions,
  command: string,
  issue: string,
  options: Record<string, unknown>,
): void {
  const message = `forestrie ${command}: not implemented yet — ${issue}`;
  if (common.json) {
    const report: NotImplementedReport = {
      error: "not_implemented",
      command,
      issue,
      message,
      options,
    };
    out.out(JSON.stringify(report, null, 2));
  } else {
    out.warn(message);
    out.log("parsed options: %s", JSON.stringify(options));
  }
  process.exitCode = 1;
}
