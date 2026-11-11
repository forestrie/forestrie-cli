import type { Out } from "@forestrie/cli-kit/reporting";
import {
  AnchorWaitSetupError,
  anchorAnswerLine,
  anchorFailureLine,
  anchorRoundNarrator,
  anchorWaitReport,
  prepareAnchorWait,
  receiptRefresher,
} from "../lib/anchor-wait-run.js";
import { waitAnchored, type AnchorChain } from "../lib/anchor-wait.js";
import { readBytesFile, readTextFile } from "../lib/fsio.js";
import type { LogWaitAnchoredOptions } from "../options/log-wait-anchored.js";

/**
 * `forestrie log wait-anchored`: wait until a log is anchored, proven from
 * public chain data (protocol ADR-0070). A child log is anchored once a
 * checkpoint its owner published on chain covers its create grant; a
 * forest root once its contract holds the genesis key and is rooted at no
 * other log. No operator answer is trusted: with `--receipt-url`, canopy
 * supplies only a receipt path, which the chain must confirm.
 *
 * Exits 0 once anchored. Exits 1 at once for a conflicted log, which never
 * anchors, and on timeout, printing the last answer either way.
 */

const COMMAND = "log wait-anchored";

/** `--json` failure shape for inputs the wait cannot start from. */
export type LogWaitAnchoredErrorReport = {
  error: AnchorWaitSetupError["code"];
  command: typeof COMMAND;
  message: string;
};

/** Test seam: the chain, receipt fetches and clock (real by default). */
export type LogWaitAnchoredDeps = {
  chain?: AnchorChain;
  fetchImpl?: typeof fetch;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
};

export async function runLogWaitAnchored(
  out: Out,
  options: LogWaitAnchoredOptions,
  deps: LogWaitAnchoredDeps = {},
): Promise<void> {
  let prepared: Awaited<ReturnType<typeof prepareAnchorWait>>;
  try {
    prepared = await prepareAnchorWait(
      {
        createGrantB64:
          options.createGrant !== undefined
            ? (
                await readTextFile(
                  options.createGrant,
                  `create grant file not found: ${options.createGrant}`,
                )
              ).trim()
            : undefined,
        genesisCbor:
          options.genesis !== undefined
            ? await readBytesFile(
                options.genesis,
                `genesis file not found: ${options.genesis}`,
              )
            : undefined,
        univocity: options.univocity,
        rpcUrl: options.rpcUrl,
      },
      deps.chain,
    );
  } catch (err) {
    const report: LogWaitAnchoredErrorReport = {
      error: err instanceof AnchorWaitSetupError ? err.code : "input_invalid",
      command: COMMAND,
      message: err instanceof Error ? err.message : String(err),
    };
    if (options.json) out.out(JSON.stringify(report, null, 2));
    else out.warn("forestrie %s: %s", COMMAND, report.message);
    process.exitCode = 1;
    return;
  }

  const { target, chain } = prepared;
  const result = await waitAnchored(target, chain, {
    timeoutMs: options.timeoutMs,
    intervalMs: options.intervalMs,
    ...(deps.now !== undefined ? { now: deps.now } : {}),
    ...(deps.sleep !== undefined ? { sleep: deps.sleep } : {}),
    onRound: anchorRoundNarrator(out),
    ...(options.receiptUrl !== undefined
      ? { refreshReceipt: receiptRefresher(options.receiptUrl, deps.fetchImpl) }
      : {}),
  });

  if (options.json) {
    out.out(
      JSON.stringify(
        { command: COMMAND, ...anchorWaitReport(target, result) },
        null,
        2,
      ),
    );
  } else {
    out.out(anchorAnswerLine(result.answer));
  }
  if (result.answer.status !== "anchored") {
    if (!options.json) {
      out.warn("%s", anchorFailureLine(COMMAND, target, result, options.timeoutMs));
    }
    process.exitCode = 1;
  }
}
