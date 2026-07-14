import type { Out } from "@forestrie/cli-kit/reporting";
import type { DelegateOptions } from "../options/delegate.js";
import {
  DelegateFlowError,
  runDelegateFlow,
  type DelegateFlowDeps,
  type DelegateFlowResult,
} from "../lib/delegate-flow.js";

/**
 * FOR-390 / ADR-0052: authorize a custodian-vouched sealer to publish
 * checkpoints for a log the caller owns (K(L)). Reads the ES256 root PEM, runs
 * the public delegation flow (`delegate-flow.ts`) — which verifies the
 * registrar voucher against the operator-pinned registrar key before binding —
 * and reports the bound lease. Public coordinator endpoints only.
 */

/** `--json` success shape. */
export type DelegateReport = {
  command: "delegate";
  status: "submitted";
  logId: string;
  sealerId: string;
  epoch: number | string;
  mmrStart: number;
  mmrEnd: number;
  expiresAt: number;
  /** Present when `--out-b64` was given. */
  outB64?: string;
};

/** `--json` failure shape. */
export type DelegateErrorReport = {
  command: "delegate";
  error: "key_read_failed" | "delegation_failed";
  message: string;
  httpStatus?: number;
};

/** Test seam: effects injected by the delegate tests (real by default). */
export type DelegateRunDeps = DelegateFlowDeps;

async function readPemFile(path: string, flag: string): Promise<string> {
  const file = Bun.file(path);
  if (!(await file.exists())) {
    throw new Error(`${flag} key file not found: ${path}`);
  }
  return file.text();
}

function reportError(
  out: Out,
  options: DelegateOptions,
  report: DelegateErrorReport,
): void {
  if (options.json) {
    out.out(JSON.stringify(report, null, 2));
  } else {
    out.warn("forestrie delegate: %s", report.message);
  }
  process.exitCode = 1;
}

async function reportResult(
  out: Out,
  options: DelegateOptions,
  result: DelegateFlowResult,
): Promise<void> {
  if (options.outB64 !== undefined) {
    await Bun.write(options.outB64, Buffer.from(result.certificate).toString("base64"));
  }
  if (options.json) {
    const report: DelegateReport = {
      command: "delegate",
      status: "submitted",
      logId: options.logId,
      sealerId: result.sealerId,
      epoch: result.epoch,
      mmrStart: result.mmrStart,
      mmrEnd: result.mmrEnd,
      expiresAt: result.expiresAt,
    };
    if (options.outB64 !== undefined) report.outB64 = options.outB64;
    out.out(JSON.stringify(report, null, 2));
    return;
  }
  out.print("standing: sealerId %s epoch %s", result.sealerId, String(result.epoch));
  out.print("voucher: ok — verifies against pinned registrar key");
  out.print("horizon: mmr %d..%d", result.mmrStart, result.mmrEnd);
  out.print("submit: ok");
  if (options.outB64 !== undefined) {
    out.print("wrote certificate (base64) to %s", options.outB64);
  }
}

export async function runDelegate(
  out: Out,
  options: DelegateOptions,
  deps: DelegateRunDeps = {},
): Promise<void> {
  // 1. Root key material (K(L)).
  let rootPem: string;
  try {
    rootPem = await readPemFile(options.signWith, "--sign-with");
  } catch (err) {
    reportError(out, options, {
      command: "delegate",
      error: "key_read_failed",
      message: err instanceof Error ? err.message : String(err),
    });
    return;
  }

  // 2. Run the public delegation flow (voucher verify is mandatory inside).
  try {
    const result = await runDelegateFlow(
      {
        coordinatorUrl: options.coordinatorUrl,
        logId: options.logId,
        rootPem,
        pinnedRegistrarKey: options.pinnedRegistrarKey,
        horizonMmrEnd: options.horizonMmrEnd,
        ttlSeconds: options.ttlSeconds,
      },
      deps,
    );
    await reportResult(out, options, result);
  } catch (err) {
    if (err instanceof DelegateFlowError) {
      const report: DelegateErrorReport = {
        command: "delegate",
        error: err.code ?? "delegation_failed",
        message: err.message,
      };
      if (err.httpStatus !== undefined) report.httpStatus = err.httpStatus;
      reportError(out, options, report);
      return;
    }
    throw err;
  }
}
