import type { Out } from "@forestrie/cli-kit/reporting";
import type { RegisterOptions } from "../options/register.js";
import {
  RegisterFlowError,
  runRegisterFlow,
  type RegisterFlowDeps,
  type RegisterFlowResult,
} from "../lib/register-flow.js";

/**
 * FOR-342: register a signed statement via SCRAPI
 * (`@forestrie/scrapi-client`) — POST with the `Authorization:
 * Forestrie-Grant` header (opaque bearer at this step), follow the 303,
 * poll, download the receipt. Any SCRAPI client, plain COSE Sign1.
 */

/** `--json` success shape. */
export type RegisterReport = {
  command: "register";
  status: "receipt";
  entryId: string;
  statusUrl: string;
  receiptUrl: string;
  receiptBytes: number;
  /** Present when `--out` was given. */
  out?: string;
  /** Receipt bytes, base64 — only when not written to `--out`. */
  receiptB64?: string;
};

/** `--json` failure shape (problem = CBOR problem-details passthrough). */
export type RegisterErrorReport = {
  error:
    | "statement_read_failed"
    | "registration_failed"
    | "status_failed"
    | "receipt_failed"
    | "network_failed"
    | "timeout";
  command: "register";
  message: string;
  httpStatus?: number;
  detail?: string;
  problem?: Record<string, unknown>;
  statusUrl?: string;
  receiptUrl?: string;
};

/** Test seam: effects injected by the register tests (real by default). */
export type RegisterRunDeps = RegisterFlowDeps & {
  /** Statement source when `--statement` is `-`/absent (default: stdin). */
  readStdin?: () => Promise<Uint8Array>;
};

const FLOW_ERROR_CODES = {
  register: "registration_failed",
  status: "status_failed",
  receipt: "receipt_failed",
  network: "network_failed",
  timeout: "timeout",
} as const;

async function readStatementBytes(
  statement: string | undefined,
  readStdin: () => Promise<Uint8Array>,
): Promise<Uint8Array> {
  if (statement === undefined || statement === "-") {
    return readStdin();
  }
  const file = Bun.file(statement);
  if (!(await file.exists())) {
    throw new Error(`statement file not found: ${statement}`);
  }
  return new Uint8Array(await file.arrayBuffer());
}

function reportError(
  out: Out,
  options: RegisterOptions,
  report: RegisterErrorReport,
): void {
  if (options.json) {
    out.out(JSON.stringify(report, null, 2));
  } else {
    out.warn("forestrie register: %s", report.message);
    if (report.detail !== undefined && !report.message.includes(report.detail)) {
      out.warn("  detail: %s", report.detail);
    }
    if (report.problem !== undefined) {
      out.log("problem details: %s", JSON.stringify(report.problem));
    }
    if (report.statusUrl !== undefined) {
      out.warn("  statusUrl: %s", report.statusUrl);
    }
    if (report.receiptUrl !== undefined) {
      out.warn("  receiptUrl: %s", report.receiptUrl);
    }
  }
  process.exitCode = 1;
}

function flowErrorReport(err: RegisterFlowError): RegisterErrorReport {
  const report: RegisterErrorReport = {
    error: FLOW_ERROR_CODES[err.stage],
    command: "register",
    message: err.message,
  };
  if (err.httpStatus !== undefined) report.httpStatus = err.httpStatus;
  if (err.detail !== undefined) report.detail = err.detail;
  if (err.problem !== undefined) report.problem = err.problem;
  if (err.statusUrl !== undefined) report.statusUrl = err.statusUrl;
  if (err.receiptUrl !== undefined) report.receiptUrl = err.receiptUrl;
  return report;
}

async function reportReceipt(
  out: Out,
  options: RegisterOptions,
  result: RegisterFlowResult,
): Promise<void> {
  if (options.out !== undefined) {
    await Bun.write(options.out, result.receipt);
  }
  if (options.json) {
    const report: RegisterReport = {
      command: "register",
      status: "receipt",
      entryId: result.entryIdHex,
      statusUrl: result.statusUrl,
      receiptUrl: result.receiptUrl,
      receiptBytes: result.receipt.length,
    };
    if (options.out !== undefined) {
      report.out = options.out;
    } else {
      report.receiptB64 = Buffer.from(result.receipt).toString("base64");
    }
    out.out(JSON.stringify(report, null, 2));
    return;
  }
  // Human mode: receipt to --out keeps stdout clean; without --out the
  // summary is the pipeable product.
  const emit = options.out !== undefined ? out.print : out.out;
  emit("entryId: %s", result.entryIdHex);
  emit("statusUrl: %s", result.statusUrl);
  emit("receiptUrl: %s", result.receiptUrl);
  if (options.out !== undefined) {
    emit(
      "wrote receipt (%d bytes) to %s",
      result.receipt.length,
      options.out,
    );
  } else {
    emit(
      "receipt: %d bytes (pass --out <path> to save the CBOR)",
      result.receipt.length,
    );
  }
}

export async function runRegister(
  out: Out,
  options: RegisterOptions,
  deps: RegisterRunDeps = {},
): Promise<void> {
  const readStdin =
    deps.readStdin ??
    (async () => new Uint8Array(await Bun.stdin.arrayBuffer()));

  let statement: Uint8Array;
  try {
    statement = await readStatementBytes(options.statement, readStdin);
  } catch (err) {
    reportError(out, options, {
      error: "statement_read_failed",
      command: "register",
      message: err instanceof Error ? err.message : String(err),
    });
    return;
  }
  if (statement.length === 0) {
    reportError(out, options, {
      error: "statement_read_failed",
      command: "register",
      message: "signed statement is empty",
    });
    return;
  }

  const flowDeps: RegisterFlowDeps = {
    ...deps,
    onProgress:
      deps.onProgress ??
      ((progress) => {
        switch (progress.phase) {
          case "registered":
            out.print("registered; status: %s", progress.statusUrl);
            break;
          case "status-pending":
            out.log(
              "sequencing pending (attempt %d): %s",
              progress.attempt,
              progress.statusUrl,
            );
            break;
          case "receipt-located":
            out.print(
              "sequenced as entry %s; receipt: %s",
              progress.entryIdHex,
              progress.receiptUrl,
            );
            break;
          case "receipt-pending":
            out.log(
              "receipt objects still writing (attempt %d): %s",
              progress.attempt,
              progress.receiptUrl,
            );
            break;
        }
      }),
  };

  try {
    const result = await runRegisterFlow(
      {
        baseUrl: options.baseUrl,
        logId: options.logId,
        grantB64: options.grantB64,
        statement,
        timeoutMs: options.timeoutMs,
        pollIntervalMs: options.pollIntervalMs,
      },
      flowDeps,
    );
    await reportReceipt(out, options, result);
  } catch (err) {
    if (err instanceof RegisterFlowError) {
      reportError(out, options, flowErrorReport(err));
      return;
    }
    throw err;
  }
}
