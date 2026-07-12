import type { Out } from "@forestrie/cli-kit/reporting";
import type { RegisterGrantOptions } from "../options/register-grant.js";
import {
  RegisterGrantBuildError,
  buildGrantStatement,
  type BuiltGrantStatement,
} from "../lib/register-grant-build.js";
import { completeGrantBase64 } from "../lib/register-grant-complete.js";
import {
  RegisterFlowError,
  runRegisterGrantFlow,
  type RegisterGrantFlowDeps,
  type RegisterGrantFlowResult,
} from "../lib/register-grant-flow.js";

/**
 * FOR-343: register a grant statement authorizing use of a child/data log.
 * One grant binds exactly ONE signer; several signers on one data log =
 * several grants naming that log, all sequenced into the OWNER (auth)
 * log. Build the signed grant (`@forestrie/grant-builder` ES256 profile),
 * POST it to `/register/{bootstrap}/grants` with the parent grant as CBOR
 * body evidence (`@forestrie/scrapi-client`), follow the 303 to the
 * receipt, then emit the COMPLETED grant (receipt + idtimestamp attached)
 * — the bearer credential `forestrie register` consumes.
 */

/** `--json` success shape. */
export type RegisterGrantReport = {
  command: "register-grant";
  status: "receipt";
  /** Owner (auth) log the grant leaf was sequenced into. */
  ownerLog: string;
  /** Target child/data log the grant authorizes. */
  dataLog: string;
  /** The ONE authorized signer (ES256 x||y, hex) committed as grantData. */
  grantDataHex: string;
  entryId: string;
  statusUrl: string;
  receiptUrl: string;
  receiptBytes: number;
  /** Present when `--out-b64` was given. */
  outB64?: string;
  /** Completed grant base64 — only when not written to `--out-b64`. */
  grantB64?: string;
};

/** `--json` failure shape (problem = CBOR problem-details passthrough). */
export type RegisterGrantErrorReport = {
  error:
    | "key_read_failed"
    | "grant_build_failed"
    | "registration_failed"
    | "status_failed"
    | "receipt_failed"
    | "network_failed"
    | "timeout";
  command: "register-grant";
  message: string;
  httpStatus?: number;
  detail?: string;
  problem?: Record<string, unknown>;
  statusUrl?: string;
  receiptUrl?: string;
};

/** Test seam: effects injected by the register-grant tests (real by default). */
export type RegisterGrantRunDeps = RegisterGrantFlowDeps;

const FLOW_ERROR_CODES = {
  register: "registration_failed",
  status: "status_failed",
  receipt: "receipt_failed",
  network: "network_failed",
  timeout: "timeout",
} as const;

async function readPemFile(path: string, flag: string): Promise<string> {
  const file = Bun.file(path);
  if (!(await file.exists())) {
    throw new Error(`${flag} key file not found: ${path}`);
  }
  return file.text();
}

function reportError(
  out: Out,
  options: RegisterGrantOptions,
  report: RegisterGrantErrorReport,
): void {
  if (options.json) {
    out.out(JSON.stringify(report, null, 2));
  } else {
    out.warn("forestrie register-grant: %s", report.message);
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

function flowErrorReport(err: RegisterFlowError): RegisterGrantErrorReport {
  const report: RegisterGrantErrorReport = {
    error: FLOW_ERROR_CODES[err.stage],
    command: "register-grant",
    message: err.message,
  };
  if (err.httpStatus !== undefined) report.httpStatus = err.httpStatus;
  if (err.detail !== undefined) report.detail = err.detail;
  if (err.problem !== undefined) report.problem = err.problem;
  if (err.statusUrl !== undefined) report.statusUrl = err.statusUrl;
  if (err.receiptUrl !== undefined) report.receiptUrl = err.receiptUrl;
  return report;
}

async function reportCompletedGrant(
  out: Out,
  options: RegisterGrantOptions,
  built: BuiltGrantStatement,
  result: RegisterGrantFlowResult,
  completedB64: string,
): Promise<void> {
  const grantDataHex = Buffer.from(built.grantData).toString("hex");
  if (options.outB64 !== undefined) {
    await Bun.write(options.outB64, completedB64);
  }
  if (options.json) {
    const report: RegisterGrantReport = {
      command: "register-grant",
      status: "receipt",
      ownerLog: options.ownerLog,
      dataLog: options.dataLog,
      grantDataHex,
      entryId: result.entryIdHex,
      statusUrl: result.statusUrl,
      receiptUrl: result.receiptUrl,
      receiptBytes: result.receipt.length,
    };
    if (options.outB64 !== undefined) {
      report.outB64 = options.outB64;
    } else {
      report.grantB64 = completedB64;
    }
    out.out(JSON.stringify(report, null, 2));
    return;
  }
  // Human mode: without --out-b64 the completed grant base64 is the
  // pipeable product on stdout; the summary narrates on stderr. With
  // --out-b64 the summary is the stdout product (mirrors register).
  const emit = options.outB64 === undefined ? out.print : out.out;
  emit("ownerLog: %s (grant leaf)", options.ownerLog);
  emit("dataLog: %s (authorized)", options.dataLog);
  emit("signer: %s", grantDataHex);
  emit("entryId: %s", result.entryIdHex);
  emit("statusUrl: %s", result.statusUrl);
  emit("receiptUrl: %s", result.receiptUrl);
  if (options.outB64 !== undefined) {
    emit("wrote completed grant (base64) to %s", options.outB64);
  } else {
    out.out("%s", completedB64);
  }
}

export async function runRegisterGrant(
  out: Out,
  options: RegisterGrantOptions,
  deps: RegisterGrantRunDeps = {},
): Promise<void> {
  // 1. Key material.
  let signWithPem: string;
  let signerPem: string | undefined;
  try {
    signWithPem = await readPemFile(options.signWith, "--sign-with");
    signerPem =
      options.signerPem !== undefined
        ? await readPemFile(options.signerPem, "--signer-pem")
        : undefined;
  } catch (err) {
    reportError(out, options, {
      error: "key_read_failed",
      command: "register-grant",
      message: err instanceof Error ? err.message : String(err),
    });
    return;
  }

  // 2. Build + sign the grant transparent statement (one grant, ONE signer).
  let built: BuiltGrantStatement;
  try {
    built = buildGrantStatement({
      targetLog: options.dataLog,
      ownerLog: options.ownerLog,
      signWithPem,
      signerPem,
      selfReferential: options.selfReferential,
      authLog: options.authLog,
    });
  } catch (err) {
    if (err instanceof RegisterGrantBuildError) {
      reportError(out, options, {
        error: "grant_build_failed",
        command: "register-grant",
        message: err.message,
      });
      return;
    }
    throw err;
  }

  const flowDeps: RegisterGrantFlowDeps = {
    ...deps,
    onProgress:
      deps.onProgress ??
      ((progress) => {
        switch (progress.phase) {
          case "registered":
            out.print("grant registered; status: %s", progress.statusUrl);
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

  // 3. Register the grant, follow to the receipt, complete the grant.
  try {
    const result = await runRegisterGrantFlow(
      {
        baseUrl: options.baseUrl,
        bootstrapLogId: options.bootstrapLog,
        grantBase64: built.grantBase64,
        parentGrantBase64: options.parentGrantB64,
        timeoutMs: options.timeoutMs,
        pollIntervalMs: options.pollIntervalMs,
      },
      flowDeps,
    );
    const completedB64 = completeGrantBase64(
      built.grantBase64,
      result.receipt,
      result.entryIdHex,
    );
    await reportCompletedGrant(out, options, built, result, completedB64);
  } catch (err) {
    if (err instanceof RegisterFlowError) {
      reportError(out, options, flowErrorReport(err));
      return;
    }
    throw err;
  }
}
