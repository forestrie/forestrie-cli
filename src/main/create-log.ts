import type { Out } from "@forestrie/cli-kit/reporting";
import { uuidToBytes } from "@forestrie/encoding";
import {
  anchorFailureLine,
  anchorRoundNarrator,
  anchorTargetFor,
  anchorWaitReport,
  bindAnchorChain,
  receiptRefresher,
  type AnchorWaitReport,
} from "../lib/anchor-wait-run.js";
import {
  waitAnchored,
  type AnchorChain,
  type AnchorTarget,
} from "../lib/anchor-wait.js";
import { authorityPendingLine } from "../lib/register-admission.js";
import { readBytesFile, readTextFile, writeOutputFile } from "../lib/fsio.js";
import type { CreateLogOptions } from "../options/create-log.js";
import {
  RegisterGrantBuildError,
  buildCreateLogGrant,
  type BuiltCreateLogGrant,
} from "../lib/create-log-build.js";
import { completeGrantBase64 } from "../lib/register-grant-complete.js";
import {
  PrepareLogError,
  prepareChildLog,
} from "../lib/create-log-prepare.js";
import {
  RegisterFlowError,
  runRegisterGrantFlow,
  type RegisterGrantFlowDeps,
  type RegisterGrantFlowResult,
} from "../lib/register-grant-flow.js";

/**
 * FOR-390 / ADR-0052: create a log and set its owner (K(L)). Build the signed
 * create grant (`@forestrie/grant-builder` ES256 profile) with
 * `GF_CREATE|GF_EXTEND` flags, POST it to `/register/{bootstrap}/grants` with
 * the parent grant as CBOR body evidence, follow the 303 to the receipt, then
 * emit the COMPLETED grant. The flow is identical to register-grant's; only the
 * grant shape and the reporter labels differ (newLog / owner).
 */

/** `--json` success shape. */
export type CreateLogReport = {
  command: "create-log";
  status: "receipt";
  /** Parent/auth log the create grant was sequenced into. */
  ownerLog: string;
  /** The log that was created. */
  newLog: string;
  /** The new log owner (ES256 x||y, hex) committed as grantData. */
  ownerHex: string;
  entryId: string;
  statusUrl: string;
  receiptUrl: string;
  receiptBytes: number;
  /** Present when `--out-b64` was given. */
  outB64?: string;
  /** Completed grant base64 — only when not written to `--out-b64`. */
  grantB64?: string;
  /** `--wait-anchored`: how the wait for the new log to anchor ended. */
  anchor?: AnchorWaitReport;
  /** `--wait-anchored`: why the wait could not start once the log existed. */
  anchorError?: string;
};

/** `--json` failure shape (problem = CBOR problem-details passthrough). */
export type CreateLogErrorReport = {
  error:
    | "key_read_failed"
    | "grant_build_failed"
    | "anchor_setup_failed"
    | "registration_failed"
    | "status_failed"
    | "receipt_failed"
    | "network_failed"
    | "timeout";
  command: "create-log";
  message: string;
  httpStatus?: number;
  detail?: string;
  problem?: Record<string, unknown>;
  statusUrl?: string;
  receiptUrl?: string;
};

/** Test seam: effects injected by the create-log tests (real by default). */
export type CreateLogRunDeps = RegisterGrantFlowDeps & {
  /** `--wait-anchored` chain reads (default: JSON-RPC to `--rpc-url`). */
  anchorChain?: AnchorChain;
};

/** `--wait-anchored`, bound before the create grant is registered. */
type BoundAnchorWait = {
  chain: AnchorChain;
  genesisCbor: Uint8Array | undefined;
  timeoutMs: number;
  intervalMs: number;
};

const FLOW_ERROR_CODES = {
  register: "registration_failed",
  status: "status_failed",
  receipt: "receipt_failed",
  network: "network_failed",
  timeout: "timeout",
} as const;

async function readPemFile(path: string, flag: string): Promise<string> {
  return readTextFile(path, `${flag} key file not found: ${path}`);
}

function reportError(
  out: Out,
  options: CreateLogOptions,
  report: CreateLogErrorReport,
): void {
  if (options.json) {
    out.out(JSON.stringify(report, null, 2));
  } else {
    out.warn("forestrie create-log: %s", report.message);
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

function flowErrorReport(err: RegisterFlowError): CreateLogErrorReport {
  const report: CreateLogErrorReport = {
    error: FLOW_ERROR_CODES[err.stage],
    command: "create-log",
    message: err.message,
  };
  if (err.httpStatus !== undefined) report.httpStatus = err.httpStatus;
  if (err.detail !== undefined) report.detail = err.detail;
  if (err.problem !== undefined) report.problem = err.problem;
  if (err.statusUrl !== undefined) report.statusUrl = err.statusUrl;
  if (err.receiptUrl !== undefined) report.receiptUrl = err.receiptUrl;
  return report;
}

function reportCompletedGrant(
  out: Out,
  options: CreateLogOptions,
  built: BuiltCreateLogGrant,
  result: RegisterGrantFlowResult,
  completedB64: string,
  anchor: Pick<CreateLogReport, "anchor" | "anchorError"> = {},
): void {
  const ownerHex = Buffer.from(built.grantData).toString("hex");
  if (options.json) {
    const report: CreateLogReport = {
      command: "create-log",
      status: "receipt",
      ownerLog: options.ownerLog,
      newLog: options.newLog,
      ownerHex,
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
    out.out(JSON.stringify({ ...report, ...anchor }, null, 2));
    return;
  }
  // Human mode: without --out-b64 the completed grant base64 is the pipeable
  // product on stdout; the summary narrates on stderr. With --out-b64 the
  // summary is the stdout product (mirrors register / register-grant).
  const emit = options.outB64 === undefined ? out.print : out.out;
  emit("ownerLog: %s (grant leaf)", options.ownerLog);
  emit("newLog: %s (created)", options.newLog);
  emit("owner: %s", ownerHex);
  emit("entryId: %s", result.entryIdHex);
  emit("statusUrl: %s", result.statusUrl);
  emit("receiptUrl: %s", result.receiptUrl);
  if (options.outB64 !== undefined) {
    emit("wrote completed grant (base64) to %s", options.outB64);
  } else {
    out.out("%s", completedB64);
  }
}

export async function runCreateLog(
  out: Out,
  options: CreateLogOptions,
  deps: CreateLogRunDeps = {},
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
      command: "create-log",
      message: err instanceof Error ? err.message : String(err),
    });
    return;
  }

  // 2. Build + sign the create grant transparent statement.
  let built: BuiltCreateLogGrant;
  try {
    built = buildCreateLogGrant({
      newLog: options.newLog,
      ownerLog: options.ownerLog,
      signWithPem,
      signerPem,
      selfReferential: options.selfReferential,
      authLog: options.authLog,
      childPaymentRequired: options.childPaymentRequired,
    });
  } catch (err) {
    if (err instanceof RegisterGrantBuildError) {
      reportError(out, options, {
        error: "grant_build_failed",
        command: "create-log",
        message: err.message,
      });
      return;
    }
    throw err;
  }

  // 2b. --prepare: pre-register the child public root with the coordinator under
  // parent authority (ADR-0053), WITHOUT sequencing. Emits the create grant so a
  // later plain `create-log` sequences it. Enables `delegate` before the log
  // exists.
  if (options.prepare) {
    if (options.selfReferential) {
      reportError(out, options, {
        error: "grant_build_failed",
        command: "create-log",
        message:
          "--prepare is for child logs; the root/bootstrap log is onboarded via genesis, not prepare",
      });
      return;
    }
    try {
      const prepared = await prepareChildLog(
        {
          baseUrl: options.baseUrl,
          childLogId: options.newLog,
          grantBase64: built.grantBase64,
        },
        { fetchImpl: deps.fetchImpl },
      );
      if (options.outB64 !== undefined) {
        await writeOutputFile(options.outB64, built.grantBase64);
      }
      if (options.json) {
        const report = {
          command: "create-log" as const,
          status: "prepared" as const,
          ownerLog: options.ownerLog,
          newLog: options.newLog,
          publicRoot: prepared.publicRoot,
          ...(prepared.webhook !== undefined
            ? { webhook: prepared.webhook }
            : {}),
          ...(options.outB64 !== undefined ? { outB64: options.outB64 } : {}),
          grantB64: options.outB64 === undefined ? built.grantBase64 : undefined,
        };
        out.out(JSON.stringify(report, null, 2));
        return;
      }
      const emit = options.outB64 === undefined ? out.print : out.out;
      emit("prepared child log %s (owner %s)", options.newLog, options.ownerLog);
      emit(
        "coordinator: public-root %s%s",
        prepared.publicRoot,
        prepared.webhook !== undefined ? `, webhook ${prepared.webhook}` : "",
      );
      emit("owner: %s", Buffer.from(built.grantData).toString("hex"));
      if (options.outB64 !== undefined) {
        emit("wrote create grant (base64) to %s", options.outB64);
      } else {
        out.out("%s", built.grantBase64);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      reportError(out, options, {
        error: "registration_failed",
        command: "create-log",
        message,
        ...(err instanceof PrepareLogError && err.httpStatus !== undefined
          ? { httpStatus: err.httpStatus }
          : {}),
      });
    }
    return;
  }

  // 2c. --wait-anchored: bind the chain now, so that with --genesis a wrong
  // forest, or an RPC that cannot say its chain id, is refused before the
  // write-once create grant is spent.
  let anchorWait: BoundAnchorWait | undefined;
  if (options.anchorWait !== undefined) {
    try {
      anchorWait = await bindCreateLogAnchorWait(options, deps.anchorChain);
    } catch (err) {
      reportError(out, options, {
        error: "anchor_setup_failed",
        command: "create-log",
        message: err instanceof Error ? err.message : String(err),
      });
      return;
    }
  }

  const { anchorChain: _anchorChain, ...registerDeps } = deps;
  const flowDeps: RegisterGrantFlowDeps = {
    ...registerDeps,
    onProgress:
      deps.onProgress ??
      ((progress) => {
        switch (progress.phase) {
          case "authority-pending":
            out.print("%s", authorityPendingLine(progress));
            break;
          case "registered":
            out.print("create grant registered; status: %s", progress.statusUrl);
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

  // 3. Register the create grant, follow to the receipt, complete the grant.
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
    if (options.outB64 !== undefined) {
      await writeOutputFile(options.outB64, completedB64);
    }
    if (anchorWait === undefined) {
      reportCompletedGrant(out, options, built, result, completedB64);
      return;
    }
    // The log exists now: the human-mode grant goes out before the wait,
    // so an interrupted wait never loses it.
    if (!options.json) {
      reportCompletedGrant(out, options, built, result, completedB64);
    }
    const anchor = await waitForCreatedLog(
      out,
      completedB64,
      result.receiptUrl,
      anchorWait,
      deps,
    );
    if (options.json) {
      reportCompletedGrant(out, options, built, result, completedB64, anchor);
    }
  } catch (err) {
    if (err instanceof RegisterFlowError) {
      reportError(out, options, flowErrorReport(err));
      return;
    }
    throw err;
  }
}

async function bindCreateLogAnchorWait(
  options: CreateLogOptions,
  chain: AnchorChain | undefined,
): Promise<BoundAnchorWait> {
  const wait = options.anchorWait!;
  const genesisCbor =
    wait.genesis !== undefined
      ? await readBytesFile(wait.genesis, `genesis file not found: ${wait.genesis}`)
      : undefined;
  if (options.selfReferential) {
    const root = await anchorTargetFor(undefined, genesisCbor);
    // Compare as bytes: --new-log may be given with or without dashes.
    const same =
      Buffer.from(uuidToBytes(root.logId)).equals(
        Buffer.from(uuidToBytes(options.newLog)),
      );
    if (!same) {
      throw new Error(
        `the genesis is for root ${root.logId}, not --new-log ${options.newLog}`,
      );
    }
  }
  return {
    chain: await bindAnchorChain(
      { genesisCbor, univocity: wait.univocity, rpcUrl: wait.rpcUrl },
      chain,
    ),
    genesisCbor,
    timeoutMs: wait.timeoutMs,
    intervalMs: wait.intervalMs,
  };
}

/**
 * Wait for the log just created to anchor, narrating on stderr, re-fetching
 * its receipt each round. A log that does not anchor in budget, or never
 * can, sets the exit code: the log exists and its grant has been emitted,
 * but it is not usable yet.
 */
async function waitForCreatedLog(
  out: Out,
  completedB64: string,
  receiptUrl: string,
  wait: BoundAnchorWait,
  deps: CreateLogRunDeps,
): Promise<Pick<CreateLogReport, "anchor" | "anchorError">> {
  let target: AnchorTarget;
  try {
    target = await anchorTargetFor(completedB64, wait.genesisCbor);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    out.warn("forestrie create-log: cannot wait for anchoring: %s", message);
    process.exitCode = 1;
    return { anchorError: message };
  }
  const result = await waitAnchored(target, wait.chain, {
    timeoutMs: wait.timeoutMs,
    intervalMs: wait.intervalMs,
    ...(deps.now !== undefined ? { now: deps.now } : {}),
    ...(deps.sleep !== undefined ? { sleep: deps.sleep } : {}),
    onRound: anchorRoundNarrator(out),
    // A root's authority is its contract; only a child has a receipt.
    ...(target.kind === "child"
      ? { refreshReceipt: receiptRefresher(receiptUrl, deps.fetchImpl) }
      : {}),
  });
  if (result.answer.status !== "anchored") {
    out.warn("%s", anchorFailureLine("create-log", target, result, wait.timeoutMs));
    process.exitCode = 1;
  }
  return { anchor: anchorWaitReport(target, result) };
}
