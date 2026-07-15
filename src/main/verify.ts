import type { Out } from "@forestrie/cli-kit/reporting";
import {
  verifyGrantReceiptOffline,
  verifyReceiptOffline,
  type ReceiptVerifyResult,
} from "@forestrie/receipt-verify";
import type { VerifyGrantOptions, VerifyOptions } from "../options/verify.js";
import {
  checkReceiptAnchored,
  type AnchorCheck,
} from "../lib/verify-anchored.js";
import {
  loadPayloadVerifyArtifacts,
  loadVerifyArtifacts,
} from "../lib/verify-inputs.js";
import {
  buildVerifyReport,
  STAGE_NARRATION,
  stageRows,
} from "../lib/verify-report.js";

/** Where an operational error broke the run (distinct from a verification
 * FAIL, which is the structured `VerifyReport` with `ok: false`). */
export type VerifyErrorStage = "input" | "verify" | "anchor";

export type VerifyErrorReport = {
  error: "verify_input_failed" | "verify_failed" | "anchor_check_failed";
  command: "verify";
  stage: VerifyErrorStage;
  message: string;
};

const VERIFY_ERROR_CODES: Record<
  VerifyErrorStage,
  VerifyErrorReport["error"]
> = {
  input: "verify_input_failed",
  verify: "verify_failed",
  anchor: "anchor_check_failed",
};

/** Fields both verify commands share for reporting + the chain-anchor check. */
type VerifyReportContext = {
  json?: boolean;
  anchor: "offline" | "chain";
  univocity: string | undefined;
  logId: string | undefined;
  rpcUrl: string | undefined;
};

/** Structured envelope under `--json`; one clean line on stderr otherwise. */
function reportRunError(
  out: Out,
  ctx: { json?: boolean },
  stage: VerifyErrorStage,
  err: unknown,
): void {
  const message = err instanceof Error ? err.message : String(err);
  if (ctx.json) {
    const report: VerifyErrorReport = {
      error: VERIFY_ERROR_CODES[stage],
      command: "verify",
      stage,
      message,
    };
    out.out(JSON.stringify(report, null, 2));
  } else {
    out.warn("forestrie verify: %s: %s", stage, message);
  }
  process.exitCode = 1;
}

/**
 * Shared tail: optional chain-anchor check, then render the stage report and
 * set the exit code. Used by both `verify` (payload) and `verify-grant`.
 */
async function finishVerify(
  out: Out,
  ctx: VerifyReportContext,
  artifacts: { genesisCbor: Uint8Array; receiptCbor: Uint8Array },
  result: ReceiptVerifyResult,
): Promise<void> {
  let anchor: AnchorCheck | undefined;
  if (ctx.anchor === "chain" && result.ok) {
    try {
      anchor = await checkReceiptAnchored({
        genesisCbor: artifacts.genesisCbor,
        receiptCbor: artifacts.receiptCbor,
        univocity: ctx.univocity!,
        logId: ctx.logId!,
        rpcUrl: ctx.rpcUrl!,
      });
    } catch (err) {
      reportRunError(out, ctx, "anchor", err);
      return;
    }
  }

  const ok = result.ok && (ctx.anchor !== "chain" || anchor?.anchored === true);

  if (ctx.json) {
    const report = buildVerifyReport({
      ok,
      result,
      mode: ctx.anchor === "chain" ? "chain-anchored" : "offline",
      anchor,
      univocity: ctx.univocity,
      logId: ctx.logId,
    });
    out.out(JSON.stringify(report, null, 2));
  } else {
    for (const row of stageRows(result)) {
      const detail =
        row.status === "failed"
          ? (row.reason ?? "unknown")
          : row.status === "skipped"
            ? "not evaluated"
            : STAGE_NARRATION[row.stage];
      out.print(
        "verify: %s %s — %s",
        row.stage.padEnd(9),
        row.status.padEnd(7),
        detail,
      );
    }
    if (anchor !== undefined) {
      if (anchor.anchored) {
        out.print(
          "verify: anchor    ok      — receipt peak matches on-chain accumulator peak %d/%d at anchored size %s",
          anchor.matchedPeak! + 1,
          anchor.accumulator.length,
          anchor.size.toString(),
        );
      } else {
        out.print(
          "verify: anchor    failed  — %s (anchored size %s, %d peaks)",
          anchor.reason ?? "unknown",
          anchor.size.toString(),
          anchor.accumulator.length,
        );
      }
    }
    if (ok) {
      out.out(
        anchor !== undefined
          ? `PASS: receipt verified offline and anchored on-chain (anchored size ${anchor.size})`
          : "PASS: receipt verified offline against the cached checkpoint",
      );
    } else if (!result.ok) {
      out.out(
        `FAIL: stage=${result.stage} reason=${result.reason ?? "unknown"}`,
      );
    } else {
      out.out(`FAIL: stage=anchor reason=${anchor?.reason ?? "unknown"}`);
    }
  }

  process.exitCode = ok ? 0 : 1;
}

/**
 * `forestrie verify` (FOR-347): the generic, SCITT-compatible offline verify.
 * The leaf commits `SHA-256(idtimestamp ‖ SHA-256(payload))`; the caller passes
 * the EXACT registered payload (`--payload`, e.g. a signed statement COSE). No
 * network during the core verify; add `--univocity/--log-id/--rpc-url` to also
 * check the on-chain accumulator.
 */
export async function runVerify(
  out: Out,
  options: VerifyOptions,
): Promise<void> {
  let artifacts: ReturnType<typeof loadPayloadVerifyArtifacts>;
  try {
    artifacts = loadPayloadVerifyArtifacts(options);
  } catch (err) {
    reportRunError(out, options, "input", err);
    return;
  }

  let result: ReceiptVerifyResult;
  try {
    result = await verifyReceiptOffline(artifacts);
  } catch (err) {
    reportRunError(out, options, "verify", err);
    return;
  }

  await finishVerify(out, options, artifacts, result);
}

/**
 * `forestrie verify-grant` (FOR-347): verify a forestrie authority/grant
 * receipt. A thin wrapper over the same core — it derives the grant commitment
 * preimage from a structured grant and verifies it as the leaf payload. The
 * receipt is a standard COSE Receipt; only the payload is forestrie-specific
 * (chosen to match the on-chain univocity accumulator).
 */
export async function runVerifyGrant(
  out: Out,
  options: VerifyGrantOptions,
): Promise<void> {
  let artifacts: ReturnType<typeof loadVerifyArtifacts>;
  try {
    artifacts = loadVerifyArtifacts(options);
  } catch (err) {
    reportRunError(out, options, "input", err);
    return;
  }

  let result: ReceiptVerifyResult;
  try {
    result = await verifyGrantReceiptOffline(artifacts);
  } catch (err) {
    reportRunError(out, options, "verify", err);
    return;
  }

  await finishVerify(out, options, artifacts, result);
}
