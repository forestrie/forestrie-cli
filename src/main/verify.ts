import type { Out } from "@forestrie/cli-kit/reporting";
import { verifyGrantReceiptOffline } from "@forestrie/receipt-verify";
import type { VerifyOptions } from "../options/verify.js";
import {
  checkReceiptAnchored,
  type AnchorCheck,
} from "../lib/verify-anchored.js";
import { loadVerifyArtifacts } from "../lib/verify-inputs.js";
import {
  buildVerifyReport,
  STAGE_NARRATION,
  stageRows,
} from "../lib/verify-report.js";

/** Where an operational error broke the run (distinct from a verification
 * FAIL, which is the structured `VerifyReport` with `ok: false`). */
export type VerifyErrorStage = "input" | "verify" | "anchor";

/**
 * `--json` operational-error shape on stdout — the demo's scripted closer
 * owns stdout in EVERY failure branch (F3, plan-2607-14 W1.3): input
 * load/decode errors, unexpected core-verify errors, and chain-mode RPC
 * failures all land here rather than escaping as stack traces.
 */
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

/** Structured envelope under `--json`; one clean line on stderr otherwise. */
function reportRunError(
  out: Out,
  options: VerifyOptions,
  stage: VerifyErrorStage,
  err: unknown,
): void {
  const message = err instanceof Error ? err.message : String(err);
  if (options.json) {
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
 * FOR-347: verify a receipt offline against the cached checkpoint /
 * on-chain accumulator trust root (`@forestrie/receipt-verify`, ES256
 * only). No network access during the core verify; exit 0 iff the receipt
 * is valid. With `--univocity --log-id --rpc-url` the receipt's peak is
 * additionally checked against the on-chain `logState` accumulator — the
 * only networked path.
 */
export async function runVerify(
  out: Out,
  options: VerifyOptions,
): Promise<void> {
  let artifacts: ReturnType<typeof loadVerifyArtifacts>;
  try {
    artifacts = loadVerifyArtifacts(options);
  } catch (err) {
    reportRunError(out, options, "input", err);
    return;
  }

  // Core verify: pure over bytes — strictly no network (ADR-0045). A
  // tampered receipt is a structured FAIL result, not a throw; anything
  // thrown here is an operational error and still owns stdout.
  let result: Awaited<ReturnType<typeof verifyGrantReceiptOffline>>;
  try {
    result = await verifyGrantReceiptOffline(artifacts);
  } catch (err) {
    reportRunError(out, options, "verify", err);
    return;
  }

  let anchor: AnchorCheck | undefined;
  if (options.anchor === "chain" && result.ok) {
    try {
      anchor = await checkReceiptAnchored({
        genesisCbor: artifacts.genesisCbor,
        receiptCbor: artifacts.receiptCbor,
        univocity: options.univocity!,
        logId: options.logId!,
        rpcUrl: options.rpcUrl!,
      });
    } catch (err) {
      // RPC transport/decode failures (the only networked path).
      reportRunError(out, options, "anchor", err);
      return;
    }
  }

  const ok =
    result.ok && (options.anchor !== "chain" || anchor?.anchored === true);

  if (options.json) {
    const report = buildVerifyReport({
      ok,
      result,
      mode: options.anchor === "chain" ? "chain-anchored" : "offline",
      anchor,
      univocity: options.univocity,
      logId: options.logId,
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
