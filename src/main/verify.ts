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
  const artifacts = loadVerifyArtifacts(options);

  // Core verify: pure over bytes — strictly no network (ADR-0045).
  const result = await verifyGrantReceiptOffline(artifacts);

  let anchor: AnchorCheck | undefined;
  if (options.anchor === "chain" && result.ok) {
    anchor = await checkReceiptAnchored({
      genesisCbor: artifacts.genesisCbor,
      receiptCbor: artifacts.receiptCbor,
      univocity: options.univocity!,
      logId: options.logId!,
      rpcUrl: options.rpcUrl!,
    });
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
