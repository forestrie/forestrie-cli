import type { Out } from "@forestrie/cli-kit/reporting";
import {
  grantCommitmentHashFromGrant,
  verifyGrantReceiptOffline,
  verifyReceiptOffline,
  type ReceiptVerifyResult,
} from "@forestrie/receipt-verify";
import type { VerifyGrantOptions, VerifyOptions } from "../options/verify.js";
import {
  checkReceiptAnchored,
  recomputeReceiptPeak,
  type AnchorCheck,
} from "../lib/verify-anchored.js";
import {
  loadPayloadVerifyArtifacts,
  loadVerifyArtifacts,
} from "../lib/verify-inputs.js";
import {
  anchorOnlyStageRows,
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
 * Anchor-only leaf material (FOR-297 approach C): what `finishVerify` needs
 * to recompute the receipt's peak without any signature — the sequenced
 * idtimestamp plus a supplier for the leaf ContentHash (`SHA-256(payload)`
 * for `verify`, the grant commitment hash for `verify-grant`).
 */
type AnchorLeaf = {
  idtimestampBe8: Uint8Array;
  inner: () => Promise<Uint8Array>;
};

/**
 * Chain-anchored fallback for delegated seals the offline verifier cannot
 * resolve (a child log's per-log delegation does not chain to the root
 * genesis — FOR-297). Recompute the peak from leaf + proof (no signature)
 * and match it against the on-chain accumulator: an anchored match proves
 * binding + inclusion under the contract's consistency-gated state, which is
 * exactly the split-view trust model. Returns true when it handled the
 * verdict (either way); false to fall through to the normal failure path.
 */
async function tryAnchorOnlyVerify(
  out: Out,
  ctx: VerifyReportContext,
  artifacts: { genesisCbor: Uint8Array; receiptCbor: Uint8Array },
  result: ReceiptVerifyResult,
  anchorLeaf: AnchorLeaf,
): Promise<boolean> {
  let recomputed: Awaited<ReturnType<typeof recomputeReceiptPeak>>;
  try {
    const inner = await anchorLeaf.inner();
    recomputed = await recomputeReceiptPeak({
      receiptCbor: artifacts.receiptCbor,
      idtimestampBe8: anchorLeaf.idtimestampBe8,
      inner,
    });
  } catch {
    return false; // unparsable leaf material — report the offline failure
  }
  if (!recomputed.inclusionOk) return false;

  let anchor: AnchorCheck;
  try {
    anchor = await checkReceiptAnchored({
      genesisCbor: artifacts.genesisCbor,
      receiptCbor: artifacts.receiptCbor,
      univocity: ctx.univocity!,
      logId: ctx.logId!,
      rpcUrl: ctx.rpcUrl!,
      recomputedPeak: recomputed.peak,
    });
  } catch (err) {
    reportRunError(out, ctx, "anchor", err);
    return true;
  }
  if (!anchor.anchored) return false; // not on-chain — offline failure stands

  const okResult: ReceiptVerifyResult = { ok: true, stage: "binding" };
  if (ctx.json) {
    const report = buildVerifyReport({
      ok: true,
      result: okResult,
      mode: "chain-anchored",
      anchor,
      univocity: ctx.univocity,
      logId: ctx.logId,
      stagesOverride: anchorOnlyStageRows(),
    });
    out.out(JSON.stringify(report, null, 2));
  } else {
    for (const row of anchorOnlyStageRows()) {
      const detail = row.reason ?? STAGE_NARRATION[row.stage];
      out.print(
        "verify: %s %s — %s",
        row.stage.padEnd(9),
        row.status.padEnd(7),
        detail,
      );
    }
    out.print(
      "verify: anchor    ok      — recomputed peak matches on-chain accumulator peak %d/%d at anchored size %s",
      anchor.matchedPeak! + 1,
      anchor.accumulator.length,
      anchor.size.toString(),
    );
    out.out(
      `PASS: receipt verified against the on-chain accumulator (anchored size ${anchor.size}; signature enforced by univocity at publish)`,
    );
  }
  process.exitCode = 0;
  return true;
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
  anchorLeaf?: AnchorLeaf,
): Promise<void> {
  // FOR-297 approach C: in chain-anchored mode, a delegation the offline
  // verifier cannot resolve is not the end — the on-chain accumulator IS the
  // split-view authority, so verify against it without the signature.
  if (
    ctx.anchor === "chain" &&
    !result.ok &&
    result.stage === "signature" &&
    result.reason === "delegation_invalid" &&
    anchorLeaf !== undefined
  ) {
    const handled = await tryAnchorOnlyVerify(
      out,
      ctx,
      artifacts,
      result,
      anchorLeaf,
    );
    if (handled) return;
  }

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

  await finishVerify(out, options, artifacts, result, {
    idtimestampBe8: artifacts.idtimestampBe8,
    inner: async () =>
      new Uint8Array(
        // Copy pins the generic to ArrayBuffer for the dom BufferSource type.
        await crypto.subtle.digest("SHA-256", new Uint8Array(artifacts.payload)),
      ),
  });
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

  await finishVerify(out, options, artifacts, result, {
    idtimestampBe8: artifacts.idtimestampBe8,
    inner: () => grantCommitmentHashFromGrant(artifacts.grant),
  });
}
