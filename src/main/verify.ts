import { readFileSync } from "node:fs";
import type { Out } from "@forestrie/cli-kit/reporting";
import {
  grantCommitmentHashFromGrant,
  importEs256PublicKeyFromGrantDataXy64,
  verifyGrantReceiptOffline,
  verifyGrantReceiptOfflineWithKeys,
  verifyReceiptOffline,
  verifyReceiptOfflineWithKeys,
  type ReceiptVerifyResult,
} from "@forestrie/receipt-verify";
import type { VerifyGrantOptions, VerifyOptions } from "../options/verify.js";
import {
  checkReceiptAnchored,
  recomputeReceiptPeak,
  type AnchorCheck,
} from "../lib/verify-anchored.js";
import {
  assertSnapshotBinding,
  checkReceiptAnchoredToSnapshot,
  decodeKnownAccumulator,
  type SnapshotAnchorCheck,
} from "../lib/verify-known-accumulator.js";
import {
  loadPayloadVerifyArtifacts,
  loadVerifyArtifacts,
} from "../lib/verify-inputs.js";
import {
  anchorOnlyStageRows,
  buildVerifyReport,
  knownKeyStageRows,
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
  anchor: "offline" | "chain" | "accumulator";
  univocity: string | undefined;
  logId: string | undefined;
  rpcUrl: string | undefined;
  /** Set when `--known-log-key` supplied the trust anchor (FOR-297 D1). */
  knownLogKey?: string | undefined;
  /** Cached chain-read snapshot path (`--known-accumulator`, FOR-297 D5). */
  knownAccumulator?: string | undefined;
  /** Local massif blob for stale-snapshot proof-path extension. */
  massif?: string | undefined;
};

/**
 * Known-accumulator anchor check (FOR-297 D5): decode the snapshot, reject a
 * wrong-log/wrong-contract binding BEFORE any peak math, then match the
 * recomputed receipt peak (directly, or via massif proof-path extension).
 */
async function checkSnapshotAnchor(
  ctx: VerifyReportContext,
  receiptCbor: Uint8Array,
  anchorLeaf: AnchorLeaf,
  recomputedPeak: Uint8Array,
): Promise<SnapshotAnchorCheck> {
  const snapshot = decodeKnownAccumulator(
    new Uint8Array(readFileSync(ctx.knownAccumulator!)),
  );
  assertSnapshotBinding(snapshot, { logId: ctx.logId });
  const massifBytes =
    ctx.massif !== undefined
      ? new Uint8Array(readFileSync(ctx.massif))
      : undefined;
  return checkReceiptAnchoredToSnapshot({
    snapshot,
    receiptCbor,
    idtimestampBe8: anchorLeaf.idtimestampBe8,
    inner: await anchorLeaf.inner(),
    recomputedPeak,
    massifBytes,
  });
}

/** Human narration for the anchor row, naming the anchor distinctly (D5). */
function printAnchorRow(
  out: Out,
  ctx: VerifyReportContext,
  anchor: AnchorCheck & Partial<SnapshotAnchorCheck>,
): void {
  const isSnapshot = ctx.anchor === "accumulator";
  if (anchor.anchored) {
    const where = isSnapshot
      ? `known accumulator peak %d/%d (read from chain at block ${anchor.blockNumber}, anchored size %s)` +
        (anchor.extended === true ? " via proof-path extension" : "")
      : "on-chain accumulator peak %d/%d at anchored size %s";
    out.print(
      `verify: anchor    ok      — receipt peak matches ${where}`,
      anchor.matchedPeak! + 1,
      anchor.accumulator.length,
      anchor.size.toString(),
    );
  } else {
    const hint =
      anchor.reason === "receipt_newer_than_known_accumulator"
        ? " — refresh the accumulator (forestrie fetch-accumulator)"
        : "";
    out.print(
      "verify: anchor    failed  — %s (anchored size %s, %d peaks)%s",
      anchor.reason ?? "unknown",
      anchor.size.toString(),
      anchor.accumulator.length,
      hint,
    );
  }
}

/**
 * Import the caller-known log OWNER key (`--known-log-key`, base64 x||y).
 * The value is the delegation-cert issuer's key, NOT the sealer key — the
 * label-1000 cert still resolves under it, so the anchor survives sealer
 * rotation and the cert-validation path is exercised (FOR-297 D1).
 */
async function importKnownLogKey(knownLogKey: string): Promise<CryptoKey> {
  const bytes = new Uint8Array(Buffer.from(knownLogKey, "base64"));
  if (bytes.length !== 64) {
    throw new Error(
      `--known-log-key must be base64 x||y (64 bytes), decoded ${bytes.length}`,
    );
  }
  return importEs256PublicKeyFromGrantDataXy64(bytes);
}

/**
 * Under a caller-known key, a broken delegation chain means the cert did not
 * verify under the CALLER's key — a different trust failure than a
 * genesis-rooted `delegation_invalid` (wrong known key, or a forged cert).
 * Rename it so the operator reaches for "check the key you were given",
 * not "check the log's delegation".
 */
function remapKnownKeyFailure(result: ReceiptVerifyResult): ReceiptVerifyResult {
  if (!result.ok && result.reason === "delegation_invalid") {
    return { ...result, reason: "known_key_mismatch" };
  }
  return result;
}

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
  artifacts: { genesisCbor: Uint8Array | undefined; receiptCbor: Uint8Array },
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

  let anchor: AnchorCheck & Partial<SnapshotAnchorCheck>;
  try {
    anchor =
      ctx.anchor === "accumulator"
        ? await checkSnapshotAnchor(
            ctx,
            artifacts.receiptCbor,
            anchorLeaf,
            recomputed.peak,
          )
        : await checkReceiptAnchored({
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
  if (!anchor.anchored) {
    // Not anchored — the offline failure stands. For a snapshot anchor,
    // narrate WHY on stderr first (a newer-than-snapshot receipt carries the
    // "refresh the accumulator" remedy; --json output stays the structured
    // offline failure).
    if (ctx.anchor === "accumulator" && ctx.json !== true) {
      printAnchorRow(out, ctx, anchor);
    }
    return false;
  }

  const isSnapshot = ctx.anchor === "accumulator";
  const okResult: ReceiptVerifyResult = { ok: true, stage: "binding" };
  if (ctx.json) {
    const report = buildVerifyReport({
      ok: true,
      result: okResult,
      mode: isSnapshot ? "accumulator-anchored" : "chain-anchored",
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
    printAnchorRow(out, ctx, anchor);
    out.out(
      isSnapshot
        ? `PASS: receipt verified against the known accumulator (anchored size ${anchor.size}, read from chain at block ${anchor.blockNumber}; signature enforced by univocity at publish)`
        : `PASS: receipt verified against the on-chain accumulator (anchored size ${anchor.size}; signature enforced by univocity at publish)`,
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
  artifacts: { genesisCbor: Uint8Array | undefined; receiptCbor: Uint8Array },
  result: ReceiptVerifyResult,
  anchorLeaf?: AnchorLeaf,
): Promise<void> {
  // FOR-297 approach C: in a chain-anchored mode (live read OR cached
  // known-accumulator snapshot), a delegation the offline verifier cannot
  // resolve is not the end — the anchored accumulator IS the split-view
  // authority, so verify against it without the signature.
  if (
    (ctx.anchor === "chain" || ctx.anchor === "accumulator") &&
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

  let anchor: (AnchorCheck & Partial<SnapshotAnchorCheck>) | undefined;
  if ((ctx.anchor === "chain" || ctx.anchor === "accumulator") && result.ok) {
    try {
      // Under a caller-known key there may be no genesis to locate a detached
      // peak by trust-key trial — recompute the peak from leaf + proof
      // instead (same strategy as the anchor-only path). The snapshot check
      // always works from the recomputed peak.
      let recomputedPeak: Uint8Array | undefined;
      if (
        (ctx.knownLogKey !== undefined || ctx.anchor === "accumulator") &&
        anchorLeaf !== undefined
      ) {
        const recomputed = await recomputeReceiptPeak({
          receiptCbor: artifacts.receiptCbor,
          idtimestampBe8: anchorLeaf.idtimestampBe8,
          inner: await anchorLeaf.inner(),
        });
        if (recomputed.inclusionOk) recomputedPeak = recomputed.peak;
      }
      if (ctx.anchor === "accumulator") {
        if (anchorLeaf === undefined || recomputedPeak === undefined) {
          throw new Error(
            "cannot recompute the receipt peak for the known-accumulator check",
          );
        }
        anchor = await checkSnapshotAnchor(
          ctx,
          artifacts.receiptCbor,
          anchorLeaf,
          recomputedPeak,
        );
      } else {
        anchor = await checkReceiptAnchored({
          genesisCbor: artifacts.genesisCbor,
          receiptCbor: artifacts.receiptCbor,
          univocity: ctx.univocity!,
          logId: ctx.logId!,
          rpcUrl: ctx.rpcUrl!,
          ...(recomputedPeak !== undefined ? { recomputedPeak } : {}),
        });
      }
    } catch (err) {
      reportRunError(out, ctx, "anchor", err);
      return;
    }
  }

  const ok =
    result.ok && (ctx.anchor === "offline" || anchor?.anchored === true);
  const rows =
    ctx.knownLogKey !== undefined ? knownKeyStageRows(result) : stageRows(result);

  if (ctx.json) {
    const report = buildVerifyReport({
      ok,
      result,
      mode:
        ctx.anchor === "chain"
          ? "chain-anchored"
          : ctx.anchor === "accumulator"
            ? "accumulator-anchored"
            : "offline",
      anchor,
      univocity: ctx.univocity,
      logId: ctx.logId,
      ...(ctx.knownLogKey !== undefined ? { stagesOverride: rows } : {}),
    });
    out.out(JSON.stringify(report, null, 2));
  } else {
    for (const row of rows) {
      const detail =
        row.status === "failed"
          ? (row.reason ?? "unknown")
          : row.status === "skipped"
            ? (row.reason ?? "not evaluated")
            : (row.reason ?? STAGE_NARRATION[row.stage]);
      out.print(
        "verify: %s %s — %s",
        row.stage.padEnd(9),
        row.status.padEnd(7),
        detail,
      );
    }
    if (anchor !== undefined) {
      printAnchorRow(out, ctx, anchor);
    }
    if (ok) {
      if (anchor !== undefined) {
        out.out(
          ctx.anchor === "accumulator"
            ? `PASS: receipt verified offline and matched the known accumulator (anchored size ${anchor.size}, read from chain at block ${anchor.blockNumber})`
            : `PASS: receipt verified offline and anchored on-chain (anchored size ${anchor.size})`,
        );
      } else if (ctx.knownLogKey !== undefined) {
        out.out(
          "PASS: receipt verified offline under the caller-known log key (not genesis-derived)",
        );
      } else {
        out.out("PASS: receipt verified offline against the cached checkpoint");
      }
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
    if (options.knownLogKey !== undefined) {
      // FOR-297 D1: caller-known log owner key replaces the genesis roots.
      const knownKey = await importKnownLogKey(options.knownLogKey);
      result = remapKnownKeyFailure(
        await verifyReceiptOfflineWithKeys({
          receiptCbor: artifacts.receiptCbor,
          payload: artifacts.payload,
          idtimestampBe8: artifacts.idtimestampBe8,
          trustKeys: [knownKey],
        }),
      );
    } else {
      // Parsing guarantees --genesis when --known-log-key is absent.
      result = await verifyReceiptOffline({
        ...artifacts,
        genesisCbor: artifacts.genesisCbor!,
      });
    }
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
    if (options.knownLogKey !== undefined) {
      // FOR-297 D1: caller-known log owner key replaces the genesis roots.
      const knownKey = await importKnownLogKey(options.knownLogKey);
      result = remapKnownKeyFailure(
        await verifyGrantReceiptOfflineWithKeys({
          receiptCbor: artifacts.receiptCbor,
          grant: artifacts.grant,
          idtimestampBe8: artifacts.idtimestampBe8,
          trustKeys: [knownKey],
        }),
      );
    } else {
      // Parsing guarantees --genesis when --known-log-key is absent.
      result = await verifyGrantReceiptOffline({
        ...artifacts,
        genesisCbor: artifacts.genesisCbor!,
      });
    }
  } catch (err) {
    reportRunError(out, options, "verify", err);
    return;
  }

  await finishVerify(out, options, artifacts, result, {
    idtimestampBe8: artifacts.idtimestampBe8,
    inner: () => grantCommitmentHashFromGrant(artifacts.grant),
  });
}
