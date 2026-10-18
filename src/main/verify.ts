import { readFileSync } from "node:fs";
import type { Out } from "@forestrie/cli-kit/reporting";
import {
  decodeKs256Attestation,
  decodeTrustRootFromGenesis,
  grantCommitmentHashFromGrant,
  type Ks256Attestation,
  verifyCheckpointChain,
  verifyGrantReceiptOffline,
  verifyGrantReceiptOfflineWithKeys,
  verifyReceiptOffline,
  verifyReceiptOfflineWithKeys,
  type ReceiptVerifyResult,
} from "@forestrie/receipt-verify";
import type { VerifyGrantOptions, VerifyOptions } from "../options/verify.js";
import { findPeakInPublishedHistory } from "../lib/verify-eventscan.js";
import {
  checkReceiptAnchored,
  receiptLeafIndex,
  recomputeReceiptPeak,
  type AnchorCheck,
} from "../lib/verify-anchored.js";
import {
  checkReceiptAnchoredToCheckpointChain,
  loadCheckpointChainFiles,
  makeCheckpointSignatureVerifier,
  type CheckpointChainAnchorCheck,
} from "../lib/verify-checkpoint-chain.js";
import {
  checkReceiptAnchoredViaConsistencyProof,
  decodeConsistencyProofArtifact,
} from "../lib/consistency-proof.js";
import {
  assertSnapshotBinding,
  checkReceiptAnchoredToSnapshot,
  decodeKnownAccumulator,
  type SnapshotAnchorCheck,
} from "../lib/verify-known-accumulator.js";
import {
  loadPayloadVerifyArtifacts,
  loadVerifyArtifacts,
  readBytes,
} from "../lib/verify-inputs.js";
import { isKs256Root, parseKnownLogKey } from "../lib/known-log-key.js";
import {
  applyKs256Rows,
  type Ks256ReportInfo,
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
  anchor: "offline" | "chain" | "accumulator" | "checkpoints";
  univocity: string | undefined;
  logId: string | undefined;
  rpcUrl: string | undefined;
  /** Set when `--known-log-key` supplied the trust anchor (FOR-297 D1). */
  knownLogKey?: string | undefined;
  /** Cached chain-read snapshot path (`--known-accumulator`, FOR-297 D5). */
  knownAccumulator?: string | undefined;
  /** Local massif blob for stale-snapshot proof-path extension. */
  massif?: string | undefined;
  /** Retained `.sth` chain — dir or comma list (FOR-368 Phase 3). */
  checkpointChain?: string | undefined;
  /** Portable top-up artifact for tile-free extension (FOR-368 Phase 3). */
  consistencyProof?: string | undefined;
  /** Genesis path, needed to root checkpoint-chain signatures. */
  genesis?: string | undefined;
  /** Lower bound for the CheckpointPublished history scan (FOR-368). */
  fromBlock?: bigint | undefined;
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
  const direct = await checkReceiptAnchoredToSnapshot({
    snapshot,
    receiptCbor,
    idtimestampBe8: anchorLeaf.idtimestampBe8,
    inner: await anchorLeaf.inner(),
    recomputedPeak,
    massifBytes,
  });
  if (
    direct.anchored ||
    ctx.consistencyProof === undefined ||
    direct.reason !== "peak_not_in_known_accumulator"
  ) {
    return direct;
  }
  // FOR-368 Phase 3: tile-free extension. The untrusted top-up artifact can
  // only fail — a pass means the receipt's peak sits in the artifact's base
  // accumulator AND that base folds into the TRUSTED snapshot state.
  const artifact = decodeConsistencyProofArtifact(
    new Uint8Array(readFileSync(ctx.consistencyProof)),
  );
  const viaProof = await checkReceiptAnchoredViaConsistencyProof({
    artifact,
    recomputedPeak,
    leafMmrIndex: receiptLeafIndex(receiptCbor),
    trustedSize: snapshot.size,
    trustedAccumulator: snapshot.accumulator,
  });
  if (!viaProof.anchored) {
    return { ...direct, reason: viaProof.reason ?? direct.reason };
  }
  const anchored: SnapshotAnchorCheck & { topUpBaseSize: bigint } = {
    accumulator: snapshot.accumulator,
    size: snapshot.size,
    blockNumber: snapshot.blockNumber,
    blockHashHex: direct.blockHashHex,
    anchored: true,
    matchedPeak: viaProof.matchedPeak,
    extended: true,
    topUpBaseSize: artifact.fromSize,
  };
  return anchored;
}

/**
 * Retained checkpoint-chain anchor (FOR-368 Phase 3): fold the store's
 * `.sth` chain — each link's accumulator computed from the previous one and
 * its signature verified over exactly that computed payload — then match
 * the recomputed receipt peak against ANY authenticated link. Signature
 * trust roots in the same anchors as the offline verify (genesis-derived
 * roots or the caller-known log key); the label-1000 delegation cert on
 * each checkpoint resolves the sealer key under them.
 */
async function checkCheckpointChainAnchor(
  ctx: VerifyReportContext,
  genesisCbor: Uint8Array | undefined,
  receiptCbor: Uint8Array,
  recomputedPeak: Uint8Array,
): Promise<CheckpointChainAnchorCheck> {
  const rootKeys: CryptoKey[] = [];
  if (ctx.knownLogKey !== undefined) {
    const known = await parseKnownLogKey(ctx.knownLogKey);
    if (isKs256Root(known)) throw new Error(KS256_CHECKPOINT_CHAIN_REFUSAL);
    rootKeys.push(known as CryptoKey);
  }
  if (genesisCbor !== undefined) {
    const root = await decodeTrustRootFromGenesis(genesisCbor);
    if (root instanceof CryptoKey) rootKeys.push(root);
  }
  if (rootKeys.length === 0) {
    throw new Error(
      "checkpoint-chain verification needs an ES256 trust root (--genesis or --known-log-key)",
    );
  }
  const { checkpoints, files } = loadCheckpointChainFiles(ctx.checkpointChain!);
  const chain = await verifyCheckpointChain({
    checkpoints,
    verifySignature: makeCheckpointSignatureVerifier(rootKeys),
  });
  if (!chain.ok) {
    throw new Error(
      `checkpoint chain did not verify (${chain.reason} at ${files[chain.at] ?? `link ${chain.at}`}): ${chain.detail}`,
    );
  }
  return checkReceiptAnchoredToCheckpointChain({
    links: chain.links,
    recomputedPeak,
    leafMmrIndex: receiptLeafIndex(receiptCbor),
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
    const historical = (anchor as Partial<HistoricalAnchorFields>).historical === true;
    const chained = anchor as Partial<CheckpointChainAnchorCheck>;
    const topUpBaseSize = (anchor as { topUpBaseSize?: bigint }).topUpBaseSize;
    const where = isSnapshot
      ? `known accumulator peak %d/%d (read from chain at block ${anchor.blockNumber}, anchored size %s)` +
        (topUpBaseSize !== undefined
          ? ` via consistency-proof top-up from size ${topUpBaseSize}`
          : anchor.extended === true
            ? " via proof-path extension"
            : "")
      : ctx.anchor === "checkpoints"
        ? `retained checkpoint-chain peak %d/%d at link sealed size %s (${chained.linkCount} links folded) — later links' signed proofs commit it forward (FOR-368)`
        : historical
          ? `HISTORICAL anchored accumulator peak %d/%d (size %s, block ${(anchor as unknown as HistoricalAnchorFields).anchoredAtBlock}) — consistency-gated forward by the contract (FOR-368)`
          : "on-chain accumulator peak %d/%d at anchored size %s";
    out.print(
      `verify: anchor    ok      — receipt peak matches ${where}`,
      anchor.matchedPeak! + 1,
      anchor.accumulator.length,
      anchor.size.toString(),
    );
  } else {
    let hint = "";
    if (anchor.reason === "receipt_newer_than_known_accumulator") {
      hint = " — refresh the accumulator (forestrie fetch-accumulator)";
    } else if (anchor.reason === "peak_not_current") {
      // FOR-368: an honest receipt whose peak the log has since buried —
      // distinguishable from tamper; growth evidence proves it.
      hint =
        " — receipt predates log growth (peak buried); NOT tamper-evidence." +
        " Re-resolve the receipt from the log, or verify with growth" +
        " evidence (grow-proof support: FOR-368)";
    } else if (anchor.reason === "receipt_newer_than_anchored_state") {
      hint =
        " — entry not anchored on-chain yet; retry after the next" +
        " checkpoint publishes";
    } else if (anchor.reason === "receipt_newer_than_checkpoint_chain") {
      hint =
        " — the supplied chain ends before this entry; fetch the newer" +
        " .sth objects and retry";
    } else if (anchor.reason === "peak_not_in_checkpoint_chain") {
      hint =
        " — no retained seal covers this peak (seals are replaced within a" +
        " massif); use --known-accumulator with a top-up, or a chain anchor";
    }
    out.print(
      "verify: anchor    failed  — %s (anchored size %s, %d peaks)%s",
      anchor.reason ?? "unknown",
      anchor.size.toString(),
      anchor.accumulator.length,
      hint,
    );
  }
}

const KS256_CHECKPOINT_CHAIN_REFUSAL =
  "--checkpoint-chain verifies checkpoint signatures, which need an ES256 trust root: a KS256 (20-byte address) known log key cannot root them";

/**
 * Load `--ks256-attestation` (decode failure is an input error). Undefined
 * when the flag is absent.
 */
function loadAttestation(path: string | undefined): Ks256Attestation | undefined {
  if (path === undefined) return undefined;
  const bytes = readBytes(path, "--ks256-attestation");
  try {
    return decodeKs256Attestation(bytes);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`--ks256-attestation '${path}' is not a valid attestation: ${message}`);
  }
}

/** Root algorithm and attestation facts for the report. */
async function ks256Info(
  options: VerifyReportContext & { ks256Attestation?: string | undefined },
  genesisCbor: Uint8Array | undefined,
  knownKey: Awaited<ReturnType<typeof parseKnownLogKey>> | undefined,
  attestation: Ks256Attestation | undefined,
  used: boolean,
): Promise<Ks256ReportInfo | undefined> {
  let ks256Root = false;
  if (knownKey !== undefined) {
    ks256Root = isKs256Root(knownKey);
  } else if (genesisCbor !== undefined) {
    try {
      ks256Root = isKs256Root(await decodeTrustRootFromGenesis(genesisCbor));
    } catch {
      // The offline verify already reported an unreadable genesis.
    }
  }
  if (!ks256Root && attestation === undefined) return undefined;
  return {
    ks256Root,
    knownKey: knownKey !== undefined,
    ...(attestation !== undefined ? { attestation, attestationUsed: used } : {}),
  };
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
  if (
    !anchor.anchored &&
    ctx.anchor === "chain" &&
    anchor.reason === "peak_not_current"
  ) {
    // FOR-368 Phase 2: buried peak — consult the anchored history. A scan
    // failure degrades to the classified Phase 0 failure (never a run
    // error): the honest-vs-tamper distinction must not be masked by a
    // provider hiccup on eth_getLogs.
    try {
      const historical = await tryHistoricalAnchor(ctx, recomputed.peak);
      if (historical !== null) anchor = historical;
    } catch (err) {
      out.warn(
        "verify: history scan unavailable (%s); reporting peak_not_current",
        err instanceof Error ? err.message : String(err),
      );
    }
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
/**
 * FOR-368 Phase 2: when the live accumulator no longer holds the peak
 * (peak_not_current — burial), scan the CheckpointPublished history. A
 * match at ANY anchored state proves the receipt: univocity's consistency
 * gating commits every anchored accumulator forward to the present.
 * Public-chain-data-only — no tiles, no holder cache.
 */
async function tryHistoricalAnchor(
  ctx: VerifyReportContext,
  peak: Uint8Array,
): Promise<(AnchorCheck & HistoricalAnchorFields) | null> {
  const hit = await findPeakInPublishedHistory({
    peak,
    univocity: ctx.univocity!,
    logId: ctx.logId!,
    rpcUrl: ctx.rpcUrl!,
    fromBlock: ctx.fromBlock,
  });
  if (hit === null) return null;
  return {
    accumulator: hit.accumulator,
    size: hit.size,
    anchored: true,
    matchedPeak: hit.matchedPeak,
    historical: true,
    anchoredAtBlock: hit.blockNumber,
    txHash: hit.txHash,
  };
}

type HistoricalAnchorFields = {
  historical: true;
  anchoredAtBlock: bigint;
  txHash: string;
};

async function finishVerify(
  out: Out,
  ctx: VerifyReportContext,
  artifacts: { genesisCbor: Uint8Array | undefined; receiptCbor: Uint8Array },
  result: ReceiptVerifyResult,
  anchorLeaf?: AnchorLeaf,
  ks256?: Ks256ReportInfo,
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
  if (ctx.anchor !== "offline" && result.ok) {
    try {
      // Under a caller-known key there may be no genesis to locate a detached
      // peak by trust-key trial — recompute the peak from leaf + proof
      // instead (same strategy as the anchor-only path). The snapshot and
      // checkpoint-chain checks always work from the recomputed peak.
      let recomputedPeak: Uint8Array | undefined;
      if (
        // A KS256 root cannot locate a detached peak by signature trial
        // (no_es256_trust_key), so it always works from the recomputed peak.
        (ctx.knownLogKey !== undefined ||
          ctx.anchor !== "chain" ||
          ks256?.ks256Root === true) &&
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
      } else if (ctx.anchor === "checkpoints") {
        if (anchorLeaf === undefined || recomputedPeak === undefined) {
          throw new Error(
            "cannot recompute the receipt peak for the checkpoint-chain check",
          );
        }
        anchor = await checkCheckpointChainAnchor(
          ctx,
          artifacts.genesisCbor,
          artifacts.receiptCbor,
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
        if (!anchor.anchored && anchor.reason === "peak_not_current") {
          // FOR-368 Phase 2: buried peak — the anchored HISTORY proves
          // honest receipts. Recompute the peak if the genesis-trust-key
          // strategy left it implicit.
          if (recomputedPeak === undefined && anchorLeaf !== undefined) {
            const recomputed = await recomputeReceiptPeak({
              receiptCbor: artifacts.receiptCbor,
              idtimestampBe8: anchorLeaf.idtimestampBe8,
              inner: await anchorLeaf.inner(),
            });
            if (recomputed.inclusionOk) recomputedPeak = recomputed.peak;
          }
          if (recomputedPeak !== undefined) {
            try {
              const historical = await tryHistoricalAnchor(
                ctx,
                recomputedPeak,
              );
              if (historical !== null) anchor = historical;
            } catch (err) {
              out.warn(
                "verify: history scan unavailable (%s); reporting peak_not_current",
                err instanceof Error ? err.message : String(err),
              );
            }
          }
        }
      }
    } catch (err) {
      reportRunError(out, ctx, "anchor", err);
      return;
    }
  }

  const ok =
    result.ok && (ctx.anchor === "offline" || anchor?.anchored === true);
  const baseRows =
    ctx.knownLogKey !== undefined ? knownKeyStageRows(result) : stageRows(result);
  const rows = ks256 !== undefined ? applyKs256Rows(baseRows, ks256) : baseRows;

  if (ctx.json) {
    const report = buildVerifyReport({
      ok,
      result,
      mode:
        ctx.anchor === "chain"
          ? "chain-anchored"
          : ctx.anchor === "accumulator"
            ? "accumulator-anchored"
            : ctx.anchor === "checkpoints"
              ? "checkpoint-chain-anchored"
              : "offline",
      anchor,
      univocity: ctx.univocity,
      logId: ctx.logId,
      ...(ctx.knownLogKey !== undefined || ks256 !== undefined
        ? { stagesOverride: rows }
        : {}),
      ...(ks256 !== undefined ? { ks256 } : {}),
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
            : ctx.anchor === "checkpoints"
              ? `PASS: receipt verified offline and anchored in the retained checkpoint chain (link sealed size ${anchor.size}; no tiles, no RPC)`
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
  let attestation: Ks256Attestation | undefined;
  let knownKey: Awaited<ReturnType<typeof parseKnownLogKey>> | undefined;
  try {
    artifacts = loadPayloadVerifyArtifacts(options);
    attestation = loadAttestation(options.ks256Attestation);
    knownKey = await parseKnownKeyForRun(options);
  } catch (err) {
    reportRunError(out, options, "input", err);
    return;
  }

  const run = (att: Ks256Attestation | undefined) =>
    knownKey !== undefined
      ? // FOR-297 D1: caller-known log owner key replaces the genesis roots.
        // Genesis, if also given, only supplies the forest chain id.
        verifyReceiptOfflineWithKeys({
          receiptCbor: artifacts.receiptCbor,
          payload: artifacts.payload,
          idtimestampBe8: artifacts.idtimestampBe8,
          trustKeys: [knownKey],
          ...(att !== undefined ? { ks256Attestation: att } : {}),
          ...(artifacts.genesisCbor !== undefined
            ? { forestGenesisCbor: artifacts.genesisCbor }
            : {}),
        }).then(remapKnownKeyFailure)
      : // Parsing guarantees --genesis when --known-log-key is absent.
        verifyReceiptOffline({
          receiptCbor: artifacts.receiptCbor,
          payload: artifacts.payload,
          idtimestampBe8: artifacts.idtimestampBe8,
          genesisCbor: artifacts.genesisCbor!,
          ...(att !== undefined ? { ks256Attestation: att } : {}),
        });

  let result: ReceiptVerifyResult;
  let ks256: Ks256ReportInfo | undefined;
  try {
    result = await run(attestation);
    ks256 = await ks256Info(
      options,
      artifacts.genesisCbor,
      knownKey,
      attestation,
      // The attestation was needed only if the certificate does not verify
      // by ecrecover alone.
      attestation !== undefined && result.ok ? !(await run(undefined)).ok : false,
    );
  } catch (err) {
    reportRunError(out, options, "verify", err);
    return;
  }

  await finishVerify(
    out,
    options,
    artifacts,
    result,
    {
      idtimestampBe8: artifacts.idtimestampBe8,
      inner: async () =>
        new Uint8Array(
          // Copy pins the generic to ArrayBuffer for the dom BufferSource type.
          await crypto.subtle.digest("SHA-256", new Uint8Array(artifacts.payload)),
        ),
    },
    ks256,
  );
}

/**
 * Parse `--known-log-key`, refusing a KS256 key where the chosen anchor mode
 * needs ES256 checkpoint signatures.
 */
async function parseKnownKeyForRun(options: {
  knownLogKey: string | undefined;
  anchor: string;
}): Promise<Awaited<ReturnType<typeof parseKnownLogKey>> | undefined> {
  if (options.knownLogKey === undefined) return undefined;
  const key = await parseKnownLogKey(options.knownLogKey);
  if (isKs256Root(key) && options.anchor === "checkpoints") {
    throw new Error(KS256_CHECKPOINT_CHAIN_REFUSAL);
  }
  return key;
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
  let attestation: Ks256Attestation | undefined;
  let knownKey: Awaited<ReturnType<typeof parseKnownLogKey>> | undefined;
  try {
    artifacts = loadVerifyArtifacts(options);
    attestation = loadAttestation(options.ks256Attestation);
    knownKey = await parseKnownKeyForRun(options);
  } catch (err) {
    reportRunError(out, options, "input", err);
    return;
  }

  const run = (att: Ks256Attestation | undefined) =>
    knownKey !== undefined
      ? verifyGrantReceiptOfflineWithKeys({
          receiptCbor: artifacts.receiptCbor,
          grant: artifacts.grant,
          idtimestampBe8: artifacts.idtimestampBe8,
          trustKeys: [knownKey],
          ...(att !== undefined ? { ks256Attestation: att } : {}),
          ...(artifacts.genesisCbor !== undefined
            ? { forestGenesisCbor: artifacts.genesisCbor }
            : {}),
        }).then(remapKnownKeyFailure)
      : verifyGrantReceiptOffline({
          receiptCbor: artifacts.receiptCbor,
          grant: artifacts.grant,
          idtimestampBe8: artifacts.idtimestampBe8,
          genesisCbor: artifacts.genesisCbor!,
          ...(att !== undefined ? { ks256Attestation: att } : {}),
        });

  let result: ReceiptVerifyResult;
  let ks256: Ks256ReportInfo | undefined;
  try {
    result = await run(attestation);
    ks256 = await ks256Info(
      options,
      artifacts.genesisCbor,
      knownKey,
      attestation,
      attestation !== undefined && result.ok ? !(await run(undefined)).ok : false,
    );
  } catch (err) {
    reportRunError(out, options, "verify", err);
    return;
  }

  await finishVerify(
    out,
    options,
    artifacts,
    result,
    {
      idtimestampBe8: artifacts.idtimestampBe8,
      inner: () => grantCommitmentHashFromGrant(artifacts.grant),
    },
    ks256,
  );
}
