import { readFileSync } from "node:fs";
import type { Out } from "@forestrie/cli-kit/reporting";
import {
  decodeKs256Attestation,
  decodeTrustRootFromGenesis,
  extractKs256DelegationDigest,
  grantCommitmentHashFromGrant,
  type Ks256Attestation,
  type Ks256AttestationUsage,
  type RootVerifyKey,
  selectKs256Attestation,
  verifyGrantReceiptOffline,
  verifyGrantReceiptOfflineWithKeys,
  verifyReceiptOffline,
  verifyReceiptAgainstCheckpointChain,
  verifyReceiptOfflineWithKeys,
  type ReceiptVerifyResult,
} from "@forestrie/receipt-verify";
import type { VerifyGrantOptions, VerifyOptions } from "../options/verify.js";
import { findPeakInPublishedHistory } from "../lib/verify-eventscan.js";
import {
  ANCHOR_FOREST_MISMATCH,
  checkReceiptAnchored,
  forestMismatchDetail,
  readRpcChainId,
  receiptLeafIndex,
  recomputeReceiptPeak,
  type AnchorCheck,
} from "../lib/verify-anchored.js";
import {
  loadCheckpointChainFiles,
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
 * Retained checkpoint-chain anchor (FOR-368 Phase 3, owner ruling D8): the
 * shared receipt-verify checkpoint-chain verifier folds the store's `.sth`
 * chain under the caller's roots (genesis-derived and/or `--known-log-key`,
 * ES256 or KS256), enforces each certificate's mmrStart/mmrEnd per link,
 * matches the leaf-recomputed peak against ANY authenticated link, then
 * judges certificate expiry on the links covering the bound leaf. Several
 * ERC-1271 attestations may vouch for contract-root certificates; their
 * usage is accounted for. Typed refusal reasons come back as the anchor's
 * `reason`.
 */
async function checkCheckpointChainAnchor(
  ctx: VerifyReportContext,
  genesisCbor: Uint8Array | undefined,
  receiptCbor: Uint8Array,
  anchorLeaf: AnchorLeaf,
  attestations: Ks256Attestation[],
): Promise<CheckpointChainAnchorCheck & { attestationUsage: Ks256AttestationUsage }> {
  const rootKeys: RootVerifyKey[] = [];
  if (ctx.knownLogKey !== undefined) {
    rootKeys.push(await parseKnownLogKey(ctx.knownLogKey));
  }
  if (genesisCbor !== undefined) {
    rootKeys.push(await decodeTrustRootFromGenesis(genesisCbor));
  }
  if (rootKeys.length === 0) {
    throw new Error(
      "checkpoint-chain verification needs a trust root (--genesis or --known-log-key)",
    );
  }
  const { checkpoints, files } = loadCheckpointChainFiles(ctx.checkpointChain!);
  const outcome = await verifyReceiptAgainstCheckpointChain({
    receiptCbor,
    idtimestampBe8: anchorLeaf.idtimestampBe8,
    inner: await anchorLeaf.inner(),
    checkpoints,
    rootKeys,
    attestations,
    ...(genesisCbor !== undefined ? { forestGenesisCbor: genesisCbor } : {}),
  });
  const final = outcome.links[outcome.links.length - 1];
  const base = {
    accumulator: final?.accumulator ?? [],
    size: final?.treeSize2 ?? 0n,
    linkCount: outcome.links.length,
    attestationUsage: outcome.attestations,
    chainRecords: outcome.records,
  };
  if (outcome.ok) {
    const link = outcome.links[outcome.matchedLink]!;
    return {
      ...base,
      anchored: true,
      matchedPeak: outcome.matchedPeak,
      matchedLinkSize: link.treeSize2,
      accumulator: link.accumulator,
      size: link.treeSize2,
    };
  }
  if (outcome.stage === "input") {
    throw new Error(`checkpoint-chain verification input: ${outcome.reason}`);
  }
  const where =
    outcome.at !== undefined
      ? ` at ${files[outcome.at] ?? `link ${outcome.at}`}`
      : "";
  return {
    ...base,
    anchored: false,
    matchedPeak: null,
    matchedLinkSize: null,
    reason: outcome.reason,
    ...(outcome.stage === "chain" || outcome.stage === "delegation"
      ? {
          chainFailure: `${outcome.stage} refused${where}${outcome.detail !== undefined ? `: ${outcome.detail}` : ""}`,
        }
      : {}),
  } as CheckpointChainAnchorCheck & { attestationUsage: Ks256AttestationUsage };
}

/** One stderr line per supplied attestation: used, or unused with a reason. */
function printAttestationUsage(out: Out, info: Ks256ReportInfo): void {
  for (const u of info.usage.used) {
    const a = info.attestations[u.index]!;
    out.print(
      "verify: attestation #%d used — digest 0x%s (chain %s, block %s)%s",
      u.index,
      u.digestHex.slice(0, 16) + "…",
      a.chainId.toString(),
      a.blockNumber.toString(),
      u.links.length > 0 ? `; carries chain link(s) ${u.links.join(", ")}` : "",
    );
  }
  for (const u of info.usage.rejected) {
    out.print(
      "verify: attestation #%d rejected — digest 0x%s%s",
      u.index,
      u.digestHex.slice(0, 16) + "…",
      u.links.length > 0 ? `; refused for chain link(s) ${u.links.join(", ")}` : "",
    );
  }
  for (const u of info.usage.unused) {
    out.print(
      "verify: attestation #%d unused — digest 0x%s: %s",
      u.index,
      u.digestHex.slice(0, 16) + "…",
      u.reason,
    );
  }
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
    } else if (anchor.reason === ANCHOR_FOREST_MISMATCH) {
      hint = ` — ${(anchor as { forestMismatch?: string }).forestMismatch ?? "anchor is not the genesis forest's"}`;
    } else if ((anchor as { chainFailure?: string }).chainFailure !== undefined) {
      hint = ` — ${(anchor as { chainFailure?: string }).chainFailure}`;
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

/**
 * Load every `--ks256-attestation` (decode failure is an input error).
 * Empty when the flag is absent.
 */
function loadAttestations(paths: readonly string[]): Ks256Attestation[] {
  return paths.map((path) => {
    const bytes = readBytes(path, "--ks256-attestation");
    try {
      return decodeKs256Attestation(bytes);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(
        `--ks256-attestation '${path}' is not a valid attestation: ${message}`,
      );
    }
  });
}

/**
 * Attestation accounting for ONE receipt. Every attestation made for the
 * receipt's certificate (digest and signature hash, via receipt-verify's
 * selection) is tried in order and the first that resolves wins. If the
 * certificate verifies without any attestation they are all `not_needed`;
 * otherwise those before the first that resolves are `rejected`, that one is
 * `used`, and later ones are `duplicate`. Others have no matching
 * certificate.
 */
async function receiptAttestationUsage(
  receiptCbor: Uint8Array,
  attestations: readonly Ks256Attestation[],
  result: ReceiptVerifyResult,
  run: (atts: Ks256Attestation[]) => Promise<ReceiptVerifyResult>,
): Promise<Ks256AttestationUsage> {
  let cert: ReturnType<typeof extractKs256DelegationDigest> = null;
  try {
    cert = extractKs256DelegationDigest(receiptCbor);
  } catch {
    cert = null;
  }
  const usage: Ks256AttestationUsage = { used: [], rejected: [], unused: [] };
  const hex = (a: Ks256Attestation) =>
    Array.from(a.digest, (b) => b.toString(16).padStart(2, "0")).join("");
  const matching: number[] = [];
  attestations.forEach((a, index) => {
    if (cert !== null && selectKs256Attestation(cert, [a]) !== undefined) {
      matching.push(index);
    } else {
      usage.unused.push({
        index,
        digestHex: hex(a),
        reason: "no_matching_certificate",
      });
    }
  });
  const withoutOk = result.ok && matching.length > 0 ? (await run([])).ok : false;
  let winner: number | undefined;
  if (result.ok && !withoutOk) {
    for (const index of matching) {
      if ((await run([attestations[index]!])).ok) {
        winner = index;
        break;
      }
    }
  }
  let seenWinner = false;
  for (const index of matching) {
    const digestHex = hex(attestations[index]!);
    if (withoutOk) {
      usage.unused.push({ index, digestHex, reason: "not_needed" });
    } else if (winner === undefined) {
      usage.rejected.push({ index, digestHex, links: [] });
    } else if (index === winner) {
      usage.used.push({ index, digestHex, links: [] });
      seenWinner = true;
    } else if (seenWinner) {
      usage.unused.push({ index, digestHex, reason: "duplicate" });
    } else {
      usage.rejected.push({ index, digestHex, links: [] });
    }
  }
  usage.unused.sort((a, b) => a.index - b.index);
  return usage;
}

/** Root algorithm and attestation facts for the report. */
async function ks256Info(
  genesisCbor: Uint8Array | undefined,
  knownKey: Awaited<ReturnType<typeof parseKnownLogKey>> | undefined,
  attestations: Ks256Attestation[],
  usage: Ks256AttestationUsage,
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
  if (!ks256Root && attestations.length === 0) return undefined;
  return { ks256Root, knownKey: knownKey !== undefined, attestations, usage };
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
  const offlineReason = result.ok ? "unknown" : (result.reason ?? "unknown");
  const okResult: ReceiptVerifyResult = { ok: true, stage: "binding" };
  if (ctx.json) {
    const report = buildVerifyReport({
      ok: true,
      result: okResult,
      mode: isSnapshot ? "accumulator-anchored" : "chain-anchored",
      anchor,
      univocity: ctx.univocity,
      logId: ctx.logId,
      stagesOverride: anchorOnlyStageRows(offlineReason),
      offlineReason,
    });
    out.out(JSON.stringify(report, null, 2));
  } else {
    for (const row of anchorOnlyStageRows(offlineReason)) {
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
        ? `PASS: verified against the known accumulator (anchored size ${anchor.size}, read from chain at block ${anchor.blockNumber}); signature not checked offline (${offlineReason})`
        : `PASS: verified against the on-chain accumulator (anchored size ${anchor.size}); signature not checked offline (${offlineReason})`,
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

/**
 * Offline signature failures the chain can stand in for (FOR-297 approach C):
 * the delegation chain or KS256 root is one the offline verifier cannot
 * resolve, but univocity accepted the checkpoint only if its receipt verified
 * under the log's root key (ES256, or KS256 via ecrecover / ERC-1271) or a
 * delegate the root signed. NOT `delegation_out_of_range` or
 * `delegation_expired`: those are claims about this receipt that the chain
 * does not vouch for (it checks neither).
 */
function isAnchorFallbackReason(reason: string | undefined): boolean {
  return (
    reason === "delegation_invalid" ||
    reason === "delegation_not_ks256" ||
    reason === "ks256_root_not_recovered" ||
    reason === "ks256_root_requires_delegation" ||
    (reason !== undefined && reason.startsWith("ks256_attestation_"))
  );
}

/**
 * Bind the anchor to the genesis forest: live reads compare `--univocity` and
 * the RPC's `eth_chainId`; a snapshot compares its recorded contract and
 * chain. Returns the mismatch detail, or undefined when they agree.
 */
async function anchorForestMismatch(
  ctx: VerifyReportContext,
  genesisCbor: Uint8Array,
): Promise<string | undefined> {
  if (ctx.anchor === "accumulator") {
    const snapshot = decodeKnownAccumulator(
      new Uint8Array(readFileSync(ctx.knownAccumulator!)),
    );
    return forestMismatchDetail(genesisCbor, {
      univocity: `0x${Array.from(snapshot.univocity, (b) =>
        b.toString(16).padStart(2, "0"),
      ).join("")}`,
      chainId: snapshot.chainId,
    });
  }
  return forestMismatchDetail(genesisCbor, {
    univocity: ctx.univocity!,
    chainId: await readRpcChainId(ctx.rpcUrl!),
  });
}

/**
 * Union of two attestation accountings (the receipt's own certificate and
 * the chain's links): used in either counts as used; otherwise unused with
 * the chain's reason when it saw the attestation, else the receipt's.
 */
function mergeAttestationUsage(
  receipt: Ks256AttestationUsage,
  chain: Ks256AttestationUsage,
): Ks256AttestationUsage {
  const used = new Map<number, Ks256AttestationUsage["used"][number]>();
  for (const u of [...receipt.used, ...chain.used]) {
    const prev = used.get(u.index);
    used.set(u.index, {
      ...u,
      links: [...new Set([...(prev?.links ?? []), ...u.links])],
    });
  }
  const rejected = new Map<number, Ks256AttestationUsage["rejected"][number]>();
  for (const u of [...receipt.rejected, ...chain.rejected]) {
    const prev = rejected.get(u.index);
    rejected.set(u.index, {
      ...u,
      links: [...new Set([...(prev?.links ?? []), ...u.links])],
    });
  }
  const unused = new Map<number, Ks256AttestationUsage["unused"][number]>();
  for (const u of [...receipt.unused, ...chain.unused]) {
    if (!used.has(u.index) && !rejected.has(u.index)) unused.set(u.index, u);
  }
  const byIndex = <T extends { index: number }>(m: Map<number, T>) =>
    [...m.values()].sort((a, b) => a.index - b.index);
  return {
    used: byIndex(used),
    rejected: byIndex(rejected),
    unused: byIndex(unused),
  };
}

async function finishVerify(
  out: Out,
  ctx: VerifyReportContext,
  artifacts: { genesisCbor: Uint8Array | undefined; receiptCbor: Uint8Array },
  result: ReceiptVerifyResult,
  anchorLeaf?: AnchorLeaf,
  ks256Info?: Ks256ReportInfo,
): Promise<void> {
  let ks256 = ks256Info;
  // FOR-297 approach C: in a chain-anchored mode (live read OR cached
  // known-accumulator snapshot), a delegation the offline verifier cannot
  // resolve is not the end — the anchored accumulator IS the split-view
  // authority, so verify against it without the signature.
  const chainAnchored = ctx.anchor === "chain" || ctx.anchor === "accumulator";
  const fallbackEligible =
    chainAnchored &&
    !result.ok &&
    result.stage === "signature" &&
    isAnchorFallbackReason(result.reason) &&
    // A caller-known key is the trust anchor: its mismatch is never excused
    // by the chain (ES256 is remapped to known_key_mismatch; KS256 reasons
    // are gated here for the same effect).
    ctx.knownLogKey === undefined &&
    anchorLeaf !== undefined;

  // The anchor must belong to the genesis forest whenever a genesis was
  // given: an accumulator from another contract/chain is never acceptable.
  let forestMismatch: string | undefined;
  if (chainAnchored && artifacts.genesisCbor !== undefined && (result.ok || fallbackEligible)) {
    try {
      forestMismatch = await anchorForestMismatch(ctx, artifacts.genesisCbor);
    } catch (err) {
      reportRunError(out, ctx, "anchor", err);
      return;
    }
  }

  if (fallbackEligible && forestMismatch === undefined) {
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
  if (forestMismatch !== undefined) {
    anchor = {
      accumulator: [],
      size: 0n,
      anchored: false,
      matchedPeak: null,
      reason: ANCHOR_FOREST_MISMATCH,
      forestMismatch,
    } as AnchorCheck & { forestMismatch: string };
  } else if (ctx.anchor !== "offline" && result.ok) {
    try {
      // Under a caller-known key there may be no genesis to locate a detached
      // peak by trust-key trial — recompute the peak from leaf + proof
      // instead (same strategy as the anchor-only path). The snapshot and
      // checkpoint-chain checks always work from the recomputed peak.
      let recomputedPeak: Uint8Array | undefined;
      // Always recompute from leaf + proof when the leaf material is known,
      // and require the inclusion proof to verify: an attached-peak receipt
      // must never anchor on its claimed peak alone (the FOR-606 shape).
      // The checkpoint-chain verifier does the same inside receipt-verify.
      if (anchorLeaf !== undefined && ctx.anchor !== "checkpoints") {
        const recomputed = await recomputeReceiptPeak({
          receiptCbor: artifacts.receiptCbor,
          idtimestampBe8: anchorLeaf.idtimestampBe8,
          inner: await anchorLeaf.inner(),
        });
        if (!recomputed.inclusionOk) {
          throw new Error(
            "the receipt's inclusion proof does not verify against its attached peak",
          );
        }
        recomputedPeak = recomputed.peak;
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
        if (anchorLeaf === undefined) {
          throw new Error(
            "cannot recompute the receipt peak for the checkpoint-chain check",
          );
        }
        const chained = await checkCheckpointChainAnchor(
          ctx,
          artifacts.genesisCbor,
          artifacts.receiptCbor,
          anchorLeaf,
          ks256?.attestations ?? [],
        );
        anchor = chained;
        if (ks256 !== undefined) {
          ks256 = {
            ...ks256,
            usage: mergeAttestationUsage(ks256.usage, chained.attestationUsage),
          };
        }
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
    if (ks256 !== undefined) {
      printAttestationUsage(out, ks256);
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
    } else if (forestMismatch !== undefined) {
      out.out(`FAIL: stage=anchor reason=${ANCHOR_FOREST_MISMATCH}`);
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
  let attestations: Ks256Attestation[];
  let knownKey: Awaited<ReturnType<typeof parseKnownLogKey>> | undefined;
  try {
    artifacts = loadPayloadVerifyArtifacts(options);
    attestations = loadAttestations(options.ks256Attestations);
    knownKey = await parseKnownKeyForRun(options);
  } catch (err) {
    reportRunError(out, options, "input", err);
    return;
  }

  const run = (atts: Ks256Attestation[]) =>
    knownKey !== undefined
      ? // FOR-297 D1: caller-known log owner key replaces the genesis roots.
        // Genesis, if also given, only supplies the forest chain id.
        verifyReceiptOfflineWithKeys({
          receiptCbor: artifacts.receiptCbor,
          payload: artifacts.payload,
          idtimestampBe8: artifacts.idtimestampBe8,
          trustKeys: [knownKey],
          ...(atts.length > 0 ? { ks256Attestations: atts } : {}),
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
          ...(atts.length > 0 ? { ks256Attestations: atts } : {}),
        });

  let result: ReceiptVerifyResult;
  let ks256: Ks256ReportInfo | undefined;
  try {
    result = await run(attestations);
    // An attestation was needed only if the certificate does not verify by
    // ecrecover alone.
    ks256 = await ks256Info(
      artifacts.genesisCbor,
      knownKey,
      attestations,
      await receiptAttestationUsage(
        artifacts.receiptCbor,
        attestations,
        result,
        run,
      ),
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

/** Parse `--known-log-key` (ES256 or KS256: every anchor mode accepts both). */
async function parseKnownKeyForRun(options: {
  knownLogKey: string | undefined;
}): Promise<Awaited<ReturnType<typeof parseKnownLogKey>> | undefined> {
  if (options.knownLogKey === undefined) return undefined;
  return parseKnownLogKey(options.knownLogKey);
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
  let attestations: Ks256Attestation[];
  let knownKey: Awaited<ReturnType<typeof parseKnownLogKey>> | undefined;
  try {
    artifacts = loadVerifyArtifacts(options);
    attestations = loadAttestations(options.ks256Attestations);
    knownKey = await parseKnownKeyForRun(options);
  } catch (err) {
    reportRunError(out, options, "input", err);
    return;
  }

  const run = (atts: Ks256Attestation[]) =>
    knownKey !== undefined
      ? verifyGrantReceiptOfflineWithKeys({
          receiptCbor: artifacts.receiptCbor,
          grant: artifacts.grant,
          idtimestampBe8: artifacts.idtimestampBe8,
          trustKeys: [knownKey],
          ...(atts.length > 0 ? { ks256Attestations: atts } : {}),
          ...(artifacts.genesisCbor !== undefined
            ? { forestGenesisCbor: artifacts.genesisCbor }
            : {}),
        }).then(remapKnownKeyFailure)
      : verifyGrantReceiptOffline({
          receiptCbor: artifacts.receiptCbor,
          grant: artifacts.grant,
          idtimestampBe8: artifacts.idtimestampBe8,
          genesisCbor: artifacts.genesisCbor!,
          ...(atts.length > 0 ? { ks256Attestations: atts } : {}),
        });

  let result: ReceiptVerifyResult;
  let ks256: Ks256ReportInfo | undefined;
  try {
    result = await run(attestations);
    ks256 = await ks256Info(
      artifacts.genesisCbor,
      knownKey,
      attestations,
      await receiptAttestationUsage(
        artifacts.receiptCbor,
        attestations,
        result,
        run,
      ),
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
