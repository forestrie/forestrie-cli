import { bytesEqual } from "./bytes.js";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { verifyCoseSign1WithParsedKey } from "@forestrie/encoding";
import {
  resolveDelegatedVerifyKey,
  type CheckpointChainLink,
} from "@forestrie/receipt-verify";
import type { AnchorCheck } from "./verify-anchored.js";

/**
 * Retained checkpoint-chain anchor (FOR-368 Phase 3, plan-2607-29).
 *
 * The log store's retained `.sth` objects chain contiguously post-FOR-410
 * (ADR-0056: every checkpoint's embedded consistency proof spans its
 * massif's entry boundary to its seal). `@forestrie/receipt-verify`'s
 * `verifyCheckpointChain` folds that chain from size 0, authenticating the
 * accumulator at EVERY retained seal — this rung depends only on the
 * public log store: no tiles, no RPC, no holder cache. It is the
 * complement of the `CheckpointPublished` event scan (public chain data
 * only); the two paths are independently sufficient and cross-checkable.
 *
 * A receipt whose recomputed peak appears in ANY authenticated link is
 * proven: each later link's signed consistency proof commits the earlier
 * accumulator forward, so burial never turns an honest receipt
 * tamper-shaped.
 */

/**
 * Resolve `--checkpoint-chain` to ordered checkpoint files: a directory of
 * `.sth` objects (store naming zero-pads massif indexes, so lexicographic
 * order IS chain order), or an explicit comma-separated list in chain
 * order.
 */
export function loadCheckpointChainFiles(pathspec: string): {
  files: string[];
  checkpoints: Uint8Array[];
} {
  let files: string[];
  let isDirectory = false;
  try {
    isDirectory = statSync(pathspec).isDirectory();
  } catch {
    // A comma-separated list is not itself a path; fall through.
  }
  if (isDirectory) {
    files = readdirSync(pathspec)
      .filter((name) => name.endsWith(".sth"))
      .sort()
      .map((name) => join(pathspec, name));
  } else {
    files = pathspec.split(",").map((f) => f.trim()).filter((f) => f !== "");
  }
  if (files.length === 0) {
    throw new Error(
      `--checkpoint-chain matched no .sth checkpoints: '${pathspec}'`,
    );
  }
  return {
    files,
    checkpoints: files.map((f) => new Uint8Array(readFileSync(f))),
  };
}

/**
 * Signature trust for chain links, rooted in the caller's trust anchor
 * (genesis-derived roots or `--known-log-key`): resolve each checkpoint's
 * label-1000 delegation cert under the root keys, then verify the COSE
 * signature over the folded accumulator as detached payload. The payload
 * is COMPUTED by the fold, never read from the checkpoint — a link only
 * authenticates the accumulator its proof actually derives (ADR-0046).
 */
export function makeCheckpointSignatureVerifier(
  rootKeys: CryptoKey[],
): (
  checkpointBytes: Uint8Array,
  detachedPayload: Uint8Array,
) => Promise<boolean> {
  return async (checkpointBytes, detachedPayload) => {
    const resolution = await resolveDelegatedVerifyKey(
      checkpointBytes,
      rootKeys,
    );
    if (resolution.kind === "broken") return false;
    const candidates =
      resolution.kind === "resolved"
        ? [resolution.delegatedKey, ...rootKeys]
        : rootKeys;
    for (const key of candidates) {
      if (
        await verifyCoseSign1WithParsedKey(checkpointBytes, key, {
          logPrefix: "checkpoint-chain",
          detachedPayload,
        })
      ) {
        return true;
      }
    }
    return false;
  };
}

export type CheckpointChainAnchorCheck = AnchorCheck & {
  /** Number of authenticated links in the fold. */
  linkCount: number;
  /** Sealed size of the link holding the peak (null when unmatched). */
  matchedLinkSize: bigint | null;
};

/**
 * Find the recomputed receipt peak in the authenticated chain. Newest-first
 * (mirrors the event-scan rung): the freshest cover gives the most useful
 * report, and a match at ANY link is proof — later links' signed
 * consistency proofs commit it forward. Newer-than-chain fails CLOSED with
 * a refresh remedy: retention limits coverage, never validity.
 */
export function checkReceiptAnchoredToCheckpointChain(opts: {
  links: CheckpointChainLink[];
  recomputedPeak: Uint8Array;
  leafMmrIndex: bigint;
}): CheckpointChainAnchorCheck {
  const final = opts.links[opts.links.length - 1]!;
  const base = {
    accumulator: final.accumulator,
    size: final.treeSize2,
    linkCount: opts.links.length,
  };
  if (opts.leafMmrIndex >= final.treeSize2) {
    return {
      ...base,
      anchored: false,
      matchedPeak: null,
      matchedLinkSize: null,
      reason: "receipt_newer_than_checkpoint_chain",
    };
  }
  for (let i = opts.links.length - 1; i >= 0; i--) {
    const link = opts.links[i]!;
    for (let p = 0; p < link.accumulator.length; p++) {
      if (bytesEqual(opts.recomputedPeak, link.accumulator[p]!)) {
        return {
          ...base,
          anchored: true,
          matchedPeak: p,
          matchedLinkSize: link.treeSize2,
          accumulator: link.accumulator,
          size: link.treeSize2,
        };
      }
    }
  }
  return {
    ...base,
    anchored: false,
    matchedPeak: null,
    matchedLinkSize: null,
    reason: "peak_not_in_checkpoint_chain",
  };
}

