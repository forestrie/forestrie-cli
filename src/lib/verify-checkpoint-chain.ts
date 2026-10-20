import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import type { AnchorCheck } from "./verify-anchored.js";

/**
 * Retained checkpoint-chain anchor (FOR-368 Phase 3, plan-2607-29).
 *
 * The log store's retained `.sth` objects chain contiguously post-FOR-410
 * (ADR-0056: every checkpoint's embedded consistency proof spans its
 * massif's entry boundary to its seal). `@forestrie/receipt-verify`'s
 * `verifyCheckpointChain` folds that chain from size 0, authenticating the
 * accumulator at EVERY retained seal — this root depends only on the
 * public log store: no tiles, no RPC, no holder cache. It is the
 * complement of the `CheckpointPublished` event scan (public chain data
 * only); the two paths are independently sufficient and cross-checkable.
 *
 * A receipt whose recomputed peak appears in ANY authenticated link is
 * proven: each later link's signed consistency proof commits the earlier
 * accumulator forward, so burial never turns an honest receipt
 * tamper-shaped. The fold, per-link signature and delegation checks and the
 * peak match live in receipt-verify's `verifyReceiptAgainstCheckpointChain`;
 * this module only loads the files.
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

export type CheckpointChainAnchorCheck = AnchorCheck & {
  /** Number of authenticated links in the fold. */
  linkCount: number;
  /** Sealed size of the link holding the peak (null when unmatched). */
  matchedLinkSize: bigint | null;
};
