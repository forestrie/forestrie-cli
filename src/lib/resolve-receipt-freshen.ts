/**
 * Tile-free freshen for `resolve-receipt` (FOR-418 Phase 3c, plan-2607-32 D1/D3).
 *
 * "Freshen" is `resolve-receipt --receipt <stale> + a tile-free source`: re-anchor
 * a stale receipt to the CURRENT sealed state without massif tiles. The stale
 * receipt supplies the leaf's MMR index and its old inclusion path (leaf → old
 * peak); a checkpoint chain supplies the climb from that old peak to the latest
 * accumulator; the latest checkpoint supplies the signature to emit under. The
 * result is a native receipt that verifies with plain `verify --genesis`.
 *
 * The leaf VALUE is not in the stale receipt (its payload is detached — verify
 * recomputes it), so freshen recomputes it exactly as `verify-grant` does:
 * `univocityLeafHash(idtimestamp, grantCommitmentHash(grant))`. `freshenReceipt`
 * needs it for its fail-closed self-check (recomputed peak == folded accumulator
 * peak), so a bad chain/leaf throws here rather than minting a bad receipt.
 *
 * This module covers the `.sth`-chain source (retained checkpoints → genesis-
 * verifiable). The calldata source (known-key rung) reuses the same
 * `freshenReceipt` with the chain read from `publishCheckpoint` calldata plus a
 * latest `.sth` for emission — added in the next increment.
 */
import {
  freshenReceipt,
  grantCommitmentHashFromGrant,
  parseReceipt,
  type Grant,
} from "@forestrie/receipt-verify";
import { sthCheckpointChain } from "./checkpoint-provider.js";
import { univocityLeafHash } from "./verify-anchored.js";

/** Structured detail for the `--json` report and human narration. */
export type FreshenDetails = {
  /** The stale receipt's leaf, addressed by MMR index. */
  leafMmrIndex: bigint;
  /** Sealed size the freshened receipt is anchored at (latest checkpoint). */
  sealedSize: bigint;
  /** Number of consistency-proof links folded from the `.sth` chain. */
  chainLinks: number;
  /** Length of the emitted (extended) inclusion path. */
  proofLength: number;
  /** The `.sth` chain sources, ascending (filenames), for narration. */
  sourceRefs: string[];
};

export type FreshenResult = {
  receiptCbor: Uint8Array;
  details: FreshenDetails;
};

/**
 * Freshen a stale receipt against a retained `.sth` checkpoint chain.
 *
 * `checkpoints` are the raw `.sth` bytes in ascending massif order (a contiguous
 * chain from the log's base); `sourceRefs` optionally names them. The last
 * checkpoint is the one the freshened receipt is emitted under. Throws (with the
 * underlying reason) if the chain is not a contiguous cover to the leaf, if the
 * chain does not match the latest checkpoint, or if the recomputed peak does not
 * match the folded accumulator.
 */
export async function freshenFromSthChain(opts: {
  oldReceiptBytes: Uint8Array;
  grant: Grant;
  idtimestampBe8: Uint8Array;
  checkpoints: readonly Uint8Array[];
  sourceRefs?: readonly string[];
}): Promise<FreshenResult> {
  if (opts.checkpoints.length === 0) {
    throw new Error("--checkpoint-chain resolved to no checkpoints");
  }
  const inner = await grantCommitmentHashFromGrant(opts.grant);
  const leafValue = await univocityLeafHash(opts.idtimestampBe8, inner);

  const links = await sthCheckpointChain(
    opts.checkpoints,
    opts.sourceRefs !== undefined ? { sourceRefs: opts.sourceRefs } : {},
  );
  const latestCheckpointBytes = opts.checkpoints[opts.checkpoints.length - 1]!;

  const result = await freshenReceipt({
    oldReceiptBytes: opts.oldReceiptBytes,
    leafValue,
    consistencyProofs: links.map((l) => l.proof),
    latestCheckpointBytes,
  });

  const { proof } = parseReceipt(result.receipt);
  return {
    receiptCbor: result.receipt,
    details: {
      leafMmrIndex: proof.mmrIndex!,
      sealedSize: result.sealedSize,
      chainLinks: links.length,
      proofLength: proof.path.length,
      sourceRefs: [...(opts.sourceRefs ?? [])],
    },
  };
}
