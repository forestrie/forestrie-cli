import { readFileSync } from "node:fs";
import { decodeEntryIdHex } from "@forestrie/receipt-verify";
import type { CreateReceiptOptions } from "../options/create-receipt.js";

/**
 * Load and resolve `forestrie create-receipt` inputs (FOR-345). Pure
 * file/decode work — strictly no network.
 *
 * Leaf addressing: `--mmr-index` is used verbatim; `--entry-id` is the
 * permanent SCRAPI entry id whose second 8 bytes ARE the big-endian
 * mmrIndex (`decodeEntryIdHex`), so entry-id addressing is fully
 * derivable offline — no massif index-region (urkle) lookup is involved.
 * (Content-hash addressing is the phase-2 feature that waits on the
 * urkle index reader, FOR-373; entry-id does not.)
 */
export type CreateReceiptLeaf = {
  mmrIndex: bigint;
  source: "mmr-index" | "entry-id";
  /** Present with `--entry-id`: the id as given. */
  entryId?: string;
  /** Present with `--entry-id`: the decoded idtimestamp (decimal). */
  idtimestamp?: bigint;
};

export type CreateReceiptArtifacts = {
  massifBytes: Uint8Array;
  /** Present in checkpoint mode (`--checkpoint`). */
  checkpointBytes: Uint8Array | undefined;
  leaf: CreateReceiptLeaf;
};

function readBytes(path: string, flag: string): Uint8Array {
  try {
    return new Uint8Array(readFileSync(path));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`cannot read ${flag} '${path}': ${message}`);
  }
}

/** Resolve the leaf mmrIndex from whichever addressing flag was given. */
export function resolveLeaf(options: CreateReceiptOptions): CreateReceiptLeaf {
  if (options.mmrIndex !== undefined) {
    return { mmrIndex: options.mmrIndex, source: "mmr-index" };
  }
  // Options parsing guarantees exactly one of the two flags.
  const entryId = options.entryId!;
  let decoded: ReturnType<typeof decodeEntryIdHex>;
  try {
    decoded = decodeEntryIdHex(entryId);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`invalid --entry-id '${entryId}': ${message}`);
  }
  return {
    mmrIndex: decoded.mmrIndex,
    source: "entry-id",
    entryId,
    idtimestamp: decoded.idtimestamp,
  };
}

/** Read massif/checkpoint artefacts from disk and resolve the leaf. */
export function loadCreateReceiptArtifacts(
  options: CreateReceiptOptions,
): CreateReceiptArtifacts {
  const leaf = resolveLeaf(options);
  const massifBytes = readBytes(options.massif, "--massif");
  const checkpointBytes =
    options.checkpoint !== undefined
      ? readBytes(options.checkpoint, "--checkpoint")
      : undefined;
  return { massifBytes, checkpointBytes, leaf };
}
