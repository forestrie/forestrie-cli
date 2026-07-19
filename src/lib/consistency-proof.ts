import {
  decodeCborDeterministic,
  encodeCborDeterministic,
} from "@forestrie/encoding";
import {
  createSyncHasher,
  indexConsistencyProof,
  openMassifNodeStore,
  peakMMRIndexes,
  verifyConsistency,
  type NodeGetter,
} from "@forestrie/merklelog";

/**
 * Portable consistency-proof artifact (FOR-368 Phase 3, plan-2607-29):
 * the "top-up" a holder of an old receipt obtains from ANY party with the
 * public massif tiles — after which the holder verifies tile-free against
 * a trusted newer state (`--known-accumulator`).
 *
 * Trust model: the artifact is UNSIGNED and untrusted. Soundness comes
 * from recomputation — the receipt's peak must appear in the artifact's
 * base accumulator, and folding the artifact's paths from that base
 * (draft-bryce `consistent_roots`) must land every proven root inside the
 * TRUSTED target accumulator. A fabricated artifact can only fail; a
 * passing one proves the old state is a committed prefix of the trusted
 * state (SCRAPI §2.4's Resolve Receipt provision, made third-party).
 *
 * Encoding is strict RFC 8949 §4.2 deterministic CBOR (hard policy).
 */

/** CBOR map labels for the artifact (strict RFC 8949 §4.2). */
const LABEL_VERSION = 1;
const LABEL_FROM_SIZE = 2;
const LABEL_TO_SIZE = 3;
const LABEL_ACCUMULATOR_FROM = 4;
const LABEL_PATHS = 5;

const ARTIFACT_VERSION = 1;

export type ConsistencyProofArtifact = {
  version: number;
  /** MMR size the proof extends FROM (the old receipt's era). */
  fromSize: bigint;
  /** MMR size the proof lands on — must equal the trusted state's size. */
  toSize: bigint;
  /** Full accumulator at `fromSize` (untrusted; proven by the fold). */
  accumulatorFrom: Uint8Array[];
  /** One inclusion path per `fromSize` peak, proven at `toSize`. */
  paths: Uint8Array[][];
};

export function encodeConsistencyProofArtifact(
  artifact: ConsistencyProofArtifact,
): Uint8Array {
  return encodeCborDeterministic(
    new Map<number, unknown>([
      [LABEL_VERSION, artifact.version],
      [LABEL_FROM_SIZE, artifact.fromSize],
      [LABEL_TO_SIZE, artifact.toSize],
      [LABEL_ACCUMULATOR_FROM, artifact.accumulatorFrom],
      [LABEL_PATHS, artifact.paths],
    ]),
  );
}

function asBigint(v: unknown, what: string): bigint {
  if (typeof v === "bigint") return v;
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0)
    return BigInt(v);
  throw new Error(`consistency proof: ${what} must be an unsigned integer`);
}

/** Strict decode + structural validation of a top-up artifact. */
export function decodeConsistencyProofArtifact(
  bytes: Uint8Array,
): ConsistencyProofArtifact {
  let decoded: unknown;
  try {
    decoded = decodeCborDeterministic(bytes);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`consistency proof is not canonical CBOR: ${message}`);
  }
  if (!(decoded instanceof Map)) {
    throw new Error("consistency proof must be a CBOR map");
  }
  const version = Number(asBigint(decoded.get(LABEL_VERSION), "version"));
  if (version !== ARTIFACT_VERSION) {
    throw new Error(`consistency proof version ${version} not supported`);
  }
  const fromSize = asBigint(decoded.get(LABEL_FROM_SIZE), "fromSize");
  const toSize = asBigint(decoded.get(LABEL_TO_SIZE), "toSize");
  if (fromSize === 0n || toSize <= fromSize) {
    throw new Error(
      `consistency proof sizes invalid: from ${fromSize} to ${toSize}`,
    );
  }
  const accRaw = decoded.get(LABEL_ACCUMULATOR_FROM);
  const pathsRaw = decoded.get(LABEL_PATHS);
  if (
    !Array.isArray(accRaw) ||
    accRaw.some((p) => !(p instanceof Uint8Array) || p.length !== 32)
  ) {
    throw new Error(
      "consistency proof: accumulatorFrom must be 32-byte peaks",
    );
  }
  if (
    !Array.isArray(pathsRaw) ||
    pathsRaw.some(
      (p) => !Array.isArray(p) || p.some((n) => !(n instanceof Uint8Array)),
    )
  ) {
    throw new Error(
      "consistency proof: paths must be arrays of byte strings",
    );
  }
  const wanted = peakMMRIndexes(fromSize - 1n).length;
  if (accRaw.length !== wanted || pathsRaw.length !== wanted) {
    throw new Error(
      `consistency proof: size ${fromSize} has ${wanted} peaks; got ${accRaw.length} accumulator values and ${pathsRaw.length} paths`,
    );
  }
  return {
    version,
    fromSize,
    toSize,
    accumulatorFrom: accRaw as Uint8Array[],
    paths: pathsRaw as Uint8Array[][],
  };
}

/**
 * Node access across one or more massif blobs (a proof spanning massifs
 * needs nodes from each). First blob covering the index wins; ancestor
 * peak-stack reads resolve through whichever blob carries them.
 */
export function multiMassifNodeGetter(blobs: Uint8Array[]): NodeGetter {
  const stores = blobs.map((b) => openMassifNodeStore(b));
  return (i: bigint) => {
    let lastErr: unknown;
    for (const store of stores) {
      try {
        return store.get(i);
      } catch (err) {
        lastErr = err;
      }
    }
    throw new Error(
      `node ${i} is not covered by the supplied massifs: ${
        lastErr instanceof Error ? lastErr.message : String(lastErr)
      }`,
    );
  };
}

/**
 * Build (and self-verify) a top-up artifact from massif node data. The
 * builder needs tiles; consumers of the artifact never do.
 */
export async function buildConsistencyProofArtifact(opts: {
  get: NodeGetter;
  fromSize: bigint;
  toSize: bigint;
}): Promise<ConsistencyProofArtifact> {
  if (opts.fromSize === 0n || opts.toSize <= opts.fromSize) {
    throw new Error(
      `--from-size must be > 0 and < --to-size (got ${opts.fromSize} -> ${opts.toSize})`,
    );
  }
  const accumulatorFrom = peakMMRIndexes(opts.fromSize - 1n).map(opts.get);
  const proof = indexConsistencyProof(
    opts.get,
    opts.fromSize - 1n,
    opts.toSize - 1n,
  );
  // Self-check before emitting: the artifact must verify against the
  // accumulator the same nodes derive at toSize — a coverage gap in the
  // supplied massifs fails HERE, not at the holder.
  const accumulatorTo = peakMMRIndexes(opts.toSize - 1n).map(opts.get);
  const hasher = await createSyncHasher();
  const check = await verifyConsistency(
    hasher,
    proof,
    accumulatorFrom,
    accumulatorTo,
  );
  if (!check.ok) {
    throw new Error(
      "self-verification failed: supplied massifs do not consistently cover the requested range",
    );
  }
  return {
    version: ARTIFACT_VERSION,
    fromSize: opts.fromSize,
    toSize: opts.toSize,
    accumulatorFrom,
    paths: proof.paths,
  };
}

export type ConsistencyProofAnchorCheck = {
  anchored: boolean;
  /** Index of the receipt peak within the artifact's base accumulator. */
  matchedPeak: number | null;
  reason?: string;
};

/**
 * Tile-free extension of an old receipt to a trusted newer accumulator:
 * peak ∈ artifact base, then fold the artifact into the trusted target.
 */
export async function checkReceiptAnchoredViaConsistencyProof(opts: {
  artifact: ConsistencyProofArtifact;
  recomputedPeak: Uint8Array;
  leafMmrIndex: bigint;
  /** Trusted target state (e.g. a known-accumulator snapshot). */
  trustedSize: bigint;
  trustedAccumulator: Uint8Array[];
}): Promise<ConsistencyProofAnchorCheck> {
  const { artifact } = opts;
  if (artifact.toSize !== opts.trustedSize) {
    return {
      anchored: false,
      matchedPeak: null,
      reason: "consistency_proof_target_mismatch",
    };
  }
  if (opts.leafMmrIndex >= artifact.fromSize) {
    return {
      anchored: false,
      matchedPeak: null,
      reason: "receipt_newer_than_consistency_proof_base",
    };
  }
  let matchedPeak: number | null = null;
  for (let i = 0; i < artifact.accumulatorFrom.length; i++) {
    if (bytesEqual(opts.recomputedPeak, artifact.accumulatorFrom[i]!)) {
      matchedPeak = i;
      break;
    }
  }
  if (matchedPeak === null) {
    return {
      anchored: false,
      matchedPeak: null,
      reason: "peak_not_in_consistency_proof_base",
    };
  }
  const hasher = await createSyncHasher();
  const check = await verifyConsistency(
    hasher,
    {
      mmrSizeA: artifact.fromSize,
      mmrSizeB: artifact.toSize,
      paths: artifact.paths,
    },
    artifact.accumulatorFrom,
    opts.trustedAccumulator,
  );
  if (!check.ok) {
    return {
      anchored: false,
      matchedPeak: null,
      reason: "consistency_proof_invalid",
    };
  }
  return { anchored: true, matchedPeak };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let x = 0;
  for (let i = 0; i < a.length; i++) x |= a[i]! ^ b[i]!;
  return x === 0;
}
