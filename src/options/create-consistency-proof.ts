import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/**
 * `forestrie create-consistency-proof` — FOR-368 Phase 3 (plan-2607-29).
 *
 * Build a portable, UNSIGNED top-up artifact from public massif tiles: one
 * inclusion path per `--from-size` peak, proven at `--to-size`, plus the
 * base accumulator. Any party with the tiles can produce it (SCRAPI §2.4
 * Resolve Receipt, made third-party); the holder then verifies an old
 * receipt tile-free with `verify --known-accumulator ... --consistency-proof`.
 * Soundness never depends on who built it — the artifact can only fail
 * against the holder's trusted snapshot, never mint trust.
 */

export type CreateConsistencyProofOptions = ForestrieCommonOptions & {
  /** Massif blob paths, comma-separated (a spanning proof needs each). */
  massifs: string[];
  fromSize: bigint;
  toSize: bigint;
  out: string;
};

function requiredSize(args: LooseParsedArgs, name: string): bigint {
  const raw = requiredStringOption(args, name);
  let value: bigint;
  try {
    value = BigInt(raw);
  } catch {
    throw new Error(`--${name} must be an MMR size (integer)`);
  }
  if (value <= 0n) {
    throw new Error(`--${name} must be a positive MMR size`);
  }
  return value;
}

export function parseCreateConsistencyProofOptions(
  args: LooseParsedArgs,
): CreateConsistencyProofOptions {
  const massifs = requiredStringOption(args, "massif")
    .split(",")
    .map((f) => f.trim())
    .filter((f) => f !== "");
  if (massifs.length === 0) {
    throw new Error("--massif requires at least one massif blob path");
  }
  const options: CreateConsistencyProofOptions = {
    ...parseForestrieCommonOptions(args),
    massifs,
    fromSize: requiredSize(args, "from-size"),
    toSize: requiredSize(args, "to-size"),
    out: requiredStringOption(args, "out"),
  };
  if (options.toSize <= options.fromSize) {
    throw new Error("--to-size must be greater than --from-size");
  }
  return options;
}
