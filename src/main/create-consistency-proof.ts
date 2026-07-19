import { readFileSync, writeFileSync } from "node:fs";
import type { Out } from "@forestrie/cli-kit/reporting";
import type { CreateConsistencyProofOptions } from "../options/create-consistency-proof.js";
import {
  buildConsistencyProofArtifact,
  encodeConsistencyProofArtifact,
  multiMassifNodeGetter,
} from "../lib/consistency-proof.js";

/** `--json` success shape on stdout — stable for demo scripting. */
export type CreateConsistencyProofReport = {
  command: "create-consistency-proof";
  fromSize: string;
  toSize: string;
  basePeakCount: number;
  pathCount: number;
  out: string;
};

export type CreateConsistencyProofErrorReport = {
  error: "create_consistency_proof_failed";
  command: "create-consistency-proof";
  message: string;
};

/**
 * Build the portable top-up artifact from massif tiles (FOR-368 Phase 3):
 * base accumulator at `--from-size` plus one inclusion path per base peak
 * proven at `--to-size`, self-verified before writing. Consumers verify
 * tile-free with `verify --known-accumulator ... --consistency-proof`.
 */
export async function runCreateConsistencyProof(
  out: Out,
  options: CreateConsistencyProofOptions,
): Promise<void> {
  try {
    const blobs = options.massifs.map(
      (f) => new Uint8Array(readFileSync(f)),
    );
    const artifact = await buildConsistencyProofArtifact({
      get: multiMassifNodeGetter(blobs),
      fromSize: options.fromSize,
      toSize: options.toSize,
    });
    writeFileSync(options.out, encodeConsistencyProofArtifact(artifact));

    if (options.json) {
      const report: CreateConsistencyProofReport = {
        command: "create-consistency-proof",
        fromSize: artifact.fromSize.toString(),
        toSize: artifact.toSize.toString(),
        basePeakCount: artifact.accumulatorFrom.length,
        pathCount: artifact.paths.length,
        out: options.out,
      };
      out.out(JSON.stringify(report, null, 2));
    } else {
      out.print(
        "create-consistency-proof: proved %s -> %s (%d base peaks; self-verified)",
        artifact.fromSize.toString(),
        artifact.toSize.toString(),
        artifact.accumulatorFrom.length,
      );
      out.out(
        `wrote consistency proof: ${options.out} (verify with --known-accumulator at size ${artifact.toSize} plus --consistency-proof)`,
      );
    }
    process.exitCode = 0;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (options.json) {
      const report: CreateConsistencyProofErrorReport = {
        error: "create_consistency_proof_failed",
        command: "create-consistency-proof",
        message,
      };
      out.out(JSON.stringify(report, null, 2));
    } else {
      out.warn("forestrie create-consistency-proof: %s", message);
    }
    process.exitCode = 1;
  }
}
