/**
 * ImutableUnivocity creation-bytecode acquisition for `forestrie deploy`
 * (FOR-340).
 *
 * Default path: fetch the deploy-manifest + sha256 sidecar from the
 * univocity GitHub release (deploy-core `fetchUnivocityReleaseManifest`,
 * `latest` resolved via the GitHub API), verify the manifest bytes
 * against the sidecar, then verify every embedded bytecode digest.
 *
 * `--release-manifest <path>` swaps the fetch for a local file (offline /
 * test escape hatch). The sidecar step is skipped — the file is operator
 * supplied — but the embedded per-contract sha256 digests are still
 * verified by `verifyAndParseImutableManifest`.
 */
import { readFileSync } from "node:fs";
import {
  fetchUnivocityReleaseManifest,
  verifyAndParseImutableManifest,
  verifyManifestBytesWithSidecar,
  type DeployManifest,
} from "@forestrie/deploy-core";
import type { Hex } from "viem";
import { errorMessage } from "./sign-statement-key.js";

/** Verified deployable artifact. */
export type ImutableDeployArtifact = {
  manifest: DeployManifest;
  /** ImutableUnivocity creation bytecode (digest-verified). */
  creationBytecode: Hex;
  /** Manifest releaseId (release tag for fetched manifests). */
  releaseId: string;
  source: "release" | "file";
};

export type LoadImutableArtifactInput = {
  /** Local deploy-manifest JSON path; overrides the release fetch. */
  manifestPath?: string | undefined;
  /** Release tag (`latest` or `vX.Y.Z`) when fetching. */
  releaseTag: string;
};

/** Load + verify the ImutableUnivocity deploy artifact. */
export async function loadImutableArtifact(
  input: LoadImutableArtifactInput,
): Promise<ImutableDeployArtifact> {
  if (input.manifestPath !== undefined) {
    let raw: string;
    try {
      raw = readFileSync(input.manifestPath, "utf8");
    } catch (err) {
      throw new Error(
        `cannot read deploy manifest ${input.manifestPath}: ${errorMessage(err)}`,
      );
    }
    const { manifest, artifact } = await verifyAndParseImutableManifest(raw);
    return {
      manifest,
      creationBytecode: artifact.bytecode,
      releaseId: manifest.releaseId,
      source: "file",
    };
  }

  const fetched = await fetchUnivocityReleaseManifest(input.releaseTag);
  await verifyManifestBytesWithSidecar(
    new TextEncoder().encode(fetched.raw),
    fetched.sidecar,
  );
  const { manifest, artifact } = await verifyAndParseImutableManifest(
    fetched.raw,
    { expectedReleaseId: fetched.releaseTag },
  );
  return {
    manifest,
    creationBytecode: artifact.bytecode,
    releaseId: manifest.releaseId,
    source: "release",
  };
}
