import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

export type BootstrapAlg = "es256" | "ks256";

/** Default univocity contract release tag (deploy-core resolves `latest`). */
export const DEFAULT_DEPLOY_RELEASE_TAG = "latest";

/** `forestrie deploy` — FOR-340. */
export type DeployOptions = ForestrieCommonOptions & {
  /** Bootstrap key algorithm. ES256 is the paved path; KS256 is the Safe/ERC-1271 aside. */
  bootstrapAlg: BootstrapAlg;
  /** Generate a fresh ES256 P-256 bootstrap keypair. */
  bootstrapEs256Generate: boolean;
  /** Where to write the generated ES256 PKCS#8 PEM. */
  bootstrapEs256PemOut: string | undefined;
  /** Existing ES256 bootstrap key PEM (PKCS#8/SEC1 private or SPKI public). */
  bootstrapEs256Pem: string | undefined;
  /** Deployer / owner address (`OWNER_ADDRESS`). */
  ownerAddress: string | undefined;
  /** JSON-RPC endpoint (`RPC_URL`). */
  rpcUrl: string;
  /**
   * Funded secp256k1 key that signs and pays gas for the deploy
   * transaction (`DEPLOYER_KEY`). Gas-only: it has no role in the log's
   * trust model — the bootstrap key (ES256) is what the contract binds.
   * Normalized to a 0x-prefixed 32-byte hex string.
   */
  deployerKey: `0x${string}`;
  /** Univocity contract release tag for the deploy manifest (default `latest`). */
  releaseTag: string;
  /** Local deploy-manifest JSON path — skips the GitHub release fetch. */
  releaseManifest: string | undefined;
  /** Deployment record output path (default: stdout). */
  out: string | undefined;
};

/** Validate/normalize a 32-byte secp256k1 private key hex string. */
function parseDeployerKey(raw: string): `0x${string}` {
  const hex = raw.startsWith("0x") ? raw.slice(2) : raw;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(
      "--deployer-key must be a 32-byte hex secp256k1 private key (0x…64 hex chars)",
    );
  }
  return `0x${hex.toLowerCase()}` as `0x${string}`;
}

export function parseDeployOptions(args: LooseParsedArgs): DeployOptions {
  const alg = optionalStringOption(args, "bootstrap-alg") ?? "es256";
  if (alg !== "es256" && alg !== "ks256") {
    throw new Error(
      `invalid --bootstrap-alg '${alg}' (expected es256 or ks256)`,
    );
  }

  const generate = args["bootstrap-es256-generate"] === true;
  const pemOut = optionalStringOption(args, "bootstrap-es256-pem-out");
  const pem = optionalStringOption(args, "bootstrap-es256-pem");

  if (alg === "es256") {
    if (generate && pem !== undefined) {
      throw new Error(
        "--bootstrap-es256-generate and --bootstrap-es256-pem are mutually exclusive",
      );
    }
    if (generate && pemOut === undefined) {
      throw new Error(
        "--bootstrap-es256-generate requires --bootstrap-es256-pem-out (the generated private key must be kept — it signs the root grant)",
      );
    }
    if (!generate && pemOut !== undefined) {
      throw new Error(
        "--bootstrap-es256-pem-out is only meaningful with --bootstrap-es256-generate",
      );
    }
    if (!generate && pem === undefined) {
      throw new Error(
        "es256 bootstrap needs a key: pass --bootstrap-es256-generate (with --bootstrap-es256-pem-out) or --bootstrap-es256-pem <path>",
      );
    }
  }

  return {
    ...parseForestrieCommonOptions(args),
    bootstrapAlg: alg,
    bootstrapEs256Generate: generate,
    bootstrapEs256PemOut: pemOut,
    bootstrapEs256Pem: pem,
    ownerAddress: optionalStringOption(args, "owner-address", "OWNER_ADDRESS"),
    rpcUrl: requiredStringOption(args, "rpc-url", "RPC_URL"),
    deployerKey: parseDeployerKey(
      requiredStringOption(args, "deployer-key", "DEPLOYER_KEY"),
    ),
    releaseTag:
      optionalStringOption(args, "release-tag") ?? DEFAULT_DEPLOY_RELEASE_TAG,
    releaseManifest: optionalStringOption(args, "release-manifest"),
    out: optionalStringOption(args, "out"),
  };
}
