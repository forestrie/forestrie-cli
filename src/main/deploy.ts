import type { Out } from "@forestrie/cli-kit/reporting";
import { getAddress, type Hex } from "viem";
import type { BootstrapAlg, DeployOptions } from "../options/deploy.js";
import {
  loadImutableArtifact,
  type ImutableDeployArtifact,
} from "../lib/deploy-artifact.js";
import {
  resolveDeployBootstrapKey,
  type ResolvedDeployBootstrap,
} from "../lib/deploy-bootstrap.js";
import {
  DeployFlowError,
  runDeployFlow,
  type DeployFlowResult,
  type DeployRpc,
} from "../lib/deploy-flow.js";
import { createDeployRpc } from "../lib/deploy-rpc.js";
import { errorMessage } from "../lib/sign-statement-key.js";

/**
 * FOR-341..347 sibling — FOR-340: deploy a univocity instance.
 *
 * ES256 paved path (forestrie-demo-01.md §R1): resolve/generate the
 * ES256 bootstrap key, fetch + verify the univocity release manifest,
 * build the ImutableUnivocity creation tx via `@forestrie/deploy-core`,
 * submit it directly from the funded deployer EOA, and write the
 * deployment record. KS256 (Safe / ERC-1271) is a pre-provisioned aside
 * — no live Safe flow is implemented here.
 */

/**
 * Deployment record (`--out` / stdout). The demo contract is the first
 * four fields — `jq -r .imutableUnivocity` / `.genesisLogId` must keep
 * working; the rest is provenance.
 */
export type DeploymentRecord = {
  kind: "imutable-deployment";
  version: 1;
  imutableUnivocity: string;
  genesisLogId: string;
  bootstrapAlg: BootstrapAlg;
  chainId: number;
  from: string;
  txHash: string;
  releaseId: string;
};

/** `--json` success shape. */
export type DeployReport = DeploymentRecord & {
  command: "deploy";
  status: "deployed";
  /** Present when the bootstrap key was generated. */
  bootstrapPemOut?: string;
  /** Present when `--out` was given. */
  out?: string;
};

/** `--json` failure shape. */
export type DeployErrorReport = {
  error:
    | "bootstrap_alg_unsupported"
    | "bootstrap_key_failed"
    | "manifest_failed"
    | "owner_mismatch"
    | "network_failed"
    | "deploy_failed";
  command: "deploy";
  message: string;
  detail?: string;
  txHash?: string;
};

/** Test seam: effects injected by the deploy tests (real by default). */
export type DeployRunDeps = {
  resolveBootstrap?: typeof resolveDeployBootstrapKey;
  loadArtifact?: typeof loadImutableArtifact;
  createRpc?: (rpcUrl: string, deployerKey: Hex) => DeployRpc;
};

const FLOW_ERROR_CODES = {
  network: "network_failed",
  deploy: "deploy_failed",
} as const;

function reportError(
  out: Out,
  options: DeployOptions,
  report: DeployErrorReport,
): void {
  if (options.json) {
    out.out(JSON.stringify(report, null, 2));
  } else {
    out.warn("forestrie deploy: %s", report.message);
    if (report.detail !== undefined && !report.message.includes(report.detail)) {
      out.warn("  detail: %s", report.detail);
    }
    if (report.txHash !== undefined) {
      out.warn("  txHash: %s", report.txHash);
    }
  }
  process.exitCode = 1;
}

function deploymentRecord(
  options: DeployOptions,
  artifact: ImutableDeployArtifact,
  result: DeployFlowResult,
): DeploymentRecord {
  return {
    kind: "imutable-deployment",
    version: 1,
    imutableUnivocity: result.imutableUnivocity,
    genesisLogId: result.genesisLogId,
    bootstrapAlg: options.bootstrapAlg,
    chainId: result.chainId,
    from: result.from,
    txHash: result.txHash,
    releaseId: artifact.releaseId,
  };
}

async function reportDeployed(
  out: Out,
  options: DeployOptions,
  bootstrap: ResolvedDeployBootstrap,
  record: DeploymentRecord,
): Promise<void> {
  const json = JSON.stringify(record, null, 2);
  if (options.out !== undefined) {
    await Bun.write(options.out, `${json}\n`);
  }
  if (options.json) {
    const report: DeployReport = {
      command: "deploy",
      status: "deployed",
      ...record,
    };
    if (bootstrap.pemOut !== undefined) report.bootstrapPemOut = bootstrap.pemOut;
    if (options.out !== undefined) report.out = options.out;
    out.out(JSON.stringify(report, null, 2));
    return;
  }
  if (bootstrap.pemOut !== undefined) {
    out.print("wrote ES256 bootstrap PEM to %s", bootstrap.pemOut);
  }
  if (options.out !== undefined) {
    // Record went to --out; keep stdout clean, summarize on stderr.
    out.print("ImutableUnivocity deployed at: %s", record.imutableUnivocity);
    out.print("genesisLogId: %s", record.genesisLogId);
    out.print("chainId: %d  txHash: %s", record.chainId, record.txHash);
    out.print("wrote deployment record to %s", options.out);
  } else {
    // No --out: the record itself is the pipeable product (demo jq's it).
    out.out("%s", json);
  }
}

export async function runDeploy(
  out: Out,
  options: DeployOptions,
  deps: DeployRunDeps = {},
): Promise<void> {
  if (options.bootstrapAlg !== "es256") {
    reportError(out, options, {
      error: "bootstrap_alg_unsupported",
      command: "deploy",
      message:
        "ks256 (Safe / ERC-1271) is the pre-provisioned aside — forestrie deploy implements the ES256 paved path only; use the univocity-tools deployer Safe flow",
    });
    return;
  }

  const resolveBootstrap = deps.resolveBootstrap ?? resolveDeployBootstrapKey;
  const loadArtifact = deps.loadArtifact ?? loadImutableArtifact;
  const createRpc = deps.createRpc ?? createDeployRpc;

  let bootstrap: ResolvedDeployBootstrap;
  try {
    bootstrap = await resolveBootstrap({
      generate: options.bootstrapEs256Generate,
      pemOut: options.bootstrapEs256PemOut,
      pemPath: options.bootstrapEs256Pem,
    });
  } catch (err) {
    reportError(out, options, {
      error: "bootstrap_key_failed",
      command: "deploy",
      message: errorMessage(err),
    });
    return;
  }

  let artifact: ImutableDeployArtifact;
  try {
    artifact = await loadArtifact({
      manifestPath: options.releaseManifest,
      releaseTag: options.releaseTag,
    });
  } catch (err) {
    reportError(out, options, {
      error: "manifest_failed",
      command: "deploy",
      message: `cannot load a verified deploy manifest: ${errorMessage(err)}`,
    });
    return;
  }

  const rpc = createRpc(options.rpcUrl, options.deployerKey);

  if (options.ownerAddress !== undefined) {
    let owner: string;
    try {
      owner = getAddress(options.ownerAddress);
    } catch {
      reportError(out, options, {
        error: "owner_mismatch",
        command: "deploy",
        message: `--owner-address is not a valid address: ${options.ownerAddress}`,
      });
      return;
    }
    if (owner !== rpc.from) {
      reportError(out, options, {
        error: "owner_mismatch",
        command: "deploy",
        message: `--owner-address ${owner} does not match the --deployer-key account ${rpc.from}`,
      });
      return;
    }
  }

  out.log(
    "deploying ImutableUnivocity (release %s) from %s via %s",
    artifact.releaseId,
    rpc.from,
    options.rpcUrl,
  );

  let result: DeployFlowResult;
  try {
    result = await runDeployFlow(rpc, {
      creationBytecode: artifact.creationBytecode,
      bootstrap: bootstrap.bootstrap,
    });
  } catch (err) {
    if (err instanceof DeployFlowError) {
      const report: DeployErrorReport = {
        error: FLOW_ERROR_CODES[err.stage],
        command: "deploy",
        message: err.message,
      };
      if (err.detail !== undefined) report.detail = err.detail;
      if (err.txHash !== undefined) report.txHash = err.txHash;
      reportError(out, options, report);
      return;
    }
    reportError(out, options, {
      error: "deploy_failed",
      command: "deploy",
      message: errorMessage(err),
    });
    return;
  }

  await reportDeployed(
    out,
    options,
    bootstrap,
    deploymentRecord(options, artifact, result),
  );
}
