/**
 * Deploy transaction construction + submission flow for `forestrie
 * deploy` (FOR-340).
 *
 * ES256 / EOA paved path: a DIRECT contract-creation transaction (no
 * `to`) whose data is the ImutableUnivocity creation bytecode followed
 * by `abi.encode(int64 bootstrapAlg, bytes bootstrapKey)` — built by
 * deploy-core `buildImutableDeploymentData`. The deployed address comes
 * from `receipt.contractAddress`. (The Safe/CreateCall CREATE2 path is
 * the pre-provisioned KS256 aside and is deliberately NOT driven here.)
 */
import {
  buildImutableDeploymentData,
  type BootstrapKey,
} from "@forestrie/deploy-core";
import { getAddress, type Address, type Hex } from "viem";
import { genesisLogIdFromImutableAddress } from "./deploy-genesis-log-id.js";

/**
 * Failure stage taxonomy:
 * - `network` — the RPC endpoint could not be reached / transport error
 * - `deploy` — the chain rejected or reverted the deploy transaction
 */
export type DeployFlowStage = "network" | "deploy";

/** Structured deploy failure; `stage` maps onto the `--json` error codes. */
export class DeployFlowError extends Error {
  readonly stage: DeployFlowStage;
  readonly detail?: string;
  readonly txHash?: Hex;

  constructor(
    stage: DeployFlowStage,
    message: string,
    extra: { detail?: string; txHash?: Hex; cause?: unknown } = {},
  ) {
    super(message, extra.cause === undefined ? undefined : { cause: extra.cause });
    this.name = "DeployFlowError";
    this.stage = stage;
    if (extra.detail !== undefined) this.detail = extra.detail;
    if (extra.txHash !== undefined) this.txHash = extra.txHash;
  }
}

/** Receipt subset the flow needs. */
export type DeployReceipt = {
  status: "success" | "reverted";
  contractAddress: string | null;
};

/**
 * Minimal RPC surface for the flow — the seam mocked by unit tests.
 * The real implementation (viem over `--rpc-url`) is in
 * `deploy-rpc.ts`.
 */
export type DeployRpc = {
  /** Deployer (gas) account address derived from `--deployer-key`. */
  readonly from: Address;
  getChainId(): Promise<number>;
  /** Send the contract-creation tx (`to` omitted); resolves to the tx hash. */
  sendDeployTransaction(data: Hex): Promise<Hex>;
  waitForReceipt(hash: Hex): Promise<DeployReceipt>;
};

export type DeployFlowInput = {
  /** Digest-verified ImutableUnivocity creation bytecode. */
  creationBytecode: Hex;
  /** Resolved bootstrap key (constructor args). */
  bootstrap: BootstrapKey;
};

export type DeployFlowResult = {
  chainId: number;
  /** Deployed ImutableUnivocity address (checksummed). */
  imutableUnivocity: Address;
  /** Root/bootstrap log UUID derived from the address. */
  genesisLogId: string;
  txHash: Hex;
  from: Address;
  /** Full creation-tx data (bytecode + encoded constructor args). */
  deploymentData: Hex;
};

/** Creation-tx data: bytecode ++ abi.encode(int64 alg, bytes key). */
export function buildDeploymentData(
  creationBytecode: Hex,
  bootstrap: BootstrapKey,
): Hex {
  return buildImutableDeploymentData(
    creationBytecode,
    bootstrap.algId,
    bootstrap.key,
  );
}

/** True when `err` (or a cause below it) is an RPC transport failure. */
export function isTransportError(err: unknown): boolean {
  for (let e: unknown = err; e instanceof Error; e = e.cause) {
    if (
      e.name === "HttpRequestError" ||
      e.name === "TimeoutError" ||
      e.name === "SocketClosedError" ||
      e.name === "WebSocketRequestError" ||
      (e instanceof TypeError && /fetch|connect/i.test(e.message))
    ) {
      return true;
    }
  }
  return false;
}

function stageFor(err: unknown, fallback: DeployFlowStage): DeployFlowStage {
  return isTransportError(err) ? "network" : fallback;
}

function detailOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Build, submit and confirm the deploy transaction. */
export async function runDeployFlow(
  rpc: DeployRpc,
  input: DeployFlowInput,
): Promise<DeployFlowResult> {
  let chainId: number;
  try {
    chainId = await rpc.getChainId();
  } catch (err) {
    throw new DeployFlowError("network", "cannot reach the RPC endpoint", {
      detail: detailOf(err),
      cause: err,
    });
  }

  const deploymentData = buildDeploymentData(
    input.creationBytecode,
    input.bootstrap,
  );

  let txHash: Hex;
  try {
    txHash = await rpc.sendDeployTransaction(deploymentData);
  } catch (err) {
    throw new DeployFlowError(
      stageFor(err, "deploy"),
      "deploy transaction submission failed",
      { detail: detailOf(err), cause: err },
    );
  }

  let receipt: DeployReceipt;
  try {
    receipt = await rpc.waitForReceipt(txHash);
  } catch (err) {
    throw new DeployFlowError(
      stageFor(err, "deploy"),
      "deploy transaction was not confirmed",
      { detail: detailOf(err), txHash, cause: err },
    );
  }

  if (receipt.status !== "success") {
    throw new DeployFlowError("deploy", "deploy transaction reverted", {
      txHash,
    });
  }
  if (receipt.contractAddress == null) {
    throw new DeployFlowError(
      "deploy",
      "deploy receipt has no contractAddress (not a contract-creation tx?)",
      { txHash },
    );
  }

  const imutableUnivocity = getAddress(receipt.contractAddress);
  return {
    chainId,
    imutableUnivocity,
    genesisLogId: genesisLogIdFromImutableAddress(imutableUnivocity),
    txHash,
    from: rpc.from,
    deploymentData,
  };
}
