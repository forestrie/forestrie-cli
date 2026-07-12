/**
 * Real `DeployRpc` implementation for `forestrie deploy` (FOR-340):
 * viem public + wallet clients over the `--rpc-url` HTTP transport,
 * signing locally with the funded `--deployer-key` (gas-only — the
 * ES256 bootstrap key is the trust root, not this key).
 *
 * Mirrors univocity-tools deployer-common's `createRpcClients` /
 * `executeProposal` EOA path: `sendTransaction` with `chain: null` and
 * no `to` is a plain contract-creation transaction.
 */
import { createPublicClient, createWalletClient, http, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { DeployRpc } from "./deploy-flow.js";

/** viem-backed `DeployRpc` over a JSON-RPC HTTP endpoint. */
export function createDeployRpc(rpcUrl: string, deployerKey: Hex): DeployRpc {
  const account = privateKeyToAccount(deployerKey);
  const transport = http(rpcUrl);
  const publicClient = createPublicClient({ transport });
  const walletClient = createWalletClient({ account, transport });

  return {
    from: account.address,
    getChainId: () => publicClient.getChainId(),
    sendDeployTransaction: (data) =>
      walletClient.sendTransaction({
        account,
        chain: null,
        data,
        value: 0n,
      }),
    waitForReceipt: async (hash) => {
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      return {
        status: receipt.status,
        contractAddress: receipt.contractAddress ?? null,
      };
    },
  };
}
