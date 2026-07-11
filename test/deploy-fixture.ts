/**
 * Fixtures for the `forestrie deploy` tests (FOR-340): a minimal valid
 * deploy-manifest (digests computed for real, so deploy-core's
 * verification passes) and a canned JSON-RPC mock server implementing
 * just enough of the eth API for viem's EOA contract-creation flow.
 */
import { bytecodeSha256 } from "@forestrie/deploy-core";
import type { Hex } from "viem";

/**
 * Minimal creation bytecode: `PUSH1 0x00 PUSH1 0x00 RETURN` deploys an
 * empty runtime and ignores the appended constructor args — enough to
 * exercise the full deploy path on anvil without a univocity release.
 */
export const TINY_CREATION_BYTECODE: Hex = "0x60006000f3";

/** anvil funded account #1 (test-only, publicly known). */
export const DEPLOYER_KEY =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
export const DEPLOYER_ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

/** Deterministic mock deploy artefacts. */
export const MOCK_TX_HASH =
  "0x59f24a3e871a615304219624ac10bd7e9d80b96a75422b28d18a13b28860bd77";
export const MOCK_CONTRACT_ADDRESS =
  "0x1528b86ff561f617602356efdbd05908a07aa788";
/** genesisLogId for MOCK_CONTRACT_ADDRESS (deployer-common test vector). */
export const MOCK_GENESIS_LOG_ID = "1528b86f-f561-f617-6023-56efdbd05908";

/** Build a digest-valid deploy-manifest JSON for `creationBytecode`. */
export async function buildManifestJson(
  creationBytecode: Hex,
  releaseId = "v0.0.0-test",
): Promise<string> {
  return JSON.stringify({
    version: 1,
    releaseId,
    contracts: {
      ImutableUnivocity: {
        contractName: "ImutableUnivocity",
        creationBytecode,
        bytecodeSha256: await bytecodeSha256(creationBytecode),
        solcVersion: "0.8.24",
      },
    },
  });
}

export type MockRpcServer = {
  url: string;
  /** Raw signed txs received by eth_sendRawTransaction. */
  rawTransactions: Hex[];
  stop(): void;
};

export type MockRpcBehaviour = {
  /** Receipt status returned for the deploy tx (default success). */
  receiptStatus?: "0x1" | "0x0";
  /** Omit contractAddress from the receipt. */
  omitContractAddress?: boolean;
};

const BLOCK = {
  baseFeePerGas: "0x7",
  difficulty: "0x0",
  extraData: "0x",
  gasLimit: "0x1c9c380",
  gasUsed: "0x0",
  hash: "0x9b78d4b62c0a63b1e8ab7c9a17558a51ea3524dbfa477a2382bf3c40f8f9a2ec",
  logsBloom: `0x${"00".repeat(256)}`,
  miner: "0x0000000000000000000000000000000000000000",
  mixHash: `0x${"00".repeat(32)}`,
  nonce: "0x0000000000000000",
  number: "0x1",
  parentHash: `0x${"00".repeat(32)}`,
  receiptsRoot: `0x${"00".repeat(32)}`,
  sha3Uncles: `0x${"00".repeat(32)}`,
  size: "0x220",
  stateRoot: `0x${"00".repeat(32)}`,
  timestamp: "0x64000000",
  totalDifficulty: "0x0",
  transactions: [],
  transactionsRoot: `0x${"00".repeat(32)}`,
  uncles: [],
};

/**
 * Canned JSON-RPC server covering viem's `sendTransaction` (EIP-1559
 * fee estimation + nonce + raw submission) and
 * `waitForTransactionReceipt`.
 */
export function startMockRpcServer(
  behaviour: MockRpcBehaviour = {},
): MockRpcServer {
  const rawTransactions: Hex[] = [];

  const receipt = () => {
    const base: Record<string, unknown> = {
      blockHash: BLOCK.hash,
      blockNumber: "0x2",
      contractAddress: behaviour.omitContractAddress
        ? null
        : MOCK_CONTRACT_ADDRESS,
      cumulativeGasUsed: "0x5208",
      effectiveGasPrice: "0x7",
      from: DEPLOYER_ADDRESS.toLowerCase(),
      gasUsed: "0x5208",
      logs: [],
      logsBloom: `0x${"00".repeat(256)}`,
      status: behaviour.receiptStatus ?? "0x1",
      to: null,
      transactionHash: MOCK_TX_HASH,
      transactionIndex: "0x0",
      type: "0x2",
    };
    return base;
  };

  const handle = (method: string, params: unknown[]): unknown => {
    switch (method) {
      case "eth_chainId":
        return "0x7a69"; // 31337
      case "eth_blockNumber":
        return "0x2";
      case "eth_getBlockByNumber":
        return BLOCK;
      case "eth_getTransactionCount":
        return "0x0";
      case "eth_estimateGas":
        return "0x100000";
      case "eth_maxPriorityFeePerGas":
        return "0x0";
      case "eth_gasPrice":
        return "0x7";
      case "eth_feeHistory":
        return {
          oldestBlock: "0x1",
          baseFeePerGas: ["0x7", "0x7"],
          gasUsedRatio: [0.1],
          reward: [["0x0"]],
        };
      case "eth_sendRawTransaction":
        rawTransactions.push(params[0] as Hex);
        return MOCK_TX_HASH;
      case "eth_getTransactionReceipt":
        return receipt();
      default:
        throw new Error(`mock rpc: unhandled method ${method}`);
    }
  };

  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const body = (await req.json()) as
        | { id: unknown; method: string; params?: unknown[] }
        | Array<{ id: unknown; method: string; params?: unknown[] }>;
      const answer = (r: { id: unknown; method: string; params?: unknown[] }) => {
        try {
          return { jsonrpc: "2.0", id: r.id, result: handle(r.method, r.params ?? []) };
        } catch (err) {
          return {
            jsonrpc: "2.0",
            id: r.id,
            error: { code: -32601, message: (err as Error).message },
          };
        }
      };
      const payload = Array.isArray(body) ? body.map(answer) : answer(body);
      return Response.json(payload);
    },
  });

  return {
    url: `http://127.0.0.1:${server.port}`,
    rawTransactions,
    stop: () => server.stop(true),
  };
}
