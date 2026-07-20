/**
 * Reconstruct a signed checkpoint from a `publishCheckpoint` transaction's
 * CALLDATA (FOR-418 Phase 1, plan-2607-32).
 *
 * The `CheckpointPublished` *event* is a lossy summary — it carries only the
 * accumulator (see verify-eventscan). The transaction *input* to
 * `publishCheckpoint(ConsistencyReceipt, InclusionProof, bytes8, PublishGrant)`
 * carries the whole `ConsistencyReceipt`: the COSE `signature`, the chain of
 * `ConsistencyProof`s (each the draft's `[tree-size-1, tree-size-2, paths,
 * right-peaks]` — the interior climb nodes), and the sealer `DelegationProof`.
 * So the publish transactions ARE the `.sth` chain, recoverable trustlessly
 * from public chain data. This module is the reader; the fold/provider that
 * consumes it lands in later phases.
 *
 * The ABI is written in viem's readable form, mirroring univocity
 * `src/interfaces/types.sol`; its selector is asserted against the
 * foundry-generated `0x87ce4c61` in the tests.
 */
import { decodeFunctionData, parseAbi } from "viem";

/** `publishCheckpoint` ABI — struct shapes mirror univocity types.sol. */
export const PUBLISH_CHECKPOINT_ABI = parseAbi([
  "struct ConsistencyProof { uint64 treeSize1; uint64 treeSize2; bytes32[][] paths; bytes32[] rightPeaks; }",
  "struct DelegationProof { bytes protectedHeader; bytes delegationKey; uint64 mmrStart; uint64 mmrEnd; bytes signature; }",
  "struct ConsistencyReceipt { bytes protectedHeader; bytes signature; ConsistencyProof[] consistencyProofs; DelegationProof delegationProof; }",
  "struct InclusionProof { uint64 index; bytes32[] path; }",
  "struct PublishGrant { bytes32 logId; uint256 grant; uint256 request; uint64 maxHeight; uint64 minGrowth; bytes32 ownerLogId; bytes grantData; }",
  "function publishCheckpoint(ConsistencyReceipt consistencyParts, InclusionProof grantInclusionProof, bytes8 grantIDTimestampBe, PublishGrant publishGrant)",
]);

/** One embedded consistency proof — the draft Receipt-of-Consistency shape. */
export type CalldataConsistencyProof = {
  treeSize1: bigint;
  treeSize2: bigint;
  /** One inclusion path per tree-size-1 peak, proven at tree-size-2. */
  paths: Uint8Array[][];
  /** New peaks completing the tree-size-2 accumulator (draft `right-peaks`). */
  rightPeaks: Uint8Array[];
};

/** Sealer-key authorization carried alongside the checkpoint (ADR-0006). */
export type CalldataDelegation = {
  protectedHeader: Uint8Array;
  /** Alg-specific key bytes; ES256 = 64-byte x‖y. */
  delegationKey: Uint8Array;
  mmrStart: bigint;
  mmrEnd: bigint;
  signature: Uint8Array;
};

/** The full `ConsistencyReceipt` recovered from `publishCheckpoint` calldata. */
export type CalldataCheckpoint = {
  protectedHeader: Uint8Array;
  /** COSE signature over the tree-size-2 accumulator (ADR-0046 detached). */
  signature: Uint8Array;
  /** Consistency-proof chain from the on-chain base to the published size. */
  consistencyProofs: CalldataConsistencyProof[];
  delegation: CalldataDelegation;
};

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) {
    throw new Error(`odd-length hex from calldata decode: ${hex.slice(0, 12)}…`);
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Decode a `publishCheckpoint` transaction input into its `ConsistencyReceipt`.
 * Throws if the calldata is not a `publishCheckpoint` call (wrong selector /
 * malformed — viem's `decodeFunctionData` rejects), if the proof chain is empty
 * (the contract requires ≥1), or if any link does not strictly grow the tree
 * (a hostile RPC returning bogus calldata for a tx hash — same posture as the
 * FOR-414 size guard).
 */
export function decodePublishCheckpointCalldata(
  inputHex: string,
): CalldataCheckpoint {
  const data = (inputHex.startsWith("0x") ? inputHex : `0x${inputHex}`) as `0x${string}`;
  const { args } = decodeFunctionData({ abi: PUBLISH_CHECKPOINT_ABI, data });
  const receipt = args[0] as {
    protectedHeader: string;
    signature: string;
    consistencyProofs: readonly {
      treeSize1: bigint;
      treeSize2: bigint;
      paths: readonly (readonly string[])[];
      rightPeaks: readonly string[];
    }[];
    delegationProof: {
      protectedHeader: string;
      delegationKey: string;
      mmrStart: bigint;
      mmrEnd: bigint;
      signature: string;
    };
  };

  if (receipt.consistencyProofs.length === 0) {
    throw new Error("publishCheckpoint calldata carries no consistency proofs");
  }
  const consistencyProofs = receipt.consistencyProofs.map((p, i) => {
    if (p.treeSize2 <= p.treeSize1) {
      throw new Error(
        `consistency proof ${i} does not grow the tree: ${p.treeSize1} -> ${p.treeSize2}`,
      );
    }
    return {
      treeSize1: p.treeSize1,
      treeSize2: p.treeSize2,
      paths: p.paths.map((path) => path.map(hexToBytes)),
      rightPeaks: p.rightPeaks.map(hexToBytes),
    };
  });

  return {
    protectedHeader: hexToBytes(receipt.protectedHeader),
    signature: hexToBytes(receipt.signature),
    consistencyProofs,
    delegation: {
      protectedHeader: hexToBytes(receipt.delegationProof.protectedHeader),
      delegationKey: hexToBytes(receipt.delegationProof.delegationKey),
      mmrStart: receipt.delegationProof.mmrStart,
      mmrEnd: receipt.delegationProof.mmrEnd,
      signature: hexToBytes(receipt.delegationProof.signature),
    },
  };
}

/**
 * Fetch a transaction's input (calldata) by hash — the tile-free chain source
 * for {@link decodePublishCheckpointCalldata}. Minimal JSON-RPC, matching the
 * raw-fetch pattern used by the event scan.
 */
export async function fetchTransactionInput(opts: {
  rpcUrl: string;
  txHash: string;
  fetchImpl?: typeof fetch;
}): Promise<string> {
  const doFetch = opts.fetchImpl ?? fetch;
  const res = await doFetch(opts.rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "eth_getTransactionByHash",
      params: [opts.txHash],
    }),
  });
  if (!res.ok) {
    throw new Error(`eth_getTransactionByHash: HTTP ${res.status}`);
  }
  const body = (await res.json()) as {
    result?: { input?: string } | null;
    error?: { message?: string };
  };
  if (body.error) {
    throw new Error(`eth_getTransactionByHash: ${body.error.message ?? "rpc error"}`);
  }
  const input = body.result?.input;
  if (typeof input !== "string" || input.length < 10) {
    throw new Error(`transaction ${opts.txHash} has no input calldata`);
  }
  // A real publishCheckpoint calldata is a few KB; cap the accepted size so a
  // hostile RPC cannot return a multi-hundred-MB `input` string (R6). 8M hex
  // chars ≈ 4 MB — generous for any legitimate proof chain.
  if (input.length > 8_000_000) {
    throw new Error(
      `transaction ${opts.txHash} input is implausibly large (${input.length} hex chars)`,
    );
  }
  return input;
}

/** Fetch and decode in one step. */
export async function fetchPublishCheckpointCalldata(opts: {
  rpcUrl: string;
  txHash: string;
  fetchImpl?: typeof fetch;
}): Promise<CalldataCheckpoint> {
  return decodePublishCheckpointCalldata(await fetchTransactionInput(opts));
}
