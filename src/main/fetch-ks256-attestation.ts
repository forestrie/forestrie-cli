import { readFileSync, writeFileSync } from "node:fs";
import type { Out } from "@forestrie/cli-kit/reporting";
import {
  bytesToHex,
  encodeIsValidSignatureCall,
  ethRpc,
  hexAddressToBytes,
  normalizeHexAddress,
} from "@forestrie/chain-rpc";
import {
  decodeChainBindingFromGenesis,
  decodeTrustRootFromGenesis,
  encodeKs256Attestation,
  ERC1271_MAGIC_VALUE,
  extractKs256DelegationDigest,
} from "@forestrie/receipt-verify";
import { keccak256 } from "viem";
import type { FetchKs256AttestationOptions } from "../options/fetch-ks256-attestation.js";
import { isKs256Root } from "../lib/known-log-key.js";

/** `--json` success shape on stdout — stable for demo scripting. */
export type FetchKs256AttestationReport = {
  command: "fetch-ks256-attestation";
  chainId: string;
  address: string;
  digest: string;
  blockNumber: string;
  blockHash: string;
  out: string;
};

export type FetchKs256AttestationErrorReport = {
  error: "fetch_ks256_attestation_failed";
  command: "fetch-ks256-attestation";
  message: string;
};

function readFile(path: string, flag: string): Uint8Array {
  try {
    return new Uint8Array(readFileSync(path));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`cannot read ${flag} '${path}': ${message}`);
  }
}

function hexToBigint(v: unknown, what: string): bigint {
  if (typeof v !== "string" || !/^0x[0-9a-fA-F]+$/.test(v)) {
    throw new Error(`${what}: expected a hex quantity, got ${String(v)}`);
  }
  return BigInt(v);
}

function hexToBytes32(v: unknown, what: string): Uint8Array {
  if (typeof v !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(v)) {
    throw new Error(`${what}: expected a 32-byte hex value, got ${String(v)}`);
  }
  return new Uint8Array(Buffer.from(v.slice(2), "hex"));
}

/**
 * Pin to one block, then: refuse an EOA root (no code), and require the
 * contract's `isValidSignature(digest, signature)` to return the ERC-1271
 * magic value for the certificate's own digest and signature. Nothing is
 * written unless every check passes.
 */
export async function runFetchKs256Attestation(
  out: Out,
  options: FetchKs256AttestationOptions,
): Promise<void> {
  try {
    const receiptCbor = readFile(options.receipt, "--receipt");
    const genesisCbor =
      options.genesis !== undefined
        ? readFile(options.genesis, "--genesis")
        : undefined;

    let root: Uint8Array;
    if (options.root !== undefined) {
      const normalized = normalizeHexAddress(options.root);
      if (normalized === null) {
        throw new Error(`--root is not a valid address: '${options.root}'`);
      }
      root = hexAddressToBytes(normalized);
    } else {
      const trust = await decodeTrustRootFromGenesis(genesisCbor!);
      if (!isKs256Root(trust)) {
        throw new Error(
          "the genesis root is not a KS256 address (an ES256 root needs no attestation)",
        );
      }
      root = (trust as { address: Uint8Array }).address;
    }

    let genesisChainId: bigint | undefined;
    if (genesisCbor !== undefined) {
      genesisChainId = BigInt(decodeChainBindingFromGenesis(genesisCbor).chainId);
    }

    let parts: ReturnType<typeof extractKs256DelegationDigest>;
    try {
      parts = extractKs256DelegationDigest(receiptCbor);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`the receipt's delegation certificate is not KS256: ${message}`);
    }
    if (parts === null) {
      throw new Error("receipt carries no delegation certificate");
    }

    const chainId = hexToBigint(
      await ethRpc(options.rpcUrl, "eth_chainId", []),
      "eth_chainId",
    );
    if (genesisChainId !== undefined && chainId !== genesisChainId) {
      throw new Error(
        `RPC chain id ${chainId} differs from the genesis chain id ${genesisChainId}`,
      );
    }

    const blockTag =
      options.block === "latest" ? "latest" : `0x${options.block.toString(16)}`;
    const block = (await ethRpc(options.rpcUrl, "eth_getBlockByNumber", [
      blockTag,
      false,
    ])) as { number?: unknown; hash?: unknown } | null;
    if (block === null || typeof block !== "object") {
      throw new Error(`eth_getBlockByNumber returned no block for ${blockTag}`);
    }
    const blockNumber = hexToBigint(block.number, "block number");
    const blockHash = hexToBytes32(block.hash, "block hash");
    const pinned = `0x${blockNumber.toString(16)}`;
    const rootHex = `0x${bytesToHex(root)}`;

    const code = await ethRpc(options.rpcUrl, "eth_getCode", [rootHex, pinned]);
    if (typeof code !== "string" || code === "0x" || code === "") {
      throw new Error(
        `${rootHex} has no contract code at block ${blockNumber}: an EOA root needs no attestation (verify recovers it by ecrecover)`,
      );
    }

    let ret: unknown;
    try {
      ret = await ethRpc(options.rpcUrl, "eth_call", [
        {
          to: rootHex,
          data: encodeIsValidSignatureCall(parts.digest, parts.signature),
        },
        pinned,
      ]);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`isValidSignature call to ${rootHex} failed: ${message}`);
    }
    if (typeof ret !== "string" || !/^0x[0-9a-fA-F]{64,}$/.test(ret)) {
      throw new Error(
        `isValidSignature returned a malformed result: ${String(ret)}`,
      );
    }
    const magic = new Uint8Array(Buffer.from(ret.slice(2, 10), "hex"));
    if (bytesToHex(magic) !== bytesToHex(ERC1271_MAGIC_VALUE)) {
      throw new Error(
        `${rootHex} did not validate the certificate signature: isValidSignature returned 0x${bytesToHex(magic)}, not the ERC-1271 magic value 0x${bytesToHex(ERC1271_MAGIC_VALUE)}`,
      );
    }

    const signatureHash = new Uint8Array(
      Buffer.from(keccak256(parts.signature).slice(2), "hex"),
    );
    writeFileSync(
      options.out,
      encodeKs256Attestation({
        version: 1,
        chainId,
        address: root,
        digest: parts.digest,
        signatureHash,
        blockNumber,
        blockHash,
        magic,
      }),
    );

    if (options.json) {
      const report: FetchKs256AttestationReport = {
        command: "fetch-ks256-attestation",
        chainId: chainId.toString(),
        address: rootHex,
        digest: `0x${bytesToHex(parts.digest)}`,
        blockNumber: blockNumber.toString(),
        blockHash: `0x${bytesToHex(blockHash)}`,
        out: options.out,
      };
      out.out(JSON.stringify(report, null, 2));
    } else {
      out.print(
        "fetch-ks256-attestation: %s signs digest 0x%s at block %s (chain %s)",
        rootHex,
        bytesToHex(parts.digest),
        blockNumber.toString(),
        chainId.toString(),
      );
      out.out(`wrote ERC-1271 attestation: ${options.out}`);
    }
    process.exitCode = 0;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (options.json) {
      const report: FetchKs256AttestationErrorReport = {
        error: "fetch_ks256_attestation_failed",
        command: "fetch-ks256-attestation",
        message,
      };
      out.out(JSON.stringify(report, null, 2));
    } else {
      out.warn("forestrie fetch-ks256-attestation: %s", message);
    }
    process.exitCode = 1;
  }
}
