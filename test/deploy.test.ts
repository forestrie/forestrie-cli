import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ALG_ES256, resolveBootstrapKey } from "@forestrie/deploy-core";
import {
  concat,
  encodeAbiParameters,
  parseTransaction,
  type Hex,
} from "viem";
import { loadImutableArtifact } from "../src/lib/deploy-artifact.js";
import { resolveDeployBootstrapKey } from "../src/lib/deploy-bootstrap.js";
import {
  DeployFlowError,
  buildDeploymentData,
  runDeployFlow,
  type DeployRpc,
} from "../src/lib/deploy-flow.js";
import { genesisLogIdFromImutableAddress } from "../src/lib/deploy-genesis-log-id.js";
import {
  DEPLOYER_KEY,
  MOCK_CONTRACT_ADDRESS,
  MOCK_GENESIS_LOG_ID,
  MOCK_TX_HASH,
  TINY_CREATION_BYTECODE,
  buildManifestJson,
  startMockRpcServer,
} from "./deploy-fixture.js";
import { runCli, runCliAsync } from "./support.js";

function tmpDir(): string {
  return mkdtempSync(path.join(tmpdir(), "forestrie-deploy-"));
}

describe("genesisLogIdFromImutableAddress", () => {
  test("matches the deployer-common test vector", () => {
    expect(
      genesisLogIdFromImutableAddress(
        "0x1528b86fF561f617602356efdbD05908a07AA788",
      ),
    ).toBe(MOCK_GENESIS_LOG_ID);
  });

  test("rejects non-addresses", () => {
    expect(() => genesisLogIdFromImutableAddress("0x1234")).toThrow(
      /20-byte address/,
    );
  });
});

describe("buildDeploymentData", () => {
  // Mirrors deploy-core's own imutable-deploy-data vectors: data is
  // creationCode ++ abi.encode(int64 alg, bytes key).
  test("appends abi.encode(int64, bytes) constructor args (golden)", async () => {
    const creation = "0x6001" as Hex;
    const key = `0x${"aa".repeat(32)}${"bb".repeat(32)}` as Hex;
    const bootstrap = await resolveBootstrapKey({ alg: "es256", pub64: key });
    expect(bootstrap.algId).toBe(ALG_ES256);
    const expected = concat([
      creation,
      encodeAbiParameters(
        [{ type: "int64" }, { type: "bytes" }],
        [ALG_ES256, key],
      ),
    ]);
    expect(buildDeploymentData(creation, bootstrap)).toBe(expected);
  });
});

describe("resolveDeployBootstrapKey", () => {
  test("generate writes the PKCS#8 PEM and the PEM round-trips to the same key", async () => {
    const dir = tmpDir();
    const pemOut = path.join(dir, "bootstrap.es256.pem");
    const generated = await resolveDeployBootstrapKey({
      generate: true,
      pemOut,
    });
    expect(generated.pemOut).toBe(pemOut);
    expect(generated.bootstrap.alg).toBe("es256");
    expect(generated.bootstrap.algId).toBe(ALG_ES256);
    // 64-byte x||y hex.
    expect(generated.bootstrap.key).toMatch(/^0x[0-9a-f]{128}$/);
    const pem = readFileSync(pemOut, "utf8");
    expect(pem).toContain("-----BEGIN PRIVATE KEY-----");
    const reloaded = await resolveDeployBootstrapKey({
      generate: false,
      pemPath: pemOut,
    });
    expect(reloaded.bootstrap.key).toBe(generated.bootstrap.key);
  });

  test("PEM write failure aborts before any key material is returned", async () => {
    await expect(
      resolveDeployBootstrapKey(
        { generate: true, pemOut: "unused" },
        async () => {
          throw new Error("disk full");
        },
      ),
    ).rejects.toThrow(/cannot write bootstrap PEM.*disk full/);
  });

  test("unreadable PEM path fails with the path in the message", async () => {
    await expect(
      resolveDeployBootstrapKey({
        generate: false,
        pemPath: "/nonexistent/bootstrap.pem",
      }),
    ).rejects.toThrow(/cannot read bootstrap PEM \/nonexistent/);
  });

  test("non-P-256 PEM content is rejected", async () => {
    const dir = tmpDir();
    const bad = path.join(dir, "bad.pem");
    writeFileSync(bad, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n");
    await expect(
      resolveDeployBootstrapKey({ generate: false, pemPath: bad }),
    ).rejects.toThrow(/not a usable ES256/);
  });
});

describe("loadImutableArtifact (local manifest)", () => {
  test("digest-valid manifest yields the creation bytecode", async () => {
    const dir = tmpDir();
    const manifestPath = path.join(dir, "deploy-manifest.json");
    writeFileSync(manifestPath, await buildManifestJson(TINY_CREATION_BYTECODE));
    const artifact = await loadImutableArtifact({
      manifestPath,
      releaseTag: "latest",
    });
    expect(artifact.creationBytecode).toBe(TINY_CREATION_BYTECODE);
    expect(artifact.releaseId).toBe("v0.0.0-test");
    expect(artifact.source).toBe("file");
  });

  test("bytecode digest mismatch is rejected", async () => {
    const dir = tmpDir();
    const manifestPath = path.join(dir, "deploy-manifest.json");
    const manifest = JSON.parse(await buildManifestJson(TINY_CREATION_BYTECODE));
    manifest.contracts.ImutableUnivocity.creationBytecode = "0x6002";
    writeFileSync(manifestPath, JSON.stringify(manifest));
    await expect(
      loadImutableArtifact({ manifestPath, releaseTag: "latest" }),
    ).rejects.toThrow(/sha256|digest/i);
  });

  test("missing manifest file fails with the path in the message", async () => {
    await expect(
      loadImutableArtifact({
        manifestPath: "/nonexistent/deploy-manifest.json",
        releaseTag: "latest",
      }),
    ).rejects.toThrow(/cannot read deploy manifest/);
  });
});

describe("runDeployFlow", () => {
  const FROM = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" as const;

  function rpcStub(overrides: Partial<DeployRpc> = {}): DeployRpc {
    return {
      from: FROM,
      getChainId: async () => 31337,
      sendDeployTransaction: async () => MOCK_TX_HASH as Hex,
      waitForReceipt: async () => ({
        status: "success",
        contractAddress: MOCK_CONTRACT_ADDRESS,
      }),
      ...overrides,
    };
  }

  async function bootstrap() {
    return resolveBootstrapKey({
      alg: "es256",
      pub64: `0x${"aa".repeat(32)}${"bb".repeat(32)}`,
    });
  }

  test("success: address, genesisLogId, chainId and txHash are reported", async () => {
    const sent: Hex[] = [];
    const rpc = rpcStub({
      sendDeployTransaction: async (data) => {
        sent.push(data);
        return MOCK_TX_HASH as Hex;
      },
    });
    const result = await runDeployFlow(rpc, {
      creationBytecode: TINY_CREATION_BYTECODE,
      bootstrap: await bootstrap(),
    });
    expect(result.chainId).toBe(31337);
    expect(result.imutableUnivocity.toLowerCase()).toBe(MOCK_CONTRACT_ADDRESS);
    expect(result.genesisLogId).toBe(MOCK_GENESIS_LOG_ID);
    expect(result.txHash).toBe(MOCK_TX_HASH as Hex);
    expect(result.from).toBe(FROM);
    expect(sent).toEqual([result.deploymentData]);
    expect(result.deploymentData.startsWith(TINY_CREATION_BYTECODE)).toBe(true);
  });

  test("unreachable RPC is a network-stage failure", async () => {
    const httpErr = Object.assign(new Error("HTTP request failed"), {
      name: "HttpRequestError",
    });
    const rpc = rpcStub({
      getChainId: async () => {
        throw httpErr;
      },
    });
    const err = await runDeployFlow(rpc, {
      creationBytecode: TINY_CREATION_BYTECODE,
      bootstrap: await bootstrap(),
    }).then(
      () => null,
      (e) => e as DeployFlowError,
    );
    expect(err).toBeInstanceOf(DeployFlowError);
    expect(err?.stage).toBe("network");
  });

  test("chain rejection at submission is a deploy-stage failure", async () => {
    const rpc = rpcStub({
      sendDeployTransaction: async () => {
        throw new Error("insufficient funds for gas * price + value");
      },
    });
    const err = await runDeployFlow(rpc, {
      creationBytecode: TINY_CREATION_BYTECODE,
      bootstrap: await bootstrap(),
    }).then(
      () => null,
      (e) => e as DeployFlowError,
    );
    expect(err?.stage).toBe("deploy");
    expect(err?.detail).toMatch(/insufficient funds/);
  });

  test("reverted receipt is a deploy-stage failure carrying the txHash", async () => {
    const rpc = rpcStub({
      waitForReceipt: async () => ({ status: "reverted", contractAddress: null }),
    });
    const err = await runDeployFlow(rpc, {
      creationBytecode: TINY_CREATION_BYTECODE,
      bootstrap: await bootstrap(),
    }).then(
      () => null,
      (e) => e as DeployFlowError,
    );
    expect(err?.stage).toBe("deploy");
    expect(err?.message).toMatch(/reverted/);
    expect(err?.txHash).toBe(MOCK_TX_HASH as Hex);
  });

  test("missing contractAddress is a deploy-stage failure", async () => {
    const rpc = rpcStub({
      waitForReceipt: async () => ({ status: "success", contractAddress: null }),
    });
    const err = await runDeployFlow(rpc, {
      creationBytecode: TINY_CREATION_BYTECODE,
      bootstrap: await bootstrap(),
    }).then(
      () => null,
      (e) => e as DeployFlowError,
    );
    expect(err?.stage).toBe("deploy");
    expect(err?.message).toMatch(/contractAddress/);
  });
});

describe("forestrie deploy (CLI, mocked RPC)", () => {
  async function writeManifest(dir: string): Promise<string> {
    const manifestPath = path.join(dir, "deploy-manifest.json");
    writeFileSync(manifestPath, await buildManifestJson(TINY_CREATION_BYTECODE));
    return manifestPath;
  }

  test("end-to-end: generates the key, sends a creation tx, writes the record", async () => {
    const server = startMockRpcServer();
    const dir = tmpDir();
    try {
      const manifestPath = await writeManifest(dir);
      const pemOut = path.join(dir, "bootstrap.es256.pem");
      const outPath = path.join(dir, "deployment.json");
      const result = await runCliAsync([
        "deploy",
        "--bootstrap-alg",
        "es256",
        "--bootstrap-es256-generate",
        "--bootstrap-es256-pem-out",
        pemOut,
        "--owner-address",
        "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "--rpc-url",
        server.url,
        "--deployer-key",
        DEPLOYER_KEY,
        "--release-manifest",
        manifestPath,
        "--out",
        outPath,
        "--json",
      ]);
      expect(result.stderr).toBe("");
      expect(result.exitCode).toBe(0);

      // Demo contract: jq -r .imutableUnivocity / .genesisLogId.
      const record = JSON.parse(readFileSync(outPath, "utf8"));
      expect(record.imutableUnivocity.toLowerCase()).toBe(
        MOCK_CONTRACT_ADDRESS,
      );
      expect(record.genesisLogId).toBe(MOCK_GENESIS_LOG_ID);
      expect(record.bootstrapAlg).toBe("es256");
      expect(record.chainId).toBe(31337);
      expect(record.txHash).toBe(MOCK_TX_HASH);
      expect(record.releaseId).toBe("v0.0.0-test");

      const report = JSON.parse(result.stdout);
      expect(report.command).toBe("deploy");
      expect(report.status).toBe("deployed");
      expect(report.out).toBe(outPath);
      expect(report.bootstrapPemOut).toBe(pemOut);

      // The generated bootstrap PEM is on disk and is a P-256 key whose
      // public point matches the constructor arg in the submitted tx.
      const pem = readFileSync(pemOut, "utf8");
      expect(pem).toContain("-----BEGIN PRIVATE KEY-----");

      // Golden tx construction: the single raw tx is a contract
      // creation (no `to`) carrying creationCode ++ abi.encode(alg, key).
      expect(server.rawTransactions).toHaveLength(1);
      const tx = parseTransaction(server.rawTransactions[0]!);
      expect(tx.to).toBeUndefined();
      expect(tx.data?.startsWith(TINY_CREATION_BYTECODE)).toBe(true);
      const bootstrap = await resolveBootstrapKey({ alg: "es256", pem });
      const expectedData = concat([
        TINY_CREATION_BYTECODE,
        encodeAbiParameters(
          [{ type: "int64" }, { type: "bytes" }],
          [ALG_ES256, bootstrap.key],
        ),
      ]);
      expect(tx.data).toBe(expectedData);
    } finally {
      server.stop();
    }
  });

  test("without --out the record itself goes to stdout (pipeable)", async () => {
    const server = startMockRpcServer();
    const dir = tmpDir();
    try {
      const manifestPath = await writeManifest(dir);
      const result = await runCliAsync([
        "deploy",
        "--bootstrap-es256-generate",
        "--bootstrap-es256-pem-out",
        path.join(dir, "bootstrap.es256.pem"),
        "--rpc-url",
        server.url,
        "--deployer-key",
        DEPLOYER_KEY,
        "--release-manifest",
        manifestPath,
      ]);
      expect(result.exitCode).toBe(0);
      const record = JSON.parse(result.stdout);
      expect(record.genesisLogId).toBe(MOCK_GENESIS_LOG_ID);
      expect(record.kind).toBe("imutable-deployment");
    } finally {
      server.stop();
    }
  });

  test("ks256 is refused: the Safe aside is pre-provisioned, not a live flow", () => {
    const result = runCli([
      "deploy",
      "--bootstrap-alg",
      "ks256",
      "--rpc-url",
      "http://127.0.0.1:1",
      "--deployer-key",
      DEPLOYER_KEY,
      "--json",
    ]);
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout);
    expect(report.error).toBe("bootstrap_alg_unsupported");
  });

  test("unreachable RPC reports network_failed", async () => {
    const dir = tmpDir();
    const manifestPath = await writeManifest(dir);
    const result = runCli([
      "deploy",
      "--bootstrap-es256-generate",
      "--bootstrap-es256-pem-out",
      path.join(dir, "bootstrap.es256.pem"),
      "--rpc-url",
      "http://127.0.0.1:9", // discard port: connection refused
      "--deployer-key",
      DEPLOYER_KEY,
      "--release-manifest",
      manifestPath,
      "--json",
    ]);
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout);
    expect(report.error).toBe("network_failed");
  });

  test("reverted deploy reports deploy_failed with the txHash", async () => {
    const server = startMockRpcServer({ receiptStatus: "0x0" });
    const dir = tmpDir();
    try {
      const manifestPath = await writeManifest(dir);
      const result = await runCliAsync([
        "deploy",
        "--bootstrap-es256-generate",
        "--bootstrap-es256-pem-out",
        path.join(dir, "bootstrap.es256.pem"),
        "--rpc-url",
        server.url,
        "--deployer-key",
        DEPLOYER_KEY,
        "--release-manifest",
        manifestPath,
        "--json",
      ]);
      expect(result.exitCode).toBe(1);
      const report = JSON.parse(result.stdout);
      expect(report.error).toBe("deploy_failed");
      expect(report.txHash).toBe(MOCK_TX_HASH);
    } finally {
      server.stop();
    }
  });

  test("owner-address / deployer-key mismatch reports owner_mismatch", async () => {
    const dir = tmpDir();
    const manifestPath = await writeManifest(dir);
    const result = runCli([
      "deploy",
      "--bootstrap-es256-generate",
      "--bootstrap-es256-pem-out",
      path.join(dir, "bootstrap.es256.pem"),
      "--owner-address",
      "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", // anvil #0, not #1
      "--rpc-url",
      "http://127.0.0.1:9",
      "--deployer-key",
      DEPLOYER_KEY,
      "--release-manifest",
      manifestPath,
      "--json",
    ]);
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout);
    expect(report.error).toBe("owner_mismatch");
  });

  test("missing local manifest reports manifest_failed", () => {
    const dir = tmpDir();
    const result = runCli([
      "deploy",
      "--bootstrap-es256-generate",
      "--bootstrap-es256-pem-out",
      path.join(dir, "bootstrap.es256.pem"),
      "--rpc-url",
      "http://127.0.0.1:9",
      "--deployer-key",
      DEPLOYER_KEY,
      "--release-manifest",
      path.join(dir, "missing.json"),
      "--json",
    ]);
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout);
    expect(report.error).toBe("manifest_failed");
  });
});
