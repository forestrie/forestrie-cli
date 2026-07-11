/**
 * Live-local `forestrie deploy` test against anvil (foundry). Skipped
 * when no anvil binary is available. Uses a digest-valid local manifest
 * with a tiny creation bytecode so the run is deterministic and does not
 * depend on a univocity GitHub release being reachable.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { genesisLogIdFromImutableAddress } from "../src/lib/deploy-genesis-log-id.js";
import {
  DEPLOYER_ADDRESS,
  DEPLOYER_KEY,
  TINY_CREATION_BYTECODE,
  buildManifestJson,
} from "./deploy-fixture.js";
import { runCli } from "./support.js";

function findAnvil(): string | null {
  const onPath = Bun.which("anvil");
  if (onPath !== null) return onPath;
  const foundry = path.join(homedir(), ".foundry", "bin", "anvil");
  return existsSync(foundry) ? foundry : null;
}

const ANVIL = findAnvil();
const PORT = 18545 + (process.pid % 1000);
const RPC_URL = `http://127.0.0.1:${PORT}`;

async function rpc(method: string, params: unknown[] = []): Promise<unknown> {
  const response = await fetch(RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = (await response.json()) as { result?: unknown };
  return body.result;
}

describe.skipIf(ANVIL === null)("forestrie deploy (live anvil)", () => {
  let anvil: ReturnType<typeof Bun.spawn> | undefined;

  beforeAll(async () => {
    anvil = Bun.spawn({
      cmd: [ANVIL!, "--port", String(PORT), "--silent"],
      stdout: "ignore",
      stderr: "ignore",
    });
    // Wait for the node to accept requests.
    for (let i = 0; i < 100; i++) {
      try {
        if ((await rpc("eth_chainId")) !== undefined) return;
      } catch {
        // not up yet
      }
      await Bun.sleep(100);
    }
    throw new Error(`anvil did not become ready on ${RPC_URL}`);
  });

  afterAll(() => {
    anvil?.kill();
  });

  test("deploys end-to-end and the record matches the chain", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "forestrie-deploy-anvil-"));
    const manifestPath = path.join(dir, "deploy-manifest.json");
    writeFileSync(manifestPath, await buildManifestJson(TINY_CREATION_BYTECODE));
    const pemOut = path.join(dir, "bootstrap.es256.pem");
    const outPath = path.join(dir, "deployment.json");

    const result = runCli(
      [
        "deploy",
        "--bootstrap-alg",
        "es256",
        "--bootstrap-es256-generate",
        "--bootstrap-es256-pem-out",
        pemOut,
        "--owner-address",
        DEPLOYER_ADDRESS,
        "--release-manifest",
        manifestPath,
        "--out",
        outPath,
        "--json",
      ],
      // Demo-style env resolution for the endpoint and gas key.
      { RPC_URL, DEPLOYER_KEY },
    );
    expect(result.exitCode).toBe(0);

    const record = JSON.parse(readFileSync(outPath, "utf8"));
    expect(record.bootstrapAlg).toBe("es256");
    expect(record.chainId).toBe(31337);
    expect(record.from).toBe(DEPLOYER_ADDRESS);
    expect(record.genesisLogId).toBe(
      genesisLogIdFromImutableAddress(record.imutableUnivocity),
    );
    expect(readFileSync(pemOut, "utf8")).toContain(
      "-----BEGIN PRIVATE KEY-----",
    );

    // The chain agrees: the tx exists, created that contract, succeeded.
    const receipt = (await rpc("eth_getTransactionReceipt", [
      record.txHash,
    ])) as {
      status: string;
      contractAddress: string;
      from: string;
      to: string | null;
    };
    expect(receipt.status).toBe("0x1");
    expect(receipt.to).toBeNull();
    expect(receipt.contractAddress.toLowerCase()).toBe(
      record.imutableUnivocity.toLowerCase(),
    );
    expect(receipt.from.toLowerCase()).toBe(DEPLOYER_ADDRESS.toLowerCase());
  }, 30_000);
});
