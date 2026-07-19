import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCaptureOut } from "@forestrie/cli-kit/reporting";
import {
  buildEs256GenesisBody,
  es256PublicKeyXy,
} from "../src/lib/onboard-genesis-body.js";
import { runOnboardGenesis } from "../src/main/onboard-genesis.js";
import type { OnboardGenesisOptions } from "../src/options/onboard-genesis.js";
import { runCli } from "./support.js";

const ADDRESS = "0x" + "ab".repeat(20);
const LOG_ID = "0a1b2c3d-0000-4000-8000-000000000001";
const GENESIS_BYTES = new Uint8Array([0xa1, 0x01, 0x02]);

const work = mkdtempSync(join(tmpdir(), "onboard-genesis-"));
const pemPath = join(work, "bootstrap.pem");
const pem = generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  .privateKey.export({ type: "pkcs8", format: "pem" }) as string;
writeFileSync(pemPath, pem, "utf8");
const deploymentPath = join(work, "deployment.json");
writeFileSync(
  deploymentPath,
  JSON.stringify({ imutableUnivocity: ADDRESS, genesisLogId: LOG_ID }),
  "utf8",
);

const baseOptions: OnboardGenesisOptions = {
  json: false,
  verbosity: 0,
  baseUrl: "https://api.example.dev",
  deployment: deploymentPath,
  univocity: undefined,
  logId: undefined,
  bootstrapPem: pemPath,
  chainId: "84532",
  coordinatorUrl: "https://coordinator.example.dev",
  webhookUrl: undefined,
  onboardToken: "minted-token",
  out: undefined,
};

type Seen = { url: string; method: string; auth: string | null; body?: Uint8Array };

function fakeFetch(seen: Seen[]): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const headers = new Headers(init?.headers);
    const record: Seen = { url, method, auth: headers.get("Authorization") };
    if (init?.body) record.body = new Uint8Array(init.body as ArrayBuffer);
    seen.push(record);
    if (method === "POST") return new Response(null, { status: 201 });
    return new Response(GENESIS_BYTES, { status: 200 });
  }) as typeof fetch;
}

function stdout(out: ReturnType<typeof createCaptureOut>): string {
  return out.lines
    .filter((l) => l.stream === "stdout")
    .map((l) => l.text)
    .join("\n");
}

/** RFC 8949 §4.2 deterministic encoding of a negative-int map key. */
function negKey(label: number): Buffer {
  const buf = Buffer.alloc(5);
  buf[0] = 0x3a;
  buf.writeUInt32BE(-1 - label, 1);
  return buf;
}

describe("onboard-genesis body (exact deterministic bytes)", () => {
  test("emits the five direct-sign labels in encoded-key order", () => {
    const xy = es256PublicKeyXy(pem);
    const body = buildEs256GenesisBody({
      chainId: "84532",
      univocityAddress: ADDRESS,
      bootstrapKeyXy: xy,
    });
    const expected = Buffer.concat([
      Buffer.from([0xa5]), // map(5)
      negKey(-68009),
      Buffer.from([0x02]), // GENESIS_VERSION = 2
      negKey(-68011),
      Buffer.from([0x54]), // bstr(20)
      Buffer.from("ab".repeat(20), "hex"), // UNIVOCITY_ADDR
      negKey(-68013),
      Buffer.from([0x65]), // text(5)
      Buffer.from("84532", "utf8"), // CHAIN_ID
      negKey(-68014),
      Buffer.from([0x26]), // GENESIS_ALG = -7 (ES256)
      negKey(-68015),
      Buffer.from([0x58, 0x40]), // bstr(64)
      Buffer.from(xy), // BOOTSTRAP_KEY x||y
    ]);
    expect(Buffer.from(body)).toEqual(expected);
  });

  test("rejects a non-P-256 bootstrap key", () => {
    const ed = generateKeyPairSync("ed25519").privateKey.export({
      type: "pkcs8",
      format: "pem",
    }) as string;
    expect(() => es256PublicKeyXy(ed)).toThrow(/P-256/);
  });

  test("rejects a malformed contract address", () => {
    expect(() =>
      buildEs256GenesisBody({
        chainId: "84532",
        univocityAddress: "0x1234",
        bootstrapKeyXy: new Uint8Array(64),
      }),
    ).toThrow(/20-byte hex contract address/);
  });
});

describe("onboard-genesis", () => {
  test("POSTs under the pre-minted token with the derived signing-route webhook", async () => {
    const out = createCaptureOut();
    const seen: Seen[] = [];
    process.exitCode = 0;
    await runOnboardGenesis(out, baseOptions, { fetchImpl: fakeFetch(seen) });
    expect(process.exitCode).toBe(0);
    expect(seen).toHaveLength(1);
    const expectedWebhook = `https://coordinator.example.dev/api/logs/${LOG_ID}/signing-route`;
    expect(seen[0]!.url).toBe(
      `https://api.example.dev/api/forest/${LOG_ID}/genesis?webhookUrl=${encodeURIComponent(expectedWebhook)}`,
    );
    expect(seen[0]!.auth).toBe("Bearer minted-token");
    expect(Buffer.from(seen[0]!.body!)).toEqual(
      Buffer.from(
        buildEs256GenesisBody({
          chainId: "84532",
          univocityAddress: ADDRESS,
          bootstrapKeyXy: es256PublicKeyXy(pem),
        }),
      ),
    );
    expect(stdout(out)).toContain(`onboarded forest ${LOG_ID}`);
  });

  test("--out fetches the public genesis back after onboarding", async () => {
    const out = createCaptureOut();
    const seen: Seen[] = [];
    const genesisOut = join(work, "genesis.cbor");
    process.exitCode = 0;
    await runOnboardGenesis(
      out,
      { ...baseOptions, json: true, out: genesisOut },
      { fetchImpl: fakeFetch(seen) },
    );
    expect(process.exitCode).toBe(0);
    expect(seen).toHaveLength(2);
    expect(seen[1]!.method).toBe("GET");
    expect(seen[1]!.url).toBe(
      `https://api.example.dev/api/forest/${LOG_ID}/genesis`,
    );
    const report = JSON.parse(stdout(out)) as Record<string, unknown>;
    expect(report["status"]).toBe("onboarded");
    expect(report["genesisBytes"]).toBe(GENESIS_BYTES.length);
    expect(
      new Uint8Array(await Bun.file(genesisOut).arrayBuffer()),
    ).toEqual(GENESIS_BYTES);
  });

  test("a rejected POST surfaces the server verdict (status + body)", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    await runOnboardGenesis(
      out,
      { ...baseOptions, json: true },
      {
        fetchImpl: (async () =>
          new Response("genesis exists", { status: 409 })) as unknown as typeof fetch,
      },
    );
    expect(process.exitCode).toBe(1);
    const report = JSON.parse(stdout(out)) as Record<string, unknown>;
    expect(report["error"]).toBe("post_failed");
    expect(report["httpStatus"]).toBe(409);
    expect(report["detail"]).toBe("genesis exists");
  });

  test("a deployment file without the deploy fields is an input error", async () => {
    const badPath = join(work, "bad-deployment.json");
    writeFileSync(badPath, JSON.stringify({ nope: true }), "utf8");
    const out = createCaptureOut();
    process.exitCode = 0;
    await runOnboardGenesis(
      out,
      { ...baseOptions, json: true, deployment: badPath },
      { fetchImpl: fakeFetch([]) },
    );
    expect(process.exitCode).toBe(1);
    const report = JSON.parse(stdout(out)) as Record<string, unknown>;
    expect(report["error"]).toBe("input_failed");
  });

  test("cli: missing token and missing target are usage errors", () => {
    const noToken = runCli([
      "onboard-genesis",
      "--base-url",
      "https://api.example.dev",
      "--deployment",
      deploymentPath,
      "--bootstrap-pem",
      pemPath,
      "--coordinator-url",
      "https://coordinator.example.dev",
    ]);
    expect(noToken.exitCode).not.toBe(0);
    expect(noToken.stderr).toContain("onboard-token");

    const noTarget = runCli([
      "onboard-genesis",
      "--base-url",
      "https://api.example.dev",
      "--bootstrap-pem",
      pemPath,
      "--coordinator-url",
      "https://coordinator.example.dev",
      "--onboard-token",
      "tok",
    ]);
    expect(noTarget.exitCode).not.toBe(0);
    expect(noTarget.stderr).toContain("--deployment");
  });
});
