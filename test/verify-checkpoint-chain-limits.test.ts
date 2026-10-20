import { beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { keccak256, hexToBytes } from "viem";
import { createCaptureOut } from "@forestrie/cli-kit/reporting";
import {
  encodeKs256Attestation,
  ERC1271_MAGIC_VALUE,
} from "@forestrie/receipt-verify";
import { runVerifyGrant } from "../src/main/verify.js";
import { parseVerifyGrantOptions } from "../src/options/verify.js";
import type { VerifyReport } from "../src/lib/verify-report.js";
import { runCli } from "./support.js";
import {
  buildCheckpoint,
  buildDelegationCert,
  buildKs256ChainFixture,
  buildVerifyFixture,
  generateP256KeyPair,
  leafTimeFromIdtimestamp,
  type VerifyFixture,
} from "./verify-fixture.js";

/**
 * Checkpoint-chain anchor via receipt-verify's shared verifier (owner ruling
 * D8): per-link delegation limits, expiry on the covering links, KS256 roots
 * and several ERC-1271 attestations. Run-time fixtures; fully offline.
 */

type LooseArgs = Parameters<typeof parseVerifyGrantOptions>[0];
type Ks = Awaited<ReturnType<typeof buildKs256ChainFixture>>;

let dir: string;
const file = (name: string) => path.join(dir, name);
const forbiddenFetch = (() => {
  throw new Error("network forbidden");
}) as unknown as typeof fetch;

async function run(args: Record<string, unknown>) {
  const out = createCaptureOut(0);
  const options = parseVerifyGrantOptions(args as LooseArgs);
  const realFetch = globalThis.fetch;
  const saved = process.exitCode;
  process.exitCode = 0;
  globalThis.fetch = forbiddenFetch;
  try {
    await runVerifyGrant(out, options);
  } finally {
    globalThis.fetch = realFetch;
  }
  const exitCode = Number(process.exitCode ?? 0);
  process.exitCode = saved;
  const text = (s: "stdout" | "stderr") =>
    out.lines.filter((l) => l.stream === s).map((l) => l.text).join("\n");
  return { exitCode, stdout: text("stdout"), stderr: text("stderr") };
}
const rep = (stdout: string) => JSON.parse(stdout) as VerifyReport;

// ---------------------------------------------------------------------------
// ES256 chain with delegation limits
// ---------------------------------------------------------------------------

describe("--checkpoint-chain enforces delegation limits (ES256)", () => {
  let fx: VerifyFixture;
  let leafTime: number;

  beforeAll(async () => {
    dir = mkdtempSync(path.join(tmpdir(), "forestrie-chain-limits-"));
    fx = await buildVerifyFixture();
    leafTime = leafTimeFromIdtimestamp(fx.idtimestampBe8);
    writeFileSync(file("genesis.cbor"), fx.genesisCbor);
    writeFileSync(file("receipt.cbor"), fx.receiptCbor);
  });

  /** sth(0->3), sth(3->7), each sealed by a delegate the root vouches for. */
  async function chainDir(
    name: string,
    constraints?: {
      mmrStart: number;
      mmrEnd: number;
      issuedAt: number;
      expiresAt: number;
    },
  ): Promise<string> {
    const d = path.join(dir, name);
    mkdirSync(d, { recursive: true });
    const sealer = await generateP256KeyPair();
    const cert = await buildDelegationCert(
      fx.rootKeyPair,
      sealer.publicKey,
      constraints,
    );
    writeFileSync(
      path.join(d, "0000000000000000.sth"),
      await buildCheckpoint({
        signer: sealer,
        treeSize1: 0n,
        treeSize2: 3n,
        paths: [],
        rightPeaks: [fx.peak],
        accumulator: [fx.peak],
        delegationCert: cert,
      }),
    );
    writeFileSync(
      path.join(d, "0000000000000001.sth"),
      await buildCheckpoint({
        signer: sealer,
        treeSize1: 3n,
        treeSize2: 7n,
        paths: [[fx.node5]],
        rightPeaks: [],
        accumulator: [fx.peak7],
        delegationCert: cert,
      }),
    );
    return d;
  }

  const verifyChain = (d: string) =>
    run({
      genesis: file("genesis.cbor"),
      receipt: file("receipt.cbor"),
      "committed-grant": fx.grantCoseB64,
      "checkpoint-chain": d,
      json: true,
    });

  const window = (over: Partial<{ mmrStart: number; mmrEnd: number; expiresAt: number }> = {}) => ({
    mmrStart: 0,
    mmrEnd: 100,
    issuedAt: leafTime - 3600,
    expiresAt: leafTime + 3600,
    ...over,
  });

  test("a delegate within its window anchors the buried receipt", async () => {
    const r = await verifyChain(await chainDir("ok", window()));
    expect(r.exitCode).toBe(0);
    expect(rep(r.stdout).anchor).toMatchObject({
      anchored: true,
      linkCount: 2,
      matchedLinkSize: "3",
    });
  });

  test("a seal past the certificate's mmrEnd is delegation_out_of_range", async () => {
    const r = await verifyChain(await chainDir("end", window({ mmrEnd: 1 })));
    expect(r.exitCode).toBe(1);
    const report = rep(r.stdout);
    expect(report.anchor?.anchored).toBe(false);
    expect(report.anchor?.reason).toBe("delegation_out_of_range");
    expect(report.anchor?.detail).toContain("0000000000000000.sth");
  });

  test("a seal before the certificate's mmrStart is delegation_out_of_range", async () => {
    const r = await verifyChain(await chainDir("start", window({ mmrStart: 3 })));
    expect(r.exitCode).toBe(1);
    expect(rep(r.stdout).anchor?.reason).toBe("delegation_out_of_range");
  });

  test("a certificate expired at the leaf time is delegation_expired after the match", async () => {
    const r = await verifyChain(
      await chainDir("expired", window({ expiresAt: leafTime - 60 })),
    );
    expect(r.exitCode).toBe(1);
    const report = rep(r.stdout);
    expect(report.anchor?.reason).toBe("delegation_expired");
    expect(report.anchor?.anchored).toBe(false);
  });

  test("human output carries the typed reason", async () => {
    const d = await chainDir("end-human", window({ mmrEnd: 1 }));
    const r = await run({
      genesis: file("genesis.cbor"),
      receipt: file("receipt.cbor"),
      "committed-grant": fx.grantCoseB64,
      "checkpoint-chain": d,
    });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain("delegation_out_of_range");
    expect(r.stdout).toContain("FAIL: stage=anchor reason=delegation_out_of_range");
  });
});

// ---------------------------------------------------------------------------
// KS256 chains
// ---------------------------------------------------------------------------

function attestationFile(
  name: string,
  fx: Ks,
  cert: { digest: Uint8Array; signature: Uint8Array },
  over: { digest?: Uint8Array; address?: Uint8Array } = {},
): string {
  writeFileSync(
    file(name),
    encodeKs256Attestation({
      version: 1,
      chainId: 84532n,
      address: over.address ?? fx.rootAddress,
      digest: over.digest ?? cert.digest,
      signatureHash: hexToBytes(keccak256(cert.signature)),
      blockNumber: 123n,
      blockHash: new Uint8Array(32).fill(0xbb),
      magic: ERC1271_MAGIC_VALUE,
    }),
  );
  return file(name);
}

function writeChain(prefix: string, fx: Ks): string {
  const d = path.join(dir, `${prefix}-sths`);
  mkdirSync(d, { recursive: true });
  fx.checkpoints.forEach((cp, i) =>
    writeFileSync(path.join(d, `000000000000000${i}.sth`), cp),
  );
  writeFileSync(file(`${prefix}-genesis.cbor`), fx.genesisCbor);
  writeFileSync(file(`${prefix}-receipt.cbor`), fx.receiptCbor);
  return d;
}

const chainRun = (prefix: string, fx: Ks, extra: Record<string, unknown> = {}) =>
  run({
    genesis: file(`${prefix}-genesis.cbor`),
    receipt: file(`${prefix}-receipt.cbor`),
    "committed-grant": fx.grantCoseB64,
    "checkpoint-chain": path.join(dir, `${prefix}-sths`),
    json: true,
    ...extra,
  });

describe("--checkpoint-chain with KS256 roots", () => {
  let eoa: Ks;
  let safe: Ks;
  let rotated: Ks;

  beforeAll(async () => {
    eoa = await buildKs256ChainFixture();
    safe = await buildKs256ChainFixture({ contractRoot: true });
    rotated = await buildKs256ChainFixture({ contractRoot: true, rotate: true });
    writeChain("eoa", eoa);
    writeChain("safe", safe);
    writeChain("rot", rotated);
  });

  test("an EOA genesis root vouches for the chain by ecrecover", async () => {
    const r = await chainRun("eoa", eoa);
    expect(r.exitCode).toBe(0);
    const report = rep(r.stdout);
    expect(report.mode).toBe("checkpoint-chain-anchored");
    expect(report.anchor).toMatchObject({ anchored: true, matchedLinkSize: "3" });
    expect(report.ks256?.root).toBe(true);
  });

  test("a KS256 --known-log-key roots the chain too", async () => {
    const r = await run({
      "known-log-key": "0x" + Buffer.from(eoa.rootAddress).toString("hex"),
      receipt: file("eoa-receipt.cbor"),
      "committed-grant": eoa.grantCoseB64,
      "checkpoint-chain": path.join(dir, "eoa-sths"),
      json: true,
    });
    expect(r.exitCode).toBe(0);
    expect(rep(r.stdout).anchor?.anchored).toBe(true);
  });

  test("a Safe root with one certificate and its attestation passes; an extra attestation is reported unused", async () => {
    const a = attestationFile("safe-a.att", safe, safe.certs[0]!);
    const stray = attestationFile("safe-stray.att", safe, safe.certs[0]!, {
      digest: new Uint8Array(32).fill(0x11),
    });
    const r = await chainRun("safe", safe, { "ks256-attestation": [a, stray] });
    expect(r.exitCode).toBe(0);
    const att = rep(r.stdout).ks256?.attestations;
    expect(att?.used.map((u) => u.index)).toEqual([0]);
    expect(att?.unused).toMatchObject([
      { index: 1, reason: "no_matching_certificate" },
    ]);
  });

  test("[bad, good] repeated attestations: the good one wins, the bad one is rejected (offline and chain)", async () => {
    const bad = attestationFile("safe-bad.att", safe, safe.certs[0]!, {
      address: new Uint8Array(20).fill(0x99),
    });
    const good = attestationFile("safe-good.att", safe, safe.certs[0]!);
    for (const extra of [{}, { "checkpoint-chain": path.join(dir, "safe-sths") }]) {
      const r = runCli([
        "verify-grant",
        "--json",
        "--genesis",
        file("safe-genesis.cbor"),
        "--receipt",
        file("safe-receipt.cbor"),
        "--committed-grant",
        safe.grantCoseB64,
        ...Object.entries(extra).flatMap(([k, v]) => [`--${k}`, v]),
        "--ks256-attestation",
        bad,
        "--ks256-attestation",
        good,
      ]);
      expect(r.exitCode).toBe(0);
      const att = (JSON.parse(r.stdout) as VerifyReport).ks256?.attestations;
      expect(att?.used.map((u) => u.index)).toEqual([1]);
      expect(att?.rejected.map((u) => u.index)).toEqual([0]);
      expect(att?.unused).toEqual([]);
    }
  });

  test("a rotated Safe passes with BOTH attestations, repeated on the command line", async () => {
    const a = attestationFile("rot-a.att", rotated, rotated.certs[0]!);
    const b = attestationFile("rot-b.att", rotated, rotated.certs[1]!);
    const r = runCli([
      "verify-grant",
      "--json",
      "--genesis",
      file("rot-genesis.cbor"),
      "--receipt",
      file("rot-receipt.cbor"),
      "--committed-grant",
      rotated.grantCoseB64,
      "--checkpoint-chain",
      path.join(dir, "rot-sths"),
      "--ks256-attestation",
      a,
      "--ks256-attestation",
      b,
    ]);
    expect(r.exitCode).toBe(0);
    const report = JSON.parse(r.stdout) as VerifyReport;
    expect(report.ok).toBe(true);
    expect(report.ks256?.attestations?.used.map((u) => u.index)).toEqual([0, 1]);
    expect(report.ks256?.attestations?.used[1]?.links).toEqual([1]);
    expect(report.ks256?.attestations?.unused).toEqual([]);
  });

  test("comma-separated attestations are accepted too", async () => {
    const a = attestationFile("rot-a.att", rotated, rotated.certs[0]!);
    const b = attestationFile("rot-b.att", rotated, rotated.certs[1]!);
    const r = await chainRun("rot", rotated, { "ks256-attestation": `${a},${b}` });
    expect(r.exitCode).toBe(0);
  });

  test("a rotated Safe missing the second attestation fails with a typed KS256 reason", async () => {
    const a = attestationFile("rot-a.att", rotated, rotated.certs[0]!);
    const r = await chainRun("rot", rotated, { "ks256-attestation": a });
    expect(r.exitCode).toBe(1);
    const report = rep(r.stdout);
    expect(report.ok).toBe(false);
    expect(report.anchor?.anchored).toBe(false);
    expect(report.anchor?.reason).toBe("ks256_attestation_digest_mismatch");
    expect(report.anchor?.detail).toContain("0000000000000001.sth");
    // The first attestation did carry its link before the refusal.
    expect(report.ks256?.attestations?.used.map((u) => u.index)).toEqual([0]);
  });

  test("a Safe root with no attestation fails offline (the receipt's own certificate)", async () => {
    const r = await chainRun("safe", safe);
    expect(r.exitCode).toBe(1);
    expect(rep(r.stdout).reason).toBe("ks256_root_not_recovered");
  });

  test("attestations with --checkpoint-chain need --genesis for the chain id", () => {
    const a = attestationFile("safe-a.att", safe, safe.certs[0]!);
    expect(() =>
      parseVerifyGrantOptions({
        "known-log-key": "0x" + Buffer.from(safe.rootAddress).toString("hex"),
        receipt: file("safe-receipt.cbor"),
        "committed-grant": safe.grantCoseB64,
        "checkpoint-chain": path.join(dir, "safe-sths"),
        "ks256-attestation": a,
      } as LooseArgs),
    ).toThrow(/needs --genesis/);
  });
});
