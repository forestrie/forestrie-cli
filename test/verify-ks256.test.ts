import { beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { keccak256 } from "viem";
import { createCaptureOut } from "@forestrie/cli-kit/reporting";
import {
  decodeKs256Attestation,
  encodeKs256Attestation,
  ERC1271_MAGIC_VALUE,
} from "@forestrie/receipt-verify";
import { runFetchKs256Attestation } from "../src/main/fetch-ks256-attestation.js";
import { runVerify, runVerifyGrant } from "../src/main/verify.js";
import { parseFetchKs256AttestationOptions } from "../src/options/fetch-ks256-attestation.js";
import { parseVerifyGrantOptions, parseVerifyOptions } from "../src/options/verify.js";
import type { VerifyReport } from "../src/lib/verify-report.js";
import { runCli } from "./support.js";
import { buildKs256Fixture, bytesToHex, encodeLogStateResult, FIXTURE_LOG_ID } from "./verify-fixture.js";

type LooseArgs = Parameters<typeof parseVerifyGrantOptions>[0];
type Fx = Awaited<ReturnType<typeof buildKs256Fixture>>;

let dir: string;
const file = (name: string) => path.join(dir, name);

let eoa: Fx;
let wrongSigner: Fx;
let safe: Fx;

const forbiddenFetch = (() => {
  throw new Error("network forbidden during offline verify");
}) as unknown as typeof fetch;

const MAGIC_WORD = "0x1626ba7e" + "00".repeat(28);

beforeAll(async () => {
  delete process.env["GRANT_B64"];
  delete process.env["RPC_URL"];
  delete process.env["KNOWN_LOG_KEY"];
  dir = mkdtempSync(path.join(tmpdir(), "forestrie-ks256-"));
  eoa = await buildKs256Fixture();
  wrongSigner = await buildKs256Fixture({ wrongSigner: true });
  safe = await buildKs256Fixture({ contractRoot: true });
  for (const [name, fx] of [
    ["eoa", eoa],
    ["wrong", wrongSigner],
    ["safe", safe],
  ] as const) {
    writeFileSync(file(`${name}-genesis.cbor`), fx.genesisCbor);
    writeFileSync(file(`${name}-receipt.cbor`), fx.receiptCbor);
  }
});

async function capture(
  fn: (out: ReturnType<typeof createCaptureOut>) => Promise<void>,
  fetchImpl: typeof fetch,
) {
  const out = createCaptureOut(0);
  const realFetch = globalThis.fetch;
  const savedExitCode = process.exitCode;
  process.exitCode = 0;
  globalThis.fetch = fetchImpl;
  try {
    await fn(out);
  } finally {
    globalThis.fetch = realFetch;
  }
  const exitCode = Number(process.exitCode ?? 0);
  process.exitCode = savedExitCode;
  const text = (stream: "stdout" | "stderr") =>
    out.lines
      .filter((l) => l.stream === stream)
      .map((l) => l.text)
      .join("\n");
  return { exitCode, stdout: text("stdout"), stderr: text("stderr") };
}

function verify(
  fx: Fx,
  name: string,
  args: Record<string, unknown>,
  fetchImpl: typeof fetch = forbiddenFetch,
) {
  return capture(
    (out) =>
      runVerifyGrant(
        out,
        parseVerifyGrantOptions({
          receipt: file(`${name}-receipt.cbor`),
          "committed-grant": fx.grantCoseB64,
          json: true,
          ...args,
        } as LooseArgs),
      ),
    fetchImpl,
  );
}

type RpcCall = { method: string; params: unknown[] };

function rpc(
  overrides: Record<string, unknown> = {},
  calls: RpcCall[] = [],
): typeof fetch {
  return (async (_url: unknown, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as RpcCall;
    calls.push({ method: body.method, params: body.params });
    if (body.method === "eth_getCode" || body.method === "eth_call") {
      // EIP-1898: state reads are pinned by the recorded block hash.
      expect(body.params[1]).toEqual({
        blockHash: "0x" + "bb".repeat(32),
        requireCanonical: true,
      });
    }
    const results: Record<string, unknown> = {
      eth_chainId: "0x14a34", // 84532
      eth_getBlockByNumber: { number: "0x7b", hash: "0x" + "bb".repeat(32) },
      eth_getCode: "0x6080",
      eth_call: MAGIC_WORD,
      ...overrides,
    };
    if (!(body.method in results)) {
      throw new Error(`unexpected RPC method ${body.method}`);
    }
    const value = results[body.method];
    const result = typeof value === "function" ? (value as (p: unknown[]) => unknown)(body.params) : value;
    if (result instanceof Error) {
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          error: { code: 3, message: result.message },
        }),
        { headers: { "Content-Type": "application/json" } },
      );
    }
    return new Response(
      JSON.stringify({ jsonrpc: "2.0", id: 1, result }),
      { headers: { "Content-Type": "application/json" } },
    );
  }) as unknown as typeof fetch;
}

function fetchAttestation(
  args: Record<string, unknown>,
  fetchImpl: typeof fetch,
) {
  return capture(
    (out) =>
      runFetchKs256Attestation(
        out,
        parseFetchKs256AttestationOptions({
          "rpc-url": "http://rpc.mock",
          json: true,
          ...args,
        } as LooseArgs),
      ),
    fetchImpl,
  );
}

const hex0x = (b: Uint8Array) => `0x${bytesToHex(b)}`;
const report = (stdout: string) => JSON.parse(stdout) as VerifyReport;

describe("KS256 genesis root", () => {
  test("EOA root verifies by ecrecover with no chain call", async () => {
    const r = await verify(eoa, "eoa", { genesis: file("eoa-genesis.cbor") });
    expect(r.exitCode).toBe(0);
    expect(report(r.stdout).ok).toBe(true);
    const sig = report(r.stdout).stages.find((s) => s.stage === "signature");
    expect(sig?.reason).toContain("ecrecover");
  });

  test("a certificate signed by another key fails ks256_root_not_recovered", async () => {
    const r = await verify(wrongSigner, "wrong", {
      genesis: file("wrong-genesis.cbor"),
    });
    expect(r.exitCode).toBe(1);
    expect(report(r.stdout).reason).toBe("ks256_root_not_recovered");
  });

  test("a tampered certificate does not verify", async () => {
    const tampered = new Uint8Array(eoa.receiptCbor);
    // Flip a byte inside the certificate signature (the cert is embedded in
    // the receipt; its signature is the 65 bytes found verbatim).
    const sig = eoa.certSignature;
    let at = -1;
    outer: for (let i = 0; i + sig.length <= tampered.length; i++) {
      for (let j = 0; j < sig.length; j++) {
        if (tampered[i + j] !== sig[j]) continue outer;
      }
      at = i;
      break;
    }
    expect(at).toBeGreaterThan(0);
    tampered[at + 5]! ^= 0xff;
    writeFileSync(file("eoa-tampered.cbor"), tampered);
    const r = await verify(eoa, "eoa", {
      genesis: file("eoa-genesis.cbor"),
      receipt: file("eoa-tampered.cbor"),
    });
    expect(r.exitCode).toBe(1);
    expect(report(r.stdout).ok).toBe(false);
    expect(report(r.stdout).reason).toMatch(/ks256_root_not_recovered|delegation/);
  });
});

describe("--known-log-key with a 20-byte KS256 address", () => {
  test("0x hex form verifies", async () => {
    const r = await verify(eoa, "eoa", {
      "known-log-key": hex0x(eoa.rootAddress),
    });
    expect(r.exitCode).toBe(0);
    expect(report(r.stdout).ok).toBe(true);
  });

  test("base64 form verifies", async () => {
    const r = await verify(eoa, "eoa", {
      "known-log-key": Buffer.from(eoa.rootAddress).toString("base64"),
    });
    expect(r.exitCode).toBe(0);
  });

  test("a wrong address fails with a ks256 reason, not known_key_mismatch", async () => {
    const r = await verify(eoa, "eoa", {
      "known-log-key": hex0x(new Uint8Array(20).fill(0x11)),
    });
    expect(r.exitCode).toBe(1);
    expect(report(r.stdout).reason).toBe("ks256_root_not_recovered");
  });

  test("a key of any other length is an input error naming both forms", async () => {
    const r = await verify(eoa, "eoa", {
      "known-log-key": Buffer.alloc(32, 1).toString("base64"),
    });
    expect(r.exitCode).toBe(1);
    const e = JSON.parse(r.stdout) as { stage: string; message: string };
    expect(e.stage).toBe("input");
    expect(e.message).toContain("64-byte ES256");
    expect(e.message).toContain("20-byte KS256");
  });

  test("a KS256 key is refused for --checkpoint-chain as an input error", async () => {
    const r = await verify(eoa, "eoa", {
      "known-log-key": hex0x(eoa.rootAddress),
      "checkpoint-chain": dir,
    });
    expect(r.exitCode).toBe(1);
    const e = JSON.parse(r.stdout) as { stage: string; message: string };
    expect(e.stage).toBe("input");
    expect(e.message).toContain("ES256");
  });
});

describe("KS256 contract root and fetch-ks256-attestation", () => {
  test("without an attestation the contract root is not recovered", async () => {
    const r = await verify(safe, "safe", { genesis: file("safe-genesis.cbor") });
    expect(r.exitCode).toBe(1);
    expect(report(r.stdout).reason).toBe("ks256_root_not_recovered");
  });

  test("an attestation fetched from a mocked RPC makes it verify; verify never fetches", async () => {
    const calls: RpcCall[] = [];
    const outPath = file("safe-att.cbor");
    const f = await fetchAttestation(
      {
        receipt: file("safe-receipt.cbor"),
        genesis: file("safe-genesis.cbor"),
        out: outPath,
      },
      rpc({}, calls),
    );
    expect(f.exitCode).toBe(0);
    expect(calls.map((c) => c.method)).toEqual([
      "eth_chainId",
      "eth_getBlockByNumber",
      "eth_getCode",
      "eth_call",
    ]);
    const att = decodeKs256Attestation(new Uint8Array(readFileSync(outPath)));
    expect(att.chainId).toBe(84532n);
    expect(bytesToHex(att.address)).toBe(bytesToHex(safe.rootAddress));
    expect(bytesToHex(att.digest)).toBe(bytesToHex(safe.certDigest));
    expect(hex0x(att.signatureHash)).toBe(keccak256(safe.certSignature));
    expect(att.blockNumber).toBe(123n);
    expect(bytesToHex(att.blockHash)).toBe("bb".repeat(32));
    expect(bytesToHex(att.magic)).toBe(bytesToHex(ERC1271_MAGIC_VALUE));

    // Zero fetch calls: forbiddenFetch throws if verify touches the network.
    const r = await verify(safe, "safe", {
      genesis: file("safe-genesis.cbor"),
      "ks256-attestation": outPath,
    });
    expect(r.exitCode).toBe(0);
    const rep = report(r.stdout);
    expect(rep.ok).toBe(true);
    expect(rep.ks256?.attestation?.used).toBe(true);
    expect(rep.ks256?.attestation?.blockNumber).toBe("123");
    const sig = rep.stages.find((s) => s.stage === "signature");
    expect(sig?.reason).toContain("signers at block 123");

    const human = await verify(safe, "safe", {
      genesis: file("safe-genesis.cbor"),
      "ks256-attestation": outPath,
      json: false,
    });
    expect(human.exitCode).toBe(0);
    expect(human.stderr).toContain("block 123");
  });

  test("known-key path: --genesis supplies the chain; without it the attestation is unbound", async () => {
    const outPath = file("safe-att.cbor");
    const key = hex0x(safe.rootAddress);
    const bound = await verify(safe, "safe", {
      "known-log-key": key,
      genesis: file("safe-genesis.cbor"),
      "ks256-attestation": outPath,
    });
    expect(bound.exitCode).toBe(0);
    const unbound = await verify(safe, "safe", {
      "known-log-key": key,
      "ks256-attestation": outPath,
    });
    expect(unbound.exitCode).toBe(1);
    expect(report(unbound.stdout).reason).toBe(
      "ks256_attestation_chain_unbound",
    );
  });

  test("an attestation for another chain is ks256_attestation_chain_mismatch", async () => {
    const outPath = file("safe-att-chain1.cbor");
    const f = await fetchAttestation(
      {
        receipt: file("safe-receipt.cbor"),
        root: hex0x(safe.rootAddress), // no genesis: no chain check on fetch
        out: outPath,
      },
      rpc({ eth_chainId: "0x1" }),
    );
    expect(f.exitCode).toBe(0);
    const r = await verify(safe, "safe", {
      genesis: file("safe-genesis.cbor"),
      "ks256-attestation": outPath,
    });
    expect(r.exitCode).toBe(1);
    expect(report(r.stdout).reason).toBe("ks256_attestation_chain_mismatch");
  });

  test("an undecodable attestation file is an input error", async () => {
    writeFileSync(file("junk-att.cbor"), new Uint8Array([1, 2, 3]));
    const r = await verify(safe, "safe", {
      genesis: file("safe-genesis.cbor"),
      "ks256-attestation": file("junk-att.cbor"),
    });
    expect(r.exitCode).toBe(1);
    expect((JSON.parse(r.stdout) as { stage: string }).stage).toBe("input");
  });

  test("an attestation for an EOA root is reported as not needed", async () => {
    const outPath = file("eoa-att.cbor");
    writeFileSync(
      outPath,
      encodeKs256Attestation({
        version: 1,
        chainId: 84532n,
        address: eoa.rootAddress,
        digest: eoa.certDigest,
        signatureHash: new Uint8Array(32),
        blockNumber: 1n,
        blockHash: new Uint8Array(32),
        magic: ERC1271_MAGIC_VALUE,
      }),
    );
    const r = await verify(eoa, "eoa", {
      genesis: file("eoa-genesis.cbor"),
      "ks256-attestation": outPath,
    });
    expect(r.exitCode).toBe(0);
    // An unused attestation's fields were never checked: not echoed.
    expect(report(r.stdout).ks256?.attestation).toEqual({ used: false });
  });
});

describe("fetch-ks256-attestation refusals and pinning", () => {
  const base = () => ({
    receipt: file("safe-receipt.cbor"),
    genesis: file("safe-genesis.cbor"),
  });

  async function refused(
    name: string,
    overrides: Record<string, unknown>,
    args: Record<string, unknown> = {},
  ) {
    const outPath = file(`never-${name}.cbor`);
    const f = await fetchAttestation(
      { ...base(), out: outPath, ...args },
      rpc(overrides),
    );
    expect(f.exitCode).toBe(1);
    expect(existsSync(outPath)).toBe(false);
    return (JSON.parse(f.stdout) as { message: string }).message;
  }

  test("chain id differing from the genesis", async () => {
    expect(await refused("chain", { eth_chainId: "0x1" })).toContain(
      "differs from the genesis chain id",
    );
  });

  test("no contract code at the root", async () => {
    expect(await refused("nocode", { eth_getCode: "0x" })).toContain(
      "needs no attestation",
    );
  });

  test("a non-magic isValidSignature result", async () => {
    expect(
      await refused("badmagic", { eth_call: "0xffffffff" + "00".repeat(28) }),
    ).toContain("did not validate");
  });

  test("a short isValidSignature result", async () => {
    expect(await refused("short", { eth_call: "0x1626ba7e" })).toContain(
      "exactly one 32-byte word",
    );
  });

  test("a receipt without a delegation certificate", async () => {
    // A bare checkpoint-style receipt: reuse the EOA receipt with the
    // label-1000 cert stripped by decoding and re-encoding.
    const { decodeCborDeterministic, encodeCborDeterministic } = await import(
      "@forestrie/encoding"
    );
    const [p, u, payload, sig] = decodeCborDeterministic(
      safe.receiptCbor,
    ) as unknown[];
    (u as Map<number, unknown>).delete(1000);
    writeFileSync(
      file("nocert-receipt.cbor"),
      encodeCborDeterministic([p, u, payload, sig]),
    );
    expect(
      await refused("nocert", {}, { receipt: file("nocert-receipt.cbor") }),
    ).toContain("receipt carries no delegation certificate");
  });

  test("a non-KS256 genesis root", async () => {
    const { buildVerifyFixture } = await import("./verify-fixture.js");
    const es = await buildVerifyFixture();
    writeFileSync(file("es-genesis.cbor"), es.genesisCbor);
    expect(
      await refused("es", {}, { genesis: file("es-genesis.cbor") }),
    ).toContain("not a KS256 address");
  });

  test("dirty padding after the magic is refused", async () => {
    expect(
      await refused("dirty", { eth_call: "0x1626ba7e" + "00".repeat(27) + "01" }),
    ).toContain("did not validate");
  });

  test("magic plus an extra word is refused", async () => {
    expect(
      await refused("extra", { eth_call: MAGIC_WORD + "00".repeat(32) }),
    ).toContain("exactly one 32-byte word");
  });

  test("a calldata echo (the selector is the magic) is refused", async () => {
    const echo = (params: unknown[]) =>
      (params[0] as { data: string }).data;
    expect(await refused("echo", { eth_call: echo })).toContain(
      "exactly one 32-byte word",
    );
  });

  test("a revert is reported as not validated", async () => {
    expect(
      await refused("revert", { eth_call: new Error("execution reverted") }),
    ).toContain("reverted");
  });

  test("other RPC errors do not blame the contract", async () => {
    const m = await refused("hdr", { eth_call: new Error("header not found") });
    expect(m).toContain("RPC error");
    expect(m).not.toContain("did not validate");
  });

  test("a block other than the requested --block is refused", async () => {
    expect(
      await refused("blk", {}, { block: "124" }),
    ).toContain("returned block 123 for --block 124");
  });

  test("--block pins every call to that block", async () => {
    const calls: RpcCall[] = [];
    const outPath = file("pinned.cbor");
    const f = await fetchAttestation(
      { ...base(), out: outPath, block: "123" },
      rpc({}, calls),
    );
    expect(f.exitCode).toBe(0);
    const byMethod = Object.fromEntries(calls.map((c) => [c.method, c.params]));
    expect(byMethod["eth_getBlockByNumber"]).toEqual(["0x7b", false]);
    // State reads pin by the block hash the RPC returned for block 123
    // (asserted in the router), not by number.
    expect(byMethod["eth_getCode"]).toBeDefined();
    expect(byMethod["eth_call"]).toBeDefined();
  });

  test("requires --root or --genesis", () => {
    expect(() =>
      parseFetchKs256AttestationOptions({
        receipt: "r",
        "rpc-url": "http://x",
        out: "o",
      } as LooseArgs),
    ).toThrow(/--root/);
  });
});

describe("CLI surface", () => {
  test("fetch-ks256-attestation is listed in help", () => {
    const r = runCli(["--help"]);
    expect(r.stdout + r.stderr).toContain("fetch-ks256-attestation");
  });
});

describe("verify (statement path) with --ks256-attestation", () => {
  const payload = new TextEncoder().encode("signed statement bytes");
  let st: Fx;
  let attPath: string;

  beforeAll(async () => {
    st = await buildKs256Fixture({
      contractRoot: true,
      statementPayload: payload,
    });
    writeFileSync(file("st-genesis.cbor"), st.genesisCbor);
    writeFileSync(file("st-receipt.cbor"), st.receiptCbor);
    writeFileSync(file("st-payload.bin"), payload);
    attPath = file("st-att.cbor");
    const f = await fetchAttestation(
      {
        receipt: file("st-receipt.cbor"),
        genesis: file("st-genesis.cbor"),
        out: attPath,
      },
      rpc(),
    );
    expect(f.exitCode).toBe(0);
  });

  const verifyStatement = (args: Record<string, unknown>) =>
    capture(
      (out) =>
        runVerify(
          out,
          parseVerifyOptions({
            receipt: file("st-receipt.cbor"),
            payload: file("st-payload.bin"),
            "entry-id": st.entryIdHex,
            json: true,
            ...args,
          } as LooseArgs),
        ),
      forbiddenFetch, // any fetch call throws: zero network
    );

  test("known key + --genesis + attestation passes with no fetch", async () => {
    const r = await verifyStatement({
      "known-log-key": hex0x(st.rootAddress),
      genesis: file("st-genesis.cbor"),
      "ks256-attestation": attPath,
    });
    expect(r.exitCode).toBe(0);
    const rep = report(r.stdout);
    expect(rep.ok).toBe(true);
    expect(rep.ks256?.attestation?.used).toBe(true);
  });

  test("known key without --genesis is ks256_attestation_chain_unbound", async () => {
    const r = await verifyStatement({
      "known-log-key": hex0x(st.rootAddress),
      "ks256-attestation": attPath,
    });
    expect(r.exitCode).toBe(1);
    expect(report(r.stdout).reason).toBe("ks256_attestation_chain_unbound");
  });

  test("an attestation for an EOA root is reported used:false (statement path)", async () => {
    const eoaSt = await buildKs256Fixture({ statementPayload: payload });
    writeFileSync(file("st-eoa-genesis.cbor"), eoaSt.genesisCbor);
    writeFileSync(file("st-eoa-receipt.cbor"), eoaSt.receiptCbor);
    const r = await verifyStatement({
      receipt: file("st-eoa-receipt.cbor"),
      "entry-id": eoaSt.entryIdHex,
      genesis: file("st-eoa-genesis.cbor"),
      "ks256-attestation": attPath,
    });
    expect(r.exitCode).toBe(0);
    expect(report(r.stdout).ks256?.attestation).toEqual({ used: false });
  });

  test("without an attestation the contract root is not recovered", async () => {
    const r = await verifyStatement({ genesis: file("st-genesis.cbor") });
    expect(r.exitCode).toBe(1);
    expect(report(r.stdout).reason).toBe("ks256_root_not_recovered");
  });
});

describe("KS256 genesis with a live chain anchor", () => {
  test("a detached receipt under an EOA root anchors via the recomputed peak", async () => {
    const liveFetch = (async (_u: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { method: string };
      expect(body.method).toBe("eth_call");
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: encodeLogStateResult([eoa.peak], 3n),
        }),
        { headers: { "Content-Type": "application/json" } },
      );
    }) as unknown as typeof fetch;
    const r = await verify(
      eoa,
      "eoa",
      {
        genesis: file("eoa-genesis.cbor"),
        univocity: "0x" + "ab".repeat(20),
        "log-id": FIXTURE_LOG_ID,
        "rpc-url": "http://rpc.mock",
      },
      liveFetch,
    );
    expect(r.exitCode).toBe(0);
    const rep = report(r.stdout);
    expect(rep.mode).toBe("chain-anchored");
    expect(rep.anchor?.anchored).toBe(true);
  });
});

describe("fetch-ks256-attestation --block syntax", () => {
  test.each(["0x7b", " 123", "123 ", "-1", "0b11", "0o7", "1e3"])(
    "rejects %p",
    (block) => {
      expect(() =>
        parseFetchKs256AttestationOptions({
          receipt: "r",
          root: "0x" + "11".repeat(20),
          "rpc-url": "http://x",
          out: "o",
          block,
        } as LooseArgs),
      ).toThrow(/--block|--root/);
    },
  );
});
