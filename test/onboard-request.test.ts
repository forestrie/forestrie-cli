import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCaptureOut } from "@forestrie/cli-kit/reporting";
import {
  decodeCborDeterministic,
  encodeCborDeterministic,
  encodeSigStructure,
} from "@forestrie/encoding";
import { recoverAddress, keccak256, verifyTypedData } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { runOnboardRequest } from "../src/main/onboard-request.js";
import type { OnboardRequestOptions } from "../src/options/onboard-request.js";
import {
  CLAIM_CHAIN_BINDING,
  ONBOARD_ATTESTATION_CONTENT_TYPE,
  buildOnboardAttestationKs256,
} from "../src/lib/onboard-attestation.js";
import { signX402Payment } from "../src/lib/x402-payment.js";

const CHAIN_ID = 84532;
const UNIVOCITY = "0x53f2c45bf05046beaee65d5205398c145929b479";
const ADDR_HEX = UNIVOCITY.slice(2);
const BASE = "https://api.example.dev";
const NOW = 1_753_700_000;

function writeFixtures(): { deployment: string; pem: string } {
  const dir = mkdtempSync(join(tmpdir(), "onboard-request-"));
  const deployment = join(dir, "deployment.json");
  writeFileSync(
    deployment,
    JSON.stringify({
      kind: "imutable-deployment",
      version: 1,
      imutableUnivocity: UNIVOCITY,
      genesisLogId: "53f2c45b-f050-46be-aee6-5d5205398c14",
      bootstrapAlg: "es256",
      chainId: CHAIN_ID,
      from: "0x0",
      txHash: "0x0",
      releaseId: "test",
    }),
  );
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const pem = join(dir, "bootstrap.pem");
  writeFileSync(pem, privateKey.export({ type: "pkcs8", format: "pem" }));
  return { deployment, pem };
}

function baseOptions(
  fixtures: { deployment: string; pem: string },
  overrides: Partial<OnboardRequestOptions> = {},
): OnboardRequestOptions {
  return {
    json: false,
    verbosity: 0,
    baseUrl: BASE,
    deployment: fixtures.deployment,
    bootstrapPem: fixtures.pem,
    bootstrapKeyHex: undefined,
    contactEmail: "owner@example.test",
    label: "unit-test",
    payerKey: undefined,
    out: undefined,
    ...overrides,
  };
}

type Call = { url: string; headers: Headers; body: Uint8Array };

function cbor(map: Record<string, unknown>): Response {
  const m = new Map<string, unknown>(Object.entries(map));
  const bytes = encodeCborDeterministic(m);
  return new Response(
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
    { status: 201, headers: { "Content-Type": "application/cbor" } },
  );
}

function withStatus(res: Response, status: number): Response {
  return new Response(res.body, { status, headers: res.headers });
}

function stubFlow(opts: {
  calls: Call[];
  challengeOnRedeem?: string;
}): typeof fetch {
  let redeemAttempts = 0;
  return (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = String(input);
    const call: Call = {
      url,
      headers: new Headers(init?.headers),
      body: new Uint8Array((init?.body as ArrayBuffer) ?? new ArrayBuffer(0)),
    };
    opts.calls.push(call);
    if (url.endsWith("/api/onboarding/requests")) {
      return cbor({
        requestId: "req-1",
        status: "pending",
        expiresAt: NOW + 86400,
        redeemCode: "code-1",
      });
    }
    if (url.endsWith("/redeem")) {
      redeemAttempts += 1;
      if (
        opts.challengeOnRedeem !== undefined &&
        !call.headers.has("X-PAYMENT")
      ) {
        return new Response("payment required", {
          status: 402,
          headers: { "X-PAYMENT-REQUIRED": opts.challengeOnRedeem },
        });
      }
      return withStatus(
        cbor({ token: `token-${redeemAttempts}`, ref: "ref-1" }),
        200,
      );
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
}

function stdout(out: ReturnType<typeof createCaptureOut>): string {
  return out.lines
    .filter((l) => l.stream === "stdout")
    .map((l) => l.text)
    .join("\n");
}

function challengeB64(): string {
  return Buffer.from(
    JSON.stringify({
      x402Version: 2,
      accepts: [
        {
          scheme: "exact",
          network: `eip155:${CHAIN_ID}`,
          amount: "10000",
          asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
          payTo: "0x75be7950F26fe7F15336a10b33A8D8134faDb787",
          maxTimeoutSeconds: 300,
          extra: { name: "USDC", version: "2" },
        },
      ],
    }),
  ).toString("base64");
}

describe("onboard-request", () => {
  test("creates an attested request and redeems it (approved path)", async () => {
    const fixtures = writeFixtures();
    const calls: Call[] = [];
    const out = createCaptureOut();
    process.exitCode = 0;
    await runOnboardRequest(out, baseOptions(fixtures), {
      fetchImpl: stubFlow({ calls }),
      nowSec: () => NOW,
    });
    expect(process.exitCode).toBe(0);
    expect(calls).toHaveLength(2);
    expect(stdout(out)).toBe("token-1");

    // The create body carries the chain binding and the attestation (key 7).
    const created = decodeCborDeterministic(calls[0]!.body) as Map<
      number,
      unknown
    >;
    expect(created.get(2)).toBe(String(CHAIN_ID));
    expect(created.get(3)).toBe(ADDR_HEX);
    const attestation = created.get(7);
    expect(attestation).toBeInstanceOf(Uint8Array);

    // Attestation envelope discipline mirrors the canopy verifier: protected
    // {1: -7, 3: content type}, CWT claims payload with the binding claim.
    const [prot, , payload] = decodeCborDeterministic(
      attestation as Uint8Array,
    ) as [Uint8Array, unknown, Uint8Array, Uint8Array];
    const header = decodeCborDeterministic(prot) as Map<number, unknown>;
    expect(header.get(1)).toBe(-7);
    expect(header.get(3)).toBe(ONBOARD_ATTESTATION_CONTENT_TYPE);
    const claims = decodeCborDeterministic(payload) as Map<number, unknown>;
    expect(claims.get(1)).toBe(`eip155:${CHAIN_ID}:0x${ADDR_HEX}`);
    expect(claims.get(3)).toBe(BASE);
    expect(claims.get(6)).toBe(NOW);
    const binding = claims.get(CLAIM_CHAIN_BINDING) as Map<number, unknown>;
    expect(binding.get(1)).toBe(String(CHAIN_ID));
    expect(binding.get(2)).toBe(ADDR_HEX);
  });

  test("pays the redeem 402 challenge with the payer key", async () => {
    const fixtures = writeFixtures();
    const payer = `0x${"11".repeat(32)}`;
    const calls: Call[] = [];
    const out = createCaptureOut();
    process.exitCode = 0;
    await runOnboardRequest(
      out,
      baseOptions(fixtures, { payerKey: payer }),
      {
        fetchImpl: stubFlow({ calls, challengeOnRedeem: challengeB64() }),
        nowSec: () => NOW,
      },
    );
    expect(process.exitCode).toBe(0);
    // create, unpaid redeem (402), paid redeem.
    expect(calls).toHaveLength(3);
    const paid = calls[2]!;
    const xPayment = paid.headers.get("X-PAYMENT");
    expect(xPayment).toBeTruthy();

    // The signed payment verifies against the payer's address (EIP-712).
    const decoded = JSON.parse(
      Buffer.from(xPayment!, "base64").toString("utf8"),
    ) as {
      payload: {
        signature: `0x${string}`;
        authorization: {
          from: `0x${string}`;
          to: `0x${string}`;
          value: string;
          validAfter: string;
          validBefore: string;
          nonce: `0x${string}`;
        };
      };
    };
    const account = privateKeyToAccount(payer as `0x${string}`);
    expect(decoded.payload.authorization.from.toLowerCase()).toBe(
      account.address.toLowerCase(),
    );
    const okSig = await verifyTypedData({
      address: account.address,
      domain: {
        name: "USDC",
        version: "2",
        chainId: CHAIN_ID,
        verifyingContract: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      },
      types: {
        TransferWithAuthorization: [
          { name: "from", type: "address" },
          { name: "to", type: "address" },
          { name: "value", type: "uint256" },
          { name: "validAfter", type: "uint256" },
          { name: "validBefore", type: "uint256" },
          { name: "nonce", type: "bytes32" },
        ],
      },
      primaryType: "TransferWithAuthorization",
      message: {
        from: decoded.payload.authorization.from,
        to: decoded.payload.authorization.to,
        value: BigInt(decoded.payload.authorization.value),
        validAfter: BigInt(decoded.payload.authorization.validAfter),
        validBefore: BigInt(decoded.payload.authorization.validBefore),
        nonce: decoded.payload.authorization.nonce,
      },
      signature: decoded.payload.signature,
    });
    expect(okSig).toBe(true);
    expect(stdout(out)).toBe("token-2");
  });

  test("402 without a payer key fails with payment_failed", async () => {
    const fixtures = writeFixtures();
    const calls: Call[] = [];
    const out = createCaptureOut();
    process.exitCode = 0;
    await runOnboardRequest(out, baseOptions(fixtures), {
      fetchImpl: stubFlow({ calls, challengeOnRedeem: challengeB64() }),
      nowSec: () => NOW,
    });
    expect(process.exitCode).toBe(1);
    expect(stdout(out)).toBe("");
  });

  test("missing attestation key is input_failed before any network call", async () => {
    const fixtures = writeFixtures();
    const calls: Call[] = [];
    const out = createCaptureOut();
    process.exitCode = 0;
    await runOnboardRequest(
      out,
      baseOptions(fixtures, { bootstrapPem: undefined }),
      { fetchImpl: stubFlow({ calls }), nowSec: () => NOW },
    );
    expect(process.exitCode).toBe(1);
    expect(calls).toHaveLength(0);
  });

  test("KS256 attestation signs with the delegation-cose profile", async () => {
    const priv = `0x${"22".repeat(32)}`;
    const account = privateKeyToAccount(priv as `0x${string}`);
    const attestation = await buildOnboardAttestationKs256(priv, {
      chainId: String(CHAIN_ID),
      univocityAddr: ADDR_HEX,
      aud: BASE,
      nowSec: NOW,
    });
    const [prot, , payload, sig] = decodeCborDeterministic(attestation) as [
      Uint8Array,
      unknown,
      Uint8Array,
      Uint8Array,
    ];
    const header = decodeCborDeterministic(prot) as Map<number, unknown>;
    expect(header.get(1)).toBe(-65799);
    expect(sig).toHaveLength(65);
    // keccak256(Sig_structure) recovery lands on the signer's address.
    const digest = keccak256(encodeSigStructure(prot, new Uint8Array(0), payload));
    const sigHex = `0x${Buffer.from(sig).toString("hex")}` as `0x${string}`;
    const recovered = await recoverAddress({ hash: digest, signature: sigHex });
    expect(recovered.toLowerCase()).toBe(account.address.toLowerCase());
  });
});

describe("signX402Payment", () => {
  test("rejects a challenge without an exact option", async () => {
    const bad = Buffer.from(
      JSON.stringify({ x402Version: 2, accepts: [] }),
    ).toString("base64");
    await expect(
      signX402Payment(bad, `0x${"11".repeat(32)}`, NOW),
    ).rejects.toThrow(/exact/);
  });
});
