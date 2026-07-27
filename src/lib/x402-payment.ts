/**
 * x402 `exact` payer: sign an EIP-3009 `transferWithAuthorization` against a
 * decoded `X-PAYMENT-REQUIRED` challenge (base64 header value in, base64
 * `X-PAYMENT` header value out). Matches the payload shape canopy's
 * `parsePaymentHeader` expects and the facilitator settles.
 *
 * REAL money moves when a signed payment settles (testnet USDC on dev). The
 * payer key never leaves this process and is never logged.
 */

import { privateKeyToAccount } from "viem/accounts";

interface X402Option {
  scheme: string;
  network: string;
  payTo: string;
  asset: string;
  amount: string;
  maxTimeoutSeconds?: number;
  extra?: { name?: string; version?: string };
}

function b64ToUtf8(b64: string): string {
  return Buffer.from(b64, "base64").toString("utf8");
}

function randomNonceHex(): `0x${string}` {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}` as `0x${string}`;
}

export async function signX402Payment(
  paymentRequiredB64: string,
  payerKeyHex: string,
  nowSec = Math.floor(Date.now() / 1000),
): Promise<string> {
  const decoded = JSON.parse(b64ToUtf8(paymentRequiredB64)) as {
    accepts?: X402Option[];
  };
  const chosen = (decoded.accepts ?? []).find((o) => o.scheme === "exact");
  if (!chosen) {
    throw new Error("X-PAYMENT-REQUIRED has no 'exact' scheme option");
  }
  if (!chosen.extra?.name || !chosen.extra?.version) {
    throw new Error("challenge lacks EIP-712 domain name/version in extra");
  }

  const key = payerKeyHex.startsWith("0x")
    ? (payerKeyHex as `0x${string}`)
    : (`0x${payerKeyHex}` as `0x${string}`);
  const account = privateKeyToAccount(key);
  const nonce = randomNonceHex();
  const validAfter = BigInt(nowSec - 600);
  const validBefore = BigInt(nowSec + (chosen.maxTimeoutSeconds ?? 300));

  const signature = await account.signTypedData({
    domain: {
      name: chosen.extra.name,
      version: chosen.extra.version,
      chainId: Number(chosen.network.split(":")[1]),
      verifyingContract: chosen.asset as `0x${string}`,
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
      from: account.address,
      to: chosen.payTo as `0x${string}`,
      value: BigInt(chosen.amount),
      validAfter,
      validBefore,
      nonce,
    },
  });

  const payload = {
    x402Version: 2,
    payload: {
      authorization: {
        from: account.address,
        to: chosen.payTo,
        value: chosen.amount,
        validAfter: validAfter.toString(),
        validBefore: validBefore.toString(),
        nonce,
      },
      signature,
    },
    resource: {
      url: "",
      description: "forestrie onboard request",
      mimeType: "application/cbor",
    },
    accepted: {
      scheme: "exact",
      network: chosen.network,
      asset: chosen.asset,
      amount: chosen.amount,
      payTo: chosen.payTo,
      maxTimeoutSeconds: chosen.maxTimeoutSeconds ?? 300,
      extra: chosen.extra,
    },
  };
  return Buffer.from(JSON.stringify(payload)).toString("base64");
}
