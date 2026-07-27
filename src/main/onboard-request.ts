import type { Out } from "@forestrie/cli-kit/reporting";
import {
  decodeCborDeterministic,
  encodeCborDeterministic,
} from "@forestrie/encoding";
import {
  readDeploymentRecord,
  univocityAddrHex,
} from "../lib/deployment-record.js";
import {
  buildOnboardAttestationEs256,
  buildOnboardAttestationKs256,
} from "../lib/onboard-attestation.js";
import { loadEs256SigningKey } from "../lib/sign-statement-key.js";
import { signX402Payment } from "../lib/x402-payment.js";
import type { OnboardRequestOptions } from "../options/onboard-request.js";

/**
 * Self-service onboarding (plan-2607-43 slice 06): create → (pay) → redeem.
 *
 * 1. `POST /api/onboarding/requests` with the chain binding from the deploy
 *    artifact and a bootstrap-key attestation (ADR-0059 D8) — the proof that
 *    the requester is the deployed contract's legitimate registrant.
 * 2. `POST /api/onboarding/requests/{id}/redeem` with the one-time redeem
 *    code. An auto/ops-approved request redeems directly; a pending one
 *    answers 402 with an x402 challenge, which `--payer-key` signs
 *    (EIP-3009; REAL funds move when the payment settles) and the redeem is
 *    retried with `X-PAYMENT`.
 *
 * The redeemed onboard token is the ONLY product on stdout (or `--out`) so
 * the command composes: `ONBOARD_TOKEN=$(forestrie onboard-request …)`.
 * Private keys are never logged or echoed, including in errors.
 */

const CREATE_LABEL_KEY = 1;
const CREATE_CHAIN_ID_KEY = 2;
const CREATE_UNIVOCITY_ADDR_KEY = 3;
const CREATE_CONTACT_EMAIL_KEY = 4;
const CREATE_ATTESTATION_KEY = 7;
const REDEEM_CODE_KEY = 1;

const X_PAYMENT_REQUIRED = "X-PAYMENT-REQUIRED";
const X_PAYMENT = "X-PAYMENT";

export type OnboardRequestReport = {
  command: "onboard-request";
  status: "redeemed";
  requestId: string;
  label: string;
  admitted: "approved" | "paid";
  token: string;
  ref?: string;
  out?: string;
};

export type OnboardRequestErrorReport = {
  error:
    | "input_failed"
    | "create_failed"
    | "redeem_failed"
    | "payment_failed"
    | "network_failed"
    | "response_malformed";
  command: "onboard-request";
  message: string;
  httpStatus?: number;
};

/** Test seam. */
export type OnboardRequestDeps = {
  fetchImpl?: typeof fetch;
  nowSec?: () => number;
};

function requestsUrl(baseUrl: string): string {
  return `${baseUrl.replace(/\/$/, "")}/api/onboarding/requests`;
}

function mapField(decoded: unknown, field: string): unknown {
  if (decoded instanceof Map) return decoded.get(field);
  if (decoded && typeof decoded === "object") {
    return (decoded as Record<string, unknown>)[field];
  }
  return undefined;
}

function textField(decoded: unknown, field: string): string | undefined {
  const v = mapField(decoded, field);
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

function reportError(
  out: Out,
  options: OnboardRequestOptions,
  report: OnboardRequestErrorReport,
): void {
  if (options.json) {
    out.out(JSON.stringify(report, null, 2));
  } else {
    out.warn("forestrie onboard-request: %s", report.message);
    if (report.httpStatus !== undefined) {
      out.warn("  httpStatus: %d", report.httpStatus);
    }
  }
  process.exitCode = 1;
}

function cborBody(map: Map<number, unknown>): ArrayBuffer {
  const bytes = encodeCborDeterministic(map);
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}

export async function runOnboardRequest(
  out: Out,
  options: OnboardRequestOptions,
  deps: OnboardRequestDeps = {},
): Promise<void> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const nowSec = deps.nowSec ?? (() => Math.floor(Date.now() / 1000));

  // --- Resolve binding + build the attestation ---
  let chainId: string;
  let univocityAddr: string;
  let attestation: Uint8Array;
  try {
    const record = readDeploymentRecord(options.deployment);
    chainId = record.chainId;
    univocityAddr = univocityAddrHex(record);
    const aud = new URL(options.baseUrl).origin;
    const input = { chainId, univocityAddr, aud, nowSec: nowSec() };
    if (options.bootstrapPem !== undefined) {
      const key = await loadEs256SigningKey(options.bootstrapPem);
      attestation = await buildOnboardAttestationEs256(key, input);
    } else if (options.bootstrapKeyHex !== undefined) {
      attestation = await buildOnboardAttestationKs256(
        options.bootstrapKeyHex,
        input,
      );
    } else {
      throw new Error(
        "attestation key required: pass --bootstrap-pem (ES256) or --bootstrap-key-hex (KS256)",
      );
    }
  } catch (err) {
    reportError(out, options, {
      error: "input_failed",
      command: "onboard-request",
      message: err instanceof Error ? err.message : String(err),
    });
    return;
  }

  // --- Create the attested request ---
  let requestId: string;
  let redeemCode: string;
  try {
    const res = await fetchImpl(requestsUrl(options.baseUrl), {
      method: "POST",
      headers: {
        "Content-Type": "application/cbor",
        Accept: "application/cbor",
      },
      body: cborBody(
        new Map<number, unknown>([
          [CREATE_LABEL_KEY, options.label],
          [CREATE_CHAIN_ID_KEY, chainId],
          [CREATE_UNIVOCITY_ADDR_KEY, univocityAddr],
          [CREATE_CONTACT_EMAIL_KEY, options.contactEmail],
          [CREATE_ATTESTATION_KEY, attestation],
        ]),
      ),
    });
    if (res.status !== 201) {
      reportError(out, options, {
        error: "create_failed",
        command: "onboard-request",
        message: `request rejected: HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`,
        httpStatus: res.status,
      });
      return;
    }
    const decoded = decodeCborDeterministic(
      new Uint8Array(await res.arrayBuffer()),
    );
    const id = textField(decoded, "requestId");
    const code = textField(decoded, "redeemCode");
    if (!id || !code) {
      reportError(out, options, {
        error: "response_malformed",
        command: "onboard-request",
        message: "create response missing requestId/redeemCode",
      });
      return;
    }
    requestId = id;
    redeemCode = code;
  } catch (err) {
    reportError(out, options, {
      error: "network_failed",
      command: "onboard-request",
      message: err instanceof Error ? err.message : String(err),
    });
    return;
  }

  // --- Redeem (pay the 402 when challenged) ---
  const redeemUrl = `${requestsUrl(options.baseUrl)}/${encodeURIComponent(requestId)}/redeem`;
  const redeem = (extraHeaders: Record<string, string>) =>
    fetchImpl(redeemUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/cbor",
        Accept: "application/cbor",
        ...extraHeaders,
      },
      body: cborBody(new Map<number, unknown>([[REDEEM_CODE_KEY, redeemCode]])),
    });

  let admitted: "approved" | "paid" = "approved";
  let res: Response;
  try {
    res = await redeem({});
    if (res.status === 402) {
      const challenge = res.headers.get(X_PAYMENT_REQUIRED);
      if (!challenge) {
        reportError(out, options, {
          error: "payment_failed",
          command: "onboard-request",
          message: "402 without an X-PAYMENT-REQUIRED challenge header",
          httpStatus: 402,
        });
        return;
      }
      if (options.payerKey === undefined) {
        reportError(out, options, {
          error: "payment_failed",
          command: "onboard-request",
          message:
            "deployment requires payment to redeem; pass --payer-key (env X402_PAYER_KEY)",
          httpStatus: 402,
        });
        return;
      }
      const xPayment = await signX402Payment(
        challenge,
        options.payerKey,
        nowSec(),
      );
      admitted = "paid";
      res = await redeem({ [X_PAYMENT]: xPayment });
    }
  } catch (err) {
    reportError(out, options, {
      error: "network_failed",
      command: "onboard-request",
      message: err instanceof Error ? err.message : String(err),
    });
    return;
  }

  if (res.status !== 200) {
    reportError(out, options, {
      error: "redeem_failed",
      command: "onboard-request",
      message: `redeem rejected: HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`,
      httpStatus: res.status,
    });
    return;
  }

  let token: string | undefined;
  let ref: string | undefined;
  try {
    const decoded = decodeCborDeterministic(
      new Uint8Array(await res.arrayBuffer()),
    );
    token = textField(decoded, "token");
    ref = textField(decoded, "ref");
  } catch (err) {
    reportError(out, options, {
      error: "response_malformed",
      command: "onboard-request",
      message: `redeem response is not valid CBOR: ${err instanceof Error ? err.message : String(err)}`,
    });
    return;
  }
  if (token === undefined) {
    reportError(out, options, {
      error: "response_malformed",
      command: "onboard-request",
      message: "redeem response carried no token field",
    });
    return;
  }

  if (options.out !== undefined) {
    await Bun.write(options.out, token);
  }
  if (options.json) {
    const report: OnboardRequestReport = {
      command: "onboard-request",
      status: "redeemed",
      requestId,
      label: options.label,
      admitted,
      token,
    };
    if (ref !== undefined) report.ref = ref;
    if (options.out !== undefined) report.out = options.out;
    out.out(JSON.stringify(report, null, 2));
    return;
  }
  if (options.out !== undefined) {
    out.print(
      "wrote onboard token (request %s, %s) to %s",
      requestId,
      admitted,
      options.out,
    );
    return;
  }
  // The token is the pipeable product: nothing else on stdout.
  out.out("%s", token);
}
