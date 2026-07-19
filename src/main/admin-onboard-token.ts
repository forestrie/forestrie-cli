import type { Out } from "@forestrie/cli-kit/reporting";
import {
  decodeCborDeterministic,
  encodeCborDeterministic,
} from "@forestrie/encoding";
import type { AdminOnboardTokenOptions } from "../options/admin-onboard-token.js";

/**
 * FOR-406 (plan-2607-27 W1): mint a forest onboard token from
 * `POST /api/payments/onboard-tokens` under the operator credential.
 *
 * The minted token is the ONLY product on stdout (or `--out`) so the
 * command composes: `ONBOARD_TOKEN=$(forestrie admin onboard-token …)`.
 * The operator credential is never logged or echoed, including in errors.
 * Public onboarding is x402 (ARC-0015) — a future sibling token source
 * feeding the same `onboard-genesis --onboard-token` input.
 */

/** Mint request body label key (canopy payments onboard-tokens contract). */
const MINT_LABEL_KEY = 1;

/** `--json` success shape (the token itself; cref for operator records). */
export type AdminOnboardTokenReport = {
  command: "admin onboard-token";
  status: "minted";
  label: string;
  token: string;
  cref?: string;
  /** Present when `--out` was given (token then omitted from stdout). */
  out?: string;
};

export type AdminOnboardTokenErrorReport = {
  error: "mint_failed" | "network_failed" | "response_malformed";
  command: "admin onboard-token";
  message: string;
  httpStatus?: number;
};

/** Test seam. */
export type AdminOnboardTokenDeps = {
  fetchImpl?: typeof fetch;
};

function mintUrl(baseUrl: string): string {
  return `${baseUrl.replace(/\/$/, "")}/api/payments/onboard-tokens`;
}

/** Extract a required text field from the decoded CBOR response. */
function responseText(
  decoded: unknown,
  field: string,
): string | undefined {
  const value =
    decoded instanceof Map
      ? decoded.get(field)
      : decoded && typeof decoded === "object"
        ? (decoded as Record<string, unknown>)[field]
        : undefined;
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function reportError(
  out: Out,
  options: AdminOnboardTokenOptions,
  report: AdminOnboardTokenErrorReport,
): void {
  if (options.json) {
    out.out(JSON.stringify(report, null, 2));
  } else {
    out.warn("forestrie admin onboard-token: %s", report.message);
    if (report.httpStatus !== undefined) {
      out.warn("  httpStatus: %d", report.httpStatus);
    }
  }
  process.exitCode = 1;
}

export async function runAdminOnboardToken(
  out: Out,
  options: AdminOnboardTokenOptions,
  deps: AdminOnboardTokenDeps = {},
): Promise<void> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const body = encodeCborDeterministic(
    new Map<number, string>([[MINT_LABEL_KEY, options.label]]),
  );

  let res: Response;
  try {
    res = await fetchImpl(mintUrl(options.baseUrl), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${options.opsToken}`,
        "Content-Type": "application/cbor",
        Accept: "application/cbor",
      },
      body: body.buffer.slice(
        body.byteOffset,
        body.byteOffset + body.byteLength,
      ) as ArrayBuffer,
    });
  } catch (err) {
    reportError(out, options, {
      error: "network_failed",
      command: "admin onboard-token",
      // The ops token never appears in fetch errors; message is URL-level.
      message: err instanceof Error ? err.message : String(err),
    });
    return;
  }

  if (!res.ok) {
    reportError(out, options, {
      error: "mint_failed",
      command: "admin onboard-token",
      message: `mint rejected: HTTP ${res.status}`,
      httpStatus: res.status,
    });
    return;
  }

  let token: string | undefined;
  let cref: string | undefined;
  try {
    const decoded = decodeCborDeterministic(
      new Uint8Array(await res.arrayBuffer()),
    );
    token = responseText(decoded, "token");
    cref = responseText(decoded, "cref");
  } catch (err) {
    reportError(out, options, {
      error: "response_malformed",
      command: "admin onboard-token",
      message: `mint response is not valid CBOR: ${
        err instanceof Error ? err.message : String(err)
      }`,
    });
    return;
  }
  if (token === undefined) {
    reportError(out, options, {
      error: "response_malformed",
      command: "admin onboard-token",
      message: "mint response carried no token field",
    });
    return;
  }

  if (options.out !== undefined) {
    await Bun.write(options.out, token);
  }
  if (options.json) {
    const report: AdminOnboardTokenReport = {
      command: "admin onboard-token",
      status: "minted",
      label: options.label,
      token,
    };
    if (cref !== undefined) report.cref = cref;
    if (options.out !== undefined) report.out = options.out;
    out.out(JSON.stringify(report, null, 2));
    return;
  }
  if (options.out !== undefined) {
    out.print("wrote onboard token (label %s) to %s", options.label, options.out);
    return;
  }
  // The token is the pipeable product: nothing else on stdout.
  out.out("%s", token);
}
