/**
 * FOR-343 grant registration flow: POST the signed grant statement to
 * `POST /register/{bootstrapLogId}/grants` (`@forestrie/scrapi-client`
 * `registerGrant` — the parent grant evidence travels in the CBOR body as
 * `{ parentGrant: <bytes> }`, grants.md §11), then drive the same SCRAPI
 * 303 receipt-redirect contract as `register-flow.ts` to completion.
 *
 * The pacing/timeout/error taxonomy deliberately MIRRORS
 * `register-flow.ts` (F4, plan-2607-14 W1.4): scrapi-client ships
 * poll-once primitives with NO sleep loops, this module owns the pacing,
 * every request is bounded by an AbortSignal tied to the remaining
 * `--timeout` budget, and fetch-level failures map into the shared
 * {@link RegisterFlowError} stages instead of escaping as bare TypeErrors.
 * `boundedFetch` is not exported from register-flow, so it is mirrored
 * here (kept private there by design).
 */
import {
  ScrapiRegistrationError,
  queryRegistrationOnce,
  registerGrant,
  resolveReceiptOnce,
  toAbsoluteScrapiUrl,
} from "@forestrie/scrapi-client";
import { RegisterFlowError } from "./register-flow.js";

export { RegisterFlowError };

/** Progress callbacks so the CLI can narrate long polls on stderr. */
export type RegisterGrantProgress =
  | { phase: "registered"; statusUrl: string }
  | { phase: "status-pending"; statusUrl: string; attempt: number }
  | { phase: "receipt-located"; receiptUrl: string; entryIdHex: string }
  | { phase: "receipt-pending"; receiptUrl: string; attempt: number };

/** Injectable effects — production defaults are real fetch/sleep/clock. */
export type RegisterGrantFlowDeps = {
  fetchImpl?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  onProgress?: (progress: RegisterGrantProgress) => void;
};

export type RegisterGrantFlowParams = {
  /** SCRAPI origin, no trailing slash. */
  baseUrl: string;
  /** Forest bootstrap/root log id — first `/register/` path segment. */
  bootstrapLogId: string;
  /** Signed grant transparent statement, Forestrie-Grant header base64. */
  grantBase64: string;
  /**
   * Completed parent grant (base64) authorizing this registration; sent
   * in the CBOR request body (grants.md §11). Absent for the
   * self-referential bootstrap leaf.
   */
  parentGrantBase64?: string | undefined;
  /** Overall budget covering both poll phases. */
  timeoutMs: number;
  /** Pacing between polls; a longer `Retry-After` wins. */
  pollIntervalMs: number;
};

export type RegisterGrantFlowResult = {
  /** Final query-registration-status URL (from the register 303). */
  statusUrl: string;
  /** Permanent resolve-receipt URL. */
  receiptUrl: string;
  /** Permanent entry id (32 hex chars) from the receipt Location. */
  entryIdHex: string;
  /** Receipt wire bytes (CBOR). */
  receipt: Uint8Array;
  contentType: string | undefined;
};

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/** One line for a transport failure: `code: message (cause)` where known. */
function describeFetchError(err: unknown): string {
  if (!(err instanceof Error)) return String(err);
  const code = (err as { code?: unknown }).code;
  const cause =
    err.cause instanceof Error && err.cause.message !== err.message
      ? ` (${err.cause.message})`
      : "";
  return typeof code === "string" && code !== "" && !err.message.includes(code)
    ? `${code}: ${err.message}${cause}`
    : `${err.message}${cause}`;
}

function requestUrl(input: Parameters<typeof fetch>[0]): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

/**
 * Mirror of register-flow's F4 bounded fetch: every request carries an
 * AbortSignal tied to the remaining `--timeout` budget, and fetch-level
 * failures (ECONNREFUSED, DNS, resets) map into the RegisterFlowError
 * taxonomy. Real wall-clock timer; `remaining` from the injectable `now`.
 */
function boundedFetch(
  baseFetch: typeof fetch,
  now: () => number,
  deadline: number,
  timeoutMs: number,
): typeof fetch {
  return (async (
    input: Parameters<typeof fetch>[0],
    init?: RequestInit,
  ): Promise<Response> => {
    const remaining = deadline - now();
    if (remaining <= 0) {
      throw new RegisterFlowError(
        `timed out after ${timeoutMs}ms waiting for the grant receipt`,
        { stage: "timeout" },
      );
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), remaining);
    try {
      return await baseFetch(input, { ...init, signal: controller.signal });
    } catch (err) {
      if (err instanceof RegisterFlowError) throw err;
      const url = requestUrl(input);
      if (controller.signal.aborted) {
        throw new RegisterFlowError(
          `timed out after ${timeoutMs}ms: no response from ${url} within the --timeout budget`,
          { stage: "timeout", detail: url },
        );
      }
      throw new RegisterFlowError(
        `request to ${url} failed: ${describeFetchError(err)}`,
        { stage: "network", detail: describeFetchError(err) },
      );
    } finally {
      clearTimeout(timer);
    }
  }) as typeof fetch;
}

/**
 * Register the grant and wait for its receipt: POST → 303 status URL →
 * poll query-registration-status until the receipt redirect → poll
 * resolve-receipt (404 = objects still writing) until 200.
 */
export async function runRegisterGrantFlow(
  params: RegisterGrantFlowParams,
  deps: RegisterGrantFlowDeps = {},
): Promise<RegisterGrantFlowResult> {
  const sleep = deps.sleep ?? defaultSleep;
  const now = deps.now ?? Date.now;
  const onProgress = deps.onProgress ?? (() => {});
  const deadline = now() + params.timeoutMs;
  const fetchImpl = boundedFetch(
    deps.fetchImpl ?? fetch,
    now,
    deadline,
    params.timeoutMs,
  );

  const paceOrTimeout = async (
    waitMs: number,
    info: { statusUrl: string; receiptUrl?: string },
  ): Promise<void> => {
    if (now() + waitMs > deadline) {
      throw new RegisterFlowError(
        `timed out after ${params.timeoutMs}ms waiting for the grant receipt`,
        { stage: "timeout", ...info },
      );
    }
    await sleep(waitMs);
  };

  // 1. POST /register/{bootstrapLogId}/grants — only 303 + Location succeeds.
  let statusUrl: string;
  try {
    ({ statusUrl } = await registerGrant({
      baseUrl: params.baseUrl,
      bootstrapLogId: params.bootstrapLogId,
      grantBase64: params.grantBase64,
      ...(params.parentGrantBase64 !== undefined
        ? { parentGrantBase64: params.parentGrantBase64 }
        : {}),
      fetchImpl,
    }));
  } catch (err) {
    if (err instanceof ScrapiRegistrationError) {
      throw new RegisterFlowError(err.message, {
        stage: "register",
        httpStatus: err.httpStatus,
        detail: err.detail,
        ...(err.problem !== undefined ? { problem: err.problem } : {}),
      });
    }
    throw err;
  }
  onProgress({ phase: "registered", statusUrl });

  // 2. Poll query-registration-status until the receipt redirect.
  let receiptUrl: string;
  let entryIdHex: string;
  for (let attempt = 1; ; attempt++) {
    const status = await queryRegistrationOnce({
      statusUrl,
      baseUrl: params.baseUrl,
      fetchImpl,
    });
    if (status.status === "receipt") {
      ({ receiptUrl, entryIdHex } = status);
      break;
    }
    if (status.status === "error") {
      throw new RegisterFlowError(`registration status: ${status.detail}`, {
        stage: "status",
        httpStatus: status.httpStatus,
        detail: status.detail,
        ...(status.problem !== undefined ? { problem: status.problem } : {}),
        statusUrl,
      });
    }
    // pending — the worker may move the status Location and pace us.
    statusUrl = toAbsoluteScrapiUrl(params.baseUrl, status.location);
    onProgress({ phase: "status-pending", statusUrl, attempt });
    await paceOrTimeout(
      Math.max(params.pollIntervalMs, status.retryAfterMs ?? 0),
      { statusUrl },
    );
  }
  onProgress({ phase: "receipt-located", receiptUrl, entryIdHex });

  // 3. Poll resolve-receipt: 404 = checkpoint/massif still writing.
  for (let attempt = 1; ; attempt++) {
    const resolution = await resolveReceiptOnce({ receiptUrl, fetchImpl });
    if (resolution.status === "receipt") {
      return {
        statusUrl,
        receiptUrl,
        entryIdHex,
        receipt: resolution.body,
        contentType: resolution.headers["content-type"],
      };
    }
    if (resolution.status === "error") {
      throw new RegisterFlowError(
        `resolve receipt: HTTP ${resolution.httpStatus}`,
        {
          stage: "receipt",
          httpStatus: resolution.httpStatus,
          statusUrl,
          receiptUrl,
        },
      );
    }
    onProgress({ phase: "receipt-pending", receiptUrl, attempt });
    await paceOrTimeout(params.pollIntervalMs, { statusUrl, receiptUrl });
  }
}
