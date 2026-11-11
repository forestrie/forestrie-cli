/**
 * FOR-342 registration flow: POST the signed statement, then drive the
 * SCRAPI 303 receipt-redirect contract to completion.
 *
 * `@forestrie/scrapi-client` deliberately ships poll-once primitives with
 * NO sleep loops — this module owns the pacing (`--timeout` /
 * `--poll-interval`), honouring a longer `Retry-After` when the worker
 * sends one. Fetch/sleep/clock are injectable for tests.
 */
import {
  queryRegistrationOnce,
  registerSignedStatementRaw,
  resolveReceiptOnce,
  toAbsoluteScrapiUrl,
} from "@forestrie/scrapi-client";
import {
  postUntilAdmitted,
  type AuthorityPendingProgress,
} from "./register-admission.js";
import { RegisterFlowError } from "./register-flow-error.js";
import { REQUEST_TIMEOUT_MS } from "./timed-fetch.js";

export { RegisterFlowError };
export type { RegisterFlowStage } from "./register-flow-error.js";

/** Progress callbacks so the CLI can narrate long polls on stderr. */
export type RegisterProgress =
  | AuthorityPendingProgress
  | { phase: "registered"; statusUrl: string }
  | { phase: "status-pending"; statusUrl: string; attempt: number }
  | { phase: "receipt-located"; receiptUrl: string; entryIdHex: string }
  | { phase: "receipt-pending"; receiptUrl: string; attempt: number };

/** Injectable effects — production defaults are real fetch/sleep/clock. */
export type RegisterFlowDeps = {
  fetchImpl?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  onProgress?: (progress: RegisterProgress) => void;
};

export type RegisterFlowParams = {
  /** SCRAPI origin, no trailing slash. */
  baseUrl: string;
  /** Forest bootstrap log id — first `/register/` path segment. */
  logId: string;
  /** Completed grant, `Authorization: Forestrie-Grant` base64. */
  grantB64: string;
  /** COSE Sign1 signed statement wire bytes. */
  statement: Uint8Array;
  /** Overall budget covering both poll phases. */
  timeoutMs: number;
  /** Pacing between polls; a longer `Retry-After` wins. */
  pollIntervalMs: number;
};

export type RegisterFlowResult = {
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
 * F4 (plan-2607-14 W1.4): bound every request with an AbortSignal tied to
 * the remaining `--timeout` budget — a hung server cannot stall the flow
 * past the deadline (the deadline was previously only checked BETWEEN
 * polls) — and map fetch-level failures (ECONNREFUSED, DNS, resets) into
 * the `RegisterFlowError` taxonomy instead of letting bare TypeErrors
 * escape as unstructured crashes.
 *
 * The timer uses real wall-clock (`setTimeout`) while `remaining` comes
 * from the injectable `now` — with a fake clock the fake fetch resolves
 * immediately and the timer is cleared before it can fire.
 */
function boundedFetch(
  baseFetch: typeof fetch,
  now: () => number,
  deadline: () => number,
  timeoutMs: number,
): typeof fetch {
  return (async (
    input: Parameters<typeof fetch>[0],
    init?: RequestInit,
  ): Promise<Response> => {
    const remaining = deadline() - now();
    if (remaining <= 0) {
      throw new RegisterFlowError(
        `timed out after ${timeoutMs}ms waiting for the receipt`,
        { stage: "timeout" },
      );
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), remaining);
    try {
      const response = await baseFetch(input, {
        ...init,
        signal: controller.signal,
      });
      // Leave the abort armed for the body, which may still stall after
      // the headers; unref'd, so it never holds the process open.
      timer.unref?.();
      return response;
    } catch (err) {
      clearTimeout(timer);
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
    }
  }) as typeof fetch;
}

/** A body read cut off by {@link boundedFetch}'s abort, as a timeout. */
function asBodyTimeout(err: unknown, timeoutMs: number): unknown {
  if (
    err instanceof Error &&
    !(err instanceof RegisterFlowError) &&
    (err.name === "AbortError" || err.name === "TimeoutError")
  ) {
    return new RegisterFlowError(
      `timed out after ${timeoutMs}ms: a response body did not finish within the --timeout budget`,
      { stage: "timeout" },
    );
  }
  return err;
}

/**
 * Register `statement` and wait for its receipt: POST → 303 status URL →
 * poll query-registration-status until the receipt redirect → poll
 * resolve-receipt (404 = objects still writing) until 200.
 */
export async function runRegisterFlow(
  params: RegisterFlowParams,
  deps: RegisterFlowDeps = {},
): Promise<RegisterFlowResult> {
  try {
    return await runRegisterFlowWithin(params, deps);
  } catch (err) {
    throw asBodyTimeout(err, params.timeoutMs);
  }
}

async function runRegisterFlowWithin(
  params: RegisterFlowParams,
  deps: RegisterFlowDeps,
): Promise<RegisterFlowResult> {
  const sleep = deps.sleep ?? defaultSleep;
  const now = deps.now ?? Date.now;
  const onProgress = deps.onProgress ?? (() => {});
  // One --timeout budget for admission, and a fresh one for the receipt
  // once the POST is admitted: an admission near the deadline must not
  // strand a sequenced grant without the time to collect its receipt.
  let deadline = now() + params.timeoutMs;
  const fetchImpl = boundedFetch(
    deps.fetchImpl ?? fetch,
    now,
    () => deadline,
    params.timeoutMs,
  );
  // The admission POSTs make a last attempt at the deadline, so each gets
  // at least one request's time (capped by --timeout itself) even once the
  // budget is spent.
  const postFloorMs = Math.min(REQUEST_TIMEOUT_MS, params.timeoutMs);
  const postFetch = boundedFetch(
    deps.fetchImpl ?? fetch,
    now,
    () => Math.max(deadline, now() + postFloorMs),
    params.timeoutMs,
  );

  const paceOrTimeout = async (
    waitMs: number,
    info: { statusUrl: string; receiptUrl?: string },
  ): Promise<void> => {
    if (now() + waitMs > deadline) {
      throw new RegisterFlowError(
        `timed out after ${params.timeoutMs}ms waiting for the receipt`,
        { stage: "timeout", ...info },
      );
    }
    await sleep(waitMs);
  };

  // 1. POST /register/{logId}/entries — only 303 + Location succeeds; a 409
  //    authority-pending (the log is not anchored yet) is retried.
  let statusUrl = await postUntilAdmitted({
    post: () =>
      registerSignedStatementRaw({
        baseUrl: params.baseUrl,
        bootstrapLogId: params.logId,
        grantBase64: params.grantB64,
        statement: params.statement,
        fetchImpl: postFetch,
      }),
    baseUrl: params.baseUrl,
    pollIntervalMs: params.pollIntervalMs,
    timeoutMs: params.timeoutMs,
    deadline,
    now,
    sleep,
    onProgress,
  });
  deadline = now() + params.timeoutMs;
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
      throw new RegisterFlowError(
        `registration status: ${status.detail}`,
        {
          stage: "status",
          httpStatus: status.httpStatus,
          detail: status.detail,
          ...(status.problem !== undefined ? { problem: status.problem } : {}),
          statusUrl,
        },
      );
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
