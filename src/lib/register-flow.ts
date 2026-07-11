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
  ScrapiRegistrationError,
  queryRegistrationOnce,
  registerSignedStatement,
  resolveReceiptOnce,
  toAbsoluteScrapiUrl,
  type ProblemDetails,
} from "@forestrie/scrapi-client";

/** Where the flow failed — drives the `--json` error code. */
export type RegisterFlowStage =
  | "register" // POST /register/{logId}/entries rejected
  | "status" // query-registration-status broke the 303 contract
  | "receipt" // resolve-receipt answered non-200/404
  | "network" // fetch itself failed (ECONNREFUSED, DNS, reset) — no response
  | "timeout"; // `--timeout` budget exhausted (pending, or a hung request)

export class RegisterFlowError extends Error {
  readonly stage: RegisterFlowStage;
  readonly httpStatus: number | undefined;
  /** Problem `detail` (or body preview) from the failing response. */
  readonly detail: string | undefined;
  /** RFC 9457 problem details decoded from a CBOR error body. */
  readonly problem: ProblemDetails | undefined;
  readonly statusUrl: string | undefined;
  readonly receiptUrl: string | undefined;

  constructor(
    message: string,
    info: {
      stage: RegisterFlowStage;
      httpStatus?: number;
      detail?: string;
      problem?: ProblemDetails;
      statusUrl?: string;
      receiptUrl?: string;
    },
  ) {
    super(message);
    this.name = "RegisterFlowError";
    this.stage = info.stage;
    this.httpStatus = info.httpStatus;
    this.detail = info.detail;
    this.problem = info.problem;
    this.statusUrl = info.statusUrl;
    this.receiptUrl = info.receiptUrl;
  }
}

/** Progress callbacks so the CLI can narrate long polls on stderr. */
export type RegisterProgress =
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
        `timed out after ${timeoutMs}ms waiting for the receipt`,
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
 * Register `statement` and wait for its receipt: POST → 303 status URL →
 * poll query-registration-status until the receipt redirect → poll
 * resolve-receipt (404 = objects still writing) until 200.
 */
export async function runRegisterFlow(
  params: RegisterFlowParams,
  deps: RegisterFlowDeps = {},
): Promise<RegisterFlowResult> {
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
        `timed out after ${params.timeoutMs}ms waiting for the receipt`,
        { stage: "timeout", ...info },
      );
    }
    await sleep(waitMs);
  };

  // 1. POST /register/{logId}/entries — only 303 + Location succeeds.
  let statusUrl: string;
  try {
    ({ statusUrl } = await registerSignedStatement({
      baseUrl: params.baseUrl,
      bootstrapLogId: params.logId,
      grantBase64: params.grantB64,
      statement: params.statement,
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
