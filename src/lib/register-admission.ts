/**
 * canopy's answer to a register POST, and the retry while a log is pending.
 *
 * canopy admits a write under a log only once the chain has anchored that
 * log's authority (protocol ADR-0070; canopy `src/scrapi/log-admission.ts`).
 * Until then it refuses with 409 `authority-pending` and `Retry-After`, and
 * the log anchors when its owner next publishes a checkpoint. Retrying here
 * is the path for clients without chain access; `forestrie log
 * wait-anchored` proves the same fact from the chain instead. A 409
 * `authority-conflict` is final and is never retried. A 503 with
 * `Retry-After` (authority unreadable, queue full) is canopy refusing before
 * it sequences anything, so it is retried the same way.
 *
 * Shared by `register-flow.ts` (statements) and `register-grant-flow.ts`
 * (grants, and so `create-log`): both spend one `--timeout` budget across the
 * POST and their status and receipt polls.
 */
import { decodeCborDeterministic } from "@forestrie/encoding";
import {
  ScrapiRegistrationError,
  interpretRegisterRedirect,
  type ProblemDetails,
  type RawResponse,
} from "@forestrie/scrapi-client";
import { RegisterFlowError } from "./register-flow-error.js";

/** canopy's problem type for a claimed log the chain has not anchored. */
export const PROBLEM_AUTHORITY_PENDING = "authority-pending";

/** canopy's problem type for a log the chain recorded otherwise: final. */
export const PROBLEM_AUTHORITY_CONFLICT = "authority-conflict";

/** What a pending refusal says the caller is waiting for. */
export type AuthorityPending = {
  /** The log whose authority is pending. */
  logId?: string | undefined;
  /** Univocity's state for that log: `reserved`, `committed` or `sequenced`. */
  state?: string | undefined;
  /** The ancestor nearest the root that is not anchored: it anchors next. */
  blockedBy?: string | undefined;
  /** canopy's `Retry-After`, in milliseconds. */
  retryAfterMs?: number | undefined;
};

/**
 * One progress event per pending refusal that will be retried: `attempt`
 * counts from 1, `waitMs` is the wait before the next POST.
 */
export type AuthorityPendingProgress = {
  phase: "authority-pending";
  attempt: number;
  waitMs: number;
} & AuthorityPending;

/** The stderr line the CLI prints for a pending refusal it will retry. */
export function authorityPendingLine(progress: AuthorityPendingProgress): string {
  return `authority pending (attempt ${progress.attempt}): ${describeAuthorityPending(progress)}; retrying in ${Math.ceil(progress.waitMs / 1000)}s`;
}

/** One progress event per 503 with `Retry-After` that will be retried. */
export type ServiceUnavailableProgress = {
  phase: "service-unavailable";
  attempt: number;
  waitMs: number;
  /** canopy's problem detail, when it sent one. */
  detail?: string | undefined;
};

/** The stderr line the CLI prints for a 503 it will retry. */
export function serviceUnavailableLine(progress: ServiceUnavailableProgress): string {
  return `canopy unavailable (attempt ${progress.attempt}): ${progress.detail ?? "503"}; retrying in ${Math.ceil(progress.waitMs / 1000)}s`;
}

/** A refusal the admission loop retries. */
export type AdmissionRetryProgress =
  | AuthorityPendingProgress
  | ServiceUnavailableProgress;

/**
 * POST until canopy admits the write, and return the registration status
 * URL from its 303.
 *
 * Each 409 `authority-pending` is retried after the longer of
 * `pollIntervalMs` and the refusal's `Retry-After`, as status polls are
 * paced, and reported through `onProgress` first. A wait that would pass
 * `deadline` ends the flow with a `timeout` error that carries the refusal.
 * Any other answer than a 303 is a `register` error.
 */
export async function postUntilAdmitted(opts: {
  post: () => Promise<RawResponse>;
  baseUrl: string;
  pollIntervalMs: number;
  timeoutMs: number;
  deadline: number;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
  onProgress: (progress: AdmissionRetryProgress) => void;
}): Promise<string> {
  for (let attempt = 1; ; attempt++) {
    const raw = await opts.post();
    const problem = raw.status === 303 ? undefined : decodeCborProblem(raw);
    const refusal = retryableRefusal(raw, problem);
    if (refusal === undefined) {
      return registerStatusUrl(raw, problem, opts.baseUrl);
    }
    // Pace by Retry-After, but never past the deadline: the last wait is
    // cut short so that a final attempt lands on it.
    const remaining = opts.deadline - opts.now();
    const waitMs = Math.min(
      Math.max(opts.pollIntervalMs, refusal.retryAfterMs ?? 0),
      remaining,
    );
    if (remaining <= 0) {
      throw new RegisterFlowError(
        `timed out after ${opts.timeoutMs}ms: ${refusal.detail}`,
        {
          stage: "timeout",
          httpStatus: raw.status,
          detail: refusal.detail,
          ...(problem !== undefined ? { problem } : {}),
        },
      );
    }
    opts.onProgress(refusal.progress(attempt, waitMs));
    await opts.sleep(waitMs);
  }
}

/**
 * The refusals worth another POST: 409 `authority-pending`, and a 503 that
 * says when to come back. Anything else, 409 `authority-conflict` above
 * all, is the caller's answer.
 */
function retryableRefusal(
  raw: RawResponse,
  problem: ProblemDetails | undefined,
):
  | {
      retryAfterMs: number | undefined;
      detail: string;
      progress: (attempt: number, waitMs: number) => AdmissionRetryProgress;
    }
  | undefined {
  // A conflict is final whatever status carries it.
  if (problem?.type === PROBLEM_AUTHORITY_CONFLICT) return undefined;
  if (raw.status === 409 && problem?.type === PROBLEM_AUTHORITY_PENDING) {
    const pending = authorityPending(raw, problem);
    return {
      retryAfterMs: pending.retryAfterMs,
      detail: describeAuthorityPending(pending),
      progress: (attempt, waitMs) => ({
        phase: "authority-pending",
        attempt,
        waitMs,
        ...pending,
      }),
    };
  }
  const after = retryAfterMs(raw.headers["retry-after"]);
  if (raw.status === 503 && after !== undefined) {
    const detail = textField(problem?.detail);
    return {
      retryAfterMs: after,
      detail: `canopy is unavailable: ${detail ?? "503"}`,
      progress: (attempt, waitMs) => ({
        phase: "service-unavailable",
        attempt,
        waitMs,
        detail,
      }),
    };
  }
  return undefined;
}

/**
 * One line for a pending refusal: the log, its state and what it waits on.
 */
export function describeAuthorityPending(pending: AuthorityPending): string {
  const blocked =
    pending.blockedBy !== undefined ? `, blocked by ${pending.blockedBy}` : "";
  return `log ${pending.logId ?? "(unnamed)"} is not anchored on chain yet (state ${pending.state ?? "unknown"}${blocked})`;
}

/**
 * Decode a register error body as CBOR problem details. canopy serves
 * admission refusals as plain `application/cbor` and its other problems as
 * `application/problem+cbor`; scrapi-client decodes only the second, so
 * this accepts both. A body under any other content type is not decoded.
 */
function decodeCborProblem(raw: RawResponse): ProblemDetails | undefined {
  const contentType = raw.headers["content-type"];
  if (contentType !== undefined && !contentType.toLowerCase().includes("cbor")) {
    return undefined;
  }
  if (raw.body.length === 0) return undefined;
  try {
    const decoded = decodeCborDeterministic(raw.body);
    return decoded instanceof Map
      ? (Object.fromEntries(decoded) as ProblemDetails)
      : undefined;
  } catch {
    return undefined;
  }
}

function authorityPending(
  raw: RawResponse,
  problem: ProblemDetails,
): AuthorityPending {
  return {
    logId: textField(problem.logId),
    state: textField(problem.state),
    blockedBy: textField(problem.blockedBy),
    retryAfterMs: retryAfterMs(raw.headers["retry-after"]),
  };
}

function textField(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/** `Retry-After` as delta-seconds, the only form canopy sends. */
function retryAfterMs(header: string | undefined): number | undefined {
  if (header === undefined || !/^\d+$/.test(header.trim())) return undefined;
  return Number(header.trim()) * 1000;
}

/**
 * The status URL from a 303, or the `register` error for anything else,
 * with the decoded problem when there is one.
 */
function registerStatusUrl(
  raw: RawResponse,
  problem: ProblemDetails | undefined,
  baseUrl: string,
): string {
  if (raw.status !== 303) {
    const detail =
      typeof problem?.detail === "string"
        ? problem.detail
        : new TextDecoder().decode(raw.body).slice(0, 200) || "(empty body)";
    throw new RegisterFlowError(
      `register: expected 303, got ${raw.status} (${detail})`,
      {
        stage: "register",
        httpStatus: raw.status,
        detail,
        ...(problem !== undefined ? { problem } : {}),
      },
    );
  }
  try {
    const location = raw.headers["location"];
    return interpretRegisterRedirect(
      { status: raw.status, ...(location !== undefined ? { location } : {}) },
      baseUrl,
    ).statusUrl;
  } catch (err) {
    if (err instanceof ScrapiRegistrationError) {
      throw new RegisterFlowError(err.message, {
        stage: "register",
        httpStatus: err.httpStatus,
        detail: err.detail,
      });
    }
    throw err;
  }
}
