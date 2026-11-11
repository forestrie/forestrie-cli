import type { ProblemDetails } from "@forestrie/scrapi-client";

/** Where the flow failed — drives the `--json` error code. */
export type RegisterFlowStage =
  | "register" // POST /register/{logId}/entries rejected
  | "status" // query-registration-status broke the 303 contract
  | "receipt" // resolve-receipt answered non-200/404
  | "network" // fetch itself failed (ECONNREFUSED, DNS, reset) — no response
  | "timeout"; // `--timeout` budget exhausted (pending, or a hung request)

/**
 * A register or register-grant flow failure, shared by `register-flow.ts`,
 * `register-grant-flow.ts` and `register-admission.ts`.
 */
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
