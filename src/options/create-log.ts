import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";
import {
  DEFAULT_POLL_INTERVAL_SECONDS,
  DEFAULT_TIMEOUT_SECONDS,
  durationOptionMs,
} from "./register.js";

/**
 * `forestrie create-log` — FOR-390 / ADR-0052.
 *
 * Create a log and set its owner (K(L)). The create grant is sequenced into
 * the parent/auth log (`--owner-log`); `--new-log` is the log being created.
 * Absorbs the create / self-referential / auth-log shapes removed from
 * `register-grant` (which is now writer-only).
 */
export type CreateLogOptions = ForestrieCommonOptions & {
  /** SCRAPI origin (`FORESTRIE_BASE_URL`). */
  baseUrl: string;
  /** Parent/auth log the create grant is sequenced into. */
  ownerLog: string;
  /** The log being created. */
  newLog: string;
  /** Create a child auth log rather than a data log. */
  authLog: boolean;
  /** Root bootstrap self-referential grant (`--new-log == --owner-log`). */
  selfReferential: boolean;
  /** PEM of the new log's owner (grantData = ES256 x||y); required unless self-referential. */
  signerPem: string | undefined;
  /** Granting authority PEM (the parent log's K(L)) that signs the grant. */
  signWith: string;
  /** Parent grant credential authorizing this registration. */
  parentGrantB64: string | undefined;
  /** Completed grant base64 output path (default: stdout). */
  outB64: string | undefined;
  /**
   * Forest bootstrap/root log id — first `/register/` path segment (grant
   * genesis lookup is keyed by the forest root). Defaults to `--owner-log`.
   */
  bootstrapLog: string;
  /** Overall receipt wait budget, milliseconds (`--timeout` seconds). */
  timeoutMs: number;
  /** Poll pacing, milliseconds (`--poll-interval` seconds). */
  pollIntervalMs: number;
};

export function parseCreateLogOptions(args: LooseParsedArgs): CreateLogOptions {
  const ownerLog = requiredStringOption(args, "owner-log");
  const options: CreateLogOptions = {
    ...parseForestrieCommonOptions(args),
    baseUrl: requiredStringOption(args, "base-url", "FORESTRIE_BASE_URL"),
    ownerLog,
    newLog: requiredStringOption(args, "new-log"),
    authLog: args["auth-log"] === true,
    selfReferential: args["self-referential"] === true,
    signerPem: optionalStringOption(args, "signer-pem"),
    signWith: requiredStringOption(args, "sign-with"),
    parentGrantB64: optionalStringOption(args, "parent-grant-b64"),
    outB64: optionalStringOption(args, "out-b64"),
    bootstrapLog: optionalStringOption(args, "bootstrap-log") ?? ownerLog,
    timeoutMs: durationOptionMs(args, "timeout", DEFAULT_TIMEOUT_SECONDS),
    pollIntervalMs: durationOptionMs(
      args,
      "poll-interval",
      DEFAULT_POLL_INTERVAL_SECONDS,
    ),
  };
  if (options.selfReferential && options.parentGrantB64 !== undefined) {
    throw new Error(
      "--self-referential and --parent-grant-b64 are mutually exclusive (the bootstrap leaf has no parent)",
    );
  }
  if (!options.selfReferential && options.parentGrantB64 === undefined) {
    throw new Error(
      "either --parent-grant-b64 or --self-referential is required",
    );
  }
  return options;
}
