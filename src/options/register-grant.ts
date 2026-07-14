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
 * `forestrie register-grant` — FOR-343 (writer-only; ADR-0052).
 *
 * Authorizes ONE statement writer on an existing data log (extend-only).
 * Several signers on one data log means several grants, each naming that log.
 * Grant leaves are sequenced into the OWNER (auth) log; the data log holds
 * only statements. Log creation and bootstrap shapes live in `create-log`.
 */
export type RegisterGrantOptions = ForestrieCommonOptions & {
  /** SCRAPI origin (`FORESTRIE_BASE_URL`). */
  baseUrl: string;
  /** Owner (auth) log the grant leaf is sequenced into. */
  ownerLog: string;
  /** Child/data log the grant authorizes. */
  dataLog: string;
  /** PKCS#8 PEM key that signs the grant statement (the granting authority). */
  signWith: string;
  /** PEM of the signer being authorized (grantData = ES256 x||y). */
  signerPem: string;
  /** Parent grant credential authorizing this registration. */
  parentGrantB64: string;
  /** Completed grant base64 output path (default: stdout). */
  outB64: string | undefined;
  /**
   * Forest bootstrap/root log id — first `/register/` path segment
   * (grant genesis lookup is keyed by the forest root). Defaults to
   * `--owner-log`, which is correct whenever the owner IS the root (the
   * self-referential bootstrap and first-level child grants).
   */
  bootstrapLog: string;
  /** Overall receipt wait budget, milliseconds (`--timeout` seconds). */
  timeoutMs: number;
  /** Poll pacing, milliseconds (`--poll-interval` seconds). */
  pollIntervalMs: number;
};

export function parseRegisterGrantOptions(
  args: LooseParsedArgs,
): RegisterGrantOptions {
  const ownerLog = requiredStringOption(args, "owner-log");
  const options: RegisterGrantOptions = {
    ...parseForestrieCommonOptions(args),
    baseUrl: requiredStringOption(args, "base-url", "FORESTRIE_BASE_URL"),
    ownerLog,
    dataLog: requiredStringOption(args, "data-log"),
    signWith: requiredStringOption(args, "sign-with"),
    signerPem: requiredStringOption(args, "signer-pem"),
    parentGrantB64: requiredStringOption(args, "parent-grant-b64"),
    outB64: optionalStringOption(args, "out-b64"),
    bootstrapLog: optionalStringOption(args, "bootstrap-log") ?? ownerLog,
    timeoutMs: durationOptionMs(args, "timeout", DEFAULT_TIMEOUT_SECONDS),
    pollIntervalMs: durationOptionMs(
      args,
      "poll-interval",
      DEFAULT_POLL_INTERVAL_SECONDS,
    ),
  };
  return options;
}
