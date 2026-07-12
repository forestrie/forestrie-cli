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
 * `forestrie register-grant` — FOR-343.
 *
 * A grant binds exactly ONE signer; several signers on one data log means
 * several grants, each naming that log. Grant leaves are sequenced into
 * the OWNER (auth) log; the data log holds only statements.
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
  signerPem: string | undefined;
  /** Bootstrap-shaped self-referential grant (root log first leaf: logId == ownerLogId). */
  selfReferential: boolean;
  /** Create a child auth log rather than a data log. */
  authLog: boolean;
  /** Parent grant credential authorizing this registration. */
  parentGrantB64: string | undefined;
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
    signerPem: optionalStringOption(args, "signer-pem"),
    selfReferential: args["self-referential"] === true,
    authLog: args["auth-log"] === true,
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
