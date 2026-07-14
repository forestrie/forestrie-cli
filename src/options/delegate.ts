import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/** Default horizon MMR end — effectively unbounded (Number.MAX_SAFE_INTEGER). */
export const DEFAULT_HORIZON_MMR_END = Number.MAX_SAFE_INTEGER;

/**
 * `forestrie delegate` — FOR-390 / ADR-0052.
 *
 * Authorize a custodian-vouched sealer to publish checkpoints for a log the
 * caller owns (K(L)). Public coordinator endpoints only — no operator token,
 * no RPC. The registrar voucher is verified against an operator-pinned
 * registrar key before the delegation certificate is bound (fail closed).
 */
export type DelegateOptions = ForestrieCommonOptions & {
  /** Delegation coordinator origin (`DELEGATION_COORDINATOR_URL`). */
  coordinatorUrl: string;
  /** Target log id (UUID). */
  logId: string;
  /** ES256 log-root PEM (K(L)) that authorizes the delegation. */
  signWith: string;
  /** Pinned registrar key, base64 `x||y` (`PINNED_REGISTRAR_KEY`). */
  pinnedRegistrarKey: string;
  /** Exclusive MMR end of the horizon lease (mmrStart is fixed 0). */
  horizonMmrEnd: number;
  /** Lease TTL seconds; defaults to the standing entry's suggestedTtlSeconds. */
  ttlSeconds: number | undefined;
  /** When set, write the submitted certificate base64 to this path. */
  outB64: string | undefined;
};

/** Read `--<name>` as a finite number; a missing flag yields `fallback`. */
function numberOption(
  args: LooseParsedArgs,
  name: string,
  fallback: number | undefined,
): number | undefined {
  const raw = optionalStringOption(args, name);
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value)) {
    throw new Error(`--${name} must be a number`);
  }
  return value;
}

export function parseDelegateOptions(args: LooseParsedArgs): DelegateOptions {
  const horizonMmrEnd = numberOption(
    args,
    "horizon-mmr-end",
    DEFAULT_HORIZON_MMR_END,
  ) as number;
  // The horizon binds a durable on-chain delegation scope [0, mmrEnd) — reject
  // non-integer / out-of-range values before they flow into cert + on-chain
  // encoding (ADR-0050 V4). MMR indices are non-negative safe integers.
  if (!Number.isSafeInteger(horizonMmrEnd) || horizonMmrEnd <= 0) {
    throw new Error(
      "--horizon-mmr-end must be a positive integer no larger than 2^53-1",
    );
  }
  const ttlSeconds = numberOption(args, "ttl-seconds", undefined);
  if (
    ttlSeconds !== undefined &&
    (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0)
  ) {
    throw new Error("--ttl-seconds must be a positive integer");
  }
  const options: DelegateOptions = {
    ...parseForestrieCommonOptions(args),
    coordinatorUrl: requiredStringOption(
      args,
      "coordinator-url",
      "DELEGATION_COORDINATOR_URL",
    ),
    logId: requiredStringOption(args, "log-id"),
    signWith: requiredStringOption(args, "sign-with"),
    pinnedRegistrarKey: requiredStringOption(
      args,
      "pinned-registrar-key",
      "PINNED_REGISTRAR_KEY",
    ),
    horizonMmrEnd,
    ttlSeconds,
    outB64: optionalStringOption(args, "out-b64"),
  };
  return options;
}
