import type { LooseParsedArgs } from "@forestrie/cli-kit";
import { UINT64_MAX } from "@forestrie/delegation-cose";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/**
 * Default horizon MMR end — effectively unbounded. The value stays 2^53-1
 * (Number.MAX_SAFE_INTEGER, as before FOR-613); thinker mirrors it.
 */
export const DEFAULT_HORIZON_MMR_END = BigInt(Number.MAX_SAFE_INTEGER);

/**
 * `forestrie delegate` — FOR-390 / ADR-0052.
 *
 * Authorize a custodian-vouched sealer to publish checkpoints for a log the
 * caller owns (K(L)). Public coordinator endpoints only — no operator token,
 * no RPC. The registrar voucher is verified against a caller-known
 * registrar key before the delegation certificate is bound (fail closed).
 */
export type DelegateOptions = ForestrieCommonOptions & {
  /** Delegation coordinator origin (`DELEGATION_COORDINATOR_URL`). */
  coordinatorUrl: string;
  /** Target log id (UUID). */
  logId: string;
  /** ES256 log-root PEM (K(L)) that authorizes the delegation. */
  signWith: string;
  /** The known key that vouches for the operator's sealer — the registrar's
   * voucher-signing key, base64 `x||y` (`KNOWN_SEALER_KEY`). */
  knownSealerKey: string;
  /** Exclusive MMR end of the horizon lease (mmrStart is fixed 0); uint64. */
  horizonMmrEnd: bigint;
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

/**
 * Read `--horizon-mmr-end` as a uint64. The horizon binds a durable on-chain
 * delegation scope [0, mmrEnd), so reject non-integer / out-of-range values
 * before they flow into cert + on-chain encoding (ADR-0050 V4). Parsed with
 * `BigInt` from plain digits so values above 2^53 stay exact (FOR-613).
 */
function horizonMmrEndOption(args: LooseParsedArgs): bigint {
  const raw = optionalStringOption(args, "horizon-mmr-end");
  if (raw === undefined) return DEFAULT_HORIZON_MMR_END;
  const value = /^[0-9]+$/.test(raw) ? BigInt(raw) : -1n;
  if (value <= 0n || value > UINT64_MAX) {
    throw new Error(
      "--horizon-mmr-end must be a positive integer no larger than 2^64-1",
    );
  }
  return value;
}

export function parseDelegateOptions(args: LooseParsedArgs): DelegateOptions {
  const horizonMmrEnd = horizonMmrEndOption(args);
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
    knownSealerKey: requiredStringOption(
      args,
      "known-sealer-key",
      "KNOWN_SEALER_KEY",
    ),
    horizonMmrEnd,
    ttlSeconds,
    outB64: optionalStringOption(args, "out-b64"),
  };
  return options;
}
