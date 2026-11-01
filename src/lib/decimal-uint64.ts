/**
 * Canonical decimal-string codec for the uint64 MMR range bounds the
 * delegation coordinator's JSON routes carry (plan-2611-01 D1, FOR-613).
 *
 * JSON numbers lose precision above 2^53, so `mmrStart` / `mmrEnd` travel as
 * a decimal string matching `^(0|[1-9][0-9]*)$` with value <= 2^64-1. This
 * mirrors the coordinator's own validator
 * ([decimal-uint64.ts](https://github.com/forestrie/canopy/blob/main/packages/apps/delegation-coordinator/src/decimal-uint64.ts)).
 * A JSON number, a leading zero, a sign or whitespace is malformed: the
 * contract is a hard cutover (D5), with no fallback to numbers.
 */
import { UINT64_MAX } from "@forestrie/delegation-cose";

/** Canonical unsigned decimal: no sign, no leading zero, no whitespace. */
const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)$/;

/** Longest canonical decimal of a uint64 (2^64-1 has 20 digits). */
const MAX_UINT64_DIGITS = 20;

/**
 * Parse a decoded JSON value as a canonical decimal uint64 string.
 *
 * @param value - The decoded JSON value; only a string is accepted.
 * @param what - Field description for error messages.
 * @returns The value as `bigint` in `[0, 2^64-1]`.
 * @throws Error for a non-string (including a JSON number), a non-canonical
 *   string, or a value above 2^64-1.
 */
export function parseDecimalUint64(value: unknown, what: string): bigint {
  if (typeof value !== "string") {
    throw new Error(
      `${what} must be a decimal string (got ${value === null ? "null" : typeof value})`,
    );
  }
  if (value.length > MAX_UINT64_DIGITS || !CANONICAL_DECIMAL.test(value)) {
    throw new Error(`${what} must be a canonical decimal uint64 string`);
  }
  const parsed = BigInt(value);
  if (parsed > UINT64_MAX) {
    throw new Error(`${what} exceeds 2^64-1`);
  }
  return parsed;
}

/**
 * Format a uint64 as its canonical decimal string for a JSON body or report.
 *
 * @param value - A `bigint` in `[0, 2^64-1]`.
 * @throws Error when `value` is outside the uint64 range.
 */
export function formatDecimalUint64(value: bigint): string {
  if (value < 0n || value > UINT64_MAX) {
    throw new Error(`value ${value} is not a uint64`);
  }
  return value.toString(10);
}
