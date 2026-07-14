/**
 * Local bridge until `@forestrie/grant-builder` publishes `dataLogExtendFlags()`.
 *
 * The published grant-builder ships `dataLogCreateExtendFlags()` (byte 3 =
 * `GF_CREATE|GF_EXTEND` = 0x03) but not the extend-only shape a statement
 * *writer* grant needs. Constructing the 8-byte wire bitmap here is a plain
 * Uint8Array literal, NOT copied package logic — see ADR-0052 / plan-2607-21.
 * Drop this module once grant-builder exports `dataLogExtendFlags()`.
 */

/**
 * Extend-only data-log writer grant flags: byte 3 = `GF_EXTEND` (0x02, no
 * `GF_CREATE`), byte 7 = `GF_DATA_LOG` (0x02). Mirrors grant-builder's byte
 * layout (grant-flags.ts): byte 3 carries the capability bits, byte 7 the
 * log-class bits.
 */
export function dataLogExtendFlags(): Uint8Array {
  return Uint8Array.from([0, 0, 0, 0x02, 0, 0, 0, 0x02]);
}
