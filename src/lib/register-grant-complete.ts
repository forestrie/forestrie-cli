/**
 * FOR-343 completed-grant assembly: once the grant leaf is sequenced and
 * the receipt resolved, the *completed* grant is the original signed grant
 * statement with the receipt (header 396) and the entry's idtimestamp
 * (header -65537) merged into the UNPROTECTED headers — no re-signing
 * (mirrors e2e-kit `buildCompletedGrantBase64`). The completed grant is
 * the `Authorization: Forestrie-Grant` bearer used by `forestrie register`.
 */
import {
  HEADER_IDTIMESTAMP,
  HEADER_RECEIPT,
  base64ToBytes,
  bytesToForestrieGrantBase64,
} from "@forestrie/grant-builder";
import { mergeUnprotectedIntoCoseSign1 } from "@forestrie/encoding";

const ENTRY_ID_HEX_RE = /^[0-9a-f]{32}$/i;

/**
 * First half of the permanent 32-hex-char entry id (idtimestamp_be8 ||
 * mmrIndex_be8): the 8 idtimestamp bytes for unprotected header -65537.
 */
export function entryIdHexToIdtimestampBe8(entryIdHex: string): Uint8Array {
  if (!ENTRY_ID_HEX_RE.test(entryIdHex)) {
    throw new Error(`entryId must be 32 hex chars: ${entryIdHex}`);
  }
  return Uint8Array.from(Buffer.from(entryIdHex.slice(0, 16), "hex"));
}

/**
 * Attach receipt + idtimestamp to the signed grant statement, returning
 * the completed grant as Forestrie-Grant header base64.
 */
export function completeGrantBase64(
  grantBase64: string,
  receiptBytes: Uint8Array,
  entryIdHex: string,
): string {
  const completed = mergeUnprotectedIntoCoseSign1(
    base64ToBytes(grantBase64),
    new Map<number, unknown>([
      [HEADER_RECEIPT, receiptBytes],
      [HEADER_IDTIMESTAMP, entryIdHexToIdtimestampBe8(entryIdHex)],
    ]),
  );
  return bytesToForestrieGrantBase64(completed);
}
