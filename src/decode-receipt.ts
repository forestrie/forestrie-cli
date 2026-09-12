/**
 * Public library entry: the pure COSE-receipt decoder and renderer that
 * backs `forestrie decode-receipt`.
 *
 * Imported as `@forestrie/forestrie-cli/decode-receipt`. Everything here
 * is runtime-neutral — no `node:*`, no `Bun.*`, no I/O, no network. It
 * takes receipt bytes and returns a display model (plus a text
 * rendering of it), so it runs unchanged in Node, Bun, Deno, a worker
 * or a browser. The only dependencies are `@forestrie/receipt-verify`
 * (the load-bearing receipt parse) and `@forestrie/encoding`.
 *
 * Decoding is display only: it does NOT verify signatures or inclusion.
 * That is `forestrie verify` / `@forestrie/receipt-verify`.
 */

export {
  DecodeReceiptError,
  bytesToHex,
  decodeReceipt,
  toJson,
  type DecodeReceiptStage,
  type DecodedClaim,
  type DecodedHeaderEntry,
  type DecodedReceipt,
  type Json,
} from "./lib/decode-receipt-decode.js";

export { renderReceipt } from "./lib/decode-receipt-render.js";

export {
  ALG_NAMES,
  COSE_KEY_PARAM_NAMES,
  COSE_SIGN1_TAG,
  CWT_CLAIMS_LABEL,
  CWT_CLAIM_NAMES,
  DELEGATION_CERT_LABEL,
  HEADER_LABELS,
  PROOFS_CONSISTENCY_KEY,
  PROOFS_INCLUSION_KEY,
  PROOF_KIND_NAMES,
  SEAL_PEAK_RECEIPTS_LABEL,
  VDS_LABEL,
  VDS_NAMES,
  VERIFIABLE_PROOFS_LABEL,
  headerLabelInfo,
  type LabelInfo,
} from "./lib/decode-receipt-labels.js";

export {
  CborDecodeError,
  decodeCborMap,
  decodeCborValue,
  isCborTagged,
  type CborTagged,
  type CborValue,
} from "./lib/decode-receipt-cbor.js";
