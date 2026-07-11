/**
 * Structural decode for `forestrie decode-receipt` (FOR-346).
 *
 * `parseReceipt` (`@forestrie/receipt-verify`) does the load-bearing
 * receipt parse (COSE_Sign1 shape, tag-18 tolerance, payload rules,
 * header 396 inclusion proof). This module turns that result into a
 * display model: protected header contents (which `parseReceipt` leaves
 * as opaque bstr), named labels, and JSON-safe values. Unknown labels
 * are carried through raw — never dropped.
 */

import { parseReceipt } from "@forestrie/receipt-verify";
import { coseUnprotectedToMap, decodeCoseSign1 } from "@forestrie/encoding";

import {
  CborDecodeError,
  decodeCborMap,
  isCborTagged,
  type CborValue,
} from "./decode-receipt-cbor.js";
import {
  ALG_NAMES,
  COSE_SIGN1_TAG,
  CWT_CLAIMS_LABEL,
  CWT_CLAIM_NAMES,
  COSE_KEY_PARAM_NAMES,
  DELEGATION_CERT_LABEL,
  SEAL_PEAK_RECEIPTS_LABEL,
  VDS_LABEL,
  VDS_NAMES,
  headerLabelInfo,
} from "./decode-receipt-labels.js";

/** Parse stage names surfaced in structured errors. */
export type DecodeReceiptStage =
  | "input"
  | "envelope"
  | "cose-sign1"
  | "payload"
  | "protected-header"
  | "inclusion-proof";

/** Structured decode failure: which parse stage rejected the input. */
export class DecodeReceiptError extends Error {
  readonly stage: DecodeReceiptStage;

  constructor(stage: DecodeReceiptStage, message: string) {
    super(message);
    this.name = "DecodeReceiptError";
    this.stage = stage;
  }
}

/** JSON-safe value: bytes become `h'…'` diagnostic-notation strings. */
export type Json =
  | string
  | number
  | boolean
  | null
  | Json[]
  | { [key: string]: Json };

export type DecodedHeaderEntry = {
  /** Raw CBOR label (int, or string for text keys). */
  label: number | string;
  /** Registry name, or null when the label is unknown (shown raw). */
  name: string | null;
  /** Registry provenance note, when known. */
  note: string | null;
  /** Full-fidelity value (bytes as h'…'). */
  value: Json;
};

export type DecodedClaim = {
  key: number | string;
  name: string | null;
  value: Json;
};

export type DecodedReceipt = {
  /** Total receipt size in bytes. */
  byteLength: number;
  /** Outer CBOR tag (18 for COSE_Sign1) or null when untagged. */
  tag: number | null;
  protected: {
    byteLength: number;
    alg: { value: number; name: string | null } | null;
    kid: { hex: string; byteLength: number } | { text: string } | null;
    vds: { value: number; name: string | null } | null;
    /** CWT claims (header 15), incl. any cnf / ephemeral key material. */
    cwtClaims: DecodedClaim[] | null;
    entries: DecodedHeaderEntry[];
  };
  unprotected: {
    entries: DecodedHeaderEntry[];
    delegation: { byteLength: number; nestedCoseSign1: boolean } | null;
    /** Present when this is a checkpoint carrying pre-signed peak receipts. */
    peakReceipts: { count: number } | null;
  };
  payload:
    | { detached: true }
    | { detached: false; byteLength: number; hex: string };
  signature: { byteLength: number; hex: string };
  /** MMR inclusion proof summary (header 396, key -1). */
  inclusion: {
    mmrIndex: string;
    pathLength: number;
    path: string[];
    /** 32-byte peak hash when the payload is attached; null when detached. */
    peakHex: string | null;
    peakSource: "payload" | "derived at verify time (detached payload)";
  };
};

const HEX = Array.from({ length: 256 }, (_, i) =>
  i.toString(16).padStart(2, "0"),
);

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += HEX[b];
  return out;
}

/** Convert any decoded CBOR / cbor-x value to JSON-safe display form. */
export function toJson(value: unknown): Json {
  if (value === null || value === undefined) return null;
  if (typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : String(value);
  }
  if (typeof value === "bigint") {
    return value >= BigInt(Number.MIN_SAFE_INTEGER) &&
      value <= BigInt(Number.MAX_SAFE_INTEGER)
      ? Number(value)
      : value.toString(10);
  }
  if (value instanceof Uint8Array) return `h'${bytesToHex(value)}'`;
  if (Array.isArray(value)) return value.map(toJson);
  if (value instanceof Map) {
    const out: { [key: string]: Json } = {};
    for (const [k, v] of value) out[String(toJson(k))] = toJson(v);
    return out;
  }
  if (isCborTagged(value)) {
    return { tag: value.tag, value: toJson(value.value) };
  }
  if (typeof value === "object") {
    const out: { [key: string]: Json } = {};
    for (const [k, v] of Object.entries(value)) out[k] = toJson(v);
    return out;
  }
  return String(value);
}

function numericLabel(key: unknown): number | string {
  if (typeof key === "number") return key;
  if (typeof key === "bigint") return Number(key);
  const n = Number(key);
  return Number.isFinite(n) ? n : String(key);
}

function headerEntry(key: unknown, value: unknown): DecodedHeaderEntry {
  const label = numericLabel(key);
  const info = typeof label === "number" ? headerLabelInfo(label) : null;
  return {
    label,
    name: info?.name ?? null,
    note: info?.note ?? null,
    value: toJson(value),
  };
}

function decodeCwtClaims(claims: CborValue): DecodedClaim[] {
  if (!(claims instanceof Map)) {
    return [{ key: "(malformed)", name: null, value: toJson(claims) }];
  }
  const out: DecodedClaim[] = [];
  for (const [k, v] of claims) {
    const key = numericLabel(k);
    const name =
      typeof key === "number" ? (CWT_CLAIM_NAMES.get(key) ?? null) : null;
    // cnf (8) carries key material — name COSE_Key params for the audience.
    if (key === 8 && v instanceof Map) {
      const cnf: { [param: string]: Json } = {};
      for (const [pk, pv] of v) {
        const paramKey = numericLabel(pk);
        const paramName =
          typeof paramKey === "number"
            ? COSE_KEY_PARAM_NAMES.get(paramKey)
            : undefined;
        cnf[paramName ? `${paramKey} (${paramName})` : String(paramKey)] =
          toJson(pv);
      }
      out.push({ key, name, value: cnf });
      continue;
    }
    out.push({ key, name, value: toJson(v) });
  }
  return out;
}

/** Classify a `parseReceipt` failure by the stage that rejected the input. */
function classifyParseReceiptError(error: unknown): DecodeReceiptError {
  const message = error instanceof Error ? error.message : String(error);
  if (/COSE Sign1/i.test(message)) {
    return new DecodeReceiptError("cose-sign1", message);
  }
  if (/payload/i.test(message)) {
    return new DecodeReceiptError("payload", message);
  }
  if (/header 396|proof/i.test(message)) {
    return new DecodeReceiptError("inclusion-proof", message);
  }
  // Anything else came out of the CBOR envelope decode.
  return new DecodeReceiptError("envelope", message);
}

/**
 * Decode receipt bytes to the display model.
 *
 * @throws DecodeReceiptError naming the parse stage on malformed input
 */
export function decodeReceipt(receiptBytes: Uint8Array): DecodedReceipt {
  if (receiptBytes.length === 0) {
    throw new DecodeReceiptError("input", "receipt is empty (0 bytes)");
  }

  // Tag tolerance: parseReceipt accepts both; record which form we got.
  // Tag 18 with a 1-byte argument encodes as the initial byte 0xd2.
  const tag = receiptBytes[0] === 0xd2 ? COSE_SIGN1_TAG : null;

  let parsed: ReturnType<typeof parseReceipt>;
  try {
    parsed = parseReceipt(receiptBytes);
  } catch (error) {
    throw classifyParseReceiptError(error);
  }
  const [protectedBstr, unprotectedRaw, payload, signature] = parsed.coseSign1;

  // Protected header: parseReceipt keeps it opaque (signed bytes); open it.
  let protectedMap: Map<CborValue, CborValue>;
  try {
    protectedMap = decodeCborMap(protectedBstr);
  } catch (error) {
    const message =
      error instanceof CborDecodeError
        ? `protected header is not a valid CBOR map: ${error.message}`
        : String(error);
    throw new DecodeReceiptError("protected-header", message);
  }

  let alg: DecodedReceipt["protected"]["alg"] = null;
  let kid: DecodedReceipt["protected"]["kid"] = null;
  let vds: DecodedReceipt["protected"]["vds"] = null;
  let cwtClaims: DecodedClaim[] | null = null;
  const protectedEntries: DecodedHeaderEntry[] = [];
  for (const [k, v] of protectedMap) {
    protectedEntries.push(headerEntry(k, v));
    const label = numericLabel(k);
    if (label === 1 && (typeof v === "number" || typeof v === "bigint")) {
      const value = Number(v);
      alg = { value, name: ALG_NAMES.get(value) ?? null };
    } else if (label === 4) {
      if (v instanceof Uint8Array) {
        kid = { hex: bytesToHex(v), byteLength: v.length };
      } else if (typeof v === "string") {
        kid = { text: v };
      }
    } else if (
      label === VDS_LABEL &&
      (typeof v === "number" || typeof v === "bigint")
    ) {
      const value = Number(v);
      vds = { value, name: VDS_NAMES.get(value) ?? null };
    } else if (label === CWT_CLAIMS_LABEL) {
      cwtClaims = decodeCwtClaims(v as CborValue);
    }
  }

  // Unprotected header: already decoded by parseReceipt's CBOR pass.
  const unprotectedMap = coseUnprotectedToMap(unprotectedRaw);
  const unprotectedEntries: DecodedHeaderEntry[] = [];
  let delegation: DecodedReceipt["unprotected"]["delegation"] = null;
  let peakReceipts: DecodedReceipt["unprotected"]["peakReceipts"] = null;
  for (const [label, value] of unprotectedMap) {
    unprotectedEntries.push(headerEntry(label, value));
    if (label === DELEGATION_CERT_LABEL && value instanceof Uint8Array) {
      delegation = {
        byteLength: value.length,
        nestedCoseSign1: decodeCoseSign1(value) !== null,
      };
    } else if (label === SEAL_PEAK_RECEIPTS_LABEL && Array.isArray(value)) {
      peakReceipts = { count: value.length };
    }
  }

  const path = parsed.proof.path.map(bytesToHex);
  const peakHex = parsed.explicitPeak ? bytesToHex(parsed.explicitPeak) : null;

  return {
    byteLength: receiptBytes.length,
    tag,
    protected: {
      byteLength: protectedBstr.length,
      alg,
      kid,
      vds,
      cwtClaims,
      entries: protectedEntries,
    },
    unprotected: {
      entries: unprotectedEntries,
      delegation,
      peakReceipts,
    },
    payload:
      payload instanceof Uint8Array
        ? { detached: false, byteLength: payload.length, hex: bytesToHex(payload) }
        : { detached: true },
    signature: { byteLength: signature.length, hex: bytesToHex(signature) },
    inclusion: {
      // parseReceipt always sets mmrIndex; Proof marks it optional.
      mmrIndex: (parsed.proof.mmrIndex ?? 0n).toString(10),
      pathLength: path.length,
      path,
      peakHex,
      peakSource: peakHex
        ? "payload"
        : "derived at verify time (detached payload)",
    },
  };
}
