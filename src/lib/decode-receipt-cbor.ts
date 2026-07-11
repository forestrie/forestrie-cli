/**
 * Minimal CBOR reader for `forestrie decode-receipt` display (FOR-346).
 *
 * Only used where the published helpers stop: `parseReceipt`
 * (`@forestrie/receipt-verify`) returns the COSE protected header as an
 * opaque bstr, and this command's whole job is to show what is inside
 * it (alg, kid, vds, CWT claims). Display-only — no re-encoding, no
 * crypto. Definite lengths only: the forestrie encoders (go-cose,
 * cbor-x, `@forestrie/encoding` canonical emit) never produce
 * indefinite-length items.
 */

export class CborDecodeError extends Error {}

/** A decoded CBOR tag wrapper. */
export type CborTagged = { tag: number; value: CborValue };

export type CborValue =
  | number
  | bigint
  | string
  | boolean
  | null
  | undefined
  | Uint8Array
  | CborValue[]
  | Map<CborValue, CborValue>
  | CborTagged;

/** True when `value` is a `CborTagged` wrapper (not a Map/array/bytes). */
export function isCborTagged(value: unknown): value is CborTagged {
  return (
    typeof value === "object" &&
    value !== null &&
    !(value instanceof Map) &&
    !(value instanceof Uint8Array) &&
    !Array.isArray(value) &&
    typeof (value as CborTagged).tag === "number" &&
    "value" in value
  );
}

type Cursor = { bytes: Uint8Array; view: DataView; offset: number };

function need(c: Cursor, n: number): void {
  if (c.offset + n > c.bytes.length) {
    throw new CborDecodeError("unexpected end of CBOR data");
  }
}

function readArgument(c: Cursor, info: number): number | bigint {
  if (info < 24) return info;
  if (info === 24) {
    need(c, 1);
    return c.bytes[c.offset++]!;
  }
  if (info === 25) {
    need(c, 2);
    const v = c.view.getUint16(c.offset);
    c.offset += 2;
    return v;
  }
  if (info === 26) {
    need(c, 4);
    const v = c.view.getUint32(c.offset);
    c.offset += 4;
    return v;
  }
  if (info === 27) {
    need(c, 8);
    const v = c.view.getBigUint64(c.offset);
    c.offset += 8;
    return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
  }
  if (info === 31) {
    throw new CborDecodeError("indefinite-length CBOR items are not supported");
  }
  throw new CborDecodeError(`reserved CBOR additional info ${info}`);
}

function toLength(arg: number | bigint, what: string): number {
  if (typeof arg === "bigint" || !Number.isSafeInteger(arg)) {
    throw new CborDecodeError(`${what} length too large`);
  }
  return arg;
}

function readFloat(c: Cursor, info: number): number {
  if (info === 25) {
    // IEEE 754 half precision (RFC 8949 appendix D).
    need(c, 2);
    const half = c.view.getUint16(c.offset);
    c.offset += 2;
    const sign = half & 0x8000 ? -1 : 1;
    const exp = (half >> 10) & 0x1f;
    const frac = half & 0x03ff;
    if (exp === 0) return sign * frac * 2 ** -24;
    if (exp === 31) return frac ? Number.NaN : sign * Number.POSITIVE_INFINITY;
    return sign * (1024 + frac) * 2 ** (exp - 25);
  }
  if (info === 26) {
    need(c, 4);
    const v = c.view.getFloat32(c.offset);
    c.offset += 4;
    return v;
  }
  need(c, 8);
  const v = c.view.getFloat64(c.offset);
  c.offset += 8;
  return v;
}

function readItem(c: Cursor, depth: number): CborValue {
  if (depth > 64) throw new CborDecodeError("CBOR nesting too deep");
  need(c, 1);
  const initial = c.bytes[c.offset++]!;
  const major = initial >> 5;
  const info = initial & 0x1f;

  switch (major) {
    case 0:
      return readArgument(c, info);
    case 1: {
      const arg = readArgument(c, info);
      return typeof arg === "bigint" ? -1n - arg : -1 - arg;
    }
    case 2: {
      const len = toLength(readArgument(c, info), "byte string");
      need(c, len);
      const out = c.bytes.slice(c.offset, c.offset + len);
      c.offset += len;
      return out;
    }
    case 3: {
      const len = toLength(readArgument(c, info), "text string");
      need(c, len);
      const out = new TextDecoder("utf-8", { fatal: true }).decode(
        c.bytes.subarray(c.offset, c.offset + len),
      );
      c.offset += len;
      return out;
    }
    case 4: {
      const len = toLength(readArgument(c, info), "array");
      const out: CborValue[] = [];
      for (let i = 0; i < len; i += 1) out.push(readItem(c, depth + 1));
      return out;
    }
    case 5: {
      const len = toLength(readArgument(c, info), "map");
      const out = new Map<CborValue, CborValue>();
      for (let i = 0; i < len; i += 1) {
        const key = readItem(c, depth + 1);
        out.set(key, readItem(c, depth + 1));
      }
      return out;
    }
    case 6: {
      const tag = toLength(readArgument(c, info), "tag");
      return { tag, value: readItem(c, depth + 1) };
    }
    default: {
      // major 7: simple values and floats
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      if (info === 23) return undefined;
      if (info === 24) {
        need(c, 1);
        return c.bytes[c.offset++]!;
      }
      if (info >= 25 && info <= 27) return readFloat(c, info);
      throw new CborDecodeError(`unsupported CBOR simple value (info ${info})`);
    }
  }
}

/** Decode a single CBOR item; trailing bytes are an error. */
export function decodeCborValue(bytes: Uint8Array): CborValue {
  const cursor: Cursor = {
    bytes,
    view: new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength),
    offset: 0,
  };
  const value = readItem(cursor, 0);
  if (cursor.offset !== bytes.length) {
    throw new CborDecodeError(
      `trailing bytes after CBOR item (${bytes.length - cursor.offset} left)`,
    );
  }
  return value;
}

/** Decode CBOR bytes that must contain a map (e.g. a COSE protected header). */
export function decodeCborMap(bytes: Uint8Array): Map<CborValue, CborValue> {
  if (bytes.length === 0) return new Map();
  const value = decodeCborValue(bytes);
  if (!(value instanceof Map)) {
    throw new CborDecodeError("expected a CBOR map");
  }
  return value;
}
