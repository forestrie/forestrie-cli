/**
 * Golden receipt fixtures for `decode-receipt` tests (FOR-346).
 *
 * Hand-rolled definite-length CBOR emit (test-only) so the fixture bytes
 * are deterministic and independent of the code under test. The shape
 * mirrors what canopy-api `resolve-receipt` serves: a COSE_Sign1 peak
 * receipt with slim `{alg, kid, vds}` protected headers, the inclusion
 * proof under unprotected 396 `{-1: [{1: mmrIndex, 2: [path…]}]}`, a
 * delegation certificate under 1000, and a detached (nil) payload.
 */

function bytes(...parts: (number[] | Uint8Array)[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function head(major: number, arg: number): number[] {
  if (arg < 24) return [(major << 5) | arg];
  if (arg < 0x100) return [(major << 5) | 24, arg];
  if (arg < 0x10000) return [(major << 5) | 25, arg >> 8, arg & 0xff];
  return [
    (major << 5) | 26,
    (arg >>> 24) & 0xff,
    (arg >>> 16) & 0xff,
    (arg >>> 8) & 0xff,
    arg & 0xff,
  ];
}

export const cbor = {
  uint: (n: number): Uint8Array => bytes(head(0, n)),
  /** Encode the negative integer `-magnitude` (RFC 8949: head(1, m-1)). */
  nint: (magnitude: number): Uint8Array => bytes(head(1, magnitude - 1)),
  int: (n: number): Uint8Array => (n >= 0 ? cbor.uint(n) : cbor.nint(-n)),
  bstr: (b: Uint8Array): Uint8Array => bytes(head(2, b.length), b),
  tstr: (s: string): Uint8Array => {
    const b = new TextEncoder().encode(s);
    return bytes(head(3, b.length), b);
  },
  array: (...items: Uint8Array[]): Uint8Array =>
    bytes(head(4, items.length), ...items),
  map: (...pairs: [Uint8Array, Uint8Array][]): Uint8Array =>
    bytes(head(5, pairs.length), ...pairs.flat()),
  tag: (tag: number, value: Uint8Array): Uint8Array =>
    bytes(head(6, tag), value),
  nil: (): Uint8Array => bytes([0xf6]),
};

export function filled(byte: number, length: number): Uint8Array {
  return new Uint8Array(length).fill(byte);
}

export const FIXTURE = {
  kid: filled(0x6c, 12),
  mmrIndex: 5,
  path: [filled(0x11, 32), filled(0x22, 32), filled(0x33, 32)],
  peak: filled(0x44, 32),
  signature: filled(0x99, 64),
  /** Unknown private-use label that must be shown raw, never dropped. */
  unknownLabel: -70000,
  unknownValue: "mystery",
};

/** Protected header map bytes: {1: ES256, 4: kid, 395: vds 3}. */
export function protectedMapBytes(): Uint8Array {
  return cbor.map(
    [cbor.uint(1), cbor.nint(7)], // alg: ES256 (-7)
    [cbor.uint(4), cbor.bstr(FIXTURE.kid)],
    [cbor.uint(395), cbor.uint(3)], // vds: MMRIVER
  );
}

/** Unprotected header: inclusion proof (396), delegation (1000), unknown. */
function unprotectedMap(delegationCert: Uint8Array): Uint8Array {
  const proofEntry = cbor.map(
    [cbor.uint(1), cbor.uint(FIXTURE.mmrIndex)],
    [cbor.uint(2), cbor.array(...FIXTURE.path.map((h) => cbor.bstr(h)))],
  );
  const verifiableProofs = cbor.map([
    cbor.nint(1), // -1: inclusion proofs
    cbor.array(proofEntry),
  ]);
  return cbor.map(
    [cbor.uint(396), verifiableProofs],
    [cbor.uint(1000), cbor.bstr(delegationCert)],
    [cbor.int(FIXTURE.unknownLabel), cbor.tstr(FIXTURE.unknownValue)],
  );
}

/** A minimal nested COSE_Sign1 standing in for the delegation cert. */
function nestedDelegationCert(): Uint8Array {
  return cbor.array(
    cbor.bstr(cbor.map([cbor.uint(1), cbor.nint(7)])),
    cbor.map(),
    cbor.bstr(filled(0xab, 8)),
    cbor.bstr(filled(0xcd, 64)),
  );
}

export type ReceiptFixtureOptions = {
  /** Wrap in CBOR tag 18 (default true — matches canopy-api output). */
  tagged?: boolean;
  /** Attach the 32-byte peak as payload instead of detached nil. */
  attachedPayload?: boolean;
};

/** Build the golden receipt fixture bytes. */
export function buildReceiptFixture(
  options: ReceiptFixtureOptions = {},
): Uint8Array {
  const { tagged = true, attachedPayload = false } = options;
  const sign1 = cbor.array(
    cbor.bstr(protectedMapBytes()),
    unprotectedMap(nestedDelegationCert()),
    attachedPayload ? cbor.bstr(FIXTURE.peak) : cbor.nil(),
    cbor.bstr(FIXTURE.signature),
  );
  return tagged ? cbor.tag(18, sign1) : sign1;
}

/** A structurally valid COSE_Sign1 with no 396 inclusion proof header. */
export function buildSign1WithoutProof(): Uint8Array {
  return cbor.tag(
    18,
    cbor.array(
      cbor.bstr(protectedMapBytes()),
      cbor.map(),
      cbor.nil(),
      cbor.bstr(FIXTURE.signature),
    ),
  );
}

/** COSE_Sign1 whose protected bstr is not a CBOR map. */
export function buildSign1WithBadProtected(): Uint8Array {
  return cbor.tag(
    18,
    cbor.array(
      cbor.bstr(bytes([0xff, 0x00, 0x01])), // garbage inside the bstr
      cbor.map([
        cbor.uint(396),
        cbor.map([
          cbor.nint(1),
          cbor.array(
            cbor.map(
              [cbor.uint(1), cbor.uint(0)],
              [cbor.uint(2), cbor.array(cbor.bstr(filled(0x11, 32)))],
            ),
          ),
        ]),
      ]),
      cbor.nil(),
      cbor.bstr(FIXTURE.signature),
    ),
  );
}
