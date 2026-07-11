/**
 * COSE / forestrie header label registry for `forestrie decode-receipt`
 * (FOR-346). Naming only — decoding never requires a label to be known,
 * and unknown labels are always shown raw, never dropped.
 *
 * Sources: RFC 9052 (COSE headers), RFC 9597 (CWT claims header 15),
 * RFC 8392 (CWT claim keys), draft-ietf-cose-merkle-tree-proofs
 * (395 vds / 396 verifiable proofs), and the forestrie private-use
 * labels (canopy grants.md, ADR-0046, plan-0033 format v3,
 * `@forestrie/receipt-verify` forest-genesis-labels).
 */

/** CBOR tag for COSE_Sign1 (RFC 9052 §2). */
export const COSE_SIGN1_TAG = 18;

/** Verifiable proofs unprotected header (draft-ietf-cose-merkle-tree-proofs). */
export const VERIFIABLE_PROOFS_LABEL = 396;
/** Verifiable data structure protected header (draft-ietf-cose-merkle-tree-proofs). */
export const VDS_LABEL = 395;
/** CWT claims in a COSE header (RFC 9597). */
export const CWT_CLAIMS_LABEL = 15;
/** Delegation certificate — Custodian per-log delegation, nested COSE_Sign1. */
export const DELEGATION_CERT_LABEL = 1000;
/** Pre-signed peak inclusion receipts on a checkpoint (`SealPeakReceiptsLabel`). */
export const SEAL_PEAK_RECEIPTS_LABEL = -65931;

/** Inclusion proofs key inside header 396. */
export const PROOFS_INCLUSION_KEY = -1;
/** Consistency proofs key inside header 396. */
export const PROOFS_CONSISTENCY_KEY = -2;

export type LabelInfo = {
  name: string;
  /** Short provenance / meaning note for human output. */
  note?: string;
};

/** COSE header labels (protected and unprotected share the number space). */
export const HEADER_LABELS: ReadonlyMap<number, LabelInfo> = new Map([
  [1, { name: "alg" }],
  [2, { name: "crit" }],
  [3, { name: "content type" }],
  [4, { name: "kid" }],
  [5, { name: "IV" }],
  [6, { name: "partial IV" }],
  [CWT_CLAIMS_LABEL, { name: "CWT claims", note: "RFC 9597" }],
  [
    VDS_LABEL,
    { name: "verifiable data structure", note: "COSE receipts (draft)" },
  ],
  [
    VERIFIABLE_PROOFS_LABEL,
    { name: "verifiable proofs", note: "COSE receipts (draft)" },
  ],
  [
    DELEGATION_CERT_LABEL,
    {
      name: "delegation certificate",
      note: "forestrie: Custodian per-log delegation (nested COSE_Sign1)",
    },
  ],
  [-65537, { name: "idtimestamp", note: "forestrie private-use" }],
  [-65538, { name: "forestrie grant v0", note: "forestrie private-use" }],
  [
    SEAL_PEAK_RECEIPTS_LABEL,
    {
      name: "pre-signed peak receipts",
      note: "forestrie SealPeakReceiptsLabel (checkpoint header)",
    },
  ],
  [-68009, { name: "forest genesis version", note: "forestrie private-use" }],
  [-68011, { name: "univocity address", note: "forestrie private-use" }],
  [-68013, { name: "chain id", note: "forestrie private-use" }],
  [-68014, { name: "forest genesis alg", note: "forestrie private-use" }],
  [-68015, { name: "bootstrap key", note: "forestrie private-use" }],
]);

/** COSE algorithm names (RFC 9053 + forestrie private-use). */
export const ALG_NAMES: ReadonlyMap<number, string> = new Map([
  [-7, "ES256 (ECDSA P-256 + SHA-256)"],
  [-8, "EdDSA"],
  [-35, "ES384"],
  [-36, "ES512"],
  [-65799, "KS256 (secp256k1 + Keccak-256, forestrie private-use)"],
]);

/** Verifiable data structure ids (draft-ietf-cose-merkle-tree-proofs registry). */
export const VDS_NAMES: ReadonlyMap<number, string> = new Map([
  [1, "RFC9162_SHA256 (Certificate Transparency)"],
  [2, "CCF_LEDGER_SHA256"],
  [3, "MMRIVER (draft-bryce COSE MMR proofs)"],
]);

/** CWT claim keys (RFC 8392 §3.1, cnf per RFC 8747). */
export const CWT_CLAIM_NAMES: ReadonlyMap<number, string> = new Map([
  [1, "iss"],
  [2, "sub"],
  [3, "aud"],
  [4, "exp"],
  [5, "nbf"],
  [6, "iat"],
  [7, "cti"],
  [8, "cnf (confirmation / ephemeral key)"],
]);

/** COSE_Key parameter names (RFC 9052 §7) — for cnf / ephemeral keys. */
export const COSE_KEY_PARAM_NAMES: ReadonlyMap<number, string> = new Map([
  [1, "kty"],
  [2, "kid"],
  [3, "alg"],
  [-1, "crv"],
  [-2, "x"],
  [-3, "y"],
]);

/** Keys inside header 396 (draft-ietf-cose-merkle-tree-proofs). */
export const PROOF_KIND_NAMES: ReadonlyMap<number, string> = new Map([
  [PROOFS_INCLUSION_KEY, "inclusion proofs"],
  [PROOFS_CONSISTENCY_KEY, "consistency proofs"],
]);

/** Look up a header label name; null when unknown (caller shows it raw). */
export function headerLabelInfo(label: number): LabelInfo | null {
  return HEADER_LABELS.get(label) ?? null;
}
