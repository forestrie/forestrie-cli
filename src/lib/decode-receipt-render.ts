/**
 * Human rendering for `forestrie decode-receipt` (FOR-346).
 *
 * The demo money-shot: an annotated tree that makes the receipt legible
 * to an audience — it's just COSE (Sign1 + MMR inclusion). Works purely
 * from the display model so `--json` and the tree always agree.
 */

import type {
  DecodedHeaderEntry,
  DecodedReceipt,
  Json,
} from "./decode-receipt-decode.js";
import {
  CWT_CLAIMS_LABEL,
  DELEGATION_CERT_LABEL,
  PROOF_KIND_NAMES,
  SEAL_PEAK_RECEIPTS_LABEL,
  VDS_LABEL,
  VERIFIABLE_PROOFS_LABEL,
} from "./decode-receipt-labels.js";

/** Shorten `h'…'` / hex strings for tree display; JSON keeps full bytes. */
function shortHex(hex: string, keepBytes = 8): string {
  const byteLength = hex.length / 2;
  if (byteLength <= keepBytes * 2) return hex;
  return `${hex.slice(0, keepBytes * 2)}…${hex.slice(-4)}`;
}

function describeJson(value: Json): string {
  if (typeof value === "string") {
    const bytes = /^h'([0-9a-f]*)'$/.exec(value);
    if (bytes) {
      const hex = bytes[1] ?? "";
      return `${shortHex(hex)} (${hex.length / 2} bytes)`;
    }
    return JSON.stringify(value);
  }
  if (value === null) return "null";
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    return `array of ${value.length}`;
  }
  return `map of ${Object.keys(value).length}`;
}

function labelPrefix(entry: DecodedHeaderEntry): string {
  return entry.name !== null
    ? `${entry.label} (${entry.name})`
    : `${entry.label} (unknown label)`;
}

type Line = { depth: number; text: string; last?: boolean };

/** Render one unprotected 396 verifiable-proofs map as sub-lines. */
function proofLines(
  value: Json,
  receipt: DecodedReceipt,
  depth: number,
): Line[] {
  const lines: Line[] = [];
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    lines.push({ depth, text: describeJson(value) });
    return lines;
  }
  for (const [key, entry] of Object.entries(value)) {
    const kind = PROOF_KIND_NAMES.get(Number(key));
    const head = kind ? `${key} (${kind})` : `${key} (unknown proof kind)`;
    if (Number(key) === -1) {
      // Inclusion proofs — expand from the verified summary.
      lines.push({ depth, text: `${head}: 1 entry` });
      lines.push({
        depth: depth + 1,
        text: `1 (mmr index): ${receipt.inclusion.mmrIndex}`,
      });
      lines.push({
        depth: depth + 1,
        text: `2 (path): ${receipt.inclusion.pathLength} × 32-byte hashes`,
      });
      for (const [i, hash] of receipt.inclusion.path.entries()) {
        lines.push({ depth: depth + 2, text: `[${i}] ${shortHex(hash)}` });
      }
      continue;
    }
    lines.push({ depth, text: `${head}: ${describeJson(entry)}` });
  }
  return lines;
}

function unprotectedLines(
  entry: DecodedHeaderEntry,
  receipt: DecodedReceipt,
  depth: number,
): Line[] {
  if (entry.label === VERIFIABLE_PROOFS_LABEL) {
    return [
      { depth, text: `${labelPrefix(entry)}:` },
      ...proofLines(entry.value, receipt, depth + 1),
    ];
  }
  if (
    entry.label === DELEGATION_CERT_LABEL &&
    receipt.unprotected.delegation
  ) {
    const d = receipt.unprotected.delegation;
    const nested = d.nestedCoseSign1
      ? " — parses as a nested COSE_Sign1"
      : "";
    return [
      {
        depth,
        text: `${labelPrefix(entry)}: ${d.byteLength} bytes${nested}`,
      },
    ];
  }
  if (
    entry.label === SEAL_PEAK_RECEIPTS_LABEL &&
    receipt.unprotected.peakReceipts
  ) {
    return [
      {
        depth,
        text: `${labelPrefix(entry)}: ${receipt.unprotected.peakReceipts.count} receipts`,
      },
    ];
  }
  return [{ depth, text: `${labelPrefix(entry)}: ${describeJson(entry.value)}` }];
}

function protectedLines(
  entry: DecodedHeaderEntry,
  receipt: DecodedReceipt,
  depth: number,
): Line[] {
  const p = receipt.protected;
  if (entry.label === 1 && p.alg) {
    const name = p.alg.name ?? "unknown alg";
    return [{ depth, text: `1 (alg): ${p.alg.value} — ${name}` }];
  }
  if (entry.label === 4 && p.kid) {
    const text =
      "hex" in p.kid
        ? `${shortHex(p.kid.hex)} (${p.kid.byteLength} bytes)`
        : JSON.stringify(p.kid.text);
    return [{ depth, text: `4 (kid): ${text}` }];
  }
  if (entry.label === VDS_LABEL && p.vds) {
    const name = p.vds.name ?? "unknown verifiable data structure";
    return [
      {
        depth,
        text: `${VDS_LABEL} (verifiable data structure): ${p.vds.value} — ${name}`,
      },
    ];
  }
  if (entry.label === CWT_CLAIMS_LABEL && p.cwtClaims) {
    const lines: Line[] = [{ depth, text: `15 (CWT claims):` }];
    for (const claim of p.cwtClaims) {
      const head = claim.name ? `${claim.key} (${claim.name})` : `${claim.key}`;
      lines.push({
        depth: depth + 1,
        text: `${head}: ${describeJson(claim.value)}`,
      });
      if (
        claim.value !== null &&
        typeof claim.value === "object" &&
        !Array.isArray(claim.value)
      ) {
        for (const [k, v] of Object.entries(claim.value)) {
          lines.push({ depth: depth + 2, text: `${k}: ${describeJson(v)}` });
        }
      }
    }
    return lines;
  }
  return [{ depth, text: `${labelPrefix(entry)}: ${describeJson(entry.value)}` }];
}

/** Draw the annotated COSE tree with box-drawing connectors. */
function drawTree(lines: Line[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]!;
    if (line.depth === 0) {
      out.push(line.text);
      continue;
    }
    // A node is "last" among its siblings if no later line has its depth
    // before a shallower one appears.
    const isLast = (depth: number, from: number): boolean => {
      for (let j = from + 1; j < lines.length; j += 1) {
        const d = lines[j]!.depth;
        if (d < depth) return true;
        if (d === depth) return false;
      }
      return true;
    };
    let prefix = "";
    for (let depth = 1; depth < line.depth; depth += 1) {
      // Find the nearest ancestor line at `depth` at or before i.
      let ancestor = -1;
      for (let j = i; j >= 0; j -= 1) {
        if (lines[j]!.depth === depth) {
          ancestor = j;
          break;
        }
        if (lines[j]!.depth < depth) break;
      }
      prefix += ancestor >= 0 && isLast(depth, ancestor) ? "   " : "│  ";
    }
    prefix += isLast(line.depth, i) ? "└─ " : "├─ ";
    out.push(prefix + line.text);
  }
  return out;
}

/** Render the receipt as the annotated human tree. */
export function renderReceipt(receipt: DecodedReceipt): string {
  const tagText =
    receipt.tag !== null
      ? `tagged ${receipt.tag} (COSE_Sign1)`
      : "untagged (tag 18 omitted)";
  const lines: Line[] = [
    {
      depth: 0,
      text: `COSE_Sign1 — ${tagText} — ${receipt.byteLength} bytes`,
    },
  ];

  lines.push({
    depth: 1,
    text: `protected: ${receipt.protected.byteLength} bytes (CBOR map, covered by the signature)`,
  });
  if (receipt.protected.entries.length === 0) {
    lines.push({ depth: 2, text: "(empty)" });
  }
  for (const entry of receipt.protected.entries) {
    lines.push(...protectedLines(entry, receipt, 2));
  }

  lines.push({ depth: 1, text: "unprotected: (not covered by the signature)" });
  if (receipt.unprotected.entries.length === 0) {
    lines.push({ depth: 2, text: "(empty)" });
  }
  for (const entry of receipt.unprotected.entries) {
    lines.push(...unprotectedLines(entry, receipt, 2));
  }

  if (receipt.payload.detached) {
    lines.push({
      depth: 1,
      text: "payload: detached (nil) — the verifier recomputes the MMR peak from the inclusion path",
    });
  } else {
    lines.push({
      depth: 1,
      text: `payload: ${receipt.payload.byteLength} bytes — MMR peak hash ${shortHex(receipt.payload.hex)}`,
    });
  }

  lines.push({
    depth: 1,
    text: `signature: ${receipt.signature.byteLength} bytes — ${shortHex(receipt.signature.hex)}`,
  });

  const tree = drawTree(lines);

  const inclusion = receipt.inclusion;
  const peak =
    inclusion.peakHex !== null
      ? `${shortHex(inclusion.peakHex)} (from payload)`
      : inclusion.peakSource;
  return [
    ...tree,
    "",
    "MMR inclusion",
    `  mmr index:    ${inclusion.mmrIndex}`,
    `  path length:  ${inclusion.pathLength}`,
    `  peak:         ${peak}`,
  ].join("\n");
}
