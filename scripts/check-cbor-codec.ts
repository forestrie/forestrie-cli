#!/usr/bin/env bun
/**
 * CBOR codec gate: cbor-x is BANNED (standing platform rule, applied
 * repo-wide in mandate#74; sibling gate in canopy scripts/).
 *
 * cbor-x serialises JavaScript, not CBOR — record extensions for plain
 * objects, tag 259 for Maps, tag 64 for Uint8Array — all COSE-incompatible
 * and rejected (or surfaced as opaque tags) by canopy's strict
 * deterministic decoder. The platform codec is `@forestrie/encoding`;
 * delegation profiles come via `@forestrie/delegation-cose` >= 0.1.5.
 *
 * Fails on any cbor-x import/require or package.json dependency. Comments
 * MAY mention cbor-x (history, warnings) — only real usage trips the gate.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const IMPORT_PATTERN =
  /(from\s+["']cbor-x["'@])|(require\(\s*["']cbor-x["']\s*\))|(import\(\s*["']cbor-x["']\s*\))/;
const DEP_PATTERN = /"cbor-x"\s*:/;

const SELF = "scripts/check-cbor-codec.ts";

const files = execFileSync("git", ["ls-files", "--", "src", "scripts", "package.json"], {
  encoding: "utf8",
})
  .split("\n")
  .filter(
    (f) =>
      /\.(ts|tsx|mts|cts|js|mjs|cjs)$/.test(f) || f.endsWith("package.json"),
  );

const hits: string[] = [];
for (const file of files) {
  if (file === SELF) continue;
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    continue;
  }
  const pattern = file.endsWith("package.json") ? DEP_PATTERN : IMPORT_PATTERN;
  text.split("\n").forEach((line, i) => {
    if (pattern.test(line)) {
      hits.push(`${file}:${i + 1}: ${line.trim()}`);
    }
  });
}

if (hits.length > 0) {
  console.error(
    "cbor-codec gate: cbor-x is banned (COSE-incompatible encoding defaults).\n" +
      "Use @forestrie/encoding (encodeCborDeterministic / decodeCborDeterministic).\n",
  );
  for (const hit of hits) console.error(`  ${hit}`);
  process.exit(1);
}
console.log(`cbor-codec gate: clean (${files.length} files scanned)`);
