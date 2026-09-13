import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import path from "node:path";
import { ROOT } from "./support.js";

/**
 * Guards for the published library surface
 * (`@forestrie/forestrie-cli/decode-receipt`, package.json `exports`).
 *
 * The package is a CLI, but @forestrie/mcp-verify depends on this
 * decoder rather than vendoring it, so the entry has two contracts that
 * are easy to break by accident from inside a CLI repo:
 *
 *  1. It stays runtime-neutral — no `node:*`, no `Bun.*`. tsconfig.lib
 *     emits exactly the modules the entry reaches, so a stray
 *     `node:fs` import there would both break browser/worker consumers
 *     and start dragging CLI internals into the tarball.
 *  2. Its named exports do not silently disappear.
 */

/** The module group tsconfig.lib.json emits for the library entry. */
const LIBRARY_SOURCES = [
  "src/index.ts",
  "src/decode-receipt.ts",
  "src/lib/decode-receipt-cbor.ts",
  "src/lib/decode-receipt-decode.ts",
  "src/lib/decode-receipt-labels.ts",
  "src/lib/decode-receipt-render.ts",
];

/** Bare specifiers the library entry is allowed to reach outside itself. */
const ALLOWED_EXTERNALS = new Set([
  "@forestrie/receipt-verify",
  "@forestrie/encoding",
]);

function importSpecifiers(source: string): string[] {
  return [...source.matchAll(/(?:^|[\s;])(?:import|export)[^;]*?from\s+"([^"]+)"/g)]
    .map((match) => match[1] as string);
}

describe("published library entry — decode-receipt", () => {
  for (const relative of LIBRARY_SOURCES) {
    test(`${relative} imports no runtime-specific API`, () => {
      const source = readFileSync(path.join(ROOT, relative), "utf8");
      // Comments mention `node:*` / `Bun.*` by name; only code counts.
      const code = source
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/^\s*\/\/.*$/gm, "");
      expect(code).not.toMatch(/\bBun\s*\./);
      for (const specifier of importSpecifiers(code)) {
        if (specifier.startsWith(".")) {
          continue;
        }
        expect({ relative, specifier }).toEqual({
          relative,
          specifier: ALLOWED_EXTERNALS.has(specifier)
            ? specifier
            : `<disallowed: ${specifier}>`,
        });
      }
    });
  }

  test("the entry exports the documented surface", async () => {
    const entry = (await import("../src/decode-receipt.js")) as Record<
      string,
      unknown
    >;
    for (const name of [
      "decodeReceipt",
      "renderReceipt",
      "DecodeReceiptError",
      "CborDecodeError",
      "bytesToHex",
      "toJson",
      "decodeCborMap",
      "decodeCborValue",
      "isCborTagged",
      "headerLabelInfo",
      "HEADER_LABELS",
      "ALG_NAMES",
      "VDS_NAMES",
      "CWT_CLAIM_NAMES",
      "COSE_KEY_PARAM_NAMES",
      "PROOF_KIND_NAMES",
    ]) {
      expect(entry).toHaveProperty(name);
    }
  });

  test("package.json exports point at files build:lib emits", () => {
    const pkg = JSON.parse(
      readFileSync(path.join(ROOT, "package.json"), "utf8"),
    ) as {
      exports: Record<string, { types?: string; import?: string } | string>;
      files: string[];
      bin: Record<string, string>;
    };
    expect(pkg.exports["."]).toEqual({
      types: "./dist/index.d.ts",
      import: "./dist/index.js",
    });
    expect(pkg.exports["./decode-receipt"]).toEqual({
      types: "./dist/decode-receipt.d.ts",
      import: "./dist/decode-receipt.js",
    });
    expect(pkg.bin["forestrie"]).toBe("dist/cli.js"); // no "./": npm drops a bin whose path it has to normalise
    for (const entry of ["dist", "LICENSE", "README.md", "TRUST-MODEL.md"]) {
      expect(pkg.files).toContain(entry);
    }
  });
});
