#!/usr/bin/env bun
/**
 * Compile the `forestrie` CLI to a single static binary via Bun.build
 * (pattern: univocity-tools scripts/build-binary.ts).
 *
 * Usage: bun scripts/build-binary.ts [--target bun-linux-x64|bun-darwin-arm64] [--outfile PATH]
 * No --target: compile for the host platform.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import path from "node:path";

const ROOT = path.resolve(new URL("..", import.meta.url).pathname);
const ENTRYPOINT = path.join(ROOT, "src/cli.ts");
const OUTDIR = path.join(ROOT, "dist");
const BINARY_NAME = "forestrie";

function usage(): never {
  console.error(
    "Usage: bun scripts/build-binary.ts [--target bun-linux-x64|bun-darwin-arm64] [--outfile PATH]",
  );
  process.exit(1);
}

function readArg(flag: string): string | undefined {
  const index = process.argv.indexOf(flag);
  if (index === -1) {
    return undefined;
  }
  const value = process.argv[index + 1];
  if (!value || value.startsWith("-")) {
    usage();
  }
  return value;
}

function suffixForTarget(target: string | undefined): string {
  if (!target) {
    return "";
  }
  if (target.endsWith("linux-x64")) {
    return "-linux-x64";
  }
  if (target.endsWith("darwin-arm64")) {
    return "-darwin-arm64";
  }
  throw new Error(`Unsupported compile target: ${target}`);
}

function adHocSignDarwin(outfile: string): void {
  if (process.platform !== "darwin") {
    return;
  }

  const remove = spawnSync("codesign", ["--remove-signature", outfile], {
    stdio: "inherit",
  });
  if (remove.status !== 0) {
    process.exit(remove.status ?? 1);
  }

  const sign = spawnSync("codesign", ["--force", "--sign", "-", outfile], {
    stdio: "inherit",
  });
  if (sign.status !== 0) {
    process.exit(sign.status ?? 1);
  }

  const verify = spawnSync("codesign", ["--verify", "--verbose=2", outfile], {
    stdio: "inherit",
  });
  if (verify.status !== 0) {
    process.exit(verify.status ?? 1);
  }
}

const target = readArg("--target");
const suffix = suffixForTarget(target);
const defaultOutfile = path.join(OUTDIR, `${BINARY_NAME}${suffix}`);
const outfile = readArg("--outfile") ?? defaultOutfile;

mkdirSync(path.dirname(outfile), { recursive: true });

type CompileTarget = Exclude<
  NonNullable<Parameters<typeof Bun.build>[0]["compile"]>,
  boolean
> extends { target?: infer T }
  ? NonNullable<T>
  : never;

const compile =
  target === undefined
    ? { outfile }
    : { target: target as CompileTarget, outfile };

const result = await Bun.build({
  entrypoints: [ENTRYPOINT],
  compile,
  minify: true,
  sourcemap: "linked",
  bytecode: false,
});

if (!result.success) {
  for (const message of result.logs) {
    console.error(message);
  }
  process.exit(1);
}

if (!target || target.includes("darwin")) {
  adHocSignDarwin(outfile);
}

console.log(`Wrote ${path.relative(ROOT, outfile)}`);
