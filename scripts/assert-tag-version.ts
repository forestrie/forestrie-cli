#!/usr/bin/env bun
/**
 * Fail-closed release gate: assert that the git tag being released matches
 * the package.json version exactly (tag == "v" + version).
 *
 * Usage:
 *   bun scripts/assert-tag-version.ts [tag]
 *
 * With no argument the tag is taken from $GITHUB_REF_NAME; in that case
 * $GITHUB_REF must be the corresponding refs/tags/ ref — releases are built
 * from tags only, never from branches (workflow_dispatch recovery must be
 * dispatched with a v* tag ref).
 */
import path from "node:path";

function fail(message: string): never {
  console.error(`assert-tag-version: ${message}`);
  process.exit(1);
}

const tag = process.argv[2] ?? process.env.GITHUB_REF_NAME;
if (!tag) {
  fail("no tag: pass a tag argument or set GITHUB_REF_NAME");
}

// When the tag comes from the environment, refuse anything that is not a
// real tag ref (e.g. workflow_dispatch from a branch).
if (process.argv[2] === undefined) {
  const ref = process.env.GITHUB_REF;
  if (ref !== `refs/tags/${tag}`) {
    fail(
      `GITHUB_REF ${ref ?? "(unset)"} is not refs/tags/${tag} — releases build from v* tags only`,
    );
  }
}

if (!/^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(tag)) {
  fail(`tag ${tag} is not a v<semver> tag`);
}

const ROOT = path.resolve(new URL("..", import.meta.url).pathname);
const pkg = (await Bun.file(path.join(ROOT, "package.json")).json()) as {
  version?: string;
};
if (typeof pkg.version !== "string" || pkg.version.length === 0) {
  fail("package.json has no version");
}

const expected = `v${pkg.version}`;
if (tag !== expected) {
  fail(
    `tag ${tag} does not match package.json version ${pkg.version} (expected tag ${expected})`,
  );
}

console.log(
  `assert-tag-version: ok — tag ${tag} matches package.json version ${pkg.version}`,
);
