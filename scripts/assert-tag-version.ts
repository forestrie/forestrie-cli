#!/usr/bin/env bun
/**
 * Fail-closed release gate shared by release.yml (GitHub binaries) and
 * publish.yml (npmjs), modelled on canopy scripts/assert-publish-version.sh.
 *
 * Usage:
 *   bun scripts/assert-tag-version.ts [tag]          # tag mode
 *   bun scripts/assert-tag-version.ts --registry ... # + registry check
 *
 * Two modes, selected the same way canopy selects them:
 *
 *   Tag build (GITHUB_REF is refs/tags/v*, or a tag is passed):
 *     the tag must name exactly the package.json version, so a tag can
 *     never release a version other than the one it names.
 *
 *   Dispatch build (workflow_dispatch recovery, no tag ref):
 *     refuse. Releases build from v* tags only.
 *
 * `--registry` additionally asserts the version is NOT already on npmjs,
 * so a re-run of publish.yml over an existing tag fails here with a
 * readable message instead of half-way through `npm publish`. It is
 * advisory-strict: an ambiguous registry answer fails closed.
 *
 * Runtime-neutral (node:fs / node:child_process) so it runs under both
 * `bun` and `node` — publish.yml has both on PATH.
 */
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

function fail(message: string): never {
  console.error(`assert-tag-version: ${message}`);
  process.exit(1);
}

const argv = process.argv.slice(2);
const checkRegistry = argv.includes("--registry");
const positional = argv.filter((arg) => !arg.startsWith("-"));

const tag = positional[0] ?? process.env["GITHUB_REF_NAME"];
if (!tag) {
  fail("no tag: pass a tag argument or set GITHUB_REF_NAME");
}

// When the tag comes from the environment, refuse anything that is not a
// real tag ref (e.g. workflow_dispatch from a branch).
if (positional[0] === undefined) {
  const ref = process.env["GITHUB_REF"];
  if (ref !== `refs/tags/${tag}`) {
    fail(
      `GITHUB_REF ${ref ?? "(unset)"} is not refs/tags/${tag} — releases build from v* tags only`,
    );
  }
}

if (!/^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(tag)) {
  fail(`tag ${tag} is not a v<semver> tag`);
}

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const pkg = JSON.parse(
  readFileSync(path.join(ROOT, "package.json"), "utf8"),
) as { name?: string; version?: string };
if (typeof pkg.version !== "string" || pkg.version.length === 0) {
  fail("package.json has no version");
}
if (typeof pkg.name !== "string" || pkg.name.length === 0) {
  fail("package.json has no name");
}

const expected = `v${pkg.version}`;
if (tag !== expected) {
  fail(
    `tag ${tag} does not match package.json version ${pkg.version} (expected tag ${expected})`,
  );
}

if (checkRegistry) {
  const spec = `${pkg.name}@${pkg.version}`;
  const view = spawnSync("npm", ["view", spec, "version"], {
    encoding: "utf8",
  });
  const output = `${view.stdout ?? ""}${view.stderr ?? ""}`;
  if (view.error) {
    fail(`could not run npm view ${spec}: ${view.error.message}`);
  }
  if (view.status === 0 && output.trim().length > 0) {
    fail(
      `${spec} is already published — bump package.json and retag rather than republishing`,
    );
  }
  if (view.status === 0) {
    // exit 0 with empty output is ambiguous — refuse rather than guess.
    fail(`npm view ${spec} succeeded with no output; refusing on ambiguity`);
  }
  if (!output.includes("E404")) {
    fail(
      `could not determine whether ${spec} exists on the registry (npm view exit ${view.status}):\n${output}`,
    );
  }
  console.log(`assert-tag-version: ok — ${spec} is not on the registry`);
}

console.log(
  `assert-tag-version: ok — tag ${tag} matches package.json version ${pkg.version}`,
);
