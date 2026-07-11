import { describe, expect, test } from "bun:test";

/**
 * The FOR-339 acceptance substrate: every package the subcommand
 * implementations will build on must resolve and import from the
 * published npmjs set — no workspace or repo-internal dependencies
 * (plan-2607-12).
 */
const PUBLISHED_PACKAGES = [
  "@forestrie/cli-kit",
  "@forestrie/cli-kit/reporting",
  "@forestrie/delegation-cose",
  "@forestrie/deploy-core",
  "@forestrie/encoding",
  "@forestrie/grant-builder",
  "@forestrie/merklelog",
  "@forestrie/receipt-verify",
  "@forestrie/scrapi-client",
];

describe("published package substrate", () => {
  for (const name of PUBLISHED_PACKAGES) {
    test(`${name} imports`, async () => {
      const module = (await import(name)) as Record<string, unknown>;
      expect(Object.keys(module).length).toBeGreaterThan(0);
    });
  }
});
