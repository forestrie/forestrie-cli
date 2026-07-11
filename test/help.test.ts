import { describe, expect, test } from "bun:test";
import { runCli, SUBCOMMANDS } from "./support.js";

describe("forestrie --help", () => {
  test("exits 0 and lists every subcommand", () => {
    const result = runCli(["--help"]);
    expect(result.exitCode).toBe(0);
    const text = result.stdout + result.stderr;
    expect(text).toContain("forestrie");
    for (const name of Object.keys(SUBCOMMANDS)) {
      expect(text).toContain(name);
    }
  });

  test("subcommand --help exits 0 and names its FOR-34x issue", () => {
    for (const [name, spec] of Object.entries(SUBCOMMANDS)) {
      const result = runCli([name, "--help"]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout + result.stderr).toContain(spec.issue);
    }
  });

  test("verify help notes ES256 and offline", () => {
    const result = runCli(["verify", "--help"]);
    const text = result.stdout + result.stderr;
    expect(text).toContain("ES256");
    expect(text.toLowerCase()).toContain("no network");
  });
});
