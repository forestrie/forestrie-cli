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

  // Spawns `forestrie <cmd> --help` once per subcommand — real subprocess
  // cold-starts that scale with the command set, so the default 5s per-test
  // timeout is too tight on a loaded CI runner. Give it headroom.
  test("subcommand --help exits 0 and names its FOR-34x issue", () => {
    for (const [name, spec] of Object.entries(SUBCOMMANDS)) {
      const result = runCli([name, "--help"]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout + result.stderr).toContain(spec.issue);
    }
  }, 30_000);

  test("log groups wait-anchored, whose help names its inputs", () => {
    const root = runCli(["--help"]);
    expect(root.stdout + root.stderr).toContain("log");
    const group = runCli(["log", "--help"]);
    expect(group.exitCode).toBe(0);
    expect(group.stdout + group.stderr).toContain("wait-anchored");
    const wait = runCli(["log", "wait-anchored", "--help"]);
    expect(wait.exitCode).toBe(0);
    const text = wait.stdout + wait.stderr;
    for (const flag of [
      "--create-grant",
      "--genesis",
      "--univocity",
      "--rpc-url",
      "--timeout",
      "--interval",
    ]) {
      expect(text).toContain(flag);
    }
  });

  test("verify help notes ES256 and offline", () => {
    const result = runCli(["verify", "--help"]);
    const text = result.stdout + result.stderr;
    expect(text).toContain("ES256");
    expect(text.toLowerCase()).toContain("no network");
  });
});
