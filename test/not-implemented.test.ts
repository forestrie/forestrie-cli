import { describe, expect, test } from "bun:test";
import { runCli, SUBCOMMANDS } from "./support.js";

describe("subcommand stubs", () => {
  for (const [name, spec] of Object.entries(SUBCOMMANDS)) {
    test(`${name}: human mode exits non-zero with the ${spec.issue} message`, () => {
      const result = runCli([name, ...spec.args]);
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain(
        `forestrie ${name}: not implemented yet — ${spec.issue}`,
      );
    });

    test(`${name}: --json emits the structured report on stdout`, () => {
      const result = runCli([name, "--json", ...spec.args]);
      expect(result.exitCode).toBe(1);
      const report = JSON.parse(result.stdout) as Record<string, unknown>;
      expect(report["error"]).toBe("not_implemented");
      expect(report["command"]).toBe(name);
      expect(report["issue"]).toBe(spec.issue);
      expect(typeof report["message"]).toBe("string");
      expect(typeof report["options"]).toBe("object");
    });
  }
});
