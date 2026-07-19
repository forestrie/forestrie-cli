import { describe, expect, test } from "bun:test";
import { createCaptureOut } from "@forestrie/cli-kit/reporting";
import {
  decodeCborDeterministic,
  encodeCborDeterministic,
} from "@forestrie/encoding";
import { runAdminOnboardToken } from "../src/main/admin-onboard-token.js";
import type { AdminOnboardTokenOptions } from "../src/options/admin-onboard-token.js";
import { runCli } from "./support.js";

const OPS_TOKEN = "ops-secret-never-printed";
const MINTED = "onboard-token-abc123";

const baseOptions: AdminOnboardTokenOptions = {
  json: false,
  verbosity: 0,
  baseUrl: "https://api.example.dev",
  opsToken: OPS_TOKEN,
  label: "unit-test",
  out: undefined,
};

type Seen = {
  url: string;
  auth: string | null;
  contentType: string | null;
  body: Uint8Array;
};

function mintFetch(
  seen: Seen[],
  respond: () => Response,
): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const body = new Uint8Array(init?.body as ArrayBuffer);
    const headers = new Headers(init?.headers);
    seen.push({
      url: String(input),
      auth: headers.get("Authorization"),
      contentType: headers.get("Content-Type"),
      body,
    });
    return respond();
  }) as typeof fetch;
}

function stdout(out: ReturnType<typeof createCaptureOut>): string {
  return out.lines
    .filter((l) => l.stream === "stdout")
    .map((l) => l.text)
    .join("\n");
}

function allOutput(out: ReturnType<typeof createCaptureOut>): string {
  return out.lines.map((l) => l.text).join("\n");
}

const okResponse = () =>
  new Response(
    encodeCborDeterministic(
      new Map<string, string>([
        ["cref", "cref-1"],
        ["label", "unit-test"],
        ["token", MINTED],
      ]),
    ),
    { status: 201, headers: { "Content-Type": "application/cbor" } },
  );

describe("admin onboard-token", () => {
  test("mints against /api/payments/onboard-tokens with the exact deterministic body", async () => {
    const out = createCaptureOut();
    const seen: Seen[] = [];
    process.exitCode = 0;
    await runAdminOnboardToken(out, baseOptions, {
      fetchImpl: mintFetch(seen, okResponse),
    });
    expect(process.exitCode).toBe(0);
    expect(seen).toHaveLength(1);
    expect(seen[0]!.url).toBe(
      "https://api.example.dev/api/payments/onboard-tokens",
    );
    expect(seen[0]!.auth).toBe(`Bearer ${OPS_TOKEN}`);
    expect(seen[0]!.contentType).toBe("application/cbor");
    // Exact wire bytes: {1: "unit-test"} — A1 01 69 "unit-test".
    expect(Buffer.from(seen[0]!.body)).toEqual(
      Buffer.concat([
        Buffer.from([0xa1, 0x01, 0x69]),
        Buffer.from("unit-test", "utf8"),
      ]),
    );
    // Round-trip sanity through the sanctioned decoder.
    const decoded = decodeCborDeterministic(seen[0]!.body);
    const label =
      decoded instanceof Map
        ? decoded.get(1)
        : (decoded as Record<string, unknown>)["1"];
    expect(label).toBe("unit-test");
    // The token is the only stdout product.
    expect(stdout(out)).toBe(MINTED);
    // The operator credential never appears anywhere in the output.
    expect(allOutput(out)).not.toContain(OPS_TOKEN);
  });

  test("--json reports the token, label, and cref", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    await runAdminOnboardToken(
      out,
      { ...baseOptions, json: true },
      { fetchImpl: mintFetch([], okResponse) },
    );
    expect(process.exitCode).toBe(0);
    const report = JSON.parse(stdout(out)) as Record<string, unknown>;
    expect(report["command"]).toBe("admin onboard-token");
    expect(report["status"]).toBe("minted");
    expect(report["token"]).toBe(MINTED);
    expect(report["cref"]).toBe("cref-1");
    expect(allOutput(out)).not.toContain(OPS_TOKEN);
  });

  test("a rejected mint fails with the HTTP status and no secret leakage", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    await runAdminOnboardToken(out, baseOptions, {
      fetchImpl: mintFetch([], () => new Response("nope", { status: 403 })),
    });
    expect(process.exitCode).toBe(1);
    expect(allOutput(out)).toContain("HTTP 403");
    expect(allOutput(out)).not.toContain(OPS_TOKEN);
  });

  test("a token-less response fails as response_malformed", async () => {
    const out = createCaptureOut();
    process.exitCode = 0;
    await runAdminOnboardToken(
      out,
      { ...baseOptions, json: true },
      {
        fetchImpl: mintFetch([], () =>
          new Response(
            encodeCborDeterministic(new Map([["label", "unit-test"]])),
            { status: 201 },
          ),
        ),
      },
    );
    expect(process.exitCode).toBe(1);
    const report = JSON.parse(stdout(out)) as Record<string, unknown>;
    expect(report["error"]).toBe("response_malformed");
  });

  test("cli: admin family and onboard-token surface in help", () => {
    const root = runCli(["--help"]);
    expect(root.exitCode).toBe(0);
    expect(`${root.stdout}${root.stderr}`).toContain("admin");
    const admin = runCli(["admin", "--help"]);
    expect(admin.exitCode).toBe(0);
    expect(`${admin.stdout}${admin.stderr}`).toContain("onboard-token");
  });

  test("cli: missing ops token is a usage error", () => {
    const result = runCli([
      "admin",
      "onboard-token",
      "--base-url",
      "https://api.example.dev",
    ]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("ops-token");
  });
});
