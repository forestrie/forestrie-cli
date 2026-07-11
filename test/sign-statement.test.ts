import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  coseUnprotectedToMap,
  decodeCoseSign1,
  encodeCoseProtectedMapBytes,
  verifyCoseSign1WithParsedKey,
} from "@forestrie/encoding";
import {
  buildSignedStatement,
  COSE_CONTENT_TYPE,
  readPayloadBytes,
} from "../src/lib/sign-statement-build.js";
import {
  ES256_KID_BYTES,
  loadEs256SigningKey,
} from "../src/lib/sign-statement-key.js";
import { ROOT, runCli } from "./support.js";

const PAYLOAD = new TextEncoder().encode(
  '{"claim":"hello scitt wg","ts":"2026-07-11"}',
);

let dir: string;
let pemPath: string;
let x: Uint8Array;
let y: Uint8Array;

beforeAll(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), "forestrie-sign-statement-"));
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });

  pemPath = path.join(dir, "alice.es256.pem");
  writeFileSync(
    pemPath,
    privateKey.export({ type: "pkcs8", format: "pem" }) as string,
  );
  writeFileSync(
    path.join(dir, "alice.sec1.pem"),
    privateKey.export({ type: "sec1", format: "pem" }) as string,
  );
  const jwk = privateKey.export({ format: "jwk" });
  writeFileSync(path.join(dir, "alice.jwk.json"), JSON.stringify(jwk));

  x = new Uint8Array(Buffer.from(jwk.x as string, "base64url"));
  y = new Uint8Array(Buffer.from(jwk.y as string, "base64url"));

  writeFileSync(path.join(dir, "statement.json"), PAYLOAD);
  writeFileSync(path.join(dir, "garbage.pem"), "not a key at all");
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** Expected kid: first 32 bytes of x||y (= the x coordinate). */
function expectedKid(): Uint8Array {
  const xy = new Uint8Array(64);
  xy.set(x, 0);
  xy.set(y, 32);
  return xy.slice(0, ES256_KID_BYTES);
}

/** As `runCli`, but with binary stdout and optional stdin bytes. */
function runCliRaw(
  args: string[],
  stdin?: Uint8Array,
): { exitCode: number; stdout: Uint8Array; stderr: string } {
  const proc = Bun.spawnSync({
    cmd: ["bun", path.join(ROOT, "src/cli.ts"), ...args],
    cwd: ROOT,
    ...(stdin === undefined ? {} : { stdin }),
    stdout: "pipe",
    stderr: "pipe",
  });
  return {
    exitCode: proc.exitCode,
    stdout: new Uint8Array(proc.stdout),
    stderr: proc.stderr.toString(),
  };
}

describe("sign-statement key loading", () => {
  test("kid is the first 32 bytes of x||y", async () => {
    const key = await loadEs256SigningKey(pemPath);
    expect(key.kid).toEqual(expectedKid());
    expect(key.publicXY.subarray(0, 32)).toEqual(x);
    expect(key.publicXY.subarray(32)).toEqual(y);
  });

  test("SEC1 PEM and JWK files load to the same kid", async () => {
    const sec1 = await loadEs256SigningKey(path.join(dir, "alice.sec1.pem"));
    const jwk = await loadEs256SigningKey(path.join(dir, "alice.jwk.json"));
    expect(sec1.kid).toEqual(expectedKid());
    expect(jwk.kid).toEqual(expectedKid());
  });

  test("garbage key file is a structured error", async () => {
    expect(loadEs256SigningKey(path.join(dir, "garbage.pem"))).rejects.toThrow(
      /neither a PEM nor a JWK/,
    );
  });

  test("missing key file is a structured error", async () => {
    expect(loadEs256SigningKey(path.join(dir, "no-such.pem"))).rejects.toThrow(
      /cannot read key file/,
    );
  });
});

describe("sign-statement build (golden path)", () => {
  test("sign then decode round-trips and verifies", async () => {
    const key = await loadEs256SigningKey(pemPath);
    const statement = await buildSignedStatement(
      PAYLOAD,
      key,
      "application/json",
    );

    // Plain COSE Sign1: untagged array(4), protected as a plain bstr
    // (0x58 0x24 = bstr(36) for map { 4: kid(32) }) — no cbor-x tag 64.
    expect(Array.from(statement.subarray(0, 3))).toEqual([0x84, 0x58, 0x24]);

    const decoded = decodeCoseSign1(statement);
    expect(decoded).not.toBeNull();
    if (decoded === null) throw new Error("unreachable");

    // Protected header is exactly { 4: kid }.
    expect(decoded.protectedBstr).toEqual(encodeCoseProtectedMapBytes(key.kid));
    // Payload round-trips.
    expect(decoded.payloadBstr).toEqual(PAYLOAD);
    // Content type (label 3) in the unprotected header.
    const unprotected = coseUnprotectedToMap(decoded.unprotected);
    expect(unprotected.get(COSE_CONTENT_TYPE)).toBe("application/json");
    // Signature verifies against the public point.
    expect(
      await verifyCoseSign1WithParsedKey(statement, { x, y, curve: "P-256" }),
    ).toBe(true);
  });

  test("readPayloadBytes surfaces missing files as errors", () => {
    expect(() => readPayloadBytes(path.join(dir, "no-such.json"))).toThrow(
      /cannot read payload file/,
    );
  });
});

describe("forestrie sign-statement (CLI)", () => {
  test("--out writes a verifiable COSE Sign1; summary on stderr", async () => {
    const outPath = path.join(dir, "statement.cose");
    const result = runCli([
      "sign-statement",
      "--key",
      pemPath,
      "--payload",
      path.join(dir, "statement.json"),
      "--content-type",
      "application/json",
      "--out",
      outPath,
    ]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("plain COSE Sign1 (ES256)");
    expect(result.stderr).toContain(Buffer.from(expectedKid()).toString("hex"));

    const statement = new Uint8Array(readFileSync(outPath));
    expect(
      await verifyCoseSign1WithParsedKey(statement, { x, y, curve: "P-256" }),
    ).toBe(true);
  });

  test("no --out streams raw CBOR to stdout", async () => {
    const result = runCliRaw([
      "sign-statement",
      "--key",
      pemPath,
      "--payload",
      path.join(dir, "statement.json"),
    ]);
    expect(result.exitCode).toBe(0);
    const decoded = decodeCoseSign1(result.stdout);
    expect(decoded).not.toBeNull();
    expect(decoded?.payloadBstr).toEqual(PAYLOAD);
    expect(
      await verifyCoseSign1WithParsedKey(result.stdout, {
        x,
        y,
        curve: "P-256",
      }),
    ).toBe(true);
  });

  test("--payload - reads stdin", async () => {
    const outPath = path.join(dir, "stdin.cose");
    const result = runCliRaw(
      ["sign-statement", "--key", pemPath, "--payload", "-", "--out", outPath],
      PAYLOAD,
    );
    expect(result.exitCode).toBe(0);
    const statement = new Uint8Array(readFileSync(outPath));
    expect(decodeCoseSign1(statement)?.payloadBstr).toEqual(PAYLOAD);
    expect(
      await verifyCoseSign1WithParsedKey(statement, { x, y, curve: "P-256" }),
    ).toBe(true);
  });

  test("--json emits the structured report with statementB64", async () => {
    const result = runCli([
      "sign-statement",
      "--json",
      "--key",
      pemPath,
      "--payload",
      path.join(dir, "statement.json"),
      "--content-type",
      "text/plain",
    ]);
    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.stdout) as Record<string, unknown>;
    expect(report["command"]).toBe("sign-statement");
    expect(report["alg"]).toBe("ES256");
    expect(report["kid"]).toBe(Buffer.from(expectedKid()).toString("hex"));
    expect(report["payloadBytes"]).toBe(PAYLOAD.length);
    expect(report["contentType"]).toBe("text/plain");
    expect(typeof report["statementBytes"]).toBe("number");
    expect(report["out"]).toBeUndefined();

    const statement = new Uint8Array(
      Buffer.from(report["statementB64"] as string, "base64"),
    );
    expect(statement.length).toBe(report["statementBytes"] as number);
    const unprotected = coseUnprotectedToMap(
      decodeCoseSign1(statement)?.unprotected,
    );
    expect(unprotected.get(COSE_CONTENT_TYPE)).toBe("text/plain");
    expect(
      await verifyCoseSign1WithParsedKey(statement, { x, y, curve: "P-256" }),
    ).toBe(true);
  });

  test("--json with --out reports the path, not statementB64", () => {
    const outPath = path.join(dir, "json-out.cose");
    const result = runCli([
      "sign-statement",
      "--json",
      "--key",
      pemPath,
      "--payload",
      path.join(dir, "statement.json"),
      "--out",
      outPath,
    ]);
    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.stdout) as Record<string, unknown>;
    expect(report["out"]).toBe(outPath);
    expect(report["statementB64"]).toBeUndefined();
  });

  test("bad key: --json error shape and non-zero exit", () => {
    const result = runCli([
      "sign-statement",
      "--json",
      "--key",
      path.join(dir, "garbage.pem"),
      "--payload",
      path.join(dir, "statement.json"),
    ]);
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout) as Record<string, unknown>;
    expect(report["error"]).toBe("sign_statement_failed");
    expect(report["command"]).toBe("sign-statement");
    expect(typeof report["message"]).toBe("string");
  });

  test("bad key: human mode reports on stderr and exits non-zero", () => {
    const result = runCli([
      "sign-statement",
      "--key",
      path.join(dir, "garbage.pem"),
      "--payload",
      path.join(dir, "statement.json"),
    ]);
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("forestrie sign-statement:");
  });
});
