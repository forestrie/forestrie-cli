import { writeFileSync } from "node:fs";
import type { Out } from "@forestrie/cli-kit/reporting";
import type { SignStatementOptions } from "../options/sign-statement.js";
import {
  buildSignedStatement,
  readPayloadBytes,
  type SignedStatement,
} from "../lib/sign-statement-build.js";
import {
  errorMessage,
  loadEs256SigningKey,
} from "../lib/sign-statement-key.js";

/** Structured `--json` success report — the shape is a contract. */
export type SignStatementReport = {
  command: "sign-statement";
  /** COSE algorithm used for the signature. */
  alg: "ES256";
  /** Signer binding, hex: first 32 bytes of `x||y`. */
  kid: string;
  /** Payload size in bytes. */
  payloadBytes: number;
  /** COSE content type header value (label 3, protected). */
  contentType: string;
  /** Issuer (CWT claim 1, protected label 15). */
  iss: string;
  /** Subject (CWT claim 2, protected label 15). */
  sub: string;
  /** Issued-at (CWT claim 6), when `--iat` was given. */
  iat?: number;
  /** Signed statement (COSE Sign1 CBOR) size in bytes. */
  statementBytes: number;
  /** Output path, when `--out` was given. */
  out?: string;
  /** Base64 COSE Sign1 bytes, when no `--out` (JSON owns stdout). */
  statementB64?: string;
};

/** Structured `--json` error report. */
export type SignStatementError = {
  error: "sign_statement_failed";
  command: "sign-statement";
  message: string;
};

/**
 * FOR-341: build a plain COSE Sign1 signed statement
 * (`@forestrie/encoding`). `kid` = first 32 bytes of x||y under ES256;
 * alg (label 1), content type (label 3), and kid (label 4) all in the
 * **protected** header — the signature covers them; nothing interpretable
 * rides unprotected (review F1). Statement bytes go to `--out`, or raw to
 * stdout — except under `--json` without `--out`, where they are returned
 * base64 inside the report (stdout carries JSON).
 */
export async function runSignStatement(
  out: Out,
  options: SignStatementOptions,
): Promise<void> {
  let payload: Uint8Array;
  let signed: SignedStatement;
  let kidHex: string;
  try {
    payload = readPayloadBytes(options.payload);
    const key = await loadEs256SigningKey(options.key);
    signed = await buildSignedStatement(payload, key, {
      contentType: options.contentType,
      iss: options.iss,
      sub: options.sub,
      iat:
        options.iat === "now"
          ? Math.floor(Date.now() / 1000)
          : options.iat,
    });
    kidHex = Buffer.from(key.kid).toString("hex");
    if (options.out !== undefined) {
      writeFileSync(options.out, signed.statement);
    }
  } catch (err) {
    reportFailure(out, options, errorMessage(err));
    return;
  }
  const statement = signed.statement;

  if (options.json) {
    const report: SignStatementReport = {
      command: "sign-statement",
      alg: "ES256",
      kid: kidHex,
      payloadBytes: payload.length,
      contentType: options.contentType,
      iss: signed.iss,
      sub: signed.sub,
      ...(signed.iat !== undefined && { iat: signed.iat }),
      statementBytes: statement.length,
      ...(options.out !== undefined
        ? { out: options.out }
        : { statementB64: Buffer.from(statement).toString("base64") }),
    };
    out.out(JSON.stringify(report, null, 2));
    return;
  }

  if (options.out === undefined) {
    // Raw CBOR to stdout (pipeable); the summary stays on stderr.
    writeFileSync(1, statement);
  }
  out.print("signed statement: plain COSE Sign1 (ES256)");
  out.print("  kid:       %s", kidHex);
  out.print("  iss:       %s", signed.iss);
  out.print("  sub:       %s", signed.sub);
  if (signed.iat !== undefined) out.print("  iat:       %d", signed.iat);
  out.print("  payload:   %d bytes (%s)", payload.length, options.contentType);
  out.print(
    "  statement: %d bytes -> %s",
    statement.length,
    options.out ?? "stdout",
  );
}

/** Human mode: one line on stderr. `--json`: the report on stdout. */
function reportFailure(
  out: Out,
  options: SignStatementOptions,
  message: string,
): void {
  if (options.json) {
    const report: SignStatementError = {
      error: "sign_statement_failed",
      command: "sign-statement",
      message,
    };
    out.out(JSON.stringify(report, null, 2));
  } else {
    out.warn("forestrie sign-statement: %s", message);
  }
  process.exitCode = 1;
}
