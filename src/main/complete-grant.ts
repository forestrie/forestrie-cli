import { readFileSync, writeFileSync } from "node:fs";
import type { Out } from "@forestrie/cli-kit/reporting";
import type { CompleteGrantOptions } from "../options/complete-grant.js";
import {
  CompleteGrantFailure,
  deriveCompletedGrant,
  type CompletedGrant,
  type CompleteGrantReason,
  type CompleteGrantStage,
} from "../lib/complete-grant-derive.js";

/**
 * FOR-344: self-create the `Authorization: Forestrie-Grant` header content
 * from a checkpoint (+ local massif) — grants are derivable from log data,
 * not operator-issued. The offline twin of `register-grant`'s completion:
 * locate the grant's leaf in the massif, rebuild its inclusion receipt against
 * the checkpoint's pre-signed peak, and attach receipt + idtimestamp with no
 * re-signing.
 */

/** Where an operational error broke the run. */
export type CompleteGrantErrorStage = "input" | CompleteGrantStage;

/** `--json` operational-error shape — stable stage + reason tokens. */
export type CompleteGrantErrorReport = {
  error:
    | "complete_grant_input_failed"
    | "complete_grant_decode_failed"
    | "complete_grant_locate_failed"
    | "complete_grant_parse_failed"
    | "complete_grant_derive_failed";
  command: "complete-grant";
  stage: CompleteGrantErrorStage;
  reason?: CompleteGrantReason;
  message: string;
};

/** Structured `--json` success report — the shape is a contract. */
export type CompleteGrantReport = {
  command: "complete-grant";
  status: "completed";
  entryId: string;
  mmrIndex: string;
  idtimestamp: string;
  idtimestampSource: CompletedGrant["idtimestampSource"];
  proof: {
    length: number;
    peakIndex: number;
    peakCount: number;
  };
  sealedSize: string;
  certCopied: boolean;
  receiptBytes: number;
  /** Present when `--out-b64` was given. */
  outB64?: string;
  /** Completed grant base64 — only when not written to `--out-b64`. */
  grantB64?: string;
};

const ERROR_CODES: Record<
  CompleteGrantErrorStage,
  CompleteGrantErrorReport["error"]
> = {
  input: "complete_grant_input_failed",
  decode: "complete_grant_decode_failed",
  locate: "complete_grant_locate_failed",
  parse: "complete_grant_parse_failed",
  derive: "complete_grant_derive_failed",
};

const IDTIMESTAMP_HEX_RE = /^[0-9a-f]{16}$/i;

/** An operational error that carries the stage but no lib reason. */
class InputError extends Error {}

function readBytes(path: string, flag: string): Uint8Array {
  try {
    return new Uint8Array(readFileSync(path));
  } catch (err) {
    throw new InputError(
      `cannot read ${flag} '${path}': ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

function hexToBe8(hex: string): Uint8Array {
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Resolve `--idtimestamp <hex|path>` to 8 big-endian bytes: a bare 16-char hex
 * value, or a file holding either the 8 raw bytes or a hex string.
 */
function parseIdtimestampOption(value: string): Uint8Array {
  const trimmed = value.trim();
  if (IDTIMESTAMP_HEX_RE.test(trimmed)) return hexToBe8(trimmed);
  let raw: Uint8Array;
  try {
    raw = new Uint8Array(readFileSync(value));
  } catch (err) {
    throw new InputError(
      `--idtimestamp is neither 16 hex chars nor a readable file '${value}': ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (raw.length === 8) return raw;
  const text = new TextDecoder().decode(raw).trim();
  if (IDTIMESTAMP_HEX_RE.test(text)) return hexToBe8(text);
  throw new InputError(
    `--idtimestamp file '${value}' must be 8 raw bytes or 16 hex chars`,
  );
}

/** Structured envelope under `--json`; one clean line on stderr otherwise. */
function reportRunError(
  out: Out,
  options: CompleteGrantOptions,
  stage: CompleteGrantErrorStage,
  err: unknown,
): void {
  const message = err instanceof Error ? err.message : String(err);
  const reason = err instanceof CompleteGrantFailure ? err.reason : undefined;
  if (options.json) {
    const report: CompleteGrantErrorReport = {
      error: ERROR_CODES[stage],
      command: "complete-grant",
      stage,
      ...(reason !== undefined ? { reason } : {}),
      message,
    };
    out.out(JSON.stringify(report, null, 2));
  } else {
    out.warn("forestrie complete-grant: %s: %s", stage, message);
  }
  process.exitCode = 1;
}

export async function runCompleteGrant(
  out: Out,
  options: CompleteGrantOptions,
): Promise<void> {
  // 1. Inputs. The massif is required — it is what carries the leaf we recover
  //    the mmrIndex and idtimestamp from.
  let grantBase64: string;
  let massifBytes: Uint8Array;
  let checkpointBytes: Uint8Array;
  let idtimestampOverride: Uint8Array | undefined;
  try {
    if (options.massif === undefined) {
      throw new InputError(
        "--massif is required: the grant's leaf (mmrIndex + idtimestamp) is " +
          "recovered from the local massif blob",
      );
    }
    grantBase64 = readFileSync(options.grant, "utf8").trim();
    massifBytes = readBytes(options.massif, "--massif");
    checkpointBytes = readBytes(options.checkpoint, "--checkpoint");
    idtimestampOverride =
      options.idtimestamp !== undefined
        ? parseIdtimestampOption(options.idtimestamp)
        : undefined;
  } catch (err) {
    if (err instanceof InputError) {
      reportRunError(out, options, "input", err);
      return;
    }
    reportRunError(
      out,
      options,
      "input",
      new InputError(
        `cannot read --grant '${options.grant}': ${
          err instanceof Error ? err.message : String(err)
        }`,
      ),
    );
    return;
  }

  // 2. Derive the completed grant.
  let completed: CompletedGrant;
  try {
    completed = await deriveCompletedGrant({
      grantBase64,
      massifBytes,
      checkpointBytes,
      idtimestampOverride,
    });
  } catch (err) {
    const stage = err instanceof CompleteGrantFailure ? err.stage : "derive";
    reportRunError(out, options, stage, err);
    return;
  }

  // 3. Emit.
  try {
    if (options.outB64 !== undefined) {
      writeFileSync(options.outB64, completed.completedBase64);
    }
  } catch (err) {
    reportRunError(out, options, "input", new InputError(
      `cannot write --out-b64 '${options.outB64}': ${
        err instanceof Error ? err.message : String(err)
      }`,
    ));
    return;
  }

  const idtimestampHex = completed.entryIdHex.slice(0, 16);
  if (options.json) {
    const report: CompleteGrantReport = {
      command: "complete-grant",
      status: "completed",
      entryId: completed.entryIdHex,
      mmrIndex: completed.mmrIndex.toString(10),
      idtimestamp: idtimestampHex,
      idtimestampSource: completed.idtimestampSource,
      proof: {
        length: completed.proofLength,
        peakIndex: completed.peakIndex,
        peakCount: completed.peakCount,
      },
      sealedSize: completed.sealedSize.toString(10),
      certCopied: completed.certCopied,
      receiptBytes: completed.receiptBytes,
      ...(options.outB64 !== undefined
        ? { outB64: options.outB64 }
        : { grantB64: completed.completedBase64 }),
    };
    out.out(JSON.stringify(report, null, 2));
    return;
  }

  // Human mode: without --out-b64 the completed grant base64 is the pipeable
  // product on stdout; the summary narrates on stderr (mirrors register-grant).
  const emit = options.outB64 === undefined ? out.print : out.out;
  emit("complete-grant: leaf       — mmrIndex %s (recovered from massif)", completed.mmrIndex.toString(10));
  emit(
    "complete-grant: entry id   — %s (idtimestamp from %s)",
    completed.entryIdHex,
    completed.idtimestampSource,
  );
  emit(
    "complete-grant: proof      — %d node(s) to peak %d/%d",
    completed.proofLength,
    completed.peakIndex + 1,
    completed.peakCount,
  );
  emit(
    "complete-grant: checkpoint — sealed size %s, delegation cert copied: %s",
    completed.sealedSize.toString(10),
    completed.certCopied ? "yes" : "no",
  );
  emit("complete-grant: receipt    — %d bytes attached (header 396)", completed.receiptBytes);
  if (options.outB64 !== undefined) {
    emit("complete-grant: wrote completed grant (base64) to %s", options.outB64);
  } else {
    out.out("%s", completed.completedBase64);
  }
}
