import { readFileSync } from "node:fs";

import type { Out } from "@forestrie/cli-kit/reporting";
import type { DecodeReceiptOptions } from "../options/decode-receipt.js";
import {
  DecodeReceiptError,
  decodeReceipt,
  type DecodedReceipt,
} from "../lib/decode-receipt-decode.js";
import { renderReceipt } from "../lib/decode-receipt-render.js";

/** `--json` decode failure shape (stage names the parse step that failed). */
export type DecodeReceiptFailure = {
  error: "decode_failed";
  command: "decode-receipt";
  stage: string;
  message: string;
};

function readReceiptBytes(options: DecodeReceiptOptions): Uint8Array {
  const source = options.receipt ?? "-";
  try {
    // fd 0: read stdin when the positional is omitted or `-`.
    const buffer = source === "-" ? readFileSync(0) : readFileSync(source);
    return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new DecodeReceiptError(
      "input",
      source === "-"
        ? `cannot read receipt from stdin: ${detail}`
        : `cannot read receipt file ${source}: ${detail}`,
    );
  }
}

/**
 * FOR-346: decode a COSE receipt so the audience sees it is just COSE
 * (Sign1 + MMR inclusion). Display only — no signature verification
 * (that is `forestrie verify`, FOR-347).
 */
export async function runDecodeReceipt(
  out: Out,
  options: DecodeReceiptOptions,
): Promise<void> {
  let decoded: DecodedReceipt;
  try {
    decoded = decodeReceipt(readReceiptBytes(options));
  } catch (error) {
    const stage = error instanceof DecodeReceiptError ? error.stage : "decode";
    const message = error instanceof Error ? error.message : String(error);
    if (options.json) {
      const failure: DecodeReceiptFailure = {
        error: "decode_failed",
        command: "decode-receipt",
        stage,
        message,
      };
      out.out(JSON.stringify(failure, null, 2));
    } else {
      out.warn("forestrie decode-receipt: %s: %s", stage, message);
    }
    process.exitCode = 1;
    return;
  }

  if (options.json) {
    out.out(JSON.stringify(decoded, null, 2));
    return;
  }
  out.out(renderReceipt(decoded));
}
