import { readFileSync } from "node:fs";
import {
  decodeForestrieGrantCose,
  decodeGrantPayload,
  entryIdHexToIdtimestampBe8,
  type VerifyGrantReceiptOfflineInput,
} from "@forestrie/receipt-verify";

/**
 * Load and decode `forestrie verify` inputs into the exact
 * `verifyGrantReceiptOffline` input shape (FOR-347). Pure file/decode work
 * — strictly no network.
 *
 * Grant sources (mirrors the canopy FOR-282 tracer):
 * - `--committed-grant`: base64 of either a Forestrie-Grant COSE Sign1
 *   (carries the idtimestamp in unprotected header -65537) or a raw grant
 *   payload CBOR (keys 1–6; then `--entry-id` must supply the idtimestamp).
 * - `--committed-grant-file` + `--entry-id`: grant CBOR file (COSE or raw
 *   payload); the idtimestamp comes from the permanent SCRAPI entry id.
 */
export type VerifyInputOptions = {
  genesis: string;
  receipt: string;
  committedGrant: string | undefined;
  committedGrantFile: string | undefined;
  entryId: string | undefined;
};

function readBytes(path: string, flag: string): Uint8Array {
  try {
    return new Uint8Array(readFileSync(path));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`cannot read ${flag} '${path}': ${message}`);
  }
}

function decodeBase64(b64: string): Uint8Array {
  const bytes = new Uint8Array(Buffer.from(b64, "base64"));
  if (bytes.length === 0) {
    throw new Error(
      "--committed-grant is not valid base64 (decoded to 0 bytes)",
    );
  }
  return bytes;
}

/** Decode grant bytes: Forestrie-Grant COSE Sign1 first, raw payload CBOR second. */
function decodeGrantBytes(
  bytes: Uint8Array,
  entryId: string | undefined,
  source: string,
): Pick<VerifyGrantReceiptOfflineInput, "grant" | "idtimestampBe8"> {
  try {
    const decoded = decodeForestrieGrantCose(bytes);
    return {
      grant: decoded.grant,
      idtimestampBe8:
        entryId !== undefined
          ? entryIdHexToIdtimestampBe8(entryId)
          : decoded.idtimestampBe8,
    };
  } catch {
    // Not a Forestrie-Grant COSE Sign1 — fall through to raw payload CBOR.
  }
  const grant = decodeGrantPayload(bytes);
  if (entryId === undefined) {
    throw new Error(
      `${source} is a raw grant payload (no embedded idtimestamp) — pass --entry-id`,
    );
  }
  return { grant, idtimestampBe8: entryIdHexToIdtimestampBe8(entryId) };
}

/** Read genesis/receipt/grant artefacts from disk into verify input bytes. */
export function loadVerifyArtifacts(
  options: VerifyInputOptions,
): VerifyGrantReceiptOfflineInput {
  const genesisCbor = readBytes(options.genesis, "--genesis");
  const receiptCbor = readBytes(options.receipt, "--receipt");

  let grantBytes: Uint8Array;
  let source: string;
  if (options.committedGrant !== undefined) {
    grantBytes = decodeBase64(options.committedGrant);
    source = "--committed-grant";
  } else if (options.committedGrantFile !== undefined) {
    grantBytes = readBytes(options.committedGrantFile, "--committed-grant-file");
    source = `--committed-grant-file '${options.committedGrantFile}'`;
  } else {
    throw new Error(
      "either --committed-grant or --committed-grant-file is required",
    );
  }

  const { grant, idtimestampBe8 } = decodeGrantBytes(
    grantBytes,
    options.entryId,
    source,
  );
  return { genesisCbor, receiptCbor, grant, idtimestampBe8 };
}
