import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runCreateReceipt } from "../main/create-receipt.js";
import { parseCreateReceiptOptions } from "../options/create-receipt.js";

export default defineForestrieCommand({
  meta: {
    name: "resolve-receipt",
    description:
      "Produce or freshen a COSE receipt (SCRAPI §2.4) — source by flags: --massif (tiles), --receipt + --checkpoint-chain (.sth freshen, genesis-verifiable), or --receipt + --rpc-url/--univocity/--log-id + --checkpoint (calldata freshen) [FOR-345/FOR-418]. Alias: create-receipt.",
  },
  args: {
    // --- tiles source (--massif) ---
    massif: {
      type: "string",
      description: "Massif .log blob holding the leaf and its proof nodes (tiles source)",
      valueHint: "path",
    },
    "mmr-index": {
      type: "string",
      description:
        "MMR index of the leaf to prove (tiles source; exactly one of --mmr-index / --entry-id)",
      valueHint: "n",
    },
    checkpoint: {
      type: "string",
      description:
        "Checkpoint (.sth) with pre-signed peak receipts (tiles source, offline mode)",
      valueHint: "path",
    },
    univocity: {
      type: "string",
      description:
        "ImutableUnivocity contract address (tiles source, chain-anchored; needs --log-id and --rpc-url)",
      valueHint: "0x…",
    },
    "log-id": {
      type: "string",
      description: "Log id for the on-chain accumulator read (chain-anchored mode)",
      valueHint: "uuid",
    },
    "rpc-url": {
      type: "string",
      description: "JSON-RPC endpoint (env RPC_URL; chain-anchored mode)",
      valueHint: "url",
    },
    // --- freshen source (--receipt + a tile-free chain) ---
    receipt: {
      type: "string",
      description: "Stale receipt to freshen tile-free (freshen source)",
      valueHint: "path",
    },
    "checkpoint-chain": {
      type: "string",
      description:
        "Retained .sth checkpoint chain — a directory or comma-separated files (freshen source; genesis-verifiable)",
      valueHint: "dir|files",
    },
    "committed-grant": {
      type: "string",
      description:
        "Committed grant, base64 — recomputes the leaf value (freshen source)",
      valueHint: "b64",
    },
    "committed-grant-file": {
      type: "string",
      description:
        "Committed grant CBOR file — recomputes the leaf value (freshen; needs --entry-id)",
      valueHint: "path",
    },
    payload: {
      type: "string",
      description:
        "Registered statement payload — the leaf ContentHash (freshen statement receipts; alternative to --committed-grant, needs --entry-id)",
      valueHint: "path",
    },
    // --- shared ---
    "entry-id": {
      type: "string",
      description:
        "Permanent SCRAPI entry id (leaf addressing for tiles; idtimestamp for freshen), 32 hex chars",
      valueHint: "hex",
    },
    out: {
      type: "string",
      description: "Receipt output path (default: stdout)",
      valueHint: "path",
    },
    "in-place": {
      type: "boolean",
      description:
        "Rewrite the --receipt file with the freshened receipt (freshen only; mutually exclusive with --out)",
    },
    "known-accumulator": {
      type: "string",
      description:
        "Trusted accumulator snapshot (fetch-accumulator output) — bind the freshened state to it (freshen only; the accumulator trust rung, no genesis)",
      valueHint: "path",
    },
  },
  run: defineCommandRunner(parseCreateReceiptOptions, runCreateReceipt),
});
