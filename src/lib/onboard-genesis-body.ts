/**
 * Direct-sign ES256 forest genesis body (FOR-406, plan-2607-27 W2).
 *
 * The operator onboarding payload for a `forestrie deploy`ed forest: the
 * five-label v2 genesis map canopy's forest-genesis expects for the
 * direct-sign path, encoded with the sanctioned deterministic RFC 8949
 * §4.2 codec. This is the single shipped implementation that retires the
 * demo's onboard-genesis.mjs and system-testing's es256-genesis helper.
 */
import { createPublicKey } from "node:crypto";
import { encodeCborDeterministic } from "@forestrie/encoding";

/** CBOR labels aligned with canopy forest-genesis-labels (v2 direct-sign). */
const LABEL_GENESIS_VERSION = -68009;
const LABEL_UNIVOCITY_ADDR = -68011;
const LABEL_CHAIN_ID = -68013;
const LABEL_GENESIS_ALG = -68014;
const LABEL_BOOTSTRAP_KEY = -68015;
const SCHEMA_V2 = 2;
const COSE_ALG_ES256 = -7;

function hexToBytes20(hex: string): Uint8Array {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]{40}$/.test(stripped)) {
    throw new Error(`expected a 20-byte hex contract address, got ${hex}`);
  }
  const out = new Uint8Array(20);
  for (let i = 0; i < 20; i += 1) {
    out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Raw 64-byte x||y public key from a P-256 PEM (private or public). */
export function es256PublicKeyXy(pem: string): Uint8Array {
  const jwk = createPublicKey(pem).export({ format: "jwk" });
  if (jwk.crv !== "P-256" || !jwk.x || !jwk.y) {
    throw new Error("bootstrap PEM must be a P-256 (ES256) key");
  }
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  if (x.length !== 32 || y.length !== 32) {
    throw new Error(
      `expected 32-byte P-256 coordinates, got x=${x.length} y=${y.length}`,
    );
  }
  const xy = new Uint8Array(64);
  xy.set(x, 0);
  xy.set(y, 32);
  return xy;
}

/** Build the v2 direct-sign genesis CBOR body. */
export function buildEs256GenesisBody(opts: {
  chainId: string;
  univocityAddress: string;
  bootstrapKeyXy: Uint8Array;
}): Uint8Array {
  if (opts.bootstrapKeyXy.length !== 64) {
    throw new Error(
      `bootstrap key must be 64 bytes (x||y), got ${opts.bootstrapKeyXy.length}`,
    );
  }
  if (!opts.chainId.trim()) {
    throw new Error("chainId must be a non-empty string");
  }
  return encodeCborDeterministic(
    new Map<number, unknown>([
      [LABEL_GENESIS_VERSION, SCHEMA_V2],
      [LABEL_UNIVOCITY_ADDR, hexToBytes20(opts.univocityAddress)],
      [LABEL_CHAIN_ID, opts.chainId],
      [LABEL_GENESIS_ALG, COSE_ALG_ES256],
      [LABEL_BOOTSTRAP_KEY, opts.bootstrapKeyXy],
    ]),
  );
}

/** Genesis POST URL with the sealing-callback webhook query param. */
export function genesisPostUrl(
  baseUrl: string,
  logId: string,
  webhookUrl: string,
): string {
  const base = baseUrl.replace(/\/$/, "");
  return `${base}/api/forest/${logId}/genesis?webhookUrl=${encodeURIComponent(webhookUrl)}`;
}

/** Coordinator signing-route webhook for a log (ADR-0050 sealing wiring). */
export function coordinatorSigningRouteUrl(
  coordinatorUrl: string,
  logId: string,
): string {
  return `${coordinatorUrl.replace(/\/$/, "")}/api/logs/${logId}/signing-route`;
}
