/**
 * Bootstrap-key registrant attestation producer (devdocs plan-2607-43 slice
 * 06, ADR-0059 D8) — the client half of canopy's
 * `onboarding/onboard-attestation.ts` verifier; the two must agree
 * byte-for-byte on Sig_structure.
 *
 * COSE_Sign1, protected `{1: alg, 3: content type}`, payload = CWT claims:
 * `iss` = the CAIP-10 univocityInstanceId, `aud` = the operator origin,
 * `iat`/`exp` = a bounded freshness window, and a private claim (-70000)
 * carrying the exact chain binding. Signed by the deployment's bootstrap key
 * — the only key that can ever produce the instance's first checkpoint, so
 * holder-of-key and whose-instance-this-is are the same party.
 */

import { sign as signSecp256k1 } from "viem/accounts";
import { keccak256, hexToBytes as viemHexToBytes } from "viem";
import {
  encodeCborDeterministic,
  encodeSigStructure,
} from "@forestrie/encoding";
import type { Es256SigningKey } from "./sign-statement-key.js";

export const ONBOARD_ATTESTATION_CONTENT_TYPE =
  "application/forestrie-onboard-attestation+cwt";

export const COSE_ALG_ES256 = -7;
export const COSE_ALG_KS256 = -65799;

/** Private CWT claim: map {1: chainId tstr, 2: univocityAddr 40-lowerhex}. */
export const CLAIM_CHAIN_BINDING = -70000;

/** Default freshness window (canopy's policy ceiling is 24 h). */
export const DEFAULT_ATTESTATION_WINDOW_SEC = 3600;

export interface OnboardAttestationInput {
  chainId: string;
  /** 40-hex lowercase address body, no 0x. */
  univocityAddr: string;
  /** Operator deployment origin, e.g. `https://api-a.forest-2.forestrie.dev`. */
  aud: string;
  nowSec: number;
  windowSec?: number;
}

function claimsBytes(input: OnboardAttestationInput): Uint8Array {
  const window = input.windowSec ?? DEFAULT_ATTESTATION_WINDOW_SEC;
  const claims = new Map<number, unknown>([
    [1, `eip155:${input.chainId}:0x${input.univocityAddr}`],
    [3, input.aud],
    [4, input.nowSec + window],
    [6, input.nowSec],
    [
      CLAIM_CHAIN_BINDING,
      new Map<number, unknown>([
        [1, input.chainId],
        [2, input.univocityAddr],
      ]),
    ],
  ]);
  return encodeCborDeterministic(claims);
}

function protectedBytes(alg: number): Uint8Array {
  return encodeCborDeterministic(
    new Map<number, unknown>([
      [1, alg],
      [3, ONBOARD_ATTESTATION_CONTENT_TYPE],
    ]),
  );
}

function assemble(
  prot: Uint8Array,
  payload: Uint8Array,
  signature: Uint8Array,
): Uint8Array {
  return encodeCborDeterministic([prot, new Map(), payload, signature]);
}

/** ES256 attestation signed with the deploy-generated bootstrap PEM key. */
export async function buildOnboardAttestationEs256(
  key: Es256SigningKey,
  input: OnboardAttestationInput,
): Promise<Uint8Array> {
  const prot = protectedBytes(COSE_ALG_ES256);
  const payload = claimsBytes(input);
  const sigStructure = encodeSigStructure(prot, new Uint8Array(0), payload);
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key.privateKey,
      sigStructure as unknown as ArrayBuffer,
    ),
  );
  return assemble(prot, payload, signature);
}

/**
 * KS256 attestation: the delegation-cose profile — keccak256(Sig_structure),
 * 65-byte `r‖s‖v` EOA signature by the bootstrap key.
 */
export async function buildOnboardAttestationKs256(
  privateKeyHex: string,
  input: OnboardAttestationInput,
): Promise<Uint8Array> {
  const prot = protectedBytes(COSE_ALG_KS256);
  const payload = claimsBytes(input);
  const sigStructure = encodeSigStructure(prot, new Uint8Array(0), payload);
  const hash = keccak256(sigStructure);
  const key = privateKeyHex.startsWith("0x")
    ? (privateKeyHex as `0x${string}`)
    : (`0x${privateKeyHex}` as `0x${string}`);
  const sig = await signSecp256k1({ hash, privateKey: key, to: "bytes" });
  if (sig.length !== 65) {
    throw new Error(`KS256 signature must be 65 bytes, got ${sig.length}`);
  }
  return assemble(prot, payload, sig);
}

export { viemHexToBytes as hexToBytes };
