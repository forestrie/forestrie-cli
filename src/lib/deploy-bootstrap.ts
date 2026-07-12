/**
 * ES256 bootstrap key resolution for `forestrie deploy` (FOR-340).
 *
 * The bootstrap key is the log's trust root: its public P-256 point
 * (`x||y`, 64 bytes) is bound into the ImutableUnivocity constructor.
 * Only the PUBLIC coordinates go on-chain, so — unlike sign-statement's
 * `loadEs256SigningKey` (src/lib/sign-statement-key.ts), which needs the
 * private scalar — this resolver uses `@forestrie/deploy-core`'s
 * `resolveBootstrapKey`, which also accepts public-only SPKI PEMs.
 */
import { readFileSync } from "node:fs";
import {
  generateEs256BootstrapKey,
  resolveBootstrapKey,
  type BootstrapKey,
} from "@forestrie/deploy-core";
import { drainOpenSslErrorQueue } from "./openssl-error-queue.js";
import { errorMessage } from "./sign-statement-key.js";

/** Resolved ES256 bootstrap key ready for constructor encoding. */
export type ResolvedDeployBootstrap = {
  /** deploy-core bootstrap key: `algId` (COSE -7) + 64-byte `x||y`. */
  bootstrap: BootstrapKey;
  /** Path the generated PKCS#8 PEM was written to (generate mode only). */
  pemOut?: string;
};

/** Inputs already validated by `parseDeployOptions`. */
export type DeployBootstrapInput = {
  /** Generate a fresh keypair (requires `pemOut`). */
  generate: boolean;
  /** Where to persist the generated PKCS#8 PEM. */
  pemOut?: string | undefined;
  /** Existing key PEM path (mutually exclusive with `generate`). */
  pemPath?: string | undefined;
};

/** Test seam: PEM persistence (real `Bun.write` by default). */
export type WritePem = (path: string, pem: string) => Promise<unknown>;

/**
 * Resolve or generate the ES256 bootstrap key.
 *
 * Generate mode writes the PKCS#8 private key PEM to `pemOut` BEFORE the
 * deploy transaction is built: if the write fails, nothing is deployed
 * with an unrecoverable trust root.
 */
export async function resolveDeployBootstrapKey(
  input: DeployBootstrapInput,
  writePem: WritePem = (path, pem) => Bun.write(path, pem),
): Promise<ResolvedDeployBootstrap> {
  if (input.generate) {
    if (input.pemOut === undefined) {
      throw new Error("--bootstrap-es256-generate requires --bootstrap-es256-pem-out");
    }
    const generated = await generateEs256BootstrapKey();
    try {
      await writePem(input.pemOut, generated.pem);
    } catch (err) {
      throw new Error(
        `cannot write bootstrap PEM to ${input.pemOut}: ${errorMessage(err)}`,
      );
    }
    const bootstrap = await resolveBootstrapKey({
      alg: "es256",
      x: generated.x,
      y: generated.y,
    });
    return { bootstrap, pemOut: input.pemOut };
  }

  if (input.pemPath === undefined) {
    throw new Error(
      "es256 bootstrap needs --bootstrap-es256-generate or --bootstrap-es256-pem",
    );
  }
  let pem: string;
  try {
    pem = readFileSync(input.pemPath, "utf8");
  } catch (err) {
    throw new Error(
      `cannot read bootstrap PEM ${input.pemPath}: ${errorMessage(err)}`,
    );
  }
  let bootstrap: BootstrapKey;
  try {
    bootstrap = await resolveBootstrapKey({ alg: "es256", pem });
  } catch (err) {
    // deploy-core parses via `crypto.subtle.importKey`; on bun a failed
    // import over malformed DER leaves a stale entry on the OpenSSL error
    // queue that would poison the next node:crypto PEM parse (FOR-343).
    // Drain it here so the failure stays contained to this call.
    drainOpenSslErrorQueue();
    throw new Error(
      `${input.pemPath}: not a usable ES256 (P-256) key PEM: ${errorMessage(err)}`,
    );
  }
  return { bootstrap };
}
