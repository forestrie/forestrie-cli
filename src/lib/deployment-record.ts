import { readFileSync } from "node:fs";

/**
 * A `forestrie deploy --out` artifact. Single shared reader (FOR-480):
 * `onboard-genesis`, `admin onboard-token`, and `onboard-request` all resolve
 * their chain binding from the same file the deploy wrote, so the binding is
 * stated exactly once per ceremony.
 */
export type DeploymentRecord = {
  imutableUnivocity: string;
  genesisLogId: string;
  /**
   * Bare decimal string (the file stores a JSON number; coerced here).
   * Optional: hand-crafted two-field artifacts remain valid for
   * onboard-genesis, which sources chainId from its own flag.
   */
  chainId?: string | undefined;
  bootstrapAlg?: "es256" | "ks256" | undefined;
  txHash?: string | undefined;
};

export function readDeploymentRecord(path: string): DeploymentRecord {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as {
    imutableUnivocity?: string;
    genesisLogId?: string;
    chainId?: number | string;
    bootstrapAlg?: string;
    txHash?: string;
  };
  const imutableUnivocity = parsed.imutableUnivocity?.trim();
  const genesisLogId = parsed.genesisLogId?.trim();
  if (!imutableUnivocity || !genesisLogId) {
    throw new Error(
      `${path}: expected imutableUnivocity and genesisLogId ` +
        "(a forestrie deploy --out artifact)",
    );
  }
  const chainIdRaw = parsed.chainId;
  const chainId =
    typeof chainIdRaw === "number"
      ? String(chainIdRaw)
      : (chainIdRaw?.trim() ?? "");
  if (chainId && !/^[0-9]+$/.test(chainId)) {
    throw new Error(`${path}: expected a numeric chainId`);
  }
  const bootstrapAlg =
    parsed.bootstrapAlg === "es256" || parsed.bootstrapAlg === "ks256"
      ? parsed.bootstrapAlg
      : undefined;
  const record: DeploymentRecord = { imutableUnivocity, genesisLogId };
  if (chainId) record.chainId = chainId;
  if (bootstrapAlg !== undefined) record.bootstrapAlg = bootstrapAlg;
  const txHash = parsed.txHash?.trim();
  if (txHash) record.txHash = txHash;
  return record;
}

/** 40-hex lowercase address body (no 0x) from a deployment address. */
export function univocityAddrHex(record: Pick<DeploymentRecord, "imutableUnivocity">): string {
  const hex = record.imutableUnivocity.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{40}$/.test(hex)) {
    throw new Error("imutableUnivocity is not a 20-byte hex address");
  }
  return hex;
}
