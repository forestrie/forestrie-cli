/**
 * Genesis (root/bootstrap) logId derivation for `forestrie deploy`
 * (FOR-340).
 *
 * The root log's UUID is the first 16 bytes of the deployed
 * ImutableUnivocity contract address, formatted 8-4-4-4-12 (the last 4
 * address bytes are dropped). This is a cross-repo contract with the
 * canopy naming scheme; the same derivation lives in univocity-tools
 * `@univocity-tools/deployer-common` `genesisLogIdFromImutableAddress`
 * (unpublished — mirrored here rather than depended on; graduating it
 * into `@forestrie/deploy-core` is a univocity-tools follow-up).
 *
 * Test vector (shared with deployer-common):
 * `0x1528b86fF561f617602356efdbD05908a07AA788` →
 * `1528b86f-f561-f617-6023-56efdbd05908`.
 */
import { getAddress } from "viem";

/** Derive the root/bootstrap log UUID from an ImutableUnivocity address. */
export function genesisLogIdFromImutableAddress(address: string): string {
  let normalized: string;
  try {
    normalized = getAddress(address);
  } catch {
    throw new Error(`expected 20-byte address, got ${address}`);
  }
  const h = normalized.slice(2).toLowerCase();
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}
