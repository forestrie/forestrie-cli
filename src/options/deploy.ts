import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

export type BootstrapAlg = "es256" | "ks256";

/** `forestrie deploy` — FOR-340. */
export type DeployOptions = ForestrieCommonOptions & {
  /** Bootstrap key algorithm. ES256 is the paved path; KS256 is the Safe/ERC-1271 aside. */
  bootstrapAlg: BootstrapAlg;
  /** Generate a fresh ES256 P-256 bootstrap keypair. */
  bootstrapEs256Generate: boolean;
  /** Where to write the generated ES256 PKCS#8 PEM. */
  bootstrapEs256PemOut: string | undefined;
  /** Deployer / owner address (`OWNER_ADDRESS`). */
  ownerAddress: string | undefined;
  /** JSON-RPC endpoint (`RPC_URL`). */
  rpcUrl: string;
  /** Deployment record output path (default: stdout). */
  out: string | undefined;
};

export function parseDeployOptions(args: LooseParsedArgs): DeployOptions {
  const alg = optionalStringOption(args, "bootstrap-alg") ?? "es256";
  if (alg !== "es256" && alg !== "ks256") {
    throw new Error(
      `invalid --bootstrap-alg '${alg}' (expected es256 or ks256)`,
    );
  }
  return {
    ...parseForestrieCommonOptions(args),
    bootstrapAlg: alg,
    bootstrapEs256Generate: args["bootstrap-es256-generate"] === true,
    bootstrapEs256PemOut: optionalStringOption(args, "bootstrap-es256-pem-out"),
    ownerAddress: optionalStringOption(args, "owner-address", "OWNER_ADDRESS"),
    rpcUrl: requiredStringOption(args, "rpc-url", "RPC_URL"),
    out: optionalStringOption(args, "out"),
  };
}
