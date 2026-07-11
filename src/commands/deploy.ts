import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runDeploy } from "../main/deploy.js";
import { parseDeployOptions } from "../options/deploy.js";

export default defineForestrieCommand({
  meta: {
    name: "deploy",
    description:
      "Deploy a univocity instance (ES256 bootstrap is the paved path; KS256 only for the Safe/ERC-1271 aside) [FOR-340]",
  },
  args: {
    "bootstrap-alg": {
      type: "string",
      description: "Bootstrap key algorithm: es256 (paved path) or ks256",
      valueHint: "es256|ks256",
      default: "es256",
    },
    "bootstrap-es256-generate": {
      type: "boolean",
      description: "Generate a fresh ES256 P-256 bootstrap keypair",
      default: false,
    },
    "bootstrap-es256-pem-out": {
      type: "string",
      description: "Write the generated ES256 PKCS#8 PEM to this path",
      valueHint: "path",
    },
    "owner-address": {
      type: "string",
      description: "Deployer / owner address (env OWNER_ADDRESS)",
      valueHint: "0x…",
    },
    "rpc-url": {
      type: "string",
      description: "JSON-RPC endpoint (env RPC_URL)",
      valueHint: "url",
    },
    out: {
      type: "string",
      description:
        "Write the deployment record JSON here (default: stdout) — { imutableUnivocity, genesisLogId, bootstrapAlg, chainId }",
      valueHint: "path",
    },
  },
  run: defineCommandRunner(parseDeployOptions, runDeploy),
});
