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
      description:
        "Generate a fresh ES256 P-256 bootstrap keypair (requires --bootstrap-es256-pem-out)",
      default: false,
    },
    "bootstrap-es256-pem-out": {
      type: "string",
      description: "Write the generated ES256 PKCS#8 PEM to this path",
      valueHint: "path",
    },
    "bootstrap-es256-pem": {
      type: "string",
      description:
        "Use an existing ES256 bootstrap key PEM (PKCS#8/SEC1 private or SPKI public — only the public point is bound on-chain)",
      valueHint: "path",
    },
    "owner-address": {
      type: "string",
      description:
        "Deployer / owner address (env OWNER_ADDRESS); must match --deployer-key when both are given",
      valueHint: "0x…",
    },
    "rpc-url": {
      type: "string",
      description: "JSON-RPC endpoint (env RPC_URL)",
      valueHint: "url",
    },
    "deployer-key": {
      type: "string",
      description:
        "Funded secp256k1 private key that pays gas for the deploy tx (env DEPLOYER_KEY). Gas-only — the ES256 bootstrap key is the trust root, not this key",
      valueHint: "0x…",
    },
    "release-tag": {
      type: "string",
      description:
        "Univocity contract release tag for the deploy manifest (default: latest)",
      valueHint: "tag",
    },
    "release-manifest": {
      type: "string",
      description:
        "Local deploy-manifest JSON (bytecode digests still verified) — skips the GitHub release fetch",
      valueHint: "path",
    },
    out: {
      type: "string",
      description:
        "Write the deployment record JSON here (default: stdout) — { imutableUnivocity, genesisLogId, bootstrapAlg, chainId, … }",
      valueHint: "path",
    },
  },
  run: defineCommandRunner(parseDeployOptions, runDeploy),
});
