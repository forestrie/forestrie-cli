import path from "node:path";

export const ROOT = path.resolve(new URL("..", import.meta.url).pathname);

export type CliResult = {
  exitCode: number;
  stdout: string;
  stderr: string;
};

/** Env vars the CLI reads implicitly — cleared so tests are hermetic. */
const CLI_ENV_VARS = [
  "FORESTRIE_BASE_URL",
  "FORESTRIE_CONFIG",
  "RPC_URL",
  "GRANT_B64",
  "OWNER_ADDRESS",
];

/** Run the CLI from source (`bun src/cli.ts …`) with a scrubbed env. */
export function runCli(
  args: string[],
  env: Record<string, string> = {},
): CliResult {
  const spawnEnv: Record<string, string | undefined> = {
    ...process.env,
    ...env,
  };
  for (const name of CLI_ENV_VARS) {
    if (!(name in env)) {
      delete spawnEnv[name];
    }
  }
  const proc = Bun.spawnSync({
    cmd: ["bun", path.join(ROOT, "src/cli.ts"), ...args],
    cwd: ROOT,
    env: spawnEnv,
    stdout: "pipe",
    stderr: "pipe",
  });
  return {
    exitCode: proc.exitCode,
    stdout: proc.stdout.toString(),
    stderr: proc.stderr.toString(),
  };
}

/** Minimal valid argv per subcommand (parse succeeds; run is the stub). */
export const SUBCOMMANDS: Record<
  string,
  { issue: string; args: string[] }
> = {
  deploy: {
    issue: "FOR-340",
    args: ["--rpc-url", "http://localhost:8545"],
  },
  "sign-statement": {
    issue: "FOR-341",
    args: ["--key", "alice.es256.pem", "--payload", "statement.json"],
  },
  register: {
    issue: "FOR-342",
    args: [
      "--base-url",
      "https://api.example.dev",
      "--log-id",
      "00000000-0000-0000-0000-000000000000",
      "--statement",
      "statement.cose",
      "--grant-b64",
      "AAAA",
    ],
  },
  "register-grant": {
    issue: "FOR-343",
    args: [
      "--base-url",
      "https://api.example.dev",
      "--owner-log",
      "00000000-0000-0000-0000-000000000000",
      "--data-log",
      "11111111-1111-1111-1111-111111111111",
      "--sign-with",
      "bootstrap.es256.pem",
      "--self-referential",
    ],
  },
  "complete-grant": {
    issue: "FOR-344",
    args: ["--grant", "grant.b64", "--checkpoint", "checkpoint.sth"],
  },
  "create-receipt": {
    issue: "FOR-345",
    args: [
      "--massif",
      "massif.log",
      "--mmr-index",
      "0",
      "--checkpoint",
      "checkpoint.sth",
    ],
  },
  "decode-receipt": {
    issue: "FOR-346",
    args: ["receipt.cbor"],
  },
  verify: {
    issue: "FOR-347",
    args: [
      "--genesis",
      "genesis.cbor",
      "--receipt",
      "receipt.cbor",
      "--grant-b64",
      "AAAA",
    ],
  },
};
