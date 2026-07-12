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
  "DEPLOYER_KEY",
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

/**
 * As `runCli`, but asynchronous — required when the CLI must talk to a
 * server hosted by the test process itself (`spawnSync` blocks the
 * event loop, deadlocking in-process mock servers).
 */
export async function runCliAsync(
  args: string[],
  env: Record<string, string> = {},
): Promise<CliResult> {
  const spawnEnv: Record<string, string | undefined> = {
    ...process.env,
    ...env,
  };
  for (const name of CLI_ENV_VARS) {
    if (!(name in env)) {
      delete spawnEnv[name];
    }
  }
  const proc = Bun.spawn({
    cmd: ["bun", path.join(ROOT, "src/cli.ts"), ...args],
    cwd: ROOT,
    env: spawnEnv,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}

/**
 * Minimal valid argv per subcommand (parse succeeds). `implemented`
 * commands have real behaviour — the not-implemented stub contract
 * no longer applies to them (they have their own test files).
 */
export const SUBCOMMANDS: Record<
  string,
  { issue: string; args: string[]; implemented?: boolean }
> = {
  deploy: {
    issue: "FOR-340",
    args: [
      "--rpc-url",
      "http://localhost:8545",
      "--deployer-key",
      "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
      "--bootstrap-es256-generate",
      "--bootstrap-es256-pem-out",
      "bootstrap.es256.pem",
    ],
    implemented: true,
  },
  "sign-statement": {
    issue: "FOR-341",
    args: ["--key", "alice.es256.pem", "--payload", "statement.json"],
    implemented: true,
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
    implemented: true,
  },
  "register-grant": {
    issue: "FOR-343",
    args: [
      "--base-url",
      "https://api.example.dev",
      "--owner-log",
      "00000000-0000-0000-0000-000000000000",
      "--data-log",
      "00000000-0000-0000-0000-000000000000",
      "--sign-with",
      "bootstrap.es256.pem",
      "--self-referential",
    ],
    implemented: true,
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
    implemented: true,
  },
  "decode-receipt": {
    issue: "FOR-346",
    args: ["receipt.cbor"],
    implemented: true,
  },
  verify: {
    issue: "FOR-347",
    args: [
      "--genesis",
      "genesis.cbor",
      "--receipt",
      "receipt.cbor",
      "--committed-grant",
      "AAAA",
    ],
    implemented: true,
  },
};
