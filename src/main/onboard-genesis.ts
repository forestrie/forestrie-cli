import { readFileSync } from "node:fs";
import type { Out } from "@forestrie/cli-kit/reporting";
import {
  buildEs256GenesisBody,
  coordinatorSigningRouteUrl,
  es256PublicKeyXy,
  genesisPostUrl,
} from "../lib/onboard-genesis-body.js";
import type { OnboardGenesisOptions } from "../options/onboard-genesis.js";

/**
 * FOR-406 (plan-2607-27 W2): operator genesis onboarding — turn a
 * `forestrie deploy` into a usable forest. POSTs the five-label v2
 * direct-sign genesis body under a PRE-MINTED onboard token (from
 * `forestrie admin onboard-token`, or x402 settlement in future), wiring
 * the coordinator signing-route webhook for sealing callbacks, then
 * fetches the public genesis back to `--out` — the offline trust root
 * every later `verify --genesis` consumes.
 */

export type OnboardGenesisReport = {
  command: "onboard-genesis";
  status: "onboarded";
  logId: string;
  univocity: string;
  chainId: string;
  webhookUrl: string;
  httpStatus: number;
  /** Present when `--out` was given. */
  out?: string;
  genesisBytes?: number;
};

export type OnboardGenesisErrorReport = {
  error:
    | "input_failed"
    | "post_failed"
    | "network_failed"
    | "genesis_fetch_failed";
  command: "onboard-genesis";
  message: string;
  httpStatus?: number;
  /** Server response body (text) for post failures — surfaced, not masked. */
  detail?: string;
};

/** Test seam. */
export type OnboardGenesisDeps = {
  fetchImpl?: typeof fetch;
};

type ResolvedTarget = { univocity: string; logId: string };

function resolveTarget(options: OnboardGenesisOptions): ResolvedTarget {
  if (options.deployment !== undefined) {
    const parsed = JSON.parse(readFileSync(options.deployment, "utf8")) as {
      imutableUnivocity?: string;
      genesisLogId?: string;
    };
    const univocity = parsed.imutableUnivocity?.trim();
    const logId = parsed.genesisLogId?.trim();
    if (!univocity || !logId) {
      throw new Error(
        `${options.deployment}: expected imutableUnivocity and genesisLogId ` +
          "(a forestrie deploy --out artifact)",
      );
    }
    return { univocity, logId };
  }
  return { univocity: options.univocity!, logId: options.logId! };
}

function reportError(
  out: Out,
  options: OnboardGenesisOptions,
  report: OnboardGenesisErrorReport,
): void {
  if (options.json) {
    out.out(JSON.stringify(report, null, 2));
  } else {
    out.warn("forestrie onboard-genesis: %s", report.message);
    if (report.detail !== undefined) {
      out.warn("  detail: %s", report.detail);
    }
  }
  process.exitCode = 1;
}

export async function runOnboardGenesis(
  out: Out,
  options: OnboardGenesisOptions,
  deps: OnboardGenesisDeps = {},
): Promise<void> {
  const fetchImpl = deps.fetchImpl ?? fetch;

  let target: ResolvedTarget;
  let body: Uint8Array;
  try {
    target = resolveTarget(options);
    body = buildEs256GenesisBody({
      chainId: options.chainId,
      univocityAddress: target.univocity,
      bootstrapKeyXy: es256PublicKeyXy(
        readFileSync(options.bootstrapPem, "utf8"),
      ),
    });
  } catch (err) {
    reportError(out, options, {
      error: "input_failed",
      command: "onboard-genesis",
      message: err instanceof Error ? err.message : String(err),
    });
    return;
  }

  const webhookUrl =
    options.webhookUrl ??
    coordinatorSigningRouteUrl(options.coordinatorUrl!, target.logId);
  const url = genesisPostUrl(options.baseUrl, target.logId, webhookUrl);

  let res: Response;
  try {
    res = await fetchImpl(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${options.onboardToken}`,
        "Content-Type": "application/cbor",
      },
      body: body.buffer.slice(
        body.byteOffset,
        body.byteOffset + body.byteLength,
      ) as ArrayBuffer,
    });
  } catch (err) {
    reportError(out, options, {
      error: "network_failed",
      command: "onboard-genesis",
      message: err instanceof Error ? err.message : String(err),
    });
    return;
  }
  if (!res.ok) {
    // Includes the repeat-onboarding case: surface the server's verdict
    // (status + body) clearly rather than masking it.
    reportError(out, options, {
      error: "post_failed",
      command: "onboard-genesis",
      message: `genesis POST rejected: HTTP ${res.status}`,
      httpStatus: res.status,
      detail: (await res.text()).slice(0, 512),
    });
    return;
  }

  let genesisBytes: number | undefined;
  if (options.out !== undefined) {
    const genesisRes = await fetchImpl(
      `${options.baseUrl.replace(/\/$/, "")}/api/forest/${target.logId}/genesis`,
    );
    if (!genesisRes.ok) {
      reportError(out, options, {
        error: "genesis_fetch_failed",
        command: "onboard-genesis",
        message: `onboarded, but genesis fetch-back failed: HTTP ${genesisRes.status}`,
        httpStatus: genesisRes.status,
      });
      return;
    }
    const genesis = new Uint8Array(await genesisRes.arrayBuffer());
    await Bun.write(options.out, genesis);
    genesisBytes = genesis.length;
  }

  if (options.json) {
    const report: OnboardGenesisReport = {
      command: "onboard-genesis",
      status: "onboarded",
      logId: target.logId,
      univocity: target.univocity,
      chainId: options.chainId,
      webhookUrl,
      httpStatus: res.status,
    };
    if (options.out !== undefined) {
      report.out = options.out;
      report.genesisBytes = genesisBytes!;
    }
    out.out(JSON.stringify(report, null, 2));
    return;
  }
  out.out("onboarded forest %s (HTTP %d)", target.logId, res.status);
  out.print("  univocity: %s (chain %s)", target.univocity, options.chainId);
  out.print("  sealing webhook: %s", webhookUrl);
  if (options.out !== undefined) {
    out.out(
      "wrote public genesis (%d bytes) to %s — the offline trust root for verify --genesis",
      genesisBytes!,
      options.out,
    );
  }
}
