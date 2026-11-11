/**
 * Turn `wait-anchored` inputs into a target and the chain to read, and the
 * lines and report a run prints. Shared by `forestrie log wait-anchored`
 * and `forestrie create-log --wait-anchored`.
 */
import type { Out } from "@forestrie/cli-kit/reporting";
import { base64ToBytes, hasCreateAndExtend } from "@forestrie/grant-builder";
import { resolveReceiptOnce } from "@forestrie/scrapi-client";
import {
  decodeChainBindingFromGenesis,
  decodeForestrieGrantCose,
} from "@forestrie/receipt-verify";
import { rpcAnchorChain } from "./anchor-chain-rpc.js";
import { REQUEST_TIMEOUT_MS, timedFetch } from "./timed-fetch.js";
import {
  childAnchorTarget,
  rootAnchorTarget,
  type AnchorAnswer,
  type AnchorChain,
  type AnchorTarget,
  type AnchorWaitResult,
} from "./anchor-wait.js";
import { forestMismatchDetail } from "./verify-anchored.js";

/** Why a wait could not start: bad inputs, or reads bound to another forest. */
export class AnchorWaitSetupError extends Error {
  readonly code: "input_invalid" | "forest_mismatch" | "chain_unavailable";
  constructor(code: AnchorWaitSetupError["code"], message: string) {
    super(message);
    this.name = "AnchorWaitSetupError";
    this.code = code;
  }
}

/**
 * Resolve the target and the chain:
 * - a child's completed create grant waits for its owner's checkpoint;
 * - a genesis alone, or a forest root's own bootstrap grant with its
 *   genesis, waits for the root's contract.
 */
export async function prepareAnchorWait(
  inputs: {
    createGrantB64?: string | undefined;
    genesisCbor?: Uint8Array | undefined;
    univocity?: string | undefined;
    rpcUrl: string;
  },
  chain?: AnchorChain,
): Promise<{ target: AnchorTarget; chain: AnchorChain }> {
  const target = await anchorTargetFor(inputs.createGrantB64, inputs.genesisCbor);
  return { target, chain: await bindAnchorChain(inputs, chain) };
}

/**
 * The chain to read. With a genesis, the contract defaults to the
 * genesis's, and both the contract and the RPC's chain id must be the
 * genesis forest's, as `verify --genesis` requires of its anchor.
 */
export async function bindAnchorChain(
  inputs: {
    genesisCbor?: Uint8Array | undefined;
    univocity?: string | undefined;
    rpcUrl: string;
  },
  chain?: AnchorChain,
): Promise<AnchorChain> {
  let univocity = inputs.univocity;
  try {
    univocity ??=
      inputs.genesisCbor !== undefined
        ? decodeChainBindingFromGenesis(inputs.genesisCbor).univocity
        : undefined;
  } catch (err) {
    throw new AnchorWaitSetupError("input_invalid", `genesis: ${messageOf(err)}`);
  }
  if (univocity === undefined) {
    throw new AnchorWaitSetupError(
      "input_invalid",
      "pass --univocity or --genesis (whose contract it names) to read the chain",
    );
  }
  let reader: AnchorChain;
  try {
    reader = chain ?? rpcAnchorChain({ univocity, rpcUrl: inputs.rpcUrl });
  } catch (err) {
    throw new AnchorWaitSetupError("input_invalid", messageOf(err));
  }
  if (inputs.genesisCbor === undefined) return reader;
  let chainId: bigint;
  try {
    chainId = await reader.chainId();
  } catch (err) {
    throw new AnchorWaitSetupError(
      "chain_unavailable",
      `reading the RPC's chain id: ${messageOf(err)}`,
    );
  }
  const mismatch = forestMismatchDetail(inputs.genesisCbor, { univocity, chainId });
  if (mismatch !== undefined) {
    throw new AnchorWaitSetupError("forest_mismatch", mismatch);
  }
  return reader;
}

/**
 * What to wait for. A create grant names a child, unless it names itself
 * as owner: then it is a forest root's bootstrap, whose authority is its
 * contract, and the genesis must be that root's.
 */
export async function anchorTargetFor(
  createGrantB64: string | undefined,
  genesisCbor: Uint8Array | undefined,
): Promise<AnchorTarget> {
  try {
    if (createGrantB64 === undefined) {
      if (genesisCbor === undefined) {
        throw new Error("pass a create grant or a genesis");
      }
      return rootAnchorTarget(genesisCbor);
    }
    const { grant } = decodeForestrieGrantCose(base64ToBytes(createGrantB64));
    if (!hasCreateAndExtend(grant.grant)) {
      throw new Error(
        "the grant is not a create grant (GF_CREATE): pass the grant that created the log",
      );
    }
    const child = await childAnchorTarget(createGrantB64);
    if (child.logId !== child.ownerLogId) return child;
    if (genesisCbor === undefined) {
      throw new Error(
        `log ${child.logId} is a forest root (its grant names itself as owner): pass its --genesis`,
      );
    }
    const root = rootAnchorTarget(genesisCbor);
    if (root.logId !== child.logId) {
      throw new Error(`the genesis is for root ${root.logId}, not ${child.logId}`);
    }
    return root;
  } catch (err) {
    throw new AnchorWaitSetupError("input_invalid", messageOf(err));
  }
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Re-fetch a create grant's receipt from its permanent SCRAPI receipt URL,
 * for {@link waitAnchored}'s `refreshReceipt`. The receipt is proof
 * material only: the wait recomputes its peak from the grant's own leaf.
 */
export function receiptRefresher(
  receiptUrl: string,
  fetchImpl?: typeof fetch,
  requestTimeoutMs: number = REQUEST_TIMEOUT_MS,
): () => Promise<Uint8Array> {
  const bounded = timedFetch(fetchImpl, requestTimeoutMs);
  return async () => {
    const resolution = await resolveReceiptOnce({
      receiptUrl,
      fetchImpl: bounded,
    });
    if (resolution.status === "receipt") return resolution.body;
    throw new Error(
      resolution.status === "not_found"
        ? `no receipt at ${receiptUrl}`
        : `GET ${receiptUrl}: HTTP ${resolution.httpStatus}`,
    );
  };
}

/** `--json` shape of a finished wait. */
export type AnchorWaitReport = {
  status: AnchorAnswer["status"];
  reason: string;
  detail: string;
  logId: string;
  /** A child's owner, whose checkpoint anchors it. */
  ownerLogId?: string;
  rounds: number;
  timedOut: boolean;
};

export function anchorWaitReport(
  target: AnchorTarget,
  result: AnchorWaitResult,
): AnchorWaitReport {
  return {
    status: result.answer.status,
    reason: result.answer.reason,
    detail: result.answer.detail,
    logId: target.logId,
    ...(target.kind === "child" ? { ownerLogId: target.ownerLogId } : {}),
    rounds: result.rounds,
    timedOut: result.timedOut,
  };
}

/** The stdout line for the final answer, in human mode. */
export function anchorAnswerLine(answer: AnchorAnswer): string {
  return `${answer.status} (${answer.reason}): ${answer.detail}`;
}

/**
 * Narrate rounds on stderr: each change of answer at the default
 * verbosity, every round at `-vvv`.
 */
export function anchorRoundNarrator(
  out: Out,
): (answer: AnchorAnswer, round: number) => void {
  let last: string | undefined;
  return (answer, round) => {
    const line = `round ${round}: ${anchorAnswerLine(answer)}`;
    if (answer.reason !== last) out.print("%s", line);
    else out.log("%s", line);
    last = answer.reason;
  };
}

/** The stderr line saying why a wait ended without anchoring. */
export function anchorFailureLine(
  command: string,
  target: AnchorTarget,
  result: AnchorWaitResult,
  timeoutMs: number,
): string {
  return result.timedOut
    ? `forestrie ${command}: log ${target.logId} is not anchored after ${Math.round(timeoutMs / 1000)}s (${result.rounds} rounds)`
    : `forestrie ${command}: log ${target.logId} is ${result.answer.status} and will never anchor`;
}
