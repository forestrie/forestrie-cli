/**
 * Wait until a log is anchored, proven from public chain data alone
 * (protocol ADR-0070, platform rule P17; `forestrie log wait-anchored`).
 *
 * A child log is anchored once a checkpoint its owner published on chain
 * covers its create grant: the grant's leaf, hashed up a receipt's
 * inclusion path, reaches a peak of an accumulator the contract accepted.
 * No key and no operator answer is involved (P2): the contract checked the
 * checkpoint when it was published.
 *
 * Once the contract has initialized the child (its first checkpoint), the
 * chain's record decides instead, as univocity's authority answer does
 * (forestrie/arbor `services/univocity/src/authority.go`): the owner and
 * root key it recorded are the grant's, or the child is conflicted for good
 * (protocol ADR-0070 decision 6). A conflicted ancestor of the owner is not
 * visible here: that needs the ancestor's own claim.
 *
 * The receipt is only the path. The one in the grant proves against the
 * seal current when the grant was sequenced, and a re-seal replaces that
 * seal (protocol `spec/checkpoints-and-receipts.md` §1.2), so it may never
 * reach the chain. Re-fetching the receipt each round gives a path against
 * the latest seal, whose peak over the leaf has been a peak since it formed:
 * it is in the on-chain accumulator once the chain reaches that size. The
 * fetch is proof material, not an answer: the peak is recomputed from the
 * grant's own leaf, so a wrong receipt can only fail to match.
 */
import { base64ToBytes } from "@forestrie/grant-builder";
import {
  coseUnprotectedToMap,
  decodeCborDeterministic,
  grantDataToBytes,
} from "@forestrie/encoding";
import {
  FOREST_GENESIS_LABEL_BOOTSTRAP_KEY,
  FOREST_GENESIS_LABEL_GENESIS_ALG,
  decodeChainBindingFromGenesis,
  decodeForestrieGrantCose,
  grantCommitmentHashFromGrant,
} from "@forestrie/receipt-verify";
import { bytesEqual } from "./bytes.js";
import {
  classifyUnanchoredPeak,
  receiptLeafIndex,
  recomputeReceiptPeak,
  type OnChainLogState,
} from "./verify-anchored.js";

const HEADER_RECEIPT = 396;
const HEADER_IDTIMESTAMP = -65537;

/** A child log, identified by its completed create grant. */
export type ChildAnchorTarget = {
  kind: "child";
  /** The log the grant creates. */
  logId: string;
  /** The log the grant is sequenced into, whose checkpoints anchor it. */
  ownerLogId: string;
  /** The grant's MMR index in the owner log. */
  leafMmrIndex: bigint;
  /** The root key the grant names for the child (64 or 20 bytes). */
  grantData: Uint8Array;
  /** The leaf, `SHA-256(idtimestamp ‖ grant commitment)`, in parts. */
  idtimestampBe8: Uint8Array;
  inner: Uint8Array;
  /**
   * The accumulator peak the grant's receipt reaches from the leaf.
   * Computed from bytes alone, so no key is involved and a tampered path
   * or leaf reaches a peak no published accumulator holds.
   */
  peak: Uint8Array;
};

/**
 * A forest root, identified by its genesis. Its key is the contract's
 * bootstrap key (devdocs ADR-0075 decision 7), so it has no create grant to
 * anchor: it is anchored once that contract exists with the genesis key and
 * is rooted at no other log.
 */
export type RootAnchorTarget = {
  kind: "root";
  /** The forest's root log id, R. */
  logId: string;
  bootstrapAlg: bigint;
  /** Opaque bootstrap key: 64 bytes ES256 x||y, or a 20-byte KS256 address. */
  bootstrapKey: Uint8Array;
};

export type AnchorTarget = ChildAnchorTarget | RootAnchorTarget;

/** One accumulator the chain committed to, from the publish calldata. */
export type PublishedStep = { size: bigint; accumulator: Uint8Array[] };

/** The contract reads the wait needs; {@link rpcAnchorChain} is the real one. */
export interface AnchorChain {
  /** The log's current on-chain accumulator and size. */
  logState(logId: string): Promise<OnChainLogState>;
  /** Every accumulator the log's published checkpoints committed to. */
  publishedSteps(logId: string): Promise<PublishedStep[]>;
  /**
   * The owner and root key the contract recorded for a log at its first
   * checkpoint, or undefined while it is not initialized.
   */
  logConfig(
    logId: string,
  ): Promise<{ ownerLogId: string; rootKey: Uint8Array } | undefined>;
  hasCode(): Promise<boolean>;
  bootstrapConfig(): Promise<{ alg: bigint; key: Uint8Array }>;
  /** The contract's root log, or undefined before its first checkpoint. */
  rootLogId(): Promise<string | undefined>;
  /** The RPC's chain id, to bind the reads to a genesis forest. */
  chainId(): Promise<bigint>;
}

/** The answer of one round. */
export type AnchorAnswer = {
  /**
   * `anchored`: proven from the chain. `pending`: not yet; waiting may
   * change it. `conflicted`: final; this log never anchors.
   */
  status: "anchored" | "pending" | "conflicted";
  /** Stable token for scripts. */
  reason: string;
  /** One line for people. */
  detail: string;
};

export type AnchorWaitResult = {
  /** The last round's answer. */
  answer: AnchorAnswer;
  rounds: number;
  /** True when the budget ran out while the answer was still pending. */
  timedOut: boolean;
};

/**
 * Read a completed create grant (as `register-grant` and `create-log`
 * write it) into a child target. Throws when it carries no receipt or
 * idtimestamp, which only a completed grant has.
 */
export async function childAnchorTarget(
  completedGrantB64: string,
): Promise<ChildAnchorTarget> {
  const bytes = base64ToBytes(completedGrantB64);
  const { grant } = decodeForestrieGrantCose(bytes);
  const sign1 = decodeCborDeterministic(bytes) as unknown[];
  const unprotected = coseUnprotectedToMap(sign1[1]);
  const receiptCbor = unprotected.get(HEADER_RECEIPT);
  const idtimestampBe8 = unprotected.get(HEADER_IDTIMESTAMP);
  if (!(receiptCbor instanceof Uint8Array) || receiptCbor.length === 0) {
    throw new Error(
      "the grant carries no receipt (header 396): pass the completed grant create-log wrote",
    );
  }
  if (!(idtimestampBe8 instanceof Uint8Array) || idtimestampBe8.length !== 8) {
    throw new Error(
      "the grant carries no idtimestamp (header -65537): pass the completed grant create-log wrote",
    );
  }
  const receipt = new Uint8Array(receiptCbor);
  const leaf = {
    idtimestampBe8: new Uint8Array(idtimestampBe8),
    inner: await grantCommitmentHashFromGrant(grant),
  };
  const { peak, inclusionOk } = await recomputeReceiptPeak({
    receiptCbor: receipt,
    ...leaf,
  });
  if (!inclusionOk) {
    throw new Error(
      "the grant's receipt does not include its leaf: its inclusion path does not reach the peak it carries",
    );
  }
  return {
    kind: "child",
    logId: uuidOf(grant.logId),
    ownerLogId: uuidOf(grant.ownerLogId),
    leafMmrIndex: receiptLeafIndex(receipt),
    grantData: new Uint8Array(grantDataToBytes(grant.grantData)),
    ...leaf,
    peak,
  };
}

/** Read a forest genesis (v2) into a root target. */
export function rootAnchorTarget(genesisCbor: Uint8Array): RootAnchorTarget {
  const binding = decodeChainBindingFromGenesis(genesisCbor);
  const raw = decodeCborDeterministic(genesisCbor);
  const labels =
    raw instanceof Map
      ? (raw as Map<number, unknown>)
      : new Map<number, unknown>();
  const alg = labels.get(FOREST_GENESIS_LABEL_GENESIS_ALG);
  const key = labels.get(FOREST_GENESIS_LABEL_BOOTSTRAP_KEY);
  if (typeof alg !== "number" && typeof alg !== "bigint") {
    throw new Error("genesis carries no bootstrap alg (label -68014)");
  }
  if (!(key instanceof Uint8Array) || (key.length !== 20 && key.length !== 64)) {
    throw new Error(
      "genesis bootstrap key (label -68015) is not a 20-byte KS256 address or a 64-byte ES256 key",
    );
  }
  return {
    kind: "root",
    logId: uuidOf(binding.logId),
    bootstrapAlg: BigInt(alg),
    bootstrapKey: new Uint8Array(key),
  };
}

/** Peaks held from refreshed receipts, besides the grant's own. */
const MAX_REFRESHED_PEAKS = 32;

/**
 * Check, round by round, until the target is anchored or conflicted, or
 * the budget is spent. The first round runs at once; later ones every
 * `intervalMs`. For a child, `refreshReceipt` fetches the grant's receipt
 * again at the start of each round; every peak it has reached so far is
 * matched.
 */
export async function waitAnchored(
  target: AnchorTarget,
  chain: AnchorChain,
  opts: {
    timeoutMs: number;
    intervalMs: number;
    now?: () => number;
    sleep?: (ms: number) => Promise<void>;
    onRound?: (answer: AnchorAnswer, round: number) => void;
    refreshReceipt?: () => Promise<Uint8Array>;
  },
): Promise<AnchorWaitResult> {
  const now = opts.now ?? Date.now;
  const sleep =
    opts.sleep ??
    ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const deadline = now() + opts.timeoutMs;
  const refreshed: Uint8Array[] = [];
  for (let round = 1; ; round++) {
    let note: string | undefined;
    if (target.kind === "child" && opts.refreshReceipt !== undefined) {
      note = await refreshPeak(target, opts.refreshReceipt, refreshed);
    }
    let answer: AnchorAnswer;
    try {
      answer =
        target.kind === "root"
          ? await checkRootAnchored(target, chain)
          : await checkChildAnchored(target, chain, [target.peak, ...refreshed]);
    } catch (err) {
      // Only chain reads can fail here (the target was decoded up front),
      // and a reader that fails may answer next round.
      answer = {
        status: "pending",
        reason: "chain_unavailable",
        detail: `chain read failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    if (answer.status === "pending" && note !== undefined) {
      answer = { ...answer, detail: `${answer.detail}; ${note}` };
    }
    opts.onRound?.(answer, round);
    if (answer.status !== "pending") {
      return { answer, rounds: round, timedOut: false };
    }
    if (now() + opts.intervalMs > deadline) {
      return { answer, rounds: round, timedOut: true };
    }
    await sleep(opts.intervalMs);
  }
}

/**
 * Fetch the grant's receipt again and hold the peak it reaches from the
 * grant's leaf. Returns a note when the fetch fails or proves nothing; the
 * round then goes on with the peaks already held.
 */
async function refreshPeak(
  target: ChildAnchorTarget,
  refreshReceipt: () => Promise<Uint8Array>,
  refreshed: Uint8Array[],
): Promise<string | undefined> {
  let receiptCbor: Uint8Array;
  try {
    receiptCbor = await refreshReceipt();
  } catch (err) {
    return `receipt refresh failed: ${err instanceof Error ? err.message : String(err)}`;
  }
  let peak: Uint8Array;
  try {
    if (receiptLeafIndex(receiptCbor) !== target.leafMmrIndex) {
      throw new Error("it is for another leaf");
    }
    const recomputed = await recomputeReceiptPeak({ receiptCbor, ...target });
    if (!recomputed.inclusionOk) {
      throw new Error("its path does not reach its peak from the grant's leaf");
    }
    peak = recomputed.peak;
  } catch (err) {
    return `the refreshed receipt does not include the create grant: ${err instanceof Error ? err.message : String(err)}`;
  }
  if (
    !bytesEqual(peak, target.peak) &&
    !refreshed.some((p) => bytesEqual(p, peak))
  ) {
    refreshed.push(peak);
    if (refreshed.length > MAX_REFRESHED_PEAKS) refreshed.shift();
  }
  return undefined;
}

/**
 * A root's answer, in the order univocity's root authority gives it
 * (forestrie/arbor `services/univocity/src/authority.go`): no contract is
 * pending; a contract whose bootstrap key differs from the genesis can
 * never take this root; a contract takes one root (platform rule P14), so
 * one rooted at another log is conflicted for good. Before the root's
 * first checkpoint the contract records no root, and the root is anchored.
 */
async function checkRootAnchored(
  target: RootAnchorTarget,
  chain: AnchorChain,
): Promise<AnchorAnswer> {
  if (!(await chain.hasCode())) {
    return {
      status: "pending",
      reason: "contract_not_deployed",
      detail: `no contract is deployed at the genesis address for root ${target.logId} yet`,
    };
  }
  const boot = await chain.bootstrapConfig();
  if (
    boot.alg !== target.bootstrapAlg ||
    !bytesEqual(boot.key, target.bootstrapKey)
  ) {
    return {
      status: "conflicted",
      reason: "bootstrap_key_mismatch",
      detail: `the contract's bootstrap key (alg ${boot.alg}) is not the genesis key of root ${target.logId}`,
    };
  }
  const onChainRoot = await chain.rootLogId();
  if (onChainRoot !== undefined && onChainRoot !== target.logId) {
    return {
      status: "conflicted",
      reason: "contract_rooted_elsewhere",
      detail: `the contract is rooted at log ${onChainRoot}, not ${target.logId}; a contract takes one root`,
    };
  }
  return onChainRoot === undefined
    ? {
        status: "anchored",
        reason: "contract_root_unset",
        detail: `root ${target.logId}'s contract holds its key and records no root yet`,
      }
    : {
        status: "anchored",
        reason: "contract_rooted_here",
        detail: `root ${target.logId}'s contract holds its key and records it as root`,
      };
}

/** A child's answer: is any peak over its leaf one the chain committed to? */
async function checkChildAnchored(
  target: ChildAnchorTarget,
  chain: AnchorChain,
  peaks: Uint8Array[],
): Promise<AnchorAnswer> {
  const config = await chain.logConfig(target.logId);
  if (config !== undefined) return initializedAnswer(target, config);
  const { leafMmrIndex } = target;
  const held = (acc: Uint8Array[]) =>
    acc.some((p) => peaks.some((peak) => bytesEqual(p, peak)));
  const state = await chain.logState(target.ownerLogId);
  if (held(state.accumulator)) {
    return {
      status: "anchored",
      reason: "peak_in_current_state",
      detail: `owner ${target.ownerLogId}'s on-chain state (size ${state.size}) holds the create grant's peak`,
    };
  }
  const reason = classifyUnanchoredPeak(leafMmrIndex, state.size);
  if (reason === "peak_not_current") {
    // The leaf is within the published size but later growth buried the
    // peaks held. A publish relays each massif's current seal, so an
    // earlier accumulator the chain committed to may still hold one.
    const steps = await chain.publishedSteps(target.ownerLogId);
    for (let i = steps.length - 1; i >= 0; i--) {
      const step = steps[i]!;
      if (held(step.accumulator)) {
        return {
          status: "anchored",
          reason: "peak_in_published_step",
          detail: `owner ${target.ownerLogId}'s checkpoint at size ${step.size}, published on chain, holds the create grant's peak`,
        };
      }
    }
  }
  return {
    status: "pending",
    reason,
    detail: `owner ${target.ownerLogId} has published up to size ${state.size}; the create grant is leaf ${leafMmrIndex}`,
  };
}

/**
 * A child the contract has initialized: final either way. Keys are opaque
 * and compared byte for byte at the two lengths a root key can have, 64
 * (ES256 x||y) or 20 (KS256 address), as univocity compares them.
 */
function initializedAnswer(
  target: ChildAnchorTarget,
  config: { ownerLogId: string; rootKey: Uint8Array },
): AnchorAnswer {
  const keyOk =
    (target.grantData.length === 64 || target.grantData.length === 20) &&
    bytesEqual(config.rootKey, target.grantData);
  if (config.ownerLogId === target.ownerLogId && keyOk) {
    return {
      status: "anchored",
      reason: "log_initialized_as_claimed",
      detail: `the contract records log ${target.logId} under owner ${target.ownerLogId} with the grant's key`,
    };
  }
  return {
    status: "conflicted",
    reason: "log_initialized_elsewhere",
    detail:
      config.ownerLogId !== target.ownerLogId
        ? `the contract records log ${target.logId} under owner ${config.ownerLogId}, not ${target.ownerLogId}; start a new log`
        : `the contract records log ${target.logId} with another root key than the grant's; start a new log`,
  };
}

function uuidOf(bytes: Uint8Array): string {
  const h = Buffer.from(bytes.slice(-16)).toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
