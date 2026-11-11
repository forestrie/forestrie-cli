import { beforeAll, describe, expect, test } from "bun:test";
import {
  childAnchorTarget,
  rootAnchorTarget,
  waitAnchored,
  type AnchorChain,
  type PublishedStep,
} from "../src/lib/anchor-wait.js";
import type { OnChainLogState } from "../src/lib/verify-anchored.js";
import {
  CHILD_LOG,
  OWNER_LOG,
  buildChildAnchorFixture,
  type ChildAnchorFixture,
} from "./anchor-wait-fixture.js";
import {
  FIXTURE_LOG_ID,
  buildGenesisCbor,
  buildPeakReceipt,
  generateP256KeyPair,
} from "./verify-fixture.js";

/** Deterministic clock: `sleep` advances `now` instead of waiting. */
function fakeClock() {
  let t = 0;
  const waits: number[] = [];
  return {
    now: () => t,
    sleep: async (ms: number) => {
      waits.push(ms);
      t += ms;
    },
    waits,
  };
}

/**
 * A chain whose owner-log state is scripted per round: round n reads
 * `states[n]`, and the last entry repeats. Reads of any other log fail.
 */
function fakeChain(opts: {
  states: OnChainLogState[];
  steps?: PublishedStep[];
  /** What the contract records for the child, once it is initialized. */
  childConfig?: { ownerLogId: string; rootKey: Uint8Array };
}): AnchorChain & { logStateReads: number } {
  const chain = {
    logStateReads: 0,
    async logConfig(logId: string) {
      if (logId !== CHILD_LOG) throw new Error(`unexpected log ${logId}`);
      return opts.childConfig;
    },
    async logState(logId: string): Promise<OnChainLogState> {
      if (logId !== OWNER_LOG) throw new Error(`unexpected log ${logId}`);
      const state =
        opts.states[Math.min(chain.logStateReads, opts.states.length - 1)]!;
      chain.logStateReads++;
      return state;
    },
    async publishedSteps(logId: string): Promise<PublishedStep[]> {
      if (logId !== OWNER_LOG) throw new Error(`unexpected log ${logId}`);
      return opts.steps ?? [];
    },
    async hasCode(): Promise<boolean> {
      throw new Error("not a root check");
    },
    async bootstrapConfig(): Promise<{ alg: bigint; key: Uint8Array }> {
      throw new Error("not a root check");
    },
    async rootLogId(): Promise<string | undefined> {
      throw new Error("not a root check");
    },
    async chainId(): Promise<bigint> {
      return 84532n;
    },
  };
  return chain;
}

let fx: ChildAnchorFixture;
beforeAll(async () => {
  fx = await buildChildAnchorFixture();
});

const WAIT = { timeoutMs: 60_000, intervalMs: 5_000 };

describe("waitAnchored (child log)", () => {
  test("a child the contract initialized with its claimed owner and key is anchored, without the owner's state", async () => {
    const clock = fakeClock();
    const chain = fakeChain({
      states: [{ accumulator: [], size: 0n }],
      childConfig: { ownerLogId: OWNER_LOG, rootKey: fx.grantData },
    });
    const result = await waitAnchored(
      await childAnchorTarget(fx.completedGrantB64),
      chain,
      { ...WAIT, ...clock },
    );
    expect(result.answer).toMatchObject({
      status: "anchored",
      reason: "log_initialized_as_claimed",
    });
    expect(chain.logStateReads).toBe(0);
  });

  test("a child the contract initialized under another owner is conflicted at once, even with its grant anchored", async () => {
    // Another owner log named this child in a create grant of its own and
    // reached the chain first. This grant is still in its owner's
    // published state, but the chain records the other claim for good.
    const clock = fakeClock();
    const chain = fakeChain({
      states: [{ accumulator: [fx.peak], size: 3n }],
      childConfig: {
        ownerLogId: "0badbeef-0000-4000-8000-000000000009",
        rootKey: fx.grantData,
      },
    });
    const result = await waitAnchored(
      await childAnchorTarget(fx.completedGrantB64),
      chain,
      { ...WAIT, ...clock },
    );
    expect(result.answer).toMatchObject({
      status: "conflicted",
      reason: "log_initialized_elsewhere",
    });
    expect(result.answer.detail).toContain("0badbeef-0000-4000-8000-000000000009");
    expect(result.rounds).toBe(1);
    expect(clock.waits).toEqual([]);
  });

  test("a child the contract initialized with another key is conflicted", async () => {
    const chain = fakeChain({
      states: [{ accumulator: [fx.peak], size: 3n }],
      childConfig: { ownerLogId: OWNER_LOG, rootKey: new Uint8Array(64).fill(0x01) },
    });
    const result = await waitAnchored(
      await childAnchorTarget(fx.completedGrantB64),
      chain,
      { ...WAIT, ...fakeClock() },
    );
    expect(result.answer).toMatchObject({
      status: "conflicted",
      reason: "log_initialized_elsewhere",
    });
  });

  test("a receipt refreshed each round proves a log whose receipt's seal never reached the chain", async () => {
    // The grant's receipt is from a size-3 seal that the owner's publisher
    // coalesced away: the chain went from nothing straight to size 7, where
    // node 2 is buried. The receipt canopy serves now is for size 7.
    const clock = fakeClock();
    const chain = fakeChain({ states: [{ accumulator: [fx.peak7], size: 7n }] });
    let fetches = 0;
    const result = await waitAnchored(
      await childAnchorTarget(fx.completedGrantB64),
      chain,
      {
        ...WAIT,
        ...clock,
        refreshReceipt: async () => {
          fetches++;
          return fx.receiptCbor7;
        },
      },
    );
    expect(result.answer).toMatchObject({
      status: "anchored",
      reason: "peak_in_current_state",
    });
    expect(result.rounds).toBe(1);
    expect(fetches).toBe(1);
  });

  test("a refreshed receipt for another MMR index is set aside, with a note", async () => {
    const elsewhere = await buildPeakReceipt({
      signer: await generateP256KeyPair(),
      peak: new Uint8Array(32).fill(0x0e),
      proof: { path: [new Uint8Array(32).fill(0x0f)], mmrIndex: 0n },
    });
    const result = await waitAnchored(
      await childAnchorTarget(fx.completedGrantB64),
      fakeChain({ states: [{ accumulator: [fx.peak7], size: 7n }] }),
      {
        timeoutMs: 0,
        intervalMs: 5_000,
        ...fakeClock(),
        refreshReceipt: async () => elsewhere,
      },
    );
    expect(result.answer.status).toBe("pending");
    expect(result.answer.detail).toContain(
      "the refreshed receipt does not include the create grant: it is for another leaf",
    );
  });

  test("a refreshed receipt for another grant at this position proves nothing", async () => {
    const other = await buildChildAnchorFixture({ grantDataFill: 0x77 });
    const clock = fakeClock();
    const chain = fakeChain({ states: [{ accumulator: [other.peak7], size: 7n }] });
    const result = await waitAnchored(
      await childAnchorTarget(fx.completedGrantB64),
      chain,
      {
        timeoutMs: 5_000,
        intervalMs: 5_000,
        ...clock,
        refreshReceipt: async () => other.receiptCbor7,
      },
    );
    // Its path, hashed up from this grant's leaf, reaches a peak the chain
    // never committed to: a wrong receipt can delay the answer, not fake it.
    expect(result.answer.status).toBe("pending");
    expect(result.answer.reason).toBe("peak_not_current");
    expect(result.timedOut).toBe(true);
  });

  test("a round that never finishes ends one grace period past --timeout", async () => {
    const never = () => new Promise<never>(() => {});
    const started = Date.now();
    const result = await waitAnchored(
      await childAnchorTarget(fx.completedGrantB64),
      {
        ...fakeChain({ states: [] }),
        logConfig: never,
        logState: never,
        publishedSteps: never,
      },
      // The real clock: this is about wall-clock time.
      { timeoutMs: 30, intervalMs: 10, roundGraceMs: 30 },
    );
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(result).toMatchObject({ rounds: 1, timedOut: true });
    expect(result.answer.status).toBe("pending");
    expect(result.answer.reason).toBe("chain_unavailable");
    expect(result.answer.detail).toContain("the round did not finish");
  });

  test("a failed refresh leaves the round to the receipts already held", async () => {
    const clock = fakeClock();
    const chain = fakeChain({ states: [{ accumulator: [fx.peak], size: 3n }] });
    const result = await waitAnchored(
      await childAnchorTarget(fx.completedGrantB64),
      chain,
      {
        ...WAIT,
        ...clock,
        refreshReceipt: async () => {
          throw new Error("receipt: HTTP 503");
        },
      },
    );
    expect(result.answer.status).toBe("anchored");
    expect(result.rounds).toBe(1);
  });

  test("an already-anchored log returns at once", async () => {
    const clock = fakeClock();
    const chain = fakeChain({ states: [{ accumulator: [fx.peak], size: 3n }] });
    const result = await waitAnchored(
      await childAnchorTarget(fx.completedGrantB64),
      chain,
      { ...WAIT, ...clock },
    );
    expect(result.answer.status).toBe("anchored");
    expect(result.timedOut).toBe(false);
    expect(chain.logStateReads).toBe(1);
    expect(clock.waits).toEqual([]);
  });

  test("returns as soon as a published checkpoint of the owner covers the grant", async () => {
    const clock = fakeClock();
    const chain = fakeChain({
      states: [
        { accumulator: [new Uint8Array(32).fill(1)], size: 1n },
        { accumulator: [fx.peak], size: 3n },
      ],
    });
    const result = await waitAnchored(
      await childAnchorTarget(fx.completedGrantB64),
      chain,
      { ...WAIT, ...clock },
    );
    expect(result.answer.status).toBe("anchored");
    expect(result.rounds).toBe(2);
    expect(clock.waits).toEqual([5_000]);
  });

  test("keeps waiting while the leaf is sequenced but not published, then times out", async () => {
    // The owner has published, but only up to size 1: the grant's leaf
    // (index 1) is beyond it, so no peak can match (the slice's "confirm
    // first" case, with a non-zero size).
    const clock = fakeClock();
    const chain = fakeChain({
      states: [{ accumulator: [new Uint8Array(32).fill(1)], size: 1n }],
    });
    const result = await waitAnchored(
      await childAnchorTarget(fx.completedGrantB64),
      chain,
      { timeoutMs: 12_000, intervalMs: 5_000, ...clock },
    );
    expect(result.timedOut).toBe(true);
    expect(result.answer.status).toBe("pending");
    expect(result.answer.reason).toBe("receipt_newer_than_anchored_state");
    expect(result.rounds).toBe(3);
    expect(clock.waits).toEqual([5_000, 5_000]);
  });

  test("a peak buried by later growth is proven from the published steps", async () => {
    const chain = fakeChain({
      states: [{ accumulator: [fx.peak7], size: 7n }],
      steps: [
        { size: 3n, accumulator: [fx.peak] },
        { size: 7n, accumulator: [fx.peak7] },
      ],
    });
    const result = await waitAnchored(
      await childAnchorTarget(fx.completedGrantB64),
      chain,
      { ...WAIT, ...fakeClock() },
    );
    expect(result.answer.status).toBe("anchored");
    expect(result.answer.reason).toBe("peak_in_published_step");
    expect(result.rounds).toBe(1);
  });

  test("a failed chain read is a pending round, not the end of the wait", async () => {
    const clock = fakeClock();
    const steady = fakeChain({ states: [{ accumulator: [fx.peak], size: 3n }] });
    let reads = 0;
    const flaky: AnchorChain = {
      ...steady,
      async logState(logId: string) {
        if (reads++ === 0) throw new Error("rpc: connection reset");
        return steady.logState(logId);
      },
    };
    const answers: string[] = [];
    const result = await waitAnchored(
      await childAnchorTarget(fx.completedGrantB64),
      flaky,
      { ...WAIT, ...clock, onRound: (a) => answers.push(a.reason) },
    );
    expect(answers).toEqual(["chain_unavailable", "peak_in_current_state"]);
    expect(result.answer.status).toBe("anchored");
  });

  test("a buried peak no published step holds stays pending, not final", async () => {
    // The receipt may come from a sealed size the chain has not reached.
    const chain = fakeChain({
      states: [{ accumulator: [fx.peak7], size: 7n }],
      steps: [{ size: 7n, accumulator: [fx.peak7] }],
    });
    const result = await waitAnchored(
      await childAnchorTarget(fx.completedGrantB64),
      chain,
      { timeoutMs: 5_000, intervalMs: 5_000, ...fakeClock() },
    );
    expect(result.answer.status).toBe("pending");
    expect(result.answer.reason).toBe("peak_not_current");
    expect(result.timedOut).toBe(true);
  });
});

/** A contract scripted for the forest-root checks. */
function fakeRootChain(opts: {
  deployed?: boolean;
  bootstrap?: { alg: bigint; key: Uint8Array };
  rootLogId?: string | undefined;
}): AnchorChain {
  return {
    async logState(): Promise<OnChainLogState> {
      throw new Error("not a child check");
    },
    async publishedSteps(): Promise<PublishedStep[]> {
      throw new Error("not a child check");
    },
    async hasCode() {
      return opts.deployed ?? true;
    },
    async bootstrapConfig() {
      return opts.bootstrap ?? { alg: -7n, key: ROOT_KEY };
    },
    async logConfig() {
      return undefined;
    },
    async rootLogId() {
      return opts.rootLogId;
    },
    async chainId() {
      return 84532n;
    },
  };
}

const ROOT_KEY = new Uint8Array(64).fill(0x42);
const OTHER_ROOT = "0badbeef-0000-4000-8000-000000000009";

describe("waitAnchored (forest root)", () => {
  const root = () => rootAnchorTarget(buildGenesisCbor(ROOT_KEY));

  test("a contract that records another root is conflicted at once", async () => {
    const clock = fakeClock();
    const result = await waitAnchored(
      root(),
      fakeRootChain({ rootLogId: OTHER_ROOT }),
      { ...WAIT, ...clock },
    );
    expect(result.answer.status).toBe("conflicted");
    expect(result.answer.reason).toBe("contract_rooted_elsewhere");
    expect(result.answer.detail).toContain(OTHER_ROOT);
    expect(result.rounds).toBe(1);
    expect(clock.waits).toEqual([]);
  });

  test("a root is anchored once its contract is deployed with the genesis key", async () => {
    for (const rootLogId of [undefined, FIXTURE_LOG_ID]) {
      const result = await waitAnchored(
        root(),
        fakeRootChain({ rootLogId }),
        { ...WAIT, ...fakeClock() },
      );
      expect(result.answer.status).toBe("anchored");
    }
  });

  test("a root whose contract is not deployed yet is pending", async () => {
    const result = await waitAnchored(
      root(),
      fakeRootChain({ deployed: false }),
      { timeoutMs: 1_000, intervalMs: 5_000, ...fakeClock() },
    );
    expect(result.answer.status).toBe("pending");
    expect(result.answer.reason).toBe("contract_not_deployed");
    expect(result.timedOut).toBe(true);
  });

  test("a contract whose bootstrap key is not the genesis key is final", async () => {
    const clock = fakeClock();
    const result = await waitAnchored(
      root(),
      fakeRootChain({
        bootstrap: { alg: -7n, key: new Uint8Array(64).fill(0x43) },
      }),
      { ...WAIT, ...clock },
    );
    expect(result.answer.status).toBe("conflicted");
    expect(result.answer.reason).toBe("bootstrap_key_mismatch");
    expect(result.rounds).toBe(1);
    expect(clock.waits).toEqual([]);
  });
});
