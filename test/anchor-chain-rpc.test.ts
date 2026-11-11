import { describe, expect, test } from "bun:test";
import { encodeAbiParameters, toFunctionSelector } from "viem";
import { rpcAnchorChain } from "../src/lib/anchor-chain-rpc.js";
import { receiptRefresher } from "../src/lib/anchor-wait-run.js";
import { encodeLogStateResult } from "./verify-fixture.js";

const UNIVOCITY = "0x" + "ab".repeat(20);
const RPC = "https://rpc.example";

type Call = { method: string; params: unknown[] };

/** JSON-RPC server answering `eth_call` by selector and `eth_getCode`. */
function rpcFetch(answers: {
  calls?: Record<string, string>;
  code?: string;
  seen?: Call[];
}): typeof fetch {
  return (async (_input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const req = JSON.parse(String(init?.body)) as Call & { id: number };
    answers.seen?.push({ method: req.method, params: req.params });
    let result: unknown;
    if (req.method === "eth_getCode") result = answers.code ?? "0x";
    if (req.method === "eth_call") {
      const data = (req.params[0] as { data: string }).data;
      result = answers.calls?.[data.slice(0, 10)];
    }
    if (result === undefined) {
      return Response.json({
        jsonrpc: "2.0",
        id: req.id,
        error: { code: -32601, message: `unexpected ${req.method}` },
      });
    }
    return Response.json({ jsonrpc: "2.0", id: req.id, result });
  }) as typeof fetch;
}

// Selectors computed from the ABI signatures, not copied from the code.
const ROOT_LOG_ID = toFunctionSelector("rootLogId()");
const BOOTSTRAP_CONFIG = toFunctionSelector("bootstrapConfig()");
const LOG_STATE = toFunctionSelector("logState(bytes32)");
const LOG_CONFIG = toFunctionSelector("logConfig(bytes32)");

describe("rpcAnchorChain", () => {
  test("reads the bootstrap config as (alg, opaque key)", async () => {
    const key = new Uint8Array(64).fill(0x42);
    const chain = rpcAnchorChain({
      univocity: UNIVOCITY,
      rpcUrl: RPC,
      fetchImpl: rpcFetch({
        calls: {
          [BOOTSTRAP_CONFIG]: encodeAbiParameters(
            [{ type: "int64" }, { type: "bytes" }],
            [-7n, `0x${"42".repeat(64)}`],
          ),
        },
      }),
    });
    expect(await chain.bootstrapConfig()).toEqual({ alg: -7n, key });
  });

  test("rootLogId: unset is undefined, a UUID-shaped id is its UUID", async () => {
    const read = (word: string) =>
      rpcAnchorChain({
        univocity: UNIVOCITY,
        rpcUrl: RPC,
        fetchImpl: rpcFetch({ calls: { [ROOT_LOG_ID]: word } }),
      }).rootLogId();
    expect(await read("0x" + "00".repeat(32))).toBeUndefined();
    expect(
      await read("0x" + "00".repeat(16) + "0badbeef00004000800000000000000a"),
    ).toBe("0badbeef-0000-4000-8000-00000000000a");
    // A 32-byte id that is not UUID-shaped can never be a UUID log's id.
    const wide = "0x" + "01" + "00".repeat(15) + "0badbeef00004000800000000000000a";
    expect(await read(wide)).toBe(wide);
  });

  test("hasCode is false when the address holds no code", async () => {
    const at = (code: string) =>
      rpcAnchorChain({
        univocity: UNIVOCITY,
        rpcUrl: RPC,
        fetchImpl: rpcFetch({ code }),
      }).hasCode();
    expect(await at("0x")).toBe(false);
    expect(await at("0x6080")).toBe(true);
  });

  describe("logConfig", () => {
    const child = "7a6b5c4d-0000-4000-8000-000000000002";
    const owner = "7a6b5c4d-0000-4000-8000-000000000001";
    const ownerWord = `0x${"00".repeat(16)}${owner.replaceAll("-", "")}` as const;
    const record = (authLogId: `0x${string}`, rootKey: `0x${string}`, initializedAt: bigint) =>
      encodeAbiParameters(
        [
          {
            type: "tuple",
            components: [
              { type: "uint8" },
              { type: "bytes32" },
              { type: "bytes" },
              { type: "uint256" },
            ],
          },
        ],
        [[initializedAt === 0n ? 0 : 2, authLogId, rootKey, initializedAt]],
      );
    const read = (answer: string, seen?: Call[]) =>
      rpcAnchorChain({
        univocity: UNIVOCITY,
        rpcUrl: RPC,
        fetchImpl: rpcFetch({ calls: { [LOG_CONFIG]: answer }, ...(seen ? { seen } : {}) }),
      }).logConfig(child);

    test("the recorded owner and key, from one read of the record", async () => {
      const seen: Call[] = [];
      expect(await read(record(ownerWord, `0x${"5c".repeat(64)}`, 1234n), seen)).toEqual({
        ownerLogId: owner,
        rootKey: new Uint8Array(64).fill(0x5c),
      });
      // One eth_call: initialization is read from the same record, so two
      // nodes behind a load balancer cannot give a torn answer.
      expect(seen).toHaveLength(1);
    });

    test("undefined while the record is unset", async () => {
      expect(await read(record(`0x${"00".repeat(32)}`, "0x", 0n))).toBeUndefined();
    });

    test("an initialized record with a malformed root key is a chain error, not a claim", async () => {
      // univocity only records 64- or 20-byte keys; anything else is a bad
      // answer, and must never become a final conflicted.
      await expect(read(record(ownerWord, "0x", 99n))).rejects.toThrow(
        /root key of 0 bytes/,
      );
      await expect(read(record(ownerWord, `0x${"5c".repeat(33)}`, 99n))).rejects.toThrow(
        /root key of 33 bytes/,
      );
    });
  });

  test("logState reads the owner's accumulator through the injected fetch", async () => {
    const peak = new Uint8Array(32).fill(7);
    const seen: Call[] = [];
    const chain = rpcAnchorChain({
      univocity: UNIVOCITY,
      rpcUrl: RPC,
      fetchImpl: rpcFetch({
        calls: { [LOG_STATE]: encodeLogStateResult([peak], 3n) },
        seen,
      }),
    });
    const state = await chain.logState("7a6b5c4d-0000-4000-8000-000000000001");
    expect(state).toEqual({ accumulator: [peak], size: 3n });
    expect((seen[0]!.params[0] as { data: string }).data).toBe(
      LOG_STATE + "00".repeat(16) + "7a6b5c4d000040008000000000000001",
    );
  });
});

/** A server that accepts the request and never answers, ignoring aborts. */
const silent = (() => new Promise<Response>(() => {})) as unknown as typeof fetch;

describe("request timeouts", () => {
  test("a chain read that never answers fails within the request timeout", async () => {
    const chain = rpcAnchorChain({
      univocity: UNIVOCITY,
      rpcUrl: RPC,
      fetchImpl: silent,
      requestTimeoutMs: 20,
    });
    await expect(chain.publishedSteps("7a6b5c4d-0000-4000-8000-000000000001")).rejects.toThrow(
      /no response .* within 20 ms/,
    );
    await expect(chain.logState("7a6b5c4d-0000-4000-8000-000000000001")).rejects.toThrow();
  });

  test("a receipt URL that never answers fails the refresh within the request timeout", async () => {
    const refresh = receiptRefresher("https://scrapi.example/r", silent, 20);
    await expect(refresh()).rejects.toThrow(/no response .* within 20 ms/);
  });
});
