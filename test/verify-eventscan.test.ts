import { describe, expect, test } from "bun:test";
import {
  CHECKPOINT_PUBLISHED_TOPIC0,
  decodeCheckpointPublishedData,
  selectPublishedAtBlock,
  type PublishedCheckpoint,
} from "../src/lib/verify-eventscan.js";

const word = (v: bigint) => v.toString(16).padStart(64, "0");

function encodeData(peaks: Uint8Array[], size: bigint): string {
  let hex = "";
  hex += word(0n); // sender
  hex += word(0n); // grantIDTimestampBe
  hex += word(0n); // logKind
  hex += word(size);
  hex += word(BigInt(7 * 32)); // accumulator offset
  hex += word(0n); // grantIndex
  hex += word(BigInt((8 + peaks.length) * 32)); // grantPath offset
  hex += word(BigInt(peaks.length));
  for (const p of peaks) {
    hex += Array.from(p, (b) => b.toString(16).padStart(2, "0")).join("");
  }
  hex += word(0n); // grantPath length
  return "0x" + hex;
}

describe("decodeCheckpointPublishedData (FOR-368)", () => {
  test("decodes size and accumulator from the ABI layout", () => {
    const peaks = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)];
    const { size, accumulator } = decodeCheckpointPublishedData(
      encodeData(peaks, 206n),
    );
    expect(size).toBe(206n);
    expect(accumulator.length).toBe(2);
    expect(Buffer.from(accumulator[0]!)).toEqual(Buffer.from(peaks[0]!));
    expect(Buffer.from(accumulator[1]!)).toEqual(Buffer.from(peaks[1]!));
  });

  test("rejects truncated data", () => {
    const good = encodeData([new Uint8Array(32).fill(1)], 5n);
    // Cut into the accumulator element region (peak word + trailing words).
    expect(() =>
      decodeCheckpointPublishedData(good.slice(0, good.length - 192)),
    ).toThrow(/truncated/);
  });

  test("topic0 is the precomputed event signature hash", () => {
    expect(CHECKPOINT_PUBLISHED_TOPIC0).toMatch(/^0x[0-9a-f]{64}$/);
  });
});

describe("selectPublishedAtBlock (FOR-368)", () => {
  const cp = (blockNumber: bigint, size: bigint): PublishedCheckpoint => ({
    size,
    accumulator: [],
    blockNumber,
    txHash: "0x",
    blockHash: "0x" + "00".repeat(32),
  });

  test("picks the latest anchor at or before the block", () => {
    const published = [cp(10n, 100n), cp(20n, 200n), cp(30n, 300n)];
    expect(selectPublishedAtBlock(published, 25n)?.size).toBe(200n);
    expect(selectPublishedAtBlock(published, 20n)?.size).toBe(200n);
    expect(selectPublishedAtBlock(published, 100n)?.size).toBe(300n);
  });

  test("returns null before the first anchor", () => {
    expect(selectPublishedAtBlock([cp(10n, 100n)], 9n)).toBeNull();
  });
});
