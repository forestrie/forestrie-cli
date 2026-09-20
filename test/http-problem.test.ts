import { describe, expect, test } from "bun:test";
import { encodeCborDeterministic } from "@forestrie/encoding";
import { responseProblemDetail } from "../src/lib/http-problem.js";

const problem = { type: "about:blank", title: "Bad Request", status: 400, detail: "Invalid CBOR body" };
const cbor = (contentType: string) =>
  new Response(encodeCborDeterministic(problem), {
    status: 400,
    headers: { "content-type": contentType },
  });

describe("responseProblemDetail (FOR-579)", () => {
  test("decodes CBOR problem details under application/cbor and application/problem+cbor", async () => {
    expect(await responseProblemDetail(cbor("application/cbor"))).toBe("Bad Request: Invalid CBOR body");
    expect(await responseProblemDetail(cbor("application/problem+cbor"))).toBe("Bad Request: Invalid CBOR body");
  });

  test("decodes application/problem+json and falls back to text", async () => {
    const json = new Response(JSON.stringify({ title: "Unauthorized", status: 401 }), {
      status: 401,
      headers: { "content-type": "application/problem+json" },
    });
    expect(await responseProblemDetail(json)).toBe("Unauthorized");
    expect(await responseProblemDetail(new Response("Invalid or revoked onboard token.", { status: 401 }))).toBe(
      "Invalid or revoked onboard token.",
    );
    expect(await responseProblemDetail(new Response(null, { status: 404 }))).toBe("");
  });

  test("never throws on a body that does not decode, and respects the cap", async () => {
    const broken = new Response(new Uint8Array([0xff, 0xff]), { status: 400, headers: { "content-type": "application/cbor" } });
    expect(typeof (await responseProblemDetail(broken))).toBe("string");
    const long = new Response("x".repeat(1000), { status: 500 });
    expect((await responseProblemDetail(long, 300)).length).toBe(300);
  });
});
