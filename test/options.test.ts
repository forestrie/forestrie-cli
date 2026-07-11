import { afterEach, describe, expect, test } from "bun:test";
import { parseCreateReceiptOptions } from "../src/options/create-receipt.js";
import { parseDeployOptions } from "../src/options/deploy.js";
import { parseRegisterOptions } from "../src/options/register.js";
import { parseRegisterGrantOptions } from "../src/options/register-grant.js";
import { parseSignStatementOptions } from "../src/options/sign-statement.js";
import { parseVerifyOptions } from "../src/options/verify.js";

const SAVED = ["FORESTRIE_BASE_URL", "RPC_URL", "GRANT_B64"].map(
  (name) => [name, process.env[name]] as const,
);

afterEach(() => {
  for (const [name, value] of SAVED) {
    if (value === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = value;
    }
  }
});

describe("parseDeployOptions", () => {
  test("es256 is the default bootstrap alg (paved path)", () => {
    const options = parseDeployOptions({ "rpc-url": "http://x" });
    expect(options.bootstrapAlg).toBe("es256");
  });

  test("rejects unknown bootstrap alg", () => {
    expect(() =>
      parseDeployOptions({ "rpc-url": "http://x", "bootstrap-alg": "rsa" }),
    ).toThrow(/bootstrap-alg/);
  });

  test("rpc-url falls back to RPC_URL env", () => {
    process.env["RPC_URL"] = "http://from-env";
    expect(parseDeployOptions({}).rpcUrl).toBe("http://from-env");
  });

  test("missing rpc-url is a usage error", () => {
    delete process.env["RPC_URL"];
    expect(() => parseDeployOptions({})).toThrow(/--rpc-url.*RPC_URL/);
  });
});

describe("parseSignStatementOptions", () => {
  test("content-type defaults to application/json", () => {
    const options = parseSignStatementOptions({
      key: "k.pem",
      payload: "p.json",
    });
    expect(options.contentType).toBe("application/json");
    expect(options.out).toBeUndefined();
  });
});

describe("parseRegisterOptions", () => {
  test("base-url and grant-b64 fall back to env", () => {
    process.env["FORESTRIE_BASE_URL"] = "https://env.example";
    process.env["GRANT_B64"] = "ZW52";
    const options = parseRegisterOptions({
      "log-id": "L",
      statement: "s.cose",
    });
    expect(options.baseUrl).toBe("https://env.example");
    expect(options.grantB64).toBe("ZW52");
  });
});

describe("parseRegisterGrantOptions", () => {
  const base = {
    "base-url": "https://x",
    "owner-log": "A",
    "data-log": "B",
    "sign-with": "k.pem",
  };

  test("requires a parent grant unless self-referential", () => {
    expect(() => parseRegisterGrantOptions({ ...base })).toThrow(
      /--parent-grant-b64 or --self-referential/,
    );
  });

  test("self-referential and parent grant are mutually exclusive", () => {
    expect(() =>
      parseRegisterGrantOptions({
        ...base,
        "self-referential": true,
        "parent-grant-b64": "AAAA",
      }),
    ).toThrow(/mutually exclusive/);
  });
});

describe("parseCreateReceiptOptions", () => {
  test("checkpoint selects offline mode", () => {
    const options = parseCreateReceiptOptions({
      massif: "m.log",
      "mmr-index": "0",
      checkpoint: "c.sth",
    });
    expect(options.anchor).toBe("checkpoint");
    expect(options.mmrIndex).toBe(0);
  });

  test("univocity selects chain mode and requires log-id + rpc-url", () => {
    delete process.env["RPC_URL"];
    expect(() =>
      parseCreateReceiptOptions({
        massif: "m.log",
        "mmr-index": "0",
        univocity: "0xabc",
      }),
    ).toThrow(/--log-id and --rpc-url/);
    const options = parseCreateReceiptOptions({
      massif: "m.log",
      "mmr-index": "0",
      univocity: "0xabc",
      "log-id": "L",
      "rpc-url": "http://x",
    });
    expect(options.anchor).toBe("chain");
  });

  test("checkpoint and univocity together are rejected", () => {
    expect(() =>
      parseCreateReceiptOptions({
        massif: "m.log",
        "mmr-index": "0",
        checkpoint: "c.sth",
        univocity: "0xabc",
      }),
    ).toThrow(/exactly one/);
  });

  test("mmr-index must be a non-negative integer", () => {
    expect(() =>
      parseCreateReceiptOptions({
        massif: "m.log",
        "mmr-index": "peak",
        checkpoint: "c.sth",
      }),
    ).toThrow(/--mmr-index/);
  });
});

describe("parseVerifyOptions", () => {
  test("requires grant-b64 or grant CBOR", () => {
    delete process.env["GRANT_B64"];
    expect(() =>
      parseVerifyOptions({ genesis: "g.cbor", receipt: "r.cbor" }),
    ).toThrow(/--grant-b64 or --grant/);
  });

  test("grant CBOR requires entry-id", () => {
    expect(() =>
      parseVerifyOptions({
        genesis: "g.cbor",
        receipt: "r.cbor",
        grant: "grant.cbor",
      }),
    ).toThrow(/--entry-id/);
  });

  const base = {
    genesis: "g.cbor",
    receipt: "r.cbor",
    "grant-b64": "AAAA",
  };

  test("defaults to the offline anchor (no network)", () => {
    expect(parseVerifyOptions({ ...base }).anchor).toBe("offline");
  });

  test("univocity selects chain mode and requires log-id + rpc-url", () => {
    delete process.env["RPC_URL"];
    expect(() =>
      parseVerifyOptions({ ...base, univocity: "0xabc" }),
    ).toThrow(/--univocity, --log-id and --rpc-url/);
    const options = parseVerifyOptions({
      ...base,
      univocity: "0xabc",
      "log-id": "L",
      "rpc-url": "http://x",
    });
    expect(options.anchor).toBe("chain");
  });

  test("chain mode rpc-url falls back to RPC_URL env", () => {
    process.env["RPC_URL"] = "http://from-env";
    const options = parseVerifyOptions({
      ...base,
      univocity: "0xabc",
      "log-id": "L",
    });
    expect(options.anchor).toBe("chain");
    expect(options.rpcUrl).toBe("http://from-env");
  });
});
