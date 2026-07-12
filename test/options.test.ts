import { afterEach, describe, expect, test } from "bun:test";
import { parseCreateReceiptOptions } from "../src/options/create-receipt.js";
import { parseDeployOptions } from "../src/options/deploy.js";
import { parseRegisterOptions } from "../src/options/register.js";
import { parseRegisterGrantOptions } from "../src/options/register-grant.js";
import { parseSignStatementOptions } from "../src/options/sign-statement.js";
import { parseVerifyOptions } from "../src/options/verify.js";

const SAVED = [
  "FORESTRIE_BASE_URL",
  "RPC_URL",
  "GRANT_B64",
  "DEPLOYER_KEY",
  "OWNER_ADDRESS",
].map((name) => [name, process.env[name]] as const);

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
  const DEPLOYER_KEY =
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
  /** Minimal valid argv (generate mode). */
  const base = {
    "rpc-url": "http://x",
    "deployer-key": DEPLOYER_KEY,
    "bootstrap-es256-generate": true,
    "bootstrap-es256-pem-out": "bootstrap.es256.pem",
  };

  test("es256 is the default bootstrap alg (paved path)", () => {
    const options = parseDeployOptions({ ...base });
    expect(options.bootstrapAlg).toBe("es256");
    expect(options.releaseTag).toBe("latest");
    expect(options.deployerKey).toBe(DEPLOYER_KEY);
  });

  test("rejects unknown bootstrap alg", () => {
    expect(() =>
      parseDeployOptions({ ...base, "bootstrap-alg": "rsa" }),
    ).toThrow(/bootstrap-alg/);
  });

  test("rpc-url and deployer-key fall back to env", () => {
    process.env["RPC_URL"] = "http://from-env";
    process.env["DEPLOYER_KEY"] = DEPLOYER_KEY.slice(2).toUpperCase();
    const options = parseDeployOptions({
      "bootstrap-es256-pem": "bootstrap.es256.pem",
    });
    expect(options.rpcUrl).toBe("http://from-env");
    // Normalized: 0x-prefixed, lowercase.
    expect(options.deployerKey).toBe(DEPLOYER_KEY);
  });

  test("missing rpc-url is a usage error", () => {
    delete process.env["RPC_URL"];
    const args: Record<string, string | boolean> = { ...base };
    delete args["rpc-url"];
    expect(() => parseDeployOptions(args)).toThrow(/--rpc-url.*RPC_URL/);
  });

  test("missing deployer-key is a usage error", () => {
    delete process.env["DEPLOYER_KEY"];
    const args: Record<string, string | boolean> = { ...base };
    delete args["deployer-key"];
    expect(() => parseDeployOptions(args)).toThrow(
      /--deployer-key.*DEPLOYER_KEY/,
    );
  });

  test("malformed deployer-key is a usage error", () => {
    expect(() =>
      parseDeployOptions({ ...base, "deployer-key": "0xnothex" }),
    ).toThrow(/32-byte hex/);
  });

  test("es256 requires a key source (generate or pem)", () => {
    expect(() =>
      parseDeployOptions({ "rpc-url": "http://x", "deployer-key": DEPLOYER_KEY }),
    ).toThrow(/--bootstrap-es256-generate .* or --bootstrap-es256-pem/);
  });

  test("generate and pem are mutually exclusive", () => {
    expect(() =>
      parseDeployOptions({ ...base, "bootstrap-es256-pem": "k.pem" }),
    ).toThrow(/mutually exclusive/);
  });

  test("generate requires pem-out (key must be kept)", () => {
    const args: Record<string, string | boolean> = { ...base };
    delete args["bootstrap-es256-pem-out"];
    expect(() => parseDeployOptions(args)).toThrow(/--bootstrap-es256-pem-out/);
  });

  test("pem-out without generate is a usage error", () => {
    expect(() =>
      parseDeployOptions({
        "rpc-url": "http://x",
        "deployer-key": DEPLOYER_KEY,
        "bootstrap-es256-pem": "k.pem",
        "bootstrap-es256-pem-out": "out.pem",
      }),
    ).toThrow(/only meaningful with --bootstrap-es256-generate/);
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
    expect(options.mmrIndex).toBe(0n);
    expect(options.entryId).toBeUndefined();
  });

  test("entry-id is the other leaf address", () => {
    const options = parseCreateReceiptOptions({
      massif: "m.log",
      "entry-id": "02".repeat(16),
      checkpoint: "c.sth",
    });
    expect(options.entryId).toBe("02".repeat(16));
    expect(options.mmrIndex).toBeUndefined();
  });

  test("exactly one of mmr-index / entry-id is required", () => {
    expect(() =>
      parseCreateReceiptOptions({ massif: "m.log", checkpoint: "c.sth" }),
    ).toThrow(/--mmr-index or --entry-id/);
    expect(() =>
      parseCreateReceiptOptions({
        massif: "m.log",
        checkpoint: "c.sth",
        "mmr-index": "0",
        "entry-id": "02".repeat(16),
      }),
    ).toThrow(/--mmr-index or --entry-id/);
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
  test("requires committed-grant or committed-grant-file", () => {
    delete process.env["GRANT_B64"];
    expect(() =>
      parseVerifyOptions({ genesis: "g.cbor", receipt: "r.cbor" }),
    ).toThrow(/--committed-grant or --committed-grant-file/);
  });

  test("committed-grant-file requires entry-id", () => {
    expect(() =>
      parseVerifyOptions({
        genesis: "g.cbor",
        receipt: "r.cbor",
        "committed-grant-file": "grant.cbor",
      }),
    ).toThrow(/--entry-id/);
  });

  const base = {
    genesis: "g.cbor",
    receipt: "r.cbor",
    "committed-grant": "AAAA",
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
