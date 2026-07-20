import pkg from "../package.json" with { type: "json" };
import { defineForestrieCommand } from "./commoncli.js";

/**
 * Root `forestrie` command. Subcommands are lazy-loaded citty modules;
 * argument parsing lives in `src/options/`, behaviour in `src/main/`
 * (parse/execute split — see AGENTS.md).
 */
export default defineForestrieCommand({
  meta: {
    name: "forestrie",
    // Single source of truth: release.yml's assert-tag-version checks
    // package.json, so deriving here keeps `forestrie --version` honest
    // (the v0.3.0 binary self-reported 0.2.0 from a stale literal).
    version: pkg.version,
    description:
      "Participant CLI for forestrie transparency logs (SCITT / COSE receipts; ES256 is the paved path)",
  },
  subCommands: {
    admin: () => import("./commands/admin.js").then((m) => m.default),
    deploy: () => import("./commands/deploy.js").then((m) => m.default),
    "sign-statement": () =>
      import("./commands/sign-statement.js").then((m) => m.default),
    register: () => import("./commands/register.js").then((m) => m.default),
    "create-log": () =>
      import("./commands/create-log.js").then((m) => m.default),
    "register-grant": () =>
      import("./commands/register-grant.js").then((m) => m.default),
    delegate: () => import("./commands/delegate.js").then((m) => m.default),
    "onboard-genesis": () =>
      import("./commands/onboard-genesis.js").then((m) => m.default),
    "complete-grant": () =>
      import("./commands/complete-grant.js").then((m) => m.default),
    "resolve-receipt": () =>
      import("./commands/resolve-receipt.js").then((m) => m.default),
    // Non-breaking alias for the pre-FOR-418 name (plan-2607-32 D5).
    "create-receipt": () =>
      import("./commands/resolve-receipt.js").then((m) => m.default),
    "decode-receipt": () =>
      import("./commands/decode-receipt.js").then((m) => m.default),
    verify: () => import("./commands/verify.js").then((m) => m.default),
    "verify-grant": () =>
      import("./commands/verify-grant.js").then((m) => m.default),
    "fetch-accumulator": () =>
      import("./commands/fetch-accumulator.js").then((m) => m.default),
    "create-consistency-proof": () =>
      import("./commands/create-consistency-proof.js").then((m) => m.default),
  },
});
