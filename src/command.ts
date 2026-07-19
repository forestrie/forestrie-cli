import { defineForestrieCommand } from "./commoncli.js";

/**
 * Root `forestrie` command. Subcommands are lazy-loaded citty modules;
 * argument parsing lives in `src/options/`, behaviour in `src/main/`
 * (parse/execute split — see AGENTS.md).
 */
export default defineForestrieCommand({
  meta: {
    name: "forestrie",
    version: "0.2.0",
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
    "create-receipt": () =>
      import("./commands/create-receipt.js").then((m) => m.default),
    "decode-receipt": () =>
      import("./commands/decode-receipt.js").then((m) => m.default),
    verify: () => import("./commands/verify.js").then((m) => m.default),
    "verify-grant": () =>
      import("./commands/verify-grant.js").then((m) => m.default),
    "fetch-accumulator": () =>
      import("./commands/fetch-accumulator.js").then((m) => m.default),
  },
});
