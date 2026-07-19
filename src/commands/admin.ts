import { defineForestrieCommand } from "../commoncli.js";

/**
 * `forestrie admin` — the operator-credential command family (ADR-0052).
 *
 * Participant commands never read operator secrets; anything requiring
 * `CANOPY_OPS_ADMIN_TOKEN` (or future operator credentials) lives under
 * this family so the split is enforced by the command tree itself.
 */
export default defineForestrieCommand({
  meta: {
    name: "admin",
    description:
      "Operator commands (require operator credentials, e.g. CANOPY_OPS_ADMIN_TOKEN)",
  },
  subCommands: {
    "onboard-token": () =>
      import("./admin-onboard-token.js").then((m) => m.default),
  },
});
