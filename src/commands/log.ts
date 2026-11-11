import { defineForestrieCommand } from "../commoncli.js";

/** `forestrie log` — commands about a log as a whole. */
export default defineForestrieCommand({
  meta: {
    name: "log",
    description: "Commands about a log as a whole (its anchoring on chain)",
  },
  subCommands: {
    "wait-anchored": () =>
      import("./log-wait-anchored.js").then((m) => m.default),
  },
});
