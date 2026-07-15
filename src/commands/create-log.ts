import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runCreateLog } from "../main/create-log.js";
import { parseCreateLogOptions } from "../options/create-log.js";

export default defineForestrieCommand({
  meta: {
    name: "create-log",
    description:
      "Create a log and set its owner (K(L)) — data, child auth, or self-referential root bootstrap [FOR-390]",
  },
  args: {
    "base-url": {
      type: "string",
      description: "SCRAPI origin, no trailing slash (env FORESTRIE_BASE_URL)",
      valueHint: "url",
    },
    "owner-log": {
      type: "string",
      description:
        "Parent/auth log the create grant is sequenced into",
      valueHint: "uuid",
      required: true,
    },
    "new-log": {
      type: "string",
      description: "The log being created",
      valueHint: "uuid",
      required: true,
    },
    "auth-log": {
      type: "boolean",
      description: "Create a child auth log rather than a data log",
      default: false,
    },
    "self-referential": {
      type: "boolean",
      description:
        "Root bootstrap grant (--new-log == --owner-log; binds --sign-with itself, forbids --signer-pem)",
      default: false,
    },
    "signer-pem": {
      type: "string",
      description:
        "PEM of the new log's owner (grantData = ES256 x||y); required unless --self-referential",
      valueHint: "path",
    },
    "sign-with": {
      type: "string",
      description:
        "Granting authority PEM (the parent log's K(L)) that signs the grant",
      valueHint: "path",
      required: true,
    },
    prepare: {
      type: "boolean",
      description:
        "Pre-register the child's public root with the coordinator (parent-authorized, no operator token) WITHOUT sequencing, so you can `delegate` before the log exists; emits the create grant to --out-b64 [FOR-390]",
      default: false,
    },
    "parent-grant-b64": {
      type: "string",
      description: "Parent grant credential authorizing this registration",
      valueHint: "base64",
    },
    "out-b64": {
      type: "string",
      description: "Completed grant base64 output path (default: stdout)",
      valueHint: "path",
    },
    "bootstrap-log": {
      type: "string",
      description:
        "Forest bootstrap/root log id — first /register/ path segment (default: --owner-log)",
      valueHint: "uuid",
    },
    timeout: {
      type: "string",
      description: "Overall receipt wait budget in seconds (default 60)",
      valueHint: "seconds",
    },
    "poll-interval": {
      type: "string",
      description:
        "Pacing between registration/receipt polls in seconds (default 1; Retry-After wins when longer)",
      valueHint: "seconds",
    },
  },
  run: defineCommandRunner(parseCreateLogOptions, runCreateLog),
});
