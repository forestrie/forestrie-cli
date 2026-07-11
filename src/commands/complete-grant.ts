import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runCompleteGrant } from "../main/complete-grant.js";
import { parseCompleteGrantOptions } from "../options/complete-grant.js";

export default defineForestrieCommand({
  meta: {
    name: "complete-grant",
    description:
      "Self-create the Forestrie-Grant header content from a checkpoint — grants are derivable from log data [FOR-344]",
  },
  args: {
    grant: {
      type: "string",
      description: "Registered (uncompleted) grant, base64 file",
      valueHint: "path",
      required: true,
    },
    checkpoint: {
      type: "string",
      description: "Checkpoint (.sth) for the owner log",
      valueHint: "path",
      required: true,
    },
    massif: {
      type: "string",
      description: "Massif .log blob for local leaf/path recovery",
      valueHint: "path",
    },
    idtimestamp: {
      type: "string",
      description: "Leaf idtimestamp when the grant lacks one",
      valueHint: "hex|path",
    },
    "out-b64": {
      type: "string",
      description: "Completed grant base64 output path (default: stdout)",
      valueHint: "path",
    },
  },
  run: defineCommandRunner(parseCompleteGrantOptions, runCompleteGrant),
});
