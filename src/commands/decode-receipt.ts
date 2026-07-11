import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runDecodeReceipt } from "../main/decode-receipt.js";
import { parseDecodeReceiptOptions } from "../options/decode-receipt.js";

export default defineForestrieCommand({
  meta: {
    name: "decode-receipt",
    description:
      "Decode a COSE receipt — see that it is just COSE: Sign1 + MMR inclusion [FOR-346]",
  },
  args: {
    receipt: {
      type: "positional",
      description: "COSE receipt file",
      valueHint: "path",
      required: true,
    },
  },
  run: defineCommandRunner(parseDecodeReceiptOptions, runDecodeReceipt),
});
