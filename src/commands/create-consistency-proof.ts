import { defineCommandRunner, defineForestrieCommand } from "../commoncli.js";
import { runCreateConsistencyProof } from "../main/create-consistency-proof.js";
import { parseCreateConsistencyProofOptions } from "../options/create-consistency-proof.js";

export default defineForestrieCommand({
  meta: {
    name: "create-consistency-proof",
    description:
      "Build a portable top-up artifact from public massif tiles: the --from-size accumulator plus per-peak inclusion paths proven at --to-size (strict deterministic CBOR, unsigned). Any party with tiles can produce it; a holder then verifies an old receipt tile-free via `verify --known-accumulator ... --consistency-proof` — the artifact can only fail against the trusted snapshot, never mint trust [FOR-368]",
  },
  args: {
    massif: {
      type: "string",
      description:
        "Massif blob path(s), comma-separated — must cover the nodes from --from-size through --to-size (a spanning proof needs each massif in the range)",
      valueHint: "path[,path...]",
      required: true,
    },
    "from-size": {
      type: "string",
      description:
        "MMR size the proof extends FROM (the old receipt's era, e.g. an old checkpoint's tree-size-2)",
      valueHint: "size",
      required: true,
    },
    "to-size": {
      type: "string",
      description:
        "MMR size the proof lands ON — must equal the holder's trusted snapshot size (fetch-accumulator anchoredSize)",
      valueHint: "size",
      required: true,
    },
    out: {
      type: "string",
      description: "Output path for the consistency-proof CBOR",
      valueHint: "path",
      required: true,
    },
  },
  run: defineCommandRunner(
    parseCreateConsistencyProofOptions,
    runCreateConsistencyProof,
  ),
});
