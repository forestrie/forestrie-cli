import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/**
 * `forestrie complete-grant` — FOR-344.
 *
 * Self-create the `Authorization: Forestrie-Grant` header content from a
 * checkpoint (and possibly an idtimestamp) — grants are derivable from
 * log data, not operator-issued.
 */
export type CompleteGrantOptions = ForestrieCommonOptions & {
  /** Registered (uncompleted) grant, base64 file. */
  grant: string;
  /** Checkpoint (.sth) for the owner log. */
  checkpoint: string;
  /** Massif .log blob for local leaf/path recovery. */
  massif: string | undefined;
  /** Leaf idtimestamp (hex or be8 file) when the grant lacks one. */
  idtimestamp: string | undefined;
  /** Completed grant base64 output path (default: stdout). */
  outB64: string | undefined;
};

export function parseCompleteGrantOptions(
  args: LooseParsedArgs,
): CompleteGrantOptions {
  return {
    ...parseForestrieCommonOptions(args),
    grant: requiredStringOption(args, "grant"),
    checkpoint: requiredStringOption(args, "checkpoint"),
    massif: optionalStringOption(args, "massif"),
    idtimestamp: optionalStringOption(args, "idtimestamp"),
    outB64: optionalStringOption(args, "out-b64"),
  };
}
