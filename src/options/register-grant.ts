import type { LooseParsedArgs } from "@forestrie/cli-kit";
import {
  optionalStringOption,
  parseForestrieCommonOptions,
  requiredStringOption,
  type ForestrieCommonOptions,
} from "./common.js";

/**
 * `forestrie register-grant` — FOR-343.
 *
 * A grant binds exactly ONE signer; several signers on one data log means
 * several grants, each naming that log. Grant leaves are sequenced into
 * the OWNER (auth) log; the data log holds only statements.
 */
export type RegisterGrantOptions = ForestrieCommonOptions & {
  /** SCRAPI origin (`FORESTRIE_BASE_URL`). */
  baseUrl: string;
  /** Owner (auth) log the grant leaf is sequenced into. */
  ownerLog: string;
  /** Child/data log the grant authorizes. */
  dataLog: string;
  /** PKCS#8 PEM key that signs the grant statement (the granting authority). */
  signWith: string;
  /** PEM of the signer being authorized (grantData = ES256 x||y). */
  signerPem: string | undefined;
  /** Bootstrap-shaped self-referential grant (root log first leaf: logId == ownerLogId). */
  selfReferential: boolean;
  /** Create a child auth log rather than a data log. */
  authLog: boolean;
  /** Parent grant credential authorizing this registration. */
  parentGrantB64: string | undefined;
  /** Completed grant base64 output path (default: stdout). */
  outB64: string | undefined;
};

export function parseRegisterGrantOptions(
  args: LooseParsedArgs,
): RegisterGrantOptions {
  const options: RegisterGrantOptions = {
    ...parseForestrieCommonOptions(args),
    baseUrl: requiredStringOption(args, "base-url", "FORESTRIE_BASE_URL"),
    ownerLog: requiredStringOption(args, "owner-log"),
    dataLog: requiredStringOption(args, "data-log"),
    signWith: requiredStringOption(args, "sign-with"),
    signerPem: optionalStringOption(args, "signer-pem"),
    selfReferential: args["self-referential"] === true,
    authLog: args["auth-log"] === true,
    parentGrantB64: optionalStringOption(args, "parent-grant-b64"),
    outB64: optionalStringOption(args, "out-b64"),
  };
  if (options.selfReferential && options.parentGrantB64 !== undefined) {
    throw new Error(
      "--self-referential and --parent-grant-b64 are mutually exclusive (the bootstrap leaf has no parent)",
    );
  }
  if (!options.selfReferential && options.parentGrantB64 === undefined) {
    throw new Error(
      "either --parent-grant-b64 or --self-referential is required",
    );
  }
  return options;
}
