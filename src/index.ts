/**
 * Package entry for `@forestrie/forestrie-cli`.
 *
 * This package is primarily a CLI (`forestrie`). Its one supported
 * library surface is the pure receipt decoder/renderer, re-exported
 * here and also reachable directly as
 * `@forestrie/forestrie-cli/decode-receipt` — prefer the subpath, it is
 * the stable name and will not grow unrelated exports.
 */
export * from "./decode-receipt.js";
