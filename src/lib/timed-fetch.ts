/**
 * A fetch that always settles within `timeoutMs`: it aborts the request
 * and rejects even when the underlying fetch ignores the abort. The waits
 * that poll other parties (`log wait-anchored`, `create-log
 * --wait-anchored`) use it for every request, so a server that accepts a
 * connection and never answers cannot hold a round past its budget.
 */

/** Cap on one chain read or receipt fetch, milliseconds. */
export const REQUEST_TIMEOUT_MS = 15_000;

export function timedFetch(
  base: typeof fetch | undefined,
  timeoutMs: number,
): typeof fetch {
  return ((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const timeout = AbortSignal.timeout(timeoutMs);
    const signal =
      init?.signal != null ? AbortSignal.any([init.signal, timeout]) : timeout;
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    return new Promise<Response>((resolve, reject) => {
      const onTimeout = () =>
        reject(new Error(`no response from ${url} within ${timeoutMs} ms`));
      timeout.addEventListener("abort", onTimeout, { once: true });
      (base ?? fetch)(input, { ...init, signal })
        .then(resolve, reject)
        .finally(() => timeout.removeEventListener("abort", onTimeout));
    });
  }) as typeof fetch;
}
