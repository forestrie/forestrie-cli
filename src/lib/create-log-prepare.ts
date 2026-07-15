/**
 * FOR-390 / ADR-0053: pre-register a child log's public root with the delegation
 * coordinator under PARENT authority, WITHOUT sequencing the create leaf.
 *
 * The parent-signed create grant travels as the `Authorization: Forestrie-Grant`
 * credential; canopy-api verifies it against the parent log's registered root key
 * and forwards `{childLogId -> owner key}` to the coordinator. This lets an owner
 * pre-sign an advance delegation (`forestrie delegate`) for a child logId BEFORE
 * the log exists — no operator onboard token, authority flows down the log
 * hierarchy (ADR-0053). Node/Bun HTTP only.
 */

/** Prepare (child public-root pre-registration) failure. */
export class PrepareLogError extends Error {
  readonly httpStatus?: number;
  constructor(message: string, httpStatus?: number) {
    super(message);
    this.name = "PrepareLogError";
    if (httpStatus !== undefined) this.httpStatus = httpStatus;
  }
}

/** Coordinator forward outcome (best-effort parse of the prepare response). */
export type PrepareResult = {
  /** "ok" when the child public root was registered with the coordinator. */
  publicRoot: string;
  /** "ok" | "skipped" | "error" when a signing-route webhook was set. */
  webhook?: string | undefined;
  detail?: string | undefined;
};

export type PrepareDeps = { fetchImpl?: typeof fetch | undefined };

/**
 * POST the parent-signed create grant to
 * `POST /api/forest/{childLogId}/prepare` (Authorization: Forestrie-Grant), which
 * registers the child's public root with the coordinator under parent authority.
 * Returns the coordinator forward status; throws {@link PrepareLogError} on non-2xx.
 */
export async function prepareChildLog(
  params: { baseUrl: string; childLogId: string; grantBase64: string },
  deps: PrepareDeps = {},
): Promise<PrepareResult> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const url = `${params.baseUrl.replace(/\/$/, "")}/api/forest/${params.childLogId}/prepare`;
  const res = await fetchImpl(url, {
    method: "POST",
    headers: { Authorization: `Forestrie-Grant ${params.grantBase64}` },
  });
  if (!res.ok) {
    const preview = (await res.text().catch(() => "")).slice(0, 300);
    throw new PrepareLogError(
      `prepare failed: HTTP ${res.status} ${preview}`,
      res.status,
    );
  }
  // Lenient: the endpoint returns the coordinator forward status (JSON or CBOR).
  // A 2xx alone means the public root was registered; extract fields when the
  // body is JSON-parseable, else report a generic success.
  let publicRoot = "ok";
  let webhook: string | undefined;
  let detail: string | undefined;
  try {
    const body = (await res.json()) as Record<string, unknown> & {
      coordinator?: Record<string, unknown>;
    };
    const src = (body.coordinator ?? body) as Record<string, unknown>;
    if (typeof src.publicRoot === "string") publicRoot = src.publicRoot;
    if (typeof src.webhook === "string") webhook = src.webhook;
    if (typeof src.detail === "string") detail = src.detail;
  } catch {
    // non-JSON (e.g. CBOR) — 2xx is success.
  }
  return { publicRoot, webhook, detail };
}
