/**
 * The human-readable reason a canopy / coordinator request was rejected
 * (FOR-579).
 *
 * canopy-api answers with RFC 9457 problem details encoded as CBOR (served
 * as `application/cbor` on most routes, `application/problem+cbor` on the
 * SCRAPI ones); the delegation coordinator uses `application/problem+json`.
 * Reading such a body with `response.text()` and printing it yields
 * unreadable bytes, which is how a `400` from a strict CBOR decoder hid its
 * cause (`Invalid CBOR body`) through four qualification runs on
 * 2026-09-20. This decodes whichever form arrived and falls back to the
 * text body. It never throws.
 */
import { decodeProblemDetailsBytes } from "@forestrie/scrapi-client";

/** Longest string returned; problem bodies are short, this is a guard. */
export const MAX_PROBLEM_DETAIL = 512;

function describe(problem: {
  title?: string;
  detail?: string;
}): string | undefined {
  const { title, detail } = problem;
  if (detail && title) return `${title}: ${detail}`;
  return detail ?? title;
}

export async function responseProblemDetail(
  response: Response,
  max = MAX_PROBLEM_DETAIL,
): Promise<string> {
  const contentType = (response.headers.get("content-type") ?? "").toLowerCase();
  let text = "";
  try {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length === 0) return "";
    if (contentType.includes("cbor")) {
      // No content type passed: canopy-api serves most problem bodies as
      // plain application/cbor, so decode opportunistically.
      const problem = decodeProblemDetailsBytes(bytes);
      const described = problem && describe(problem);
      if (described) return described.slice(0, max);
    }
    text = new TextDecoder().decode(bytes);
    if (contentType.includes("json")) {
      const described = describe(JSON.parse(text) as { title?: string; detail?: string });
      if (described) return described.slice(0, max);
    }
  } catch {
    // fall through to whatever text we have
  }
  return text.slice(0, max);
}
