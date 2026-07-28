export const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers":
    "Content-Type, X-Agent-Key, X-Agent-Signature, X-Agent-Timestamp, X-Agent-Nonce",
  "Access-Control-Expose-Headers":
    "ETag, Last-Modified, Retry-After, X-Request-Id",
};

interface ErrorBody {
  code: string;
  message: string;
  details?: unknown;
}

export function jsonResponse(
  requestId: string,
  data: unknown,
  status = 200,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(
    JSON.stringify({
      data,
      meta: { request_id: requestId, timestamp: new Date().toISOString() },
    }),
    {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "X-Request-Id": requestId,
        ...corsHeaders,
        ...extraHeaders,
      },
    },
  );
}

export function errorResponse(
  requestId: string,
  code: string,
  message: string,
  status: number,
  details?: unknown,
  extraHeaders: Record<string, string> = {},
): Response {
  const error: ErrorBody = { code, message };
  if (details !== undefined) error.details = details;
  return new Response(
    JSON.stringify({
      data: null,
      error,
      meta: { request_id: requestId, timestamp: new Date().toISOString() },
    }),
    {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "X-Request-Id": requestId,
        ...corsHeaders,
        ...extraHeaders,
      },
    },
  );
}

export function parsePositiveInteger(
  value: string | null,
  fallback: number,
  maximum: number,
): number | null {
  if (value === null) return fallback;
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) return null;
  return Math.min(parsed, maximum);
}

export async function parseJson<T>(request: Request): Promise<T | null> {
  try {
    return await request.json() as T;
  } catch {
    return null;
  }
}

export function apiPath(url: URL): string {
  const marker = "/v1/agent/";
  const index = url.pathname.indexOf(marker);
  return index === -1 ? url.pathname : url.pathname.slice(index);
}
