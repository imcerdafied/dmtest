import { canonicalRequest } from "./auth.ts";
import { hmacHex, sha256Hex, verifyHmacHex } from "./crypto.ts";
import {
  apiPath,
  canonicalApiPathAndQuery,
  errorResponse,
  jsonResponse,
  parsePositiveInteger,
} from "./http.ts";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

Deno.test("HMAC matches RFC 4231 test case 1", async () => {
  const secret = "0b".repeat(20);
  const expected =
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
  assert(await hmacHex(secret, "Hi There") === expected, "unexpected HMAC");
  assert(
    await verifyHmacHex(secret, "Hi There", expected),
    "signature should verify",
  );
  assert(
    !(await verifyHmacHex(secret, "tampered", expected)),
    "tampered body verified",
  );
});

Deno.test("canonical request covers timestamp, nonce, method, path, query, and body", async () => {
  const request = new Request(
    "https://api.example.com/v1/agent/quotes?mode=fast",
    {
      method: "POST",
      body: '{"items":[]}',
    },
  );
  const timestamp = "2026-07-28T12:00:00.000Z";
  const canonical = await canonicalRequest(
    request,
    timestamp,
    "1234567890abcdef",
  );
  const expectedBodyHash = await sha256Hex('{"items":[]}');
  assert(
    canonical === [
      timestamp,
      "1234567890abcdef",
      "POST",
      "/v1/agent/quotes?mode=fast",
      expectedBodyHash,
    ].join("\n"),
    "canonical request mismatch",
  );
});

Deno.test("canonical request ignores Supabase function routing prefixes", async () => {
  const timestamp = "2026-07-28T12:00:00.000Z";
  const canonical = await canonicalRequest(
    new Request(
      "https://project.supabase.co/agent-storefront/v1/agent/catalog?page=1",
    ),
    timestamp,
    "1234567890abcdef",
  );
  const expectedBodyHash = await sha256Hex("");
  assert(
    canonical === [
      timestamp,
      "1234567890abcdef",
      "GET",
      "/v1/agent/catalog?page=1",
      expectedBodyHash,
    ].join("\n"),
    "Supabase-prefixed canonical request mismatch",
  );
});

Deno.test("API path normalizes Supabase function prefix", () => {
  assert(
    apiPath(
      new URL(
        "http://localhost/functions/v1/agent-storefront/v1/agent/catalog",
      ),
    ) ===
      "/v1/agent/catalog",
    "path was not normalized",
  );
});

Deno.test("canonical query encoding is stable across gateway rewrites", () => {
  assert(
    canonicalApiPathAndQuery(
      new URL(
        "https://project.supabase.co/agent-storefront/v1/agent/inventory?skus=A,B",
      ),
    ) === "/v1/agent/inventory?skus=A%2CB",
    "query was not normalized",
  );
});

Deno.test("pagination parser rejects malformed or non-positive values", () => {
  assert(parsePositiveInteger(null, 100, 500) === 100, "fallback failed");
  assert(parsePositiveInteger("999", 100, 500) === 500, "max failed");
  assert(parsePositiveInteger("0", 100, 500) === null, "zero accepted");
  assert(parsePositiveInteger("1x", 100, 500) === null, "junk accepted");
});

Deno.test("success and error bodies keep the versioned envelope", async () => {
  const success = await jsonResponse("request-1", { ok: true }).json();
  assert(
    success.data.ok === true && success.meta.request_id === "request-1",
    "bad success envelope",
  );
  const failure = await errorResponse("request-2", "invalid", "Invalid.", 400)
    .json();
  assert(
    failure.data === null && failure.error.code === "invalid" &&
      failure.meta.request_id === "request-2",
    "bad error envelope",
  );
});
