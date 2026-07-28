# Agent Storefront API

Drop-in Supabase implementation of the verified-agent quote-to-track API.

## What is implemented

- HMAC-SHA256 authentication with a signed timestamp and nonce, five-minute
  replay window, one-use nonce, and service-only verification keys.
- Atomic 300 requests/minute rate limiting per credential.
- Principal-scoped catalog, real-time inventory, 15-minute quotes, atomic order
  placement and inventory reservation, scoped order status, webhook registration
  and signed delivery.
- Stable JSON envelopes, request IDs, cache headers, OpenAPI 3.1, analytics
  events, database structure tests, and Deno unit tests.
- A queued webhook dispatcher with retries and a 10-second cron configuration.

The API is one Edge Function router. On Supabase's default URL it is reached as:

`https://PROJECT_REF.supabase.co/functions/v1/agent-storefront/v1/agent/...`

Map `/v1/agent/*` to that function at the custom-domain gateway to expose the
exact public paths in the specification.

## Security decisions

The prompt's `secret_hash` example cannot work as written: an irreversible hash
cannot be used as an HMAC verification key. This package stores a random 256-bit
`hmac_secret_hex` value in an RLS-protected, service-role-only table. The raw
API key is never stored; only its SHA-256 digest is retained.

Order creation runs entirely inside `public.create_agent_order(...)`. A quote
row is locked, expiry/ownership/use are checked, every inventory allocation is
conditionally reserved, the order is inserted, and only then is the quote marked
used. Any error rolls back the whole transaction.

The public RPC functions are exposed only so the Edge Function can call them
through PostgREST. `PUBLIC`, `anon`, and `authenticated` execute privileges are
revoked; only `service_role` is granted access.

## Deploy

Prerequisites: a linked Supabase project, an existing Auth user for each agent,
and production product/inventory feeds.

```bash
supabase link --project-ref PROJECT_REF
supabase db push
supabase secrets set \
  AGENT_WEBHOOK_DISPATCH_TOKEN=REPLACE_WITH_RANDOM_32_BYTE_TOKEN
supabase functions deploy agent-storefront --no-verify-jwt
supabase functions deploy agent-webhook-dispatcher --no-verify-jwt
```

Supabase injects `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` into deployed
Edge Functions automatically. Do not copy the service-role key into repository
secrets or attempt to override the platform-provided value.

`verify_jwt = false` is intentional: both functions implement non-JWT
authentication. `agent-storefront` verifies the agent HMAC;
`agent-webhook-dispatcher` verifies its private bearer token.

After deployment, run `supabase/snippets/configure_webhook_dispatch.sql` with
the real function URL and the same dispatcher token. It schedules delivery every
10 seconds. Keep Vault and `pg_cron` restricted to trusted database operators.

## Issue a credential

Call this as a service-role operator. The API key and HMAC secret are returned
once.

```sql
select *
from public.issue_agent_credential(
  'AGENT_AUTH_USER_UUID'::uuid,
  'PRINCIPAL_UUID'::uuid
);
```

Never log either returned secret. Store them in the agent's secret manager.

## Request signing

The canonical string is:

```text
X-Agent-Timestamp
X-Agent-Nonce
HTTP_METHOD
URL_PATH_AND_QUERY
SHA256_HEX(EXACT_BODY_BYTES)
```

For the hosted Supabase URL, sign the stable API path beginning with
`/v1/agent/`, not Supabase's `/functions/v1/agent-storefront` routing prefix.
The verifier normalizes the platform's internal function prefix to the same
public API path. Query parameters use the URL standard serialization produced by
`URLSearchParams.toString()` so reserved characters are signed consistently
through the Supabase gateway.

Sign that exact UTF-8 string with the credential's HMAC secret and send the
lowercase hex digest in `X-Agent-Signature`. `X-Agent-Timestamp` must be ISO
8601 and within five minutes. `X-Agent-Nonce` must be a unique 16–128 character
URL-safe value.

The helper prints headers for a request:

```bash
AGENT_API_KEY=... AGENT_HMAC_SECRET=... \
deno run scripts/sign-request.ts \
POST 'https://api.example.com/v1/agent/quotes' \
'{"items":[{"sku":"A","qty":2}]}'
```

## Verify

Fast checks that do not require Docker:

```bash
deno check supabase/functions/agent-storefront/index.ts
deno check supabase/functions/agent-webhook-dispatcher/index.ts
deno test supabase/functions/_shared/shared_test.ts
```

Full local database verification requires Docker:

```bash
supabase start
supabase db reset
supabase test db
supabase functions serve --no-verify-jwt
```

## Manual acceptance smoke test

1. Insert two principals, products, current inventory rows, and one contract
   price; issue one credential per principal.
2. Call catalog with no signature and confirm `401 unauthorized`.
3. Sign a catalog request and confirm only the credential's principal appears,
   contract price is correct, and `ETag`/`Last-Modified` exist.
4. Repeat with `If-None-Match` and confirm `304`.
5. Query 1 and 50 SKUs; query 51 and confirm `400`. Age one requested inventory
   row by over five minutes and confirm `503` plus `Retry-After: 300`.
6. Quote available stock and confirm expiry is approximately 15 minutes. Quote
   excessive stock and confirm a `422` `quote_validation_failed` response with
   per-line `insufficient_inventory`.
7. Place one order from a valid quote. Confirm order, quote consumption, and all
   inventory reservations commit together.
8. Expire a fresh quote, place it, confirm `422 quote_expired`, and verify no
   order or inventory change.
9. Fetch an order with the other credential and confirm `404`.
10. Reuse an identical signed request/nonce and confirm `401 replay_detected`.
11. Send 301 valid signed requests in one minute and confirm `429` with
    `Retry-After`.
12. Register a public HTTPS webhook, change an owned order status to `shipped`,
    and confirm delivery within 30 seconds with a valid `X-Agent-Signature`.
13. Fetch `/v1/agent/openapi.json`, extract the envelope's `data` value, and
    validate that document with an OpenAPI 3.1 validator.

## Analytics

Every authenticated or attempted API call triggers exactly one best-effort
event:

- `agent_api.request_completed` when the final status is below 400.
- `agent_api.request_failed` when the final status is 400 or greater.

Required properties are stored as columns: `request_id`, `agent_id` when known,
`principal_id` when known, `route`, `method`, `status_code`, and `duration_ms`.
The event write never blocks the API response. No API keys, HMAC secrets,
request bodies, shipping addresses, or direct contact data are recorded.

These events cover entry, success, validation/auth/rate-limit failure, and
server error paths. Funnel drop-off is derived by joining quote and order events
by agent/principal and time window; secret or personal payload data is
deliberately excluded.

## Copy and accessibility

This is a machine-only API and adds no UI, so keyboard navigation, focus order,
contrast, semantic control labels, and screen-reader checks are not applicable.
All error messages are explicit, plain-language English; clients should localize
by stable `error.code`, not by parsing or translating server message text.
Consumers must allow messages to expand and must not size UI from the English
string length.

## Known production proof boundary

Local type/unit checks prove request signing, envelopes, and compilation. The
database transaction, p95 catalog latency, real WMS freshness, custom-domain
routing, Vault cron schedule, and end-to-end webhook arrival require a
provisioned Supabase project and production-like data. Do not mark those
acceptance criteria passed until the manual smoke test and a 10,000-SKU load
test run against that project.
