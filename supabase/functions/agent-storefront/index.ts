import { SupabaseClient } from "@supabase/supabase-js";
import openapi from "./openapi.json" with { type: "json" };
import {
  adminClient,
  AgentContext,
  verifyAgentCredential,
} from "../_shared/auth.ts";
import { randomSecretHex, sha256Hex } from "../_shared/crypto.ts";
import {
  apiPath,
  corsHeaders,
  errorResponse,
  jsonResponse,
  parseJson,
  parsePositiveInteger,
} from "../_shared/http.ts";

type CartItem = { sku: string; qty: number };
type OrderBody = {
  quote_id: string;
  shipping_address: Record<string, unknown>;
  po_number?: string;
  requested_ship_date?: string;
};

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const WEBHOOK_EVENTS = new Set([
  "order.status_changed",
  "order.shipped",
  "order.cancelled",
]);
const MAX_STALENESS_MS = 5 * 60_000;

Deno.serve(async (request: Request) => {
  const startedAt = performance.now();
  const requestId = crypto.randomUUID();
  const url = new URL(request.url);
  const path = apiPath(url);
  let admin: SupabaseClient | undefined;
  let context: AgentContext | undefined;
  let response: Response | undefined;

  try {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }
    if (request.method === "GET" && path === "/v1/agent/openapi.json") {
      return jsonResponse(requestId, openapi);
    }

    admin = adminClient();
    const auth = await verifyAgentCredential(request, admin);
    if (!auth.context) {
      const status = auth.code === "rate_limited" ? 429 : 401;
      const message = {
        unauthorized: "Invalid or missing agent credentials.",
        request_expired:
          "The signed request timestamp is outside the five-minute window.",
        replay_detected: "This signed request was already used.",
        rate_limited: "Rate limit exceeded. Retry after the indicated delay.",
      }[auth.code ?? "unauthorized"];
      response = errorResponse(
        requestId,
        auth.code ?? "unauthorized",
        message,
        status,
        undefined,
        auth.retryAfter ? { "Retry-After": String(auth.retryAfter) } : {},
      );
      return response;
    }
    context = auth.context;

    if (request.method === "GET" && path === "/v1/agent/catalog") {
      response = await handleCatalog(request, requestId, context, admin);
    } else if (request.method === "GET" && path === "/v1/agent/inventory") {
      response = await handleInventory(request, requestId, context, admin);
    } else if (request.method === "POST" && path === "/v1/agent/quotes") {
      response = await handleQuote(request, requestId, context, admin);
    } else if (request.method === "POST" && path === "/v1/agent/orders") {
      response = await handleCreateOrder(request, requestId, context, admin);
    } else if (
      request.method === "GET" && path.startsWith("/v1/agent/orders/")
    ) {
      response = await handleGetOrder(path, requestId, context, admin);
    } else if (request.method === "POST" && path === "/v1/agent/webhooks") {
      response = await handleWebhookRegistration(
        request,
        requestId,
        context,
        admin,
      );
    } else {
      response = errorResponse(
        requestId,
        "not_found",
        "Endpoint not found.",
        404,
      );
    }
    return response;
  } catch (error) {
    console.error(
      JSON.stringify({ request_id: requestId, path, error: String(error) }),
    );
    response = errorResponse(
      requestId,
      "internal_error",
      "The request could not be completed.",
      500,
    );
    return response;
  } finally {
    if (admin) {
      const status = response?.status ?? 500;
      void admin.rpc("record_agent_api_event", {
        p_request_id: requestId,
        p_event_name: status < 400
          ? "agent_api.request_completed"
          : "agent_api.request_failed",
        p_agent_id: context?.agentId ?? null,
        p_principal_id: context?.principalId ?? null,
        p_route: path,
        p_method: request.method,
        p_status_code: status,
        p_duration_ms: Math.round(performance.now() - startedAt),
      });
    }
  }
});

async function handleCatalog(
  request: Request,
  requestId: string,
  context: AgentContext,
  admin: SupabaseClient,
): Promise<Response> {
  const url = new URL(request.url);
  const page = parsePositiveInteger(url.searchParams.get("page"), 1, 1_000_000);
  const pageSize = parsePositiveInteger(
    url.searchParams.get("page_size"),
    100,
    500,
  );
  if (!page || !pageSize) {
    return errorResponse(
      requestId,
      "invalid_pagination",
      "page and page_size must be positive integers.",
      400,
    );
  }

  const updatedSince = url.searchParams.get("updated_since");
  if (updatedSince && !Number.isFinite(Date.parse(updatedSince))) {
    return errorResponse(
      requestId,
      "invalid_updated_since",
      "updated_since must be an ISO 8601 timestamp.",
      400,
    );
  }

  let query = admin.from("products")
    .select(
      "sku,name,description,category,unit_of_measure,list_price,images,attributes,updated_at",
      { count: "exact" },
    )
    .eq("principal_id", context.principalId)
    .order("sku")
    .range((page - 1) * pageSize, page * pageSize - 1);
  const category = url.searchParams.get("category");
  const search = url.searchParams.get("q");
  if (category) query = query.eq("category", category);
  if (search) {
    query = query.textSearch("search_document", search, { type: "websearch" });
  }
  if (updatedSince) {
    query = query.gte("updated_at", new Date(updatedSince).toISOString());
  }

  const { data: products, count, error } = await query;
  if (error) throw error;
  const skus = (products ?? []).map((product) => product.sku);
  const today = new Date().toISOString().slice(0, 10);
  let contracts: Array<
    { sku: string; unit_price: number | string; effective_from: string }
  > = [];
  if (skus.length > 0) {
    const result = await admin.from("contract_prices")
      .select("sku,unit_price,effective_from")
      .eq("principal_id", context.principalId)
      .in("sku", skus)
      .lte("effective_from", today)
      .or(`effective_to.is.null,effective_to.gte.${today}`)
      .order("effective_from", { ascending: false });
    if (result.error) throw result.error;
    contracts = result.data ?? [];
  }
  const contractMap = new Map<string, number>();
  for (const contract of contracts) {
    if (!contractMap.has(contract.sku)) {
      contractMap.set(contract.sku, Number(contract.unit_price));
    }
  }
  const enriched = (products ?? []).map((product) => ({
    sku: product.sku,
    name: product.name,
    description: product.description,
    category: product.category,
    unit_of_measure: product.unit_of_measure,
    list_price: Number(product.list_price),
    contract_price: contractMap.get(product.sku) ?? null,
    images: product.images,
    attributes: product.attributes,
  }));
  const lastModified = (products ?? []).reduce(
    (latest, product) =>
      product.updated_at > latest ? product.updated_at : latest,
    "1970-01-01T00:00:00.000Z",
  );
  const etag = `"${
    (await sha256Hex(JSON.stringify({ enriched, page, pageSize, count })))
      .slice(0, 32)
  }"`;
  if (request.headers.get("If-None-Match") === etag) {
    return new Response(null, {
      status: 304,
      headers: { ETag: etag, "X-Request-Id": requestId, ...corsHeaders },
    });
  }
  return jsonResponse(
    requestId,
    {
      products: enriched,
      pagination: {
        page,
        page_size: pageSize,
        total: count ?? 0,
        total_pages: Math.ceil((count ?? 0) / pageSize),
      },
    },
    200,
    { ETag: etag, "Last-Modified": new Date(lastModified).toUTCString() },
  );
}

async function handleInventory(
  request: Request,
  requestId: string,
  context: AgentContext,
  admin: SupabaseClient,
): Promise<Response> {
  const raw = new URL(request.url).searchParams.get("skus");
  if (!raw) {
    return errorResponse(requestId, "missing_param", "skus is required.", 400);
  }
  const skus = [
    ...new Set(raw.split(",").map((sku) => sku.trim()).filter(Boolean)),
  ];
  if (skus.length < 1 || skus.length > 50) {
    return errorResponse(
      requestId,
      "invalid_skus",
      "Provide between 1 and 50 unique SKUs.",
      400,
    );
  }
  const { data: scopedProducts, error: productError } = await admin.from(
    "products",
  )
    .select("sku").eq("principal_id", context.principalId).in("sku", skus);
  if (productError) throw productError;
  const allowed = (scopedProducts ?? []).map((product) => product.sku);
  const { data: inventory, error } = allowed.length
    ? await admin.from("warehouse_inventory")
      .select("sku,qty_available,qty_reserved,warehouse_id,updated_at")
      .in("sku", allowed)
      .order("sku")
    : { data: [], error: null };
  if (error) throw error;
  const stale = (inventory ?? []).some(
    (row) => Date.now() - Date.parse(row.updated_at) > MAX_STALENESS_MS,
  );
  if (stale) {
    return errorResponse(
      requestId,
      "inventory_stale",
      "Inventory data is older than five minutes. Retry shortly.",
      503,
      undefined,
      { "Retry-After": "300" },
    );
  }
  return jsonResponse(requestId, {
    inventory: (inventory ?? []).map((row) => ({
      ...row,
      qty_available: Number(row.qty_available),
      qty_reserved: Number(row.qty_reserved),
    })),
  });
}

async function handleQuote(
  request: Request,
  requestId: string,
  context: AgentContext,
  admin: SupabaseClient,
): Promise<Response> {
  const body = await parseJson<{ items?: CartItem[] }>(request);
  if (
    !body || !Array.isArray(body.items) || body.items.length < 1 ||
    body.items.length > 100
  ) {
    return errorResponse(
      requestId,
      "invalid_request",
      "items must contain between 1 and 100 line items.",
      400,
    );
  }
  const combined = new Map<string, number>();
  for (const item of body.items) {
    if (
      !item || typeof item.sku !== "string" || !item.sku.trim() ||
      !Number.isSafeInteger(item.qty) || item.qty < 1
    ) {
      return errorResponse(
        requestId,
        "invalid_item",
        "Each item requires a SKU and a positive integer quantity.",
        400,
      );
    }
    const sku = item.sku.trim();
    combined.set(sku, (combined.get(sku) ?? 0) + item.qty);
  }
  const skus = [...combined.keys()];
  const { data: products, error: productError } = await admin.from("products")
    .select("sku,list_price,attributes")
    .eq("principal_id", context.principalId)
    .in("sku", skus);
  if (productError) throw productError;
  const productMap = new Map(
    (products ?? []).map((product) => [product.sku, product]),
  );

  const { data: inventory, error: inventoryError } = await admin.from(
    "warehouse_inventory",
  )
    .select("sku,warehouse_id,qty_available,updated_at")
    .in("sku", skus)
    .order("warehouse_id");
  if (inventoryError) throw inventoryError;
  if (
    (inventory ?? []).some((row) =>
      Date.now() - Date.parse(row.updated_at) > MAX_STALENESS_MS
    )
  ) {
    return errorResponse(
      requestId,
      "inventory_stale",
      "Inventory data is older than five minutes. Retry shortly.",
      503,
      undefined,
      { "Retry-After": "300" },
    );
  }

  const today = new Date().toISOString().slice(0, 10);
  const { data: contracts, error: contractError } = await admin.from(
    "contract_prices",
  )
    .select("sku,unit_price,effective_from")
    .eq("principal_id", context.principalId)
    .in("sku", skus)
    .lte("effective_from", today)
    .or(`effective_to.is.null,effective_to.gte.${today}`)
    .order("effective_from", { ascending: false });
  if (contractError) throw contractError;
  const contractMap = new Map<string, number>();
  for (const contract of contracts ?? []) {
    if (!contractMap.has(contract.sku)) {
      contractMap.set(contract.sku, Number(contract.unit_price));
    }
  }

  const errors: unknown[] = [];
  const lineItems: unknown[] = [];
  let total = 0;
  for (const [sku, qty] of combined) {
    const product = productMap.get(sku);
    if (!product) {
      errors.push({ sku, error: "sku_not_found" });
      continue;
    }
    const rows = (inventory ?? []).filter((row) => row.sku === sku);
    const available = rows.reduce(
      (sum, row) => sum + Number(row.qty_available),
      0,
    );
    if (available < qty) {
      errors.push({
        sku,
        error: "insufficient_inventory",
        available,
        requested: qty,
      });
      continue;
    }
    let remaining = qty;
    const allocations: Array<{ warehouse_id: string; qty: number }> = [];
    for (const row of rows) {
      const allocated = Math.min(remaining, Number(row.qty_available));
      if (allocated > 0) {
        allocations.push({ warehouse_id: row.warehouse_id, qty: allocated });
      }
      remaining -= allocated;
      if (remaining === 0) break;
    }
    const unitPrice = contractMap.get(sku) ?? Number(product.list_price);
    const extendedPrice = Number((unitPrice * qty).toFixed(2));
    const leadTime = Number(product.attributes?.lead_time_days ?? 0);
    const estimated = new Date();
    estimated.setUTCDate(
      estimated.getUTCDate() +
        (Number.isFinite(leadTime) ? Math.max(0, Math.ceil(leadTime)) : 0),
    );
    total += extendedPrice;
    lineItems.push({
      sku,
      qty,
      contract_price: unitPrice,
      extended_price: extendedPrice,
      estimated_ship_date: estimated.toISOString().slice(0, 10),
      allocations,
    });
  }
  if (errors.length) {
    return errorResponse(
      requestId,
      "quote_validation_failed",
      "One or more line items could not be quoted.",
      422,
      { line_items: errors },
    );
  }
  const expiresAt = new Date(Date.now() + 15 * 60_000).toISOString();
  const { data: quote, error: quoteError } = await admin.from("agent_quotes")
    .insert({
      agent_id: context.agentId,
      principal_id: context.principalId,
      items: lineItems,
      total_price: Number(total.toFixed(2)),
      expires_at: expiresAt,
    }).select("id").single();
  if (quoteError) throw quoteError;
  return jsonResponse(requestId, {
    quote_id: quote.id,
    expires_at: expiresAt,
    line_items: lineItems,
    total_price: Number(total.toFixed(2)),
  }, 201);
}

async function handleCreateOrder(
  request: Request,
  requestId: string,
  context: AgentContext,
  admin: SupabaseClient,
): Promise<Response> {
  const body = await parseJson<OrderBody>(request);
  if (
    !body || !UUID.test(body.quote_id ?? "") ||
    !body.shipping_address || typeof body.shipping_address !== "object" ||
    Array.isArray(body.shipping_address) ||
    Object.keys(body.shipping_address).length === 0
  ) {
    return errorResponse(
      requestId,
      "invalid_request",
      "quote_id and a non-empty shipping_address are required.",
      400,
    );
  }
  if (
    body.po_number !== undefined &&
    (typeof body.po_number !== "string" || body.po_number.length > 100)
  ) {
    return errorResponse(
      requestId,
      "invalid_po_number",
      "po_number must be 100 characters or fewer.",
      400,
    );
  }
  if (
    body.requested_ship_date !== undefined &&
    !DATE.test(body.requested_ship_date)
  ) {
    return errorResponse(
      requestId,
      "invalid_requested_ship_date",
      "requested_ship_date must use YYYY-MM-DD.",
      400,
    );
  }
  const { data, error } = await admin.rpc("create_agent_order", {
    p_quote_id: body.quote_id,
    p_agent_id: context.agentId,
    p_principal_id: context.principalId,
    p_shipping_address: body.shipping_address,
    p_po_number: body.po_number ?? null,
    p_requested_ship_date: body.requested_ship_date ?? null,
  });
  if (error) {
    const message = error.message ?? "";
    if (message.includes("quote_expired")) {
      return errorResponse(
        requestId,
        "quote_expired",
        "This quote has expired. Request a new quote.",
        422,
      );
    }
    if (message.includes("quote_not_found")) {
      return errorResponse(
        requestId,
        "quote_not_found",
        "Quote not found.",
        404,
      );
    }
    if (message.includes("quote_already_used")) {
      return errorResponse(
        requestId,
        "quote_already_used",
        "This quote was already used.",
        409,
      );
    }
    if (message.includes("insufficient_inventory")) {
      return errorResponse(
        requestId,
        "insufficient_inventory",
        "Inventory changed after quoting. Request a new quote.",
        422,
      );
    }
    throw error;
  }
  return jsonResponse(requestId, data, 201);
}

async function handleGetOrder(
  path: string,
  requestId: string,
  context: AgentContext,
  admin: SupabaseClient,
): Promise<Response> {
  const orderId = path.slice("/v1/agent/orders/".length);
  if (!UUID.test(orderId)) {
    return errorResponse(requestId, "not_found", "Order not found.", 404);
  }
  const { data: order, error } = await admin.from("agent_orders")
    .select(
      "id,status,items,tracking_numbers,shipped_at,estimated_delivery_at,estimated_ship_date",
    )
    .eq("id", orderId)
    .eq("agent_id", context.agentId)
    .eq("principal_id", context.principalId)
    .maybeSingle();
  if (error) throw error;
  if (!order) {
    return errorResponse(requestId, "not_found", "Order not found.", 404);
  }
  return jsonResponse(requestId, {
    order_id: order.id,
    status: order.status,
    line_items: order.items,
    tracking_numbers: order.tracking_numbers,
    shipped_at: order.shipped_at,
    estimated_delivery_at: order.estimated_delivery_at,
    estimated_ship_date: order.estimated_ship_date,
  });
}

async function handleWebhookRegistration(
  request: Request,
  requestId: string,
  context: AgentContext,
  admin: SupabaseClient,
): Promise<Response> {
  const body = await parseJson<{ url?: string; events?: string[] }>(request);
  if (
    !body || typeof body.url !== "string" || !Array.isArray(body.events) ||
    body.events.length === 0 ||
    body.events.some((event) => !WEBHOOK_EVENTS.has(event))
  ) {
    return errorResponse(
      requestId,
      "invalid_request",
      "A valid HTTPS URL and at least one supported event are required.",
      400,
    );
  }
  let webhookUrl: URL;
  try {
    webhookUrl = new URL(body.url);
  } catch {
    return errorResponse(
      requestId,
      "invalid_webhook_url",
      "Webhook URL is invalid.",
      400,
    );
  }
  if (
    webhookUrl.protocol !== "https:" || webhookUrl.username ||
    webhookUrl.password ||
    isPrivateHostname(webhookUrl.hostname)
  ) {
    return errorResponse(
      requestId,
      "invalid_webhook_url",
      "Webhook URL must be a public HTTPS endpoint.",
      400,
    );
  }
  const signingSecret = randomSecretHex();
  const { data: webhook, error } = await admin.from("agent_webhooks").insert({
    agent_id: context.agentId,
    principal_id: context.principalId,
    url: webhookUrl.toString(),
    events: [...new Set(body.events)],
    signing_secret_hex: signingSecret,
  }).select("id").single();
  if (error) throw error;
  return jsonResponse(requestId, {
    webhook_id: webhook.id,
    signing_secret: signingSecret,
    message: "Store this signing secret now. It will not be shown again.",
  }, 201);
}

function isPrivateHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    host === "localhost" || host.endsWith(".localhost") ||
    host.endsWith(".local")
  ) return true;
  if (/^(127\.|10\.|0\.|169\.254\.|192\.168\.)/.test(host)) return true;
  const match = host.match(/^172\.(\d+)\./);
  if (match && Number(match[1]) >= 16 && Number(match[1]) <= 31) return true;
  return host === "::1" || host.startsWith("fc") || host.startsWith("fd") ||
    host.startsWith("fe80:");
}
