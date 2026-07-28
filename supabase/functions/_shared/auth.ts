import { createClient, SupabaseClient } from "@supabase/supabase-js";
import { sha256Hex, verifyHmacHex } from "./crypto.ts";
import { apiPath } from "./http.ts";

export interface AgentContext {
  agentId: string;
  principalId: string;
  apiKeyHash: string;
}

export interface AuthResult {
  context?: AgentContext;
  code?:
    | "unauthorized"
    | "request_expired"
    | "replay_detected"
    | "rate_limited";
  retryAfter?: number;
}

export function adminClient(): SupabaseClient {
  const url = Deno.env.get("SUPABASE_URL");
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key) throw new Error("missing_supabase_environment");
  return createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

export async function canonicalRequest(
  request: Request,
  timestamp: string,
  nonce: string,
): Promise<string> {
  const url = new URL(request.url);
  const bodyHash = await sha256Hex(await request.clone().text());
  return [
    timestamp,
    nonce,
    request.method.toUpperCase(),
    `${apiPath(url)}${url.search}`,
    bodyHash,
  ].join("\n");
}

export async function verifyAgentCredential(
  request: Request,
  admin: SupabaseClient,
): Promise<AuthResult> {
  const apiKey = request.headers.get("X-Agent-Key");
  const signature = request.headers.get("X-Agent-Signature")?.toLowerCase();
  const timestamp = request.headers.get("X-Agent-Timestamp");
  const nonce = request.headers.get("X-Agent-Nonce");
  if (!apiKey || !signature || !timestamp || !nonce) {
    return { code: "unauthorized" };
  }

  const signedAt = Date.parse(timestamp);
  if (
    !Number.isFinite(signedAt) || Math.abs(Date.now() - signedAt) > 5 * 60_000
  ) {
    return { code: "request_expired" };
  }
  if (!/^[A-Za-z0-9._~-]{16,128}$/.test(nonce)) return { code: "unauthorized" };

  const apiKeyHash = await sha256Hex(apiKey);
  const { data: credential, error } = await admin
    .from("agent_credentials")
    .select("id,agent_id,principal_id,hmac_secret_hex")
    .eq("api_key_hash", apiKeyHash)
    .eq("active", true)
    .maybeSingle();
  if (error || !credential) return { code: "unauthorized" };
  if (typeof credential.hmac_secret_hex !== "string") {
    return { code: "unauthorized" };
  }

  const valid = await verifyHmacHex(
    credential.hmac_secret_hex,
    await canonicalRequest(request, timestamp, nonce),
    signature,
  );
  if (!valid) return { code: "unauthorized" };

  const { data: nonceAccepted, error: nonceError } = await admin.rpc(
    "register_agent_nonce",
    { p_api_key_hash: apiKeyHash, p_nonce: nonce },
  );
  if (nonceError || nonceAccepted !== true) return { code: "replay_detected" };

  const { data: rawBucket, error: rateError } = await admin
    .rpc("consume_agent_rate_limit", { p_api_key_hash: apiKeyHash })
    .single();
  if (rateError) throw rateError;
  const bucket = rawBucket as {
    allowed: boolean;
    retry_after: number;
    request_count: number;
  };
  if (!bucket.allowed) {
    return {
      code: "rate_limited",
      retryAfter: Number(bucket.retry_after) || 60,
    };
  }

  void admin.from("agent_credentials")
    .update({ last_used_at: new Date().toISOString() })
    .eq("id", credential.id);

  return {
    context: {
      agentId: credential.agent_id,
      principalId: credential.principal_id,
      apiKeyHash,
    },
  };
}
