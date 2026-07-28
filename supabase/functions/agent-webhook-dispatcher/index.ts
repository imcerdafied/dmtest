import { adminClient } from "../_shared/auth.ts";
import { hmacHex } from "../_shared/crypto.ts";
import { errorResponse, jsonResponse } from "../_shared/http.ts";

interface WebhookJob {
  job_id: number;
  event_id: string;
  event_type: string;
  payload: unknown;
  url: string;
  signing_secret_hex: string;
  attempts: number;
}

Deno.serve(async (request: Request) => {
  const requestId = crypto.randomUUID();
  if (request.method !== "POST") {
    return errorResponse(
      requestId,
      "method_not_allowed",
      "POST required.",
      405,
    );
  }
  const configuredToken = Deno.env.get("AGENT_WEBHOOK_DISPATCH_TOKEN");
  const presentedToken = request.headers.get("Authorization")?.replace(
    /^Bearer\s+/i,
    "",
  );
  if (
    !configuredToken || !presentedToken || presentedToken !== configuredToken
  ) {
    return errorResponse(
      requestId,
      "unauthorized",
      "Invalid dispatcher token.",
      401,
    );
  }

  const admin = adminClient();
  const { data, error } = await admin.rpc("claim_agent_webhook_jobs", {
    p_limit: 25,
  });
  if (error) {
    console.error(
      JSON.stringify({ request_id: requestId, error: error.message }),
    );
    return errorResponse(
      requestId,
      "claim_failed",
      "Webhook jobs could not be claimed.",
      500,
    );
  }

  const jobs = (data ?? []) as WebhookJob[];
  const results = await Promise.all(jobs.map(async (job) => {
    const body = JSON.stringify({
      id: job.event_id,
      type: job.event_type,
      created_at: new Date().toISOString(),
      data: job.payload,
    });
    const signature = await hmacHex(job.signing_secret_hex, body);
    let delivered = false;
    let failure: string | null = null;
    try {
      const response = await fetch(job.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "User-Agent": "Agent-Storefront-Webhook/1.0",
          "X-Agent-Event-Id": job.event_id,
          "X-Agent-Signature": signature,
        },
        body,
        signal: AbortSignal.timeout(10_000),
      });
      delivered = response.ok;
      if (!delivered) failure = `HTTP ${response.status}`;
    } catch (deliveryError) {
      failure = String(deliveryError);
    }
    const { error: finishError } = await admin.rpc("finish_agent_webhook_job", {
      p_job_id: job.job_id,
      p_delivered: delivered,
      p_error: failure,
    });
    if (finishError) {
      console.error(JSON.stringify({
        request_id: requestId,
        job_id: job.job_id,
        error: finishError.message,
      }));
    }
    return { job_id: job.job_id, delivered, attempt: job.attempts };
  }));

  return jsonResponse(requestId, {
    claimed: jobs.length,
    delivered: results.filter((result) => result.delivered).length,
    results,
  });
});
