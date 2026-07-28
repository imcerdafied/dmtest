import {
  hmacHex,
  randomSecretHex,
  sha256Hex,
} from "../supabase/functions/_shared/crypto.ts";

const [method = "GET", rawUrl, body = ""] = Deno.args;
const apiKey = Deno.env.get("AGENT_API_KEY");
const secret = Deno.env.get("AGENT_HMAC_SECRET");
if (!rawUrl || !apiKey || !secret) {
  console.error(
    "Usage: AGENT_API_KEY=... AGENT_HMAC_SECRET=... deno run scripts/sign-request.ts METHOD URL [BODY]",
  );
  Deno.exit(1);
}
const url = new URL(rawUrl);
const timestamp = new Date().toISOString();
const nonce = randomSecretHex().slice(0, 32);
const canonical = [
  timestamp,
  nonce,
  method.toUpperCase(),
  `${url.pathname}${url.search}`,
  await sha256Hex(body),
].join("\n");
const signature = await hmacHex(secret, canonical);

console.log(JSON.stringify(
  {
    "X-Agent-Key": apiKey,
    "X-Agent-Signature": signature,
    "X-Agent-Timestamp": timestamp,
    "X-Agent-Nonce": nonce,
  },
  null,
  2,
));
