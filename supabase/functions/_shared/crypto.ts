const encoder = new TextEncoder();

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

export function hexToBytes(hex: string): Uint8Array | null {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) return null;
  return new Uint8Array(
    hex.match(/.{2}/g)!.map((pair) => Number.parseInt(pair, 16)),
  );
}

export async function sha256Hex(value: string): Promise<string> {
  return bytesToHex(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", encoder.encode(value)),
    ),
  );
}

export async function hmacHex(
  secretHex: string,
  message: string,
): Promise<string> {
  const secret = hexToBytes(secretHex);
  if (!secret) throw new Error("invalid_hmac_secret");
  const key = await crypto.subtle.importKey(
    "raw",
    secret.slice().buffer as ArrayBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return bytesToHex(
    new Uint8Array(
      await crypto.subtle.sign("HMAC", key, encoder.encode(message)),
    ),
  );
}

export async function verifyHmacHex(
  secretHex: string,
  message: string,
  signatureHex: string,
): Promise<boolean> {
  const secret = hexToBytes(secretHex);
  const signature = hexToBytes(signatureHex);
  if (!secret || !signature || signature.byteLength !== 32) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    secret.slice().buffer as ArrayBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    "HMAC",
    key,
    signature.slice().buffer as ArrayBuffer,
    encoder.encode(message),
  );
}

export function randomSecretHex(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
}
