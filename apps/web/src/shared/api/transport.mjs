// Shared by the React console and the embedded console. WebCrypto never falls
// back to plaintext, and key/challenge material is never persisted or cached.
const encoder = new TextEncoder();
const prefix = "access-gateway/browser-transport/v1";

export class TransportError extends Error {
  constructor(message) { super(message); this.name = "TransportError"; }
}

export function requiresEncryption(method, path) {
  if (method === "GET" && /^\/api\/v1\/sessions\/[^/]+\/terminal$/.test(path)) return true;
  if (method === "POST" && /^\/api\/v1\/sessions\/[^/]+\/terminal\/demo-defaults$/.test(path)) return true;
	if (method === "POST" && (["/api/v1/auth/invitation/preview", "/api/v1/auth/invitation/accept", "/api/v1/auth/mfa", "/api/v1/auth/mfa/enroll", "/api/v1/auth/mfa/confirm", "/api/v1/auth/mfa/verify", "/api/v1/auth/account/mfa/enroll", "/api/v1/auth/account/mfa/recovery-codes", "/api/v1/auth/account/mfa/unbind", "/api/v1/admin/invitations"].includes(path) || /^\/api\/v1\/admin\/invitations\/[^/]+\/resend$/.test(path))) return true;
  if (method === "POST") {
    return ["/api/v1/auth/local/login", "/api/v1/auth/ldap/login", "/api/v1/auth/password", "/api/v1/admin/cloud-accounts", "/api/v1/admin/assets", "/api/v1/admin/users", "/api/v1/admin/settings/audit/certificates", "/api/v1/admin/assets/audit/certificates"].includes(path) ||
      /^\/api\/v1\/admin\/gateways\/[^/]+\/release$/.test(path);
  }
  return method === "PATCH" && (path === "/api/v1/admin/settings" || /^\/api\/v1\/admin\/(cloud-accounts|assets)\/[^/]+$/.test(path));
}

// The WebSocket upgrade has no request body. Seal its first message using the
// same one-time, actor/path-bound contract as sensitive HTTP requests.
export async function sealTerminalStart(path, body, signal) {
  if (!/^\/api\/v1\/sessions\/[a-zA-Z0-9-]+\/terminal$/.test(path)) throw new TransportError("终端请求地址无效。");
  if (!globalThis.crypto?.subtle) throw new TransportError("敏感信息需要加密传输，请使用 HTTPS 或 localhost 访问。");
  const response = await fetch("/api/v1/auth/transport/challenges", {
    method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error", signal,
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ method: "GET", path }),
  });
  if (!response.ok) throw new TransportError("无法获取终端加密凭据，请检查登录状态后重试。");
  const challenge = await response.json();
  if (challenge.method !== "GET" || challenge.path !== path || !challenge.id || !challenge.kid || typeof challenge.subject !== "string") {
    throw new TransportError("加密挑战校验失败，请刷新页面后重试。");
  }
  return (await sealPayload(challenge, body)).body;
}

function base64(bytes) {
  let text = "";
  for (let offset = 0; offset < bytes.length; offset += 8192) text += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  return btoa(text);
}

function unbase64(text) {
  return Uint8Array.from(atob(text), character => character.charCodeAt(0));
}

function aad(challenge, direction) {
  return encoder.encode([prefix, direction, challenge.id, challenge.kid, challenge.method, challenge.path, challenge.subject].join("\n"));
}

async function derive(seedKey, direction) {
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: encoder.encode(`${prefix}/${direction}`) },
    seedKey, { name: "AES-GCM", length: 256 }, false, direction === "request" ? ["encrypt"] : ["decrypt"]);
}

export async function sealPayload(challenge, body) {
  if (!globalThis.crypto?.subtle) throw new TransportError("敏感信息需要加密传输，请使用 HTTPS 或 localhost 访问。");
  if (challenge.algorithm !== "RSA-OAEP-256+A256GCM") throw new TransportError("服务端加密协议不兼容，请刷新页面后重试。");
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const plaintext = encoder.encode(JSON.stringify(body));
  try {
    if (plaintext.length > 512 * 1024) throw new TransportError("提交内容过大，请减少内容后重试。");
    const publicDER = unbase64(challenge.public_key.replace(/-----[\w ]+-----|\s/g, ""));
    const publicKey = await crypto.subtle.importKey("spki", publicDER, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
    if (publicKey.algorithm.modulusLength < 2048) throw new TransportError("服务端加密密钥不符合要求。");
    const seedKey = await crypto.subtle.importKey("raw", seed, "HKDF", false, ["deriveKey"]);
    const requestKey = await derive(seedKey, "request");
    const responseKey = await derive(seedKey, "response");
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad(challenge, "request"), tagLength: 128 }, requestKey, plaintext);
    const encryptedKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, seed);
    return {
      body: { challenge_id: challenge.id, envelope: { version: 1, kid: challenge.kid, encrypted_key: base64(new Uint8Array(encryptedKey)), nonce: base64(nonce), ciphertext: base64(new Uint8Array(ciphertext)) } },
      async open(response, status) {
        if (response?.version !== 1 || response.challenge_id !== challenge.id) throw new TransportError("加密响应校验失败，请重试。");
        let decrypted;
        try {
          decrypted = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unbase64(response.nonce), additionalData: aad(challenge, `response:${status}`), tagLength: 128 }, responseKey, unbase64(response.ciphertext)));
          return new TextDecoder("utf-8", { fatal: true }).decode(decrypted);
        } catch {
          throw new TransportError("加密响应校验失败，请重试。");
        } finally { decrypted?.fill(0); }
      },
    };
  } catch (error) {
    if (error instanceof TransportError) throw error;
    throw new TransportError("无法建立加密传输，请刷新页面后重试。");
  } finally { seed.fill(0); plaintext.fill(0); }
}

export async function encryptedFetch(url, options = {}) {
  if (!url.startsWith("/api/v1/") || /[#\\\r\n]/.test(url)) throw new TransportError("API 请求地址无效。");
  const method = (options.method || "GET").toUpperCase();
  const path = url.split("?")[0];
  if (!requiresEncryption(method, path)) return fetch(url, options);
  if (!globalThis.crypto?.subtle) throw new TransportError("敏感信息需要加密传输，请使用 HTTPS 或 localhost 访问。");
  // Query strings are excluded from the contract; protected operations carry all
  // arguments in the authenticated JSON body or resource path.
  if (url !== path) throw new TransportError("敏感接口不支持 URL 查询参数。");
  const headers = new Headers(options.headers);
  const challengeHeaders = new Headers({ Accept: "application/json", "Content-Type": "application/json" });
  const challengeResponse = await fetch("/api/v1/auth/transport/challenges", {
    method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error", signal: options.signal,
    headers: challengeHeaders, body: JSON.stringify({ method, path }),
  });
  if (!challengeResponse.ok) return challengeResponse;
  const challenge = await challengeResponse.json();
  if (challenge.method !== method || challenge.path !== path || !challenge.id || !challenge.kid || typeof challenge.subject !== "string") {
    throw new TransportError("加密挑战校验失败，请刷新页面后重试。");
  }
  const sealed = await sealPayload(challenge, options.body === undefined ? {} : JSON.parse(options.body));
  headers.set("Content-Type", "application/json");
  const response = await fetch(url, { ...options, method, headers, credentials: "same-origin", cache: "no-store", redirect: "error", body: JSON.stringify(sealed.body) });
  if (response.headers.get("X-AG-Encrypted") !== "1") {
    if (!response.ok) return response; // CSRF, authorization and envelope errors contain no secrets.
    throw new TransportError("服务端未返回加密响应，请刷新页面或联系管理员。");
  }
  const plaintext = await sealed.open(await response.json(), response.status);
  const responseHeaders = new Headers(response.headers);
  responseHeaders.delete("Content-Length");
  responseHeaders.delete("Content-Encoding");
  return new Response(plaintext, { status: response.status, statusText: response.statusText, headers: responseHeaders });
}
