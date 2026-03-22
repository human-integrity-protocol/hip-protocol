var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// worker.js
var DIDIT_API = "https://verification.didit.me";
var CORS_ORIGIN = "https://hipprotocol.org";
function corsHeaders(origin) {
  const allowed = origin && (origin === "https://hipprotocol.org" || origin === "https://hipverify.org" || origin === "http://hipverify.org" || origin === "http://hipprotocol.org" || origin.startsWith("http://localhost") || origin.startsWith("http://127.0.0.1"));
  return {
    "Access-Control-Allow-Origin": allowed ? origin : CORS_ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400"
  };
}
__name(corsHeaders, "corsHeaders");
function jsonResponse(data, status = 200, origin = CORS_ORIGIN) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders(origin)
    }
  });
}
__name(jsonResponse, "jsonResponse");
async function hmacSHA256(key, data) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(hmacSHA256, "hmacSHA256");
function shortenFloats(data) {
  if (Array.isArray(data)) return data.map(shortenFloats);
  if (data !== null && typeof data === "object") {
    return Object.fromEntries(
      Object.entries(data).map(([k, v]) => [k, shortenFloats(v)])
    );
  }
  if (typeof data === "number" && !Number.isInteger(data) && data % 1 === 0) {
    return Math.trunc(data);
  }
  return data;
}
__name(shortenFloats, "shortenFloats");
function sortKeysDeep(obj) {
  if (Array.isArray(obj)) return obj.map(sortKeysDeep);
  if (obj !== null && typeof obj === "object") {
    return Object.keys(obj).sort().reduce((r, k) => {
      r[k] = sortKeysDeep(obj[k]);
      return r;
    }, {});
  }
  return obj;
}
__name(sortKeysDeep, "sortKeysDeep");
async function verifyWebhookSignatureV2(jsonBody, signatureHeader, timestampHeader, secretKey) {
  const currentTime = Math.floor(Date.now() / 1e3);
  const incomingTime = parseInt(timestampHeader, 10);
  if (Math.abs(currentTime - incomingTime) > 300) return false;
  const processed = shortenFloats(jsonBody);
  const canonical = JSON.stringify(sortKeysDeep(processed));
  const expected = await hmacSHA256(secretKey, canonical);
  return expected === signatureHeader;
}
__name(verifyWebhookSignatureV2, "verifyWebhookSignatureV2");
async function verifyWebhookSignatureSimple(jsonBody, signatureHeader, timestampHeader, secretKey) {
  const currentTime = Math.floor(Date.now() / 1e3);
  const incomingTime = parseInt(timestampHeader, 10);
  if (Math.abs(currentTime - incomingTime) > 300) return false;
  const canonical = [
    jsonBody.timestamp || "",
    jsonBody.session_id || "",
    jsonBody.status || "",
    jsonBody.webhook_type || ""
  ].join(":");
  const expected = await hmacSHA256(secretKey, canonical);
  return expected === signatureHeader;
}
__name(verifyWebhookSignatureSimple, "verifyWebhookSignatureSimple");
async function computeDedupHash(idVerification, dedupSecret) {
  const docNum = (idVerification.document_number || "").trim().toUpperCase();
  const dob = (idVerification.date_of_birth || "").trim();
  const state = (idVerification.issuing_state || "").trim().toUpperCase();
  if (!docNum || !dob || !state) return null;
  const input = `${docNum}|${dob}|${state}`;
  return await hmacSHA256(dedupSecret, input);
}
__name(computeDedupHash, "computeDedupHash");
async function handleCreateSession(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;
  let vendorData = null;
  try {
    const body = await request.json();
    vendorData = body.vendor_data || null;
  } catch (_) {
  }
  const sessionPayload = {
    workflow_id: env.DIDIT_WORKFLOW_ID,
    callback: env.CALLBACK_URL
  };
  if (vendorData) sessionPayload.vendor_data = vendorData;
  const resp = await fetch(`${DIDIT_API}/v3/session/`, {
    method: "POST",
    headers: {
      "x-api-key": env.DIDIT_API_KEY,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(sessionPayload)
  });
  if (!resp.ok) {
    const errText = await resp.text();
    return jsonResponse(
      { error: "Failed to create Didit session", detail: errText },
      resp.status,
      origin
    );
  }
  const session = await resp.json();
  return jsonResponse({
    session_id: session.session_id,
    verification_url: session.verification_url || session.url
  }, 200, origin);
}
__name(handleCreateSession, "handleCreateSession");
async function handleWebhook(request, env) {
  const signatureV2 = request.headers.get("X-Signature-V2");
  const signatureSimple = request.headers.get("X-Signature-Simple");
  const timestamp = request.headers.get("X-Timestamp");
  if (!timestamp) {
    return jsonResponse({ error: "Missing timestamp header" }, 401);
  }
  const body = await request.json();
  let verified = false;
  if (signatureV2) {
    verified = await verifyWebhookSignatureV2(body, signatureV2, timestamp, env.DIDIT_WEBHOOK_SECRET);
  }
  if (!verified && signatureSimple) {
    verified = await verifyWebhookSignatureSimple(body, signatureSimple, timestamp, env.DIDIT_WEBHOOK_SECRET);
  }
  if (!verified) {
    return jsonResponse({ error: "Invalid webhook signature" }, 401);
  }
  const sessionId = body.session_id;
  const status = body.status;
  const sessionData = {
    status,
    timestamp: Date.now(),
    webhook_type: body.webhook_type || "unknown"
  };
  if (status === "Approved" && body.decision) {
    const decision = body.decision;
    const idVers = decision.id_verifications || [];
    const idVer = idVers.length > 0 ? idVers[0] : null;
    const liveness = (decision.liveness_checks || [])[0] || null;
    const faceMatch = (decision.face_matches || [])[0] || null;
    if (idVer) {
      const dedupHash = await computeDedupHash(idVer, env.DEDUP_SECRET);
      if (dedupHash) {
        const existing = await env.DEDUP_KV.get(`dedup:${dedupHash}`);
        if (existing) {
          sessionData.dedup = "exists";
          sessionData.existingCredentialId = existing;
          sessionData.message = "This identity has already been verified. Use your existing credential or initiate key rotation recovery.";
        } else {
          sessionData.dedup = "new";
          sessionData.dedupHash = dedupHash;
        }
      } else {
        sessionData.dedup = "insufficient_data";
      }
      sessionData.verificationProof = {
        type: "didit-idv-v3",
        sessionId,
        documentType: idVer.document_type || "unknown",
        issuingState: idVer.issuing_state || "unknown",
        livenessMethod: liveness ? liveness.method : "none",
        livenessScore: liveness ? liveness.score : null,
        faceMatchScore: faceMatch ? faceMatch.score : null,
        verifiedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  }
  await env.DEDUP_KV.put(`session:${sessionId}`, JSON.stringify(sessionData), {
    expirationTtl: 3600
  });
  return jsonResponse({ message: "Webhook processed" });
}
__name(handleWebhook, "handleWebhook");
async function handleStatus(sessionId, request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;
  const raw = await env.DEDUP_KV.get(`session:${sessionId}`);
  if (!raw) {
    return jsonResponse(
      { status: "pending", message: "Verification in progress or session not found." },
      200,
      origin
    );
  }
  const data = JSON.parse(raw);
  return jsonResponse(data, 200, origin);
}
__name(handleStatus, "handleStatus");
async function handleRegisterDedup(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;
  let body;
  try {
    body = await request.json();
  } catch (_) {
    return jsonResponse({ error: "Invalid JSON" }, 400, origin);
  }
  const { session_id, credential_id } = body;
  if (!session_id || !credential_id) {
    return jsonResponse({ error: "Missing session_id or credential_id" }, 400, origin);
  }
  const raw = await env.DEDUP_KV.get(`session:${session_id}`);
  if (!raw) {
    return jsonResponse({ error: "Session not found or expired" }, 404, origin);
  }
  const data = JSON.parse(raw);
  if (data.dedup !== "new" || !data.dedupHash) {
    return jsonResponse({ error: "Session not eligible for dedup registration" }, 400, origin);
  }
  await env.DEDUP_KV.put(`dedup:${data.dedupHash}`, credential_id);
  data.dedup = "registered";
  await env.DEDUP_KV.put(`session:${session_id}`, JSON.stringify(data), {
    expirationTtl: 3600
  });
  return jsonResponse({ success: true }, 200, origin);
}
__name(handleRegisterDedup, "handleRegisterDedup");
var worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    if (method === "OPTIONS") {
      const origin = request.headers.get("Origin") || CORS_ORIGIN;
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }
    if (method === "POST" && path === "/session") {
      return handleCreateSession(request, env);
    }
    if (method === "POST" && path === "/webhook") {
      return handleWebhook(request, env);
    }
    if (method === "GET" && path.startsWith("/status/")) {
      const sessionId = path.replace("/status/", "");
      if (!sessionId) return jsonResponse({ error: "Missing session ID" }, 400);
      return handleStatus(sessionId, request, env);
    }
    if (method === "POST" && path === "/register-dedup") {
      return handleRegisterDedup(request, env);
    }
    if (method === "GET" && path === "/health") {
      return jsonResponse({ status: "ok", service: "hip-tier1-worker" });
    }
    return jsonResponse({ error: "Not found" }, 404);
  }
};
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map
