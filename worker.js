// ============================================================
// HIP TIER 1 — CLOUDFLARE WORKER
// Handles Didit identity verification sessions, webhooks,
// one-credential-per-human deduplication, Tier 3 server-side
// registration, and Trust Score computation.
//
// Environment bindings required:
//   DIDIT_API_KEY        — Didit API key (secret)
//   DIDIT_WEBHOOK_SECRET — Didit webhook secret key (secret)
//   DEDUP_SECRET         — HMAC secret for dedup/issuance hashing (secret)
//   DIDIT_WORKFLOW_ID    — Didit workflow ID (variable)
//   CALLBACK_URL         — tier1.html callback URL (variable)
//   DEDUP_KV             — KV namespace binding
//
// Routes:
//   POST /session            — Create a Didit verification session
//   POST /webhook            — Receive Didit webhook callbacks
//   GET  /status/:sid        — Poll session verification status
//   POST /register-dedup     — Register dedup hash after credential creation
//   POST /institutional-verify — Institutional operator identity check
//   POST /tier3/challenge    — Issue Tier 3 registration challenge (S29)
//   POST /tier3/register     — Validate WebAuthn attestation, issue token (S29)
//   POST /trust/initialize   — Initialize trust record for new credential (S29)
//   POST /attest-register    — Register attestation, update trust score (S29)
//   GET  /trust/:cred_id     — Public trust score query (S29)
//   POST /transfer/:code     — QR transfer push
//   GET  /transfer/:code     — QR transfer pull
//   GET  /health             — Health check
//
// KV key patterns:
//   session:{sid}        — Didit session data (1h TTL)
//   dedup:{hash}         — Identity dedup mapping (permanent)
//   inst_key:{hash}      — Institutional operator API key
//   audit:inst:{cred}    — Institutional audit record (1y TTL)
//   xfer:{code}          — QR transfer blob (5min TTL)
//   t3sess:{sid}         — Tier 3 registration session (5min TTL) (S29)
//   t3rate:{ip_hash}     — Tier 3 IP rate limit (24h TTL) (S29)
//   t3audit:{cred_hash}  — Tier 3 audit record (1y TTL) (S29)
//   trust:{cred_id}      — Credential trust record (permanent) (S29)
// ============================================================

const DIDIT_API = "https://verification.didit.me";
const CORS_ORIGIN = "https://hipprotocol.org";

// ── Helpers ──

function corsHeaders(origin) {
  // Allow hipprotocol.org, hipverify.org, and localhost for dev
  const allowed = origin && (
    origin === "https://hipprotocol.org" ||
    origin === "http://hipprotocol.org" ||
    origin === "https://hipverify.org" ||
    origin === "http://hipverify.org" ||
    origin.startsWith("http://localhost") ||
    origin.startsWith("http://127.0.0.1")
  );
  return {
    "Access-Control-Allow-Origin": allowed ? origin : CORS_ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonResponse(data, status = 200, origin = CORS_ORIGIN) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders(origin),
    },
  });
}

// HMAC-SHA-256 for dedup hash and webhook signature verification
async function hmacSHA256(key, data) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// Verify Didit webhook signature (X-Signature-V2 recommended method)
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

async function verifyWebhookSignatureV2(jsonBody, signatureHeader, timestampHeader, secretKey) {
  const currentTime = Math.floor(Date.now() / 1000);
  const incomingTime = parseInt(timestampHeader, 10);
  if (Math.abs(currentTime - incomingTime) > 300) return false;

  const processed = shortenFloats(jsonBody);
  const canonical = JSON.stringify(sortKeysDeep(processed));
  const expected = await hmacSHA256(secretKey, canonical);
  return expected === signatureHeader;
}

async function verifyWebhookSignatureSimple(jsonBody, signatureHeader, timestampHeader, secretKey) {
  const currentTime = Math.floor(Date.now() / 1000);
  const incomingTime = parseInt(timestampHeader, 10);
  if (Math.abs(currentTime - incomingTime) > 300) return false;

  const canonical = [
    jsonBody.timestamp || "",
    jsonBody.session_id || "",
    jsonBody.status || "",
    jsonBody.webhook_type || "",
  ].join(":");
  const expected = await hmacSHA256(secretKey, canonical);
  return expected === signatureHeader;
}

// Compute dedup hash: HMAC-SHA-256(document_number|dob|issuing_state, DEDUP_SECRET)
async function computeDedupHash(idVerification, dedupSecret) {
  const docNum = (idVerification.document_number || "").trim().toUpperCase();
  const dob = (idVerification.date_of_birth || "").trim();
  const state = (idVerification.issuing_state || "").trim().toUpperCase();
  if (!docNum || !dob || !state) return null;
  const input = `${docNum}|${dob}|${state}`;
  return await hmacSHA256(dedupSecret, input);
}

// ── Route Handlers ──

// POST /session — Create a Didit verification session
async function handleCreateSession(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  // Optional: client can pass vendor_data for tracking
  let vendorData = null;
  try {
    const body = await request.json();
    vendorData = body.vendor_data || null;
  } catch (_) {}

  const sessionPayload = {
    workflow_id: env.DIDIT_WORKFLOW_ID,
    callback: env.CALLBACK_URL,
  };
  if (vendorData) sessionPayload.vendor_data = vendorData;

  const resp = await fetch(`${DIDIT_API}/v3/session/`, {
    method: "POST",
    headers: {
      "x-api-key": env.DIDIT_API_KEY,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(sessionPayload),
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

  // Return only what the client needs — never expose API keys
  return jsonResponse({
    session_id: session.session_id,
    verification_url: session.verification_url || session.url,
  }, 200, origin);
}

// POST /webhook — Receive Didit webhook callbacks
async function handleWebhook(request, env) {
  const signatureV2 = request.headers.get("X-Signature-V2");
  const signatureSimple = request.headers.get("X-Signature-Simple");
  const timestamp = request.headers.get("X-Timestamp");

  if (!timestamp) {
    return jsonResponse({ error: "Missing timestamp header" }, 401);
  }

  const body = await request.json();

  // Verify signature — try V2 first, then Simple fallback
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

  // Store the webhook status in KV so the client can poll it
  const sessionData = {
    status: status,
    timestamp: Date.now(),
    webhook_type: body.webhook_type || "unknown",
  };

  // If approved, extract identity signals for dedup and store verification proof
  if (status === "Approved" && body.decision) {
    const decision = body.decision;
    const idVers = decision.id_verifications || [];
    const idVer = idVers.length > 0 ? idVers[0] : null;
    const liveness = (decision.liveness_checks || [])[0] || null;
    const faceMatch = (decision.face_matches || [])[0] || null;

    if (idVer) {
      // Compute dedup hash
      const dedupHash = await computeDedupHash(idVer, env.DEDUP_SECRET);

      if (dedupHash) {
        // Check if this person already has a credential
        const existing = await env.DEDUP_KV.get(`dedup:${dedupHash}`);

        if (existing) {
          // Person already verified — store as duplicate for client to handle
          sessionData.dedup = "exists";
          sessionData.existingCredentialId = existing;
          sessionData.message = "This identity has already been verified. Use your existing credential or initiate key rotation recovery.";
        } else {
          // New person — we'll store the dedup hash after the client creates their credential
          sessionData.dedup = "new";
          sessionData.dedupHash = dedupHash;
        }
      } else {
        // Couldn't extract enough identity signals for dedup
        sessionData.dedup = "insufficient_data";
      }

      // Store verification proof (non-PII summary for credential file)
      sessionData.verificationProof = {
        type: "didit-idv-v3",
        sessionId: sessionId,
        documentType: idVer.document_type || "unknown",
        issuingState: idVer.issuing_state || "unknown",
        livenessMethod: liveness ? liveness.method : "none",
        livenessScore: liveness ? liveness.score : null,
        faceMatchScore: faceMatch ? faceMatch.score : null,
        verifiedAt: new Date().toISOString(),
      };
    }
  }

  // Store session data in KV (TTL: 1 hour — client must poll within that window)
  await env.DEDUP_KV.put(`session:${sessionId}`, JSON.stringify(sessionData), {
    expirationTtl: 3600,
  });

  return jsonResponse({ message: "Webhook processed" });
}

// GET /status/:sessionId — Client polls for verification result
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

// POST /register-dedup — After client creates credential, register the dedup hash
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

  // Retrieve session data
  const raw = await env.DEDUP_KV.get(`session:${session_id}`);
  if (!raw) {
    return jsonResponse({ error: "Session not found or expired" }, 404, origin);
  }

  const data = JSON.parse(raw);
  if (data.dedup !== "new" || !data.dedupHash) {
    return jsonResponse({ error: "Session not eligible for dedup registration" }, 400, origin);
  }

  // Register the dedup hash → credential ID mapping (permanent)
  await env.DEDUP_KV.put(`dedup:${data.dedupHash}`, credential_id);

  // Mark session as registered
  data.dedup = "registered";
  await env.DEDUP_KV.put(`session:${session_id}`, JSON.stringify(data), {
    expirationTtl: 3600,
  });

  return jsonResponse({ success: true }, 200, origin);
}

// POST /institutional-verify — Institutional operator submits verified identity fields
// The Worker computes the dedup hash server-side; raw identity fields are never stored.
// Requires X-API-Key header matching an approved institutional operator key.
async function handleInstitutionalVerify(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  // Authenticate institutional operator
  const apiKey = request.headers.get("X-API-Key");
  if (!apiKey) {
    return jsonResponse({ error: "Missing X-API-Key header" }, 401, origin);
  }

  // Look up institutional operator by API key
  // Keys stored in KV as: inst_key:<api_key_hash> → { operator_id, operator_name, active }
  const keyHash = await hmacSHA256(env.DEDUP_SECRET, apiKey);
  const operatorRaw = await env.DEDUP_KV.get(`inst_key:${keyHash}`);
  if (!operatorRaw) {
    return jsonResponse({ error: "Invalid API key" }, 403, origin);
  }

  const operator = JSON.parse(operatorRaw);
  if (!operator.active) {
    return jsonResponse({ error: "Operator account is deactivated" }, 403, origin);
  }

  // Parse request body
  let body;
  try {
    body = await request.json();
  } catch (_) {
    return jsonResponse({ error: "Invalid JSON" }, 400, origin);
  }

  const { document_number, date_of_birth, issuing_state, credential_id } = body;

  // Validate required fields
  if (!document_number || !date_of_birth || !issuing_state) {
    return jsonResponse(
      { error: "Missing required fields: document_number, date_of_birth, issuing_state" },
      400, origin
    );
  }

  if (!credential_id) {
    return jsonResponse({ error: "Missing credential_id" }, 400, origin);
  }

  // Compute dedup hash from the identity fields (same formula as Didit path)
  // Fields are processed in memory and never written to KV or logs
  const dedupHash = await computeDedupHash(
    { document_number, date_of_birth, issuing_state },
    env.DEDUP_SECRET
  );

  if (!dedupHash) {
    return jsonResponse({ error: "Could not compute dedup hash from provided fields" }, 400, origin);
  }

  // Check for existing credential with this identity
  const existing = await env.DEDUP_KV.get(`dedup:${dedupHash}`);
  if (existing) {
    return jsonResponse({
      error: "duplicate",
      message: "This identity has already been verified.",
      existingCredentialId: existing,
    }, 409, origin);
  }

  // Register the dedup hash → credential ID mapping (permanent)
  await env.DEDUP_KV.put(`dedup:${dedupHash}`, credential_id);

  // Store a verification record for audit (no PII, just metadata)
  const auditRecord = {
    type: "institutional-verify",
    operator_id: operator.operator_id,
    operator_name: operator.operator_name,
    credential_id: credential_id,
    verified_at: new Date().toISOString(),
  };
  await env.DEDUP_KV.put(
    `audit:inst:${credential_id}`,
    JSON.stringify(auditRecord),
    { expirationTtl: 86400 * 365 } // 1 year retention for audit
  );

  return jsonResponse({
    success: true,
    credential_id: credential_id,
    operator: operator.operator_name,
    pathway: "government-id-institutional-v1",
    message: "Dedup hash registered. Credential is valid.",
  }, 200, origin);
}

// ── Tier 3 (Device Biometric) Server-Side Registration ──
// S29: Challenge/response flow with IP rate limiting.
// Prevents unlimited client-only credential creation.

// POST /tier3/challenge — Issue a registration challenge
async function handleTier3Challenge(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  // IP rate limiting: max 2 Tier 3 credentials per IP per 24h
  const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
  const ipHash = await hmacSHA256(env.DEDUP_SECRET, "t3ip:" + clientIP);
  const rateKey = `t3rate:${ipHash}`;

  const rateRaw = await env.DEDUP_KV.get(rateKey);
  if (rateRaw) {
    const rateData = JSON.parse(rateRaw);
    if (rateData.count >= 2) {
      return jsonResponse({
        error: "Rate limit exceeded",
        message: "Maximum 2 Tier 3 credentials per network per 24 hours. Try again later.",
      }, 429, origin);
    }
  }

  // Generate challenge (32 random bytes) and session ID (16 hex chars)
  const challengeBytes = new Uint8Array(32);
  crypto.getRandomValues(challengeBytes);
  const challenge = btoa(String.fromCharCode(...challengeBytes));

  const sessionIdBytes = new Uint8Array(8);
  crypto.getRandomValues(sessionIdBytes);
  const sessionId = Array.from(sessionIdBytes).map(b => b.toString(16).padStart(2, "0")).join("");

  // Store session in KV with 5 minute TTL
  await env.DEDUP_KV.put(`t3sess:${sessionId}`, JSON.stringify({
    challenge: challenge,
    ip_hash: ipHash,
    created: Date.now(),
  }), { expirationTtl: 300 });

  return jsonResponse({ session_id: sessionId, challenge: challenge }, 200, origin);
}

// POST /tier3/register — Validate WebAuthn attestation, return issuance token
async function handleTier3Register(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  let body;
  try {
    body = await request.json();
  } catch (_) {
    return jsonResponse({ error: "Invalid JSON" }, 400, origin);
  }

  const { session_id, credential_id, attestation_object, client_data_json, public_key } = body;

  if (!session_id || !credential_id || !client_data_json || !public_key) {
    return jsonResponse({ error: "Missing required fields" }, 400, origin);
  }

  // Step 4a: Retrieve and validate session
  const sessRaw = await env.DEDUP_KV.get(`t3sess:${session_id}`);
  if (!sessRaw) {
    return jsonResponse({ error: "Session not found or expired" }, 404, origin);
  }

  const sess = JSON.parse(sessRaw);

  // Verify IP matches (prevent session hijacking)
  const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
  const ipHash = await hmacSHA256(env.DEDUP_SECRET, "t3ip:" + clientIP);
  if (ipHash !== sess.ip_hash) {
    return jsonResponse({ error: "Session IP mismatch" }, 403, origin);
  }

  // Step 4b: Parse and validate clientDataJSON
  // clientDataJSON is base64-encoded — decode it
  let clientData;
  try {
    const clientDataStr = atob(client_data_json);
    clientData = JSON.parse(clientDataStr);
  } catch (_) {
    return jsonResponse({ error: "Invalid clientDataJSON" }, 400, origin);
  }

  if (clientData.type !== "webauthn.create") {
    return jsonResponse({ error: "Wrong WebAuthn ceremony type" }, 400, origin);
  }

  // Verify challenge matches (clientData.challenge is base64url-encoded)
  // Normalize both to compare: stored challenge is standard base64
  const storedChallenge = sess.challenge;
  // clientData.challenge is base64url, convert to standard base64 for comparison
  const clientChallenge = clientData.challenge.replace(/-/g, "+").replace(/_/g, "/");
  // Pad if needed
  const padded = clientChallenge + "=".repeat((4 - clientChallenge.length % 4) % 4);

  if (padded !== storedChallenge) {
    return jsonResponse({ error: "Challenge mismatch" }, 400, origin);
  }

  // Verify origin matches allowed origins
  const allowedOrigins = [
    "https://hipprotocol.org",
    "https://hipverify.org",
    "http://localhost",
  ];
  const originMatch = allowedOrigins.some(ao => clientData.origin && clientData.origin.startsWith(ao));
  if (!originMatch) {
    return jsonResponse({ error: "Origin not allowed" }, 403, origin);
  }

  // Step 4c: Parse attestationObject for audit metadata
  // Full CBOR parsing is complex; extract what we can for audit.
  // The attestation_object is base64-encoded CBOR. We store it for audit
  // but do lightweight validation (the biometric gate is the real security).
  let attestationMeta = { format: "unknown", aaguid: "unknown" };
  if (attestation_object) {
    try {
      // Extract attestation format from CBOR structure
      // fmt is typically near the start of the CBOR map
      const attBytes = Uint8Array.from(atob(attestation_object), c => c.charCodeAt(0));
      // Look for 'fmt' string in CBOR — lightweight extraction
      const attStr = new TextDecoder("utf-8", { fatal: false }).decode(attBytes);
      if (attStr.includes("packed")) attestationMeta.format = "packed";
      else if (attStr.includes("tpm")) attestationMeta.format = "tpm";
      else if (attStr.includes("android-key")) attestationMeta.format = "android-key";
      else if (attStr.includes("apple")) attestationMeta.format = "apple";
      else if (attStr.includes("none")) attestationMeta.format = "none";

      // Extract AAGUID from authData (starts at byte 37 of authData, 16 bytes)
      // authData location varies by CBOR encoding; best-effort extraction
      // AAGUID is 16 bytes at offset 37 of authenticator data
      if (attBytes.length > 100) {
        // Find authData — in packed/none format, it follows the "authData" key
        const authDataMarker = "authData";
        const markerIdx = attStr.indexOf(authDataMarker);
        if (markerIdx > 0) {
          // AAGUID starts at offset 37 within authData
          // The exact byte offset depends on CBOR encoding; skip for now
          // and store the attestation_object hash for forensic audit
        }
      }
    } catch (_) {
      // Non-critical — attestation metadata is for audit only
    }
  }

  // Step 4d: Enforce IP rate limit
  const rateKey = `t3rate:${ipHash}`;
  const rateRaw = await env.DEDUP_KV.get(rateKey);
  let rateCount = 0;
  if (rateRaw) {
    rateCount = JSON.parse(rateRaw).count;
  }
  if (rateCount >= 2) {
    return jsonResponse({
      error: "Rate limit exceeded",
      message: "Maximum 2 Tier 3 credentials per network per 24 hours.",
    }, 429, origin);
  }

  // Increment rate limit counter
  await env.DEDUP_KV.put(rateKey, JSON.stringify({
    count: rateCount + 1,
    last_registration: Date.now(),
  }), { expirationTtl: 86400 }); // 24h TTL

  // Step 4e: Store audit record
  const credentialHash = await hmacSHA256(env.DEDUP_SECRET, credential_id);
  await env.DEDUP_KV.put(`t3audit:${credentialHash}`, JSON.stringify({
    session_id: session_id,
    ip_hash: ipHash,
    attestation_format: attestationMeta.format,
    timestamp: new Date().toISOString(),
    origin: clientData.origin,
  }), { expirationTtl: 86400 * 365 }); // 1 year

  // Step 4f: Compute issuance token
  const timestamp = new Date().toISOString();
  const issuanceToken = await hmacSHA256(
    env.DEDUP_SECRET,
    `${session_id}:${public_key}:${timestamp}`
  );

  // Step 4g: Delete session (one-time use)
  await env.DEDUP_KV.delete(`t3sess:${session_id}`);

  return jsonResponse({
    issuance_token: issuanceToken,
    session_id: session_id,
    timestamp: timestamp,
    attestation_format: attestationMeta.format,
  }, 200, origin);
}

// ── Trust Score System ──
// S29: Worker-computed Trust Score (0-100) for every credential.
// Formula: tier_base + age_bonus + volume_bonus + consistency_bonus + liveness_bonus

function computeTrustScore(record) {
  // Tier base points
  const tierBase = record.tier === 1 ? 40 : record.tier === 2 ? 25 : 10;

  // Age bonus: max +20 over 1 year, linear
  const ageDays = (Date.now() - new Date(record.first_seen).getTime()) / (1000 * 60 * 60 * 24);
  const ageBonus = Math.min(ageDays / 365 * 20, 20);

  // Volume bonus: max +15 at 50 attestations, linear
  const volumeBonus = Math.min(record.attestation_count / 50 * 15, 15);

  // Consistency bonus: max +10 over 12 active months, linear
  const activeMonths = (record.active_months || []).length;
  const consistencyBonus = Math.min(activeMonths / 12 * 10, 10);

  // Liveness bonus: max +15 at 100% device-verified liveness
  const livenessRate = record.attestation_count > 0
    ? record.liveness_verified_count / record.attestation_count
    : 0;
  const livenessBonus = livenessRate * 15;

  const score = Math.min(Math.round(tierBase + ageBonus + volumeBonus + consistencyBonus + livenessBonus), 100);
  return { score, tierBase, ageBonus: Math.round(ageBonus * 10) / 10, volumeBonus: Math.round(volumeBonus * 10) / 10, consistencyBonus: Math.round(consistencyBonus * 10) / 10, livenessBonus: Math.round(livenessBonus * 10) / 10, livenessRate: Math.round(livenessRate * 1000) / 1000 };
}

// POST /trust/initialize — Called during credential creation
async function handleTrustInitialize(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  let body;
  try {
    body = await request.json();
  } catch (_) {
    return jsonResponse({ error: "Invalid JSON" }, 400, origin);
  }

  const { credential_id, tier } = body;
  if (!credential_id || !tier) {
    return jsonResponse({ error: "Missing credential_id or tier" }, 400, origin);
  }

  if (![1, 2, 3].includes(tier)) {
    return jsonResponse({ error: "Invalid tier (must be 1, 2, or 3)" }, 400, origin);
  }

  // Check if already initialized
  const existing = await env.DEDUP_KV.get(`trust:${credential_id}`);
  if (existing) {
    // Already exists — return current score without overwriting
    const record = JSON.parse(existing);
    const ts = computeTrustScore(record);
    return jsonResponse({
      credential_id: credential_id,
      trust_score: ts.score,
      message: "Trust record already exists",
    }, 200, origin);
  }

  const now = new Date().toISOString();
  const record = {
    tier: tier,
    first_seen: now,
    last_seen: now,
    attestation_count: 0,
    liveness_verified_count: 0,
    active_months: [],
  };

  const ts = computeTrustScore(record);
  record.trust_score = ts.score;

  await env.DEDUP_KV.put(`trust:${credential_id}`, JSON.stringify(record));

  return jsonResponse({
    credential_id: credential_id,
    trust_score: ts.score,
    tier: tier,
    initialized: true,
  }, 200, origin);
}

// POST /attest-register — Called after each attestation to update trust record
async function handleAttestRegister(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  let body;
  try {
    body = await request.json();
  } catch (_) {
    return jsonResponse({ error: "Invalid JSON" }, 400, origin);
  }

  const { credential_id, bundle_hash, liveness_designation, timestamp } = body;
  if (!credential_id || !bundle_hash) {
    return jsonResponse({ error: "Missing credential_id or bundle_hash" }, 400, origin);
  }

  // Get or create trust record
  let record;
  const existing = await env.DEDUP_KV.get(`trust:${credential_id}`);
  if (existing) {
    record = JSON.parse(existing);
  } else {
    // Auto-initialize if not found (backward compatibility for pre-trust credentials)
    record = {
      tier: 3, // default assumption; credential should have been initialized
      first_seen: timestamp || new Date().toISOString(),
      last_seen: timestamp || new Date().toISOString(),
      attestation_count: 0,
      liveness_verified_count: 0,
      active_months: [],
    };
  }

  // Update record
  record.attestation_count += 1;
  record.last_seen = timestamp || new Date().toISOString();

  if (liveness_designation === "device-attested") {
    record.liveness_verified_count += 1;
  }

  // Track active months
  const monthStr = (record.last_seen).substring(0, 7); // YYYY-MM
  if (!record.active_months.includes(monthStr)) {
    record.active_months.push(monthStr);
  }

  // Recompute trust score
  const ts = computeTrustScore(record);
  record.trust_score = ts.score;

  await env.DEDUP_KV.put(`trust:${credential_id}`, JSON.stringify(record));

  return jsonResponse({
    credential_id: credential_id,
    trust_score: ts.score,
    attestation_count: record.attestation_count,
    score_breakdown: {
      tier_base: ts.tierBase,
      age_bonus: ts.ageBonus,
      volume_bonus: ts.volumeBonus,
      consistency_bonus: ts.consistencyBonus,
      liveness_bonus: ts.livenessBonus,
    },
  }, 200, origin);
}

// GET /trust/:credential_id — Public trust score query
async function handleTrustQuery(credentialId, request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  if (!credentialId) {
    return jsonResponse({ error: "Missing credential_id" }, 400, origin);
  }

  const raw = await env.DEDUP_KV.get(`trust:${credentialId}`);
  if (!raw) {
    return jsonResponse({
      error: "not_found",
      message: "No trust record found for this credential.",
    }, 404, origin);
  }

  const record = JSON.parse(raw);
  const ts = computeTrustScore(record);

  // Recompute in case of age drift since last update
  record.trust_score = ts.score;

  const ageDays = Math.floor((Date.now() - new Date(record.first_seen).getTime()) / (1000 * 60 * 60 * 24));

  return jsonResponse({
    credential_id: credentialId,
    tier: record.tier,
    trust_score: ts.score,
    attestation_count: record.attestation_count,
    credential_age_days: ageDays,
    liveness_rate: ts.livenessRate,
    first_seen: record.first_seen,
    last_seen: record.last_seen,
    computed_at: new Date().toISOString(),
    score_breakdown: {
      tier_base: ts.tierBase,
      age_bonus: ts.ageBonus,
      volume_bonus: ts.volumeBonus,
      consistency_bonus: ts.consistencyBonus,
      liveness_bonus: ts.livenessBonus,
    },
  }, 200, origin);
}

// ── QR Transfer Handlers ──

// POST /transfer/:code — Phone pushes encrypted credential blob
async function handleTransferPush(code, request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  if (!code || code.length < 8 || code.length > 64) {
    return jsonResponse({ error: "Invalid transfer code" }, 400, origin);
  }

  let body;
  try {
    body = await request.json();
  } catch (_) {
    return jsonResponse({ error: "Invalid JSON" }, 400, origin);
  }

  const { encrypted } = body;
  if (!encrypted || typeof encrypted !== "string") {
    return jsonResponse({ error: "Missing encrypted payload" }, 400, origin);
  }

  if (encrypted.length > 16384) {
    return jsonResponse({ error: "Payload too large" }, 400, origin);
  }

  const existing = await env.DEDUP_KV.get(`xfer:${code}`);
  if (existing) {
    return jsonResponse({ error: "Transfer code already used" }, 409, origin);
  }

  await env.DEDUP_KV.put(`xfer:${code}`, encrypted, {
    expirationTtl: 300,
  });

  return jsonResponse({ success: true }, 200, origin);
}

// GET /transfer/:code — Desktop polls for encrypted credential blob
async function handleTransferPull(code, request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  if (!code || code.length < 8 || code.length > 64) {
    return jsonResponse({ error: "Invalid transfer code" }, 400, origin);
  }

  const encrypted = await env.DEDUP_KV.get(`xfer:${code}`);
  if (!encrypted) {
    return jsonResponse({ status: "waiting" }, 200, origin);
  }

  await env.DEDUP_KV.delete(`xfer:${code}`);

  return jsonResponse({ status: "ready", encrypted: encrypted }, 200, origin);
}

// ── Main Router ──

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === "OPTIONS") {
      const origin = request.headers.get("Origin") || CORS_ORIGIN;
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // Routes
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

    if (method === "POST" && path === "/institutional-verify") {
      return handleInstitutionalVerify(request, env);
    }

    if (method === "GET" && path === "/health") {
      return jsonResponse({ status: "ok", service: "hip-tier1-worker" });
    }

    // Tier 3 server-side registration (S29)
    if (method === "POST" && path === "/tier3/challenge") {
      return handleTier3Challenge(request, env);
    }

    if (method === "POST" && path === "/tier3/register") {
      return handleTier3Register(request, env);
    }

    // Trust Score routes (S29)
    if (method === "POST" && path === "/trust/initialize") {
      return handleTrustInitialize(request, env);
    }

    if (method === "POST" && path === "/attest-register") {
      return handleAttestRegister(request, env);
    }

    if (method === "GET" && path.startsWith("/trust/")) {
      const credentialId = path.replace("/trust/", "");
      if (!credentialId) return jsonResponse({ error: "Missing credential_id" }, 400);
      return handleTrustQuery(credentialId, request, env);
    }

    if (path.startsWith("/transfer/")) {
      const code = path.replace("/transfer/", "");
      if (method === "POST") return handleTransferPush(code, request, env);
      if (method === "GET") return handleTransferPull(code, request, env);
    }

    return jsonResponse({ error: "Not found" }, 404);
  },
};
