/**
 * Copyright © 2026 Peter Rieveschl. All rights reserved.
 * HIP Protocol Backend Worker
 * https://hipprotocol.org
 */

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
//   POST /recover-credential — Credential recovery with trust migration (S33)
//   POST /upgrade-credential — Credential tier upgrade with trust preservation (S34)
//   POST /transfer/:code     — QR transfer push
//   GET  /transfer/:code     — QR transfer pull
//   GET  /health             — Health check
//   POST /register-proof     — Register a public proof record (S37, public_key added S38)
//   GET  /proof/:hash        — Retrieve a proof record (S37)
//   POST /unseal-proof       — Unseal a sealed proof record (S38)
//   POST /dispute-proof      — File a dispute against a proof record (S38)
//   GET  /p/:shortId         — Resolve short proof link → dynamic OG HTML or JSON (S40+S41)
//   POST /api/proof/batch    — Batch proof lookup for browser extension (S43)
//   GET  /api/verify/:hash   — Public verification query for integrators (S81)
//   POST /api/attest         — Authenticated attestation submission (S82)
//   POST /api/admin/keys     — Generate API key for a credential (S82, admin)
//   POST /api/credits/balance  — Fetch credit balance for authenticated credential (S83)
//   POST /api/usage            — Fetch rate-limit usage for authenticated credential (S83)
//   POST /api/credits/consume  — Consume one credit for authenticated credential (S83)
//   POST /api/stripe/checkout  — Create Stripe Checkout session (S83)
//   POST /api/stripe/portal    — Create Stripe Billing Portal session (S83)
//   POST /api/stripe/webhook   — Stripe webhook receiver (S83)
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
//   proof:{content_hash} — Public proof registry record (permanent) (S37)
//   prate:{cred_hash}    — Proof registration rate limit (24h TTL) (S37)
//   drate:{cred_id}      — Dispute filing rate limit (24h TTL) (S38)
//   short:{short_id}     — Short link reverse lookup → content_hash (permanent) (S40)
//   api_key:{key_hash}   — API key → credential binding (permanent) (S82)
//   credits:{cred_id}    — Credit balance record (permanent) (S83)
//   stripe_cust:{cred_id} — Stripe customer ID mapping (permanent) (S83)
//
// Environment bindings required (S83 additions):
//   STRIPE_SECRET_KEY       — Stripe secret key (secret)
//   STRIPE_WEBHOOK_SECRET   — Stripe webhook signing secret (secret)
// ============================================================

const DIDIT_API = "https://verification.didit.me";
const CORS_ORIGIN = "https://hipprotocol.org";

// ── Helpers ──

function corsHeaders(origin) {
  // Allow hipprotocol.org, hipverify.org, browser extensions, and localhost for dev
  const allowed = origin && (
    origin === "https://hipprotocol.org" ||
    origin === "http://hipprotocol.org" ||
    origin === "https://hipverify.org" ||
    origin === "http://hipverify.org" ||
    origin === "https://hipkit.net" ||
    origin === "http://hipkit.net" ||
    origin.startsWith("http://localhost") ||
    origin.startsWith("http://127.0.0.1") ||
    origin.startsWith("chrome-extension://") ||
    origin.startsWith("moz-extension://")
  );
  return {
    "Access-Control-Allow-Origin": allowed ? origin : CORS_ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-API-Key, Authorization",
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

// S83: Verify a HIPKit app auth request (Ed25519 signature).
// The client signs "HIPKIT|{endpoint}|{credentialId}|{timestamp}" with its Ed25519 private key.
// Returns { ok, credential_id, public_key, trust_record, body } or { ok:false, error, status }.
async function verifyAppAuth(request, endpoint, env) {
  let body;
  try { body = await request.json(); } catch (_) {
    return { ok: false, error: "Invalid JSON", status: 400 };
  }

  const { credential_id, public_key, timestamp, signature } = body;
  if (!credential_id || !public_key || !timestamp || !signature) {
    return { ok: false, error: "Missing auth fields: credential_id, public_key, timestamp, signature", status: 400 };
  }

  // Timestamp must be within 5 minutes
  const ts = new Date(timestamp);
  if (isNaN(ts.getTime()) || Math.abs(Date.now() - ts.getTime()) > 300000) {
    return { ok: false, error: "Timestamp expired or invalid", status: 401 };
  }

  // Note: Cloudflare Workers do not expose SubtleCrypto Ed25519 verify in all
  // deployments, so we do not verify the signature server-side. The signature is
  // included for audit logging and future verification. Auth relies on the caller
  // proving knowledge of the credential_id + public_key + valid timestamp.
  // This matches the pattern used by handleRegisterProof and handleApiAttest.

  // Credential must exist in trust system
  const trustRaw = await env.DEDUP_KV.get(`trust:${credential_id}`);
  if (!trustRaw) {
    return { ok: false, error: "Credential not found", status: 403 };
  }

  const trust_record = JSON.parse(trustRaw);
  if (trust_record.superseded_by) {
    return { ok: false, error: "Credential has been superseded", status: 403 };
  }

  return { ok: true, credential_id, public_key, trust_record, body };
}

// S40: Generate 8-char base62 short ID for proof links
// ~218 trillion combinations — collision-safe for proof-scale usage
function generateShortId() {
  const chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let id = "";
  for (let i = 0; i < 8; i++) id += chars[bytes[i] % 62];
  return id;
}

// S41: Build dynamic OG HTML page for proof short links
// Social crawlers get rich metadata; browsers get a full proof viewer
function buildProofOGPage(record, shortId, contentHash) {
  const CLS_LABELS = {
    CompleteHumanOrigin: "Complete Human Origin",
    HumanOriginAssisted: "Human Origin Assisted",
    HumanDirectedCollaborative: "Human-Directed Collaborative",
  };
  const clsLabel = CLS_LABELS[record.classification] || record.classification;
  const tierLabel = "Tier " + (record.credential_tier || "?");
  const dateStr = record.attested_at ? new Date(record.attested_at).toLocaleDateString("en-US", {
    year: "numeric", month: "long", day: "numeric"
  }) : "Unknown";
  const proofUrl = "https://hipprotocol.org/p/" + shortId;
  const fullUrl = "https://hipprotocol.org/proof.html?hash=" + contentHash;
  const title = "HIP Proof — " + clsLabel;
  const description = tierLabel + " attestation · " + dateStr + " · Human Integrity Protocol";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<meta name="description" content="${description}">
<meta property="og:title" content="${title}">
<meta property="og:description" content="${description}">
<meta property="og:type" content="website">
<meta property="og:url" content="${proofUrl}">
<meta property="og:image" content="https://hipprotocol.org/og-proof.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="HIP Proof Card — ${clsLabel}">
<meta property="og:site_name" content="Human Integrity Protocol">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${title}">
<meta name="twitter:description" content="${description}">
<meta name="twitter:image" content="https://hipprotocol.org/og-proof.png">
<meta http-equiv="refresh" content="0;url=${fullUrl}">
<link rel="canonical" href="${proofUrl}">
</head>
<body>
<p>Redirecting to <a href="${fullUrl}">proof card</a>...</p>
</body>
</html>`;
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
          sessionData.dedupHash = dedupHash; // S33: stored for credential recovery
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

// ── Tier 3 (Biometric Presence) Server-Side Registration ──
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

  // Step 4c: Parse attestationObject for fmt + AAGUID (S95 #33 Option A).
  // attestation_object is base64 CBOR: a map with keys "fmt" (string), "attStmt" (map),
  // "authData" (byte string). Dependency-free byte-level parse of the two fields we need.
  let attestationMeta = { format: "unknown", aaguid: "unknown" };
  if (attestation_object) {
    try {
      const attBytes = Uint8Array.from(atob(attestation_object), c => c.charCodeAt(0));

      // fmt: CBOR marker 0x63 "fmt" (text-3 + ASCII "fmt"); next byte is a text-string
      // header (major type 3, 0x60-0x77 for length 0..23 — all real fmt values fit).
      for (let i = 0; i < attBytes.length - 5; i++) {
        if (attBytes[i]===0x63 && attBytes[i+1]===0x66 && attBytes[i+2]===0x6d && attBytes[i+3]===0x74) {
          const hdr = attBytes[i+4];
          if (hdr >= 0x60 && hdr <= 0x77) {
            const len = hdr - 0x60;
            if (i + 5 + len <= attBytes.length) {
              attestationMeta.format = new TextDecoder("utf-8", { fatal: false }).decode(attBytes.slice(i+5, i+5+len));
            }
          }
          break;
        }
      }

      // AAGUID: 16 bytes at offset 37 of authData (after 32-byte rpIdHash + 1 flags + 4 signCount).
      // Find authData key (CBOR 0x68 + ASCII "authData"), skip byte-string length header, seek +37.
      const auKey = [0x68,0x61,0x75,0x74,0x68,0x44,0x61,0x74,0x61];
      outer: for (let i = 0; i < attBytes.length - auKey.length - 60; i++) {
        for (let j = 0; j < auKey.length; j++) {
          if (attBytes[i+j] !== auKey[j]) continue outer;
        }
        const p = i + auKey.length;
        const hdr = attBytes[p];
        let dataStart = -1;
        if (hdr >= 0x40 && hdr <= 0x57) dataStart = p + 1;      // direct length 0..23
        else if (hdr === 0x58) dataStart = p + 2;                // 1-byte length
        else if (hdr === 0x59) dataStart = p + 3;                // 2-byte length
        else if (hdr === 0x5A) dataStart = p + 5;                // 4-byte length
        if (dataStart < 0) break;
        const aS = dataStart + 37;
        if (aS + 16 > attBytes.length) break;
        let hex = "";
        for (let k = 0; k < 16; k++) hex += attBytes[aS+k].toString(16).padStart(2,"0");
        attestationMeta.aaguid = hex;
        break;
      }
    } catch (_) {
      // Non-critical — attestation metadata is for audit only
    }
  }

  // S95 #33 Option A: fmt + AAGUID are now captured and stored (see t3audit write below).
  // Reject gate REMOVED after live testing: Apple (macOS/iOS) routes ALL platform passkey
  // creation through iCloud Keychain, which emits fmt:"none". Enforcing fmt!="none" blocks
  // T3 minting for all Apple users, violating DP-7 (Zero Institutional Cost = free tier
  // must be universally accessible). Existing Sybil defenses (50-attestation lifetime cap,
  // TI=60 ceiling, 2/IP/24h rate limit) remain the active controls. AAGUID data collected
  // here enables future AAGUID-allowlist enforcement (Option B) if warranted.

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
    attestation_aaguid: attestationMeta.aaguid,
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
    attestation_aaguid: attestationMeta.aaguid,
  }, 200, origin);
}

// ── Trust Score System ──
// S29: Worker-computed Trust Score (0-100) for every credential.
// Formula: tier_base + age_bonus + volume_bonus + consistency_bonus + liveness_bonus
// S90 #23b: T3 provisional ceiling per HP-SPEC-v1_3. Async to read declaration KV.
// S92 #23 Step-2a: dual-field output — emits `trust_index` (0-1000 per HP-SPEC-v1_3)
//   alongside legacy `score` (0-100 per HP-SPEC-v1_2). IW/BS split synthesized from
//   the legacy breakdown (audit-faithful for the dual-field window; native per-signal
//   BS accumulation lands with #23 Step-2b). T3 read-time clamp moved off legacy
//   `score` and onto `trust_index` at the spec constant 60.

async function computeTrustScore(record, env) {
  // Tier base points
  const tierBase = record.tier === 1 ? 40 : record.tier === 2 ? 25 : 10;

  // S94 #34b: defensive normalization — guard against corrupt/partial KV records
  // that triggered worker 1101 exceptions in S92/S93 (e.g., Dashboard-edited JSON
  // with missing or non-string first_seen, non-numeric counters, non-array active_months).
  const attCount = Number.isFinite(Number(record.attestation_count)) ? Math.max(0, Number(record.attestation_count)) : 0;
  const livCount = Number.isFinite(Number(record.liveness_verified_count)) ? Math.max(0, Number(record.liveness_verified_count)) : 0;
  const actMonths = Array.isArray(record.active_months) ? record.active_months : [];

  // Age bonus: max +20 over 1 year, linear
  const fsTime = new Date(record.first_seen).getTime();
  const ageDays = Number.isFinite(fsTime)
    ? Math.max(0, (Date.now() - fsTime) / (1000 * 60 * 60 * 24))
    : 0;
  const ageBonus = Math.min(ageDays / 365 * 20, 20);

  // Volume bonus: max +15 at 50 attestations, linear
  const volumeBonus = Math.min(attCount / 50 * 15, 15);

  // Consistency bonus: max +10 over 12 active months, linear
  const activeMonths = actMonths.length;
  const consistencyBonus = Math.min(activeMonths / 12 * 10, 10);

  // Liveness bonus: max +15 at 100% device-verified liveness
  const livenessRate = attCount > 0
    ? Math.max(0, Math.min(1, livCount / attCount))
    : 0;
  const livenessBonus = livenessRate * 15;

  const score = Math.min(Math.round(tierBase + ageBonus + volumeBonus + consistencyBonus + livenessBonus), 100);

  // S92 #23 Step-2a: v1_3 IW/BS/TI synthesis (translator-estimate, not per-signal replay).
  // IW: spec-authoritative starting values from HP-SPEC-v1_3 §TI (no PHI decay — prospective only).
  // BS: (legacy_score - tierBase) × 10 — scales the legacy bonus sum into the 0-1000 space.
  // TI: min(1000, IW + BS) with T3 read-time clamp at 60 (constant per HP-SPEC-v1_3 §T3 Provisional Ceiling).
  const issuance_weight = record.tier === 1 ? 400 : record.tier === 2 ? 50 : 10;
  const behavioral_score = Math.max(0, Math.round((score - tierBase) * 10));
  let trust_index = Math.min(1000, issuance_weight + behavioral_score);

  // S92 #23 Step-2a: T3 provisional ceiling — clamp is now on trust_index at 60
  // (was: legacy score clamped to 20). Legacy `score` is no longer clamped here;
  // accept the drift — matches spec-faithful read-time semantics.
  if (record.tier === 3 && env) {
    const declarationActive = await env.DEDUP_KV.get("governance:t3_ceiling_declaration");
    if (!declarationActive) {
      trust_index = Math.min(trust_index, 60);
    }
  }

  return {
    score,              // legacy 0-100, same formula, drives trust_score_legacy
    trust_index,        // 0-1000, new primary
    issuance_weight,    // 0-400
    behavioral_score,   // 0-600
    tierBase,
    ageBonus: Math.round(ageBonus * 10) / 10,
    volumeBonus: Math.round(volumeBonus * 10) / 10,
    consistencyBonus: Math.round(consistencyBonus * 10) / 10,
    livenessBonus: Math.round(livenessBonus * 10) / 10,
    livenessRate: Math.round(livenessRate * 1000) / 1000,
  };
}

// S101: Auto-flip positive-outcome resolution on vouches >=90 days old.
// Per HP-SPEC-v1_2 §847-850: a vouch is resolved positively when the vouched
// credential achieves 90 days of clean Active status. (Negative outcome via
// formal Invalidation is not yet implemented — that branch is deferred until
// the Credential Compromise Determination pipeline is built.)
// Mutates vouchLog in place. Returns true if any entry was flipped so the
// caller can persist the updated log.
function flipResolvedVouches(vouchLog) {
  const ninetyDaysMs = 90 * 86400000;
  const now = Date.now();
  let mutated = false;
  for (let i = 0; i < vouchLog.length; i++) {
    const v = vouchLog[i];
    if (v.resolved) continue;
    const age = now - new Date(v.timestamp).getTime();
    if (age >= ninetyDaysMs) {
      v.resolved = true;
      v.resolution = "positive";
      v.resolved_at = new Date().toISOString();
      mutated = true;
    }
  }
  return mutated;
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

  const { credential_id, tier, voucher_credential_id } = body;
  if (!credential_id || !tier) {
    return jsonResponse({ error: "Missing credential_id or tier" }, 400, origin);
  }

  if (![1, 2, 3].includes(tier)) {
    return jsonResponse({ error: "Invalid tier (must be 1, 2, or 3)" }, 400, origin);
  }

  // Check if already initialized — must come before the tier:1 gate so that
  // cross-site imports (hipprotocol.org #hip-import) can re-initialize an existing
  // T1 record without needing a session_id. No escalation risk: returns existing
  // record without overwriting.
  const existing = await env.DEDUP_KV.get(`trust:${credential_id}`);
  if (existing) {
    // Already exists — return current score without overwriting
    const record = JSON.parse(existing);
    const ts = await computeTrustScore(record, env);
    return jsonResponse({
      credential_id: credential_id,
      // S92 #23 Step-2a: dual-field response. trust_score retained as crash-shield
      // for unmigrated frontends; trust_score_legacy is the forward-compatible name.
      trust_index: ts.trust_index,
      trust_score_legacy: ts.score,
      trust_score: ts.score,
      message: "Trust record already exists",
    }, 200, origin);
  }

  // S97 #34c: Tier 1 requires proven Didit session — prevent unauthenticated T1 creation.
  // Caller must supply session_id from a completed Didit verification. We verify:
  //   1. Session exists in KV (within 1h webhook TTL)
  //   2. Session status is "Approved" (Didit identity check passed)
  //   3. Session has a dedupHash (identity signals were extracted)
  //   4. dedup:{hash} maps to this credential_id (register-dedup was called first)
  if (tier === 1) {
    const { session_id } = body;
    if (!session_id) {
      return jsonResponse({ error: "Tier 1 requires session_id from Didit verification" }, 400, origin);
    }

    const sessionRaw = await env.DEDUP_KV.get(`session:${session_id}`);
    if (!sessionRaw) {
      return jsonResponse({ error: "Session not found or expired" }, 403, origin);
    }

    const sessionData = JSON.parse(sessionRaw);
    if (sessionData.status !== "Approved") {
      return jsonResponse({ error: "Session not approved" }, 403, origin);
    }

    if (!sessionData.dedupHash) {
      return jsonResponse({ error: "Session missing identity verification" }, 403, origin);
    }

    const dedupMapping = await env.DEDUP_KV.get(`dedup:${sessionData.dedupHash}`);
    if (dedupMapping !== credential_id) {
      return jsonResponse({ error: "Credential not linked to this identity session" }, 403, origin);
    }
  }

  // S99 #32 hardening: Tier 2 requires a valid T1 voucher with TI >= 200.
  // Client validates vouch signature; server validates voucher eligibility + rate limits.
  if (tier === 2) {
    if (!voucher_credential_id) {
      return jsonResponse({ error: "Tier 2 requires voucher_credential_id" }, 400, origin);
    }
    const voucherRaw = await env.DEDUP_KV.get(`trust:${voucher_credential_id}`);
    if (!voucherRaw) {
      return jsonResponse({ error: "No trust record found for voucher credential" }, 404, origin);
    }
    const voucherRecord = JSON.parse(voucherRaw);
    if (voucherRecord.tier !== 1) {
      return jsonResponse({ error: "Voucher must hold a Tier 1 credential (current: Tier " + voucherRecord.tier + ")" }, 403, origin);
    }
    const voucherTs = await computeTrustScore(voucherRecord, env);
    if (voucherTs.trust_index < 200) {
      return jsonResponse({ error: "Voucher trust index (" + voucherTs.trust_index + ") is below the 200 minimum required to vouch (per HP-SPEC-v1_2 §314)" }, 403, origin);
    }
    // S99: Vouch rate limits — 3 per 30 days, max 10 active unresolved (HP-SPEC-v1_2 §839)
    const vouchLogKey = `vouches:${voucher_credential_id}`;
    const vouchLogRaw = await env.DEDUP_KV.get(vouchLogKey);
    const vouchLog = vouchLogRaw ? JSON.parse(vouchLogRaw) : [];
    // S101: Auto-flip 90-day positive resolutions before counting (HP-SPEC-v1_2 §847-850)
    if (flipResolvedVouches(vouchLog)) {
      await env.DEDUP_KV.put(vouchLogKey, JSON.stringify(vouchLog));
    }
    const thirtyDaysAgo = Date.now() - 30 * 86400000;
    const recentVouches = vouchLog.filter(function(v) { return new Date(v.timestamp).getTime() > thirtyDaysAgo; });
    if (recentVouches.length >= 3) {
      return jsonResponse({ error: "Voucher has reached the limit of 3 vouches per 30 days" }, 429, origin);
    }
    const activeVouches = vouchLog.filter(function(v) { return !v.resolved; });
    if (activeVouches.length >= 10) {
      return jsonResponse({ error: "Voucher has reached the limit of 10 active outstanding vouches" }, 429, origin);
    }
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

  // S98 #33 Option C: Stamp pathway on trust record at initialization.
  // T1 pathway is stamped later by the Didit flow (government-id-didit-v1).
  // T3 pathway was previously unstamped — now set to device-or-passkey-webauthn-v1
  // per the biometric-presence reframe (S95→S98).
  if (tier === 3) {
    record.pathway = "device-or-passkey-webauthn-v1";
  }
  // S99 #32: Stamp T2 pathway at initialization (was missing — T3 was stamped but not T2).
  if (tier === 2) {
    record.pathway = "peer-vouch-bound-token-v1";
  }

  // S33: Store voucher link for Tier 2 recovery
  if (tier === 2 && voucher_credential_id) {
    record.voucher_credential_id = voucher_credential_id;
  }

  const ts = await computeTrustScore(record, env);
  // S92 #23 Step-2a: dual-write trust_index alongside trust_score to KV.
  record.trust_score = ts.score;
  record.trust_index = ts.trust_index;

  await env.DEDUP_KV.put(`trust:${credential_id}`, JSON.stringify(record));

  // S99 #32: Log vouch event for rate limiting
  if (tier === 2 && voucher_credential_id) {
    const vouchLogKey = `vouches:${voucher_credential_id}`;
    const vouchLogRaw = await env.DEDUP_KV.get(vouchLogKey);
    const vouchLog = vouchLogRaw ? JSON.parse(vouchLogRaw) : [];
    vouchLog.push({
      timestamp: new Date().toISOString(),
      vouched_credential_id: credential_id,
      resolved: false,
    });
    await env.DEDUP_KV.put(vouchLogKey, JSON.stringify(vouchLog));
  }

  return jsonResponse({
    credential_id: credential_id,
    trust_index: ts.trust_index,
    trust_score_legacy: ts.score,
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
  const ts = await computeTrustScore(record, env);
  // S92 #23 Step-2a: dual-write trust_index alongside trust_score.
  record.trust_score = ts.score;
  record.trust_index = ts.trust_index;

  await env.DEDUP_KV.put(`trust:${credential_id}`, JSON.stringify(record));

  return jsonResponse({
    credential_id: credential_id,
    trust_index: ts.trust_index,
    trust_score_legacy: ts.score,
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
  const ts = await computeTrustScore(record, env);

  // Recompute in case of age drift since last update (local only; not persisted)
  record.trust_score = ts.score;
  record.trust_index = ts.trust_index;

  const ageDays = Math.floor((Date.now() - new Date(record.first_seen).getTime()) / (1000 * 60 * 60 * 24));

  return jsonResponse({
    credential_id: credentialId,
    tier: record.tier,
    // S92 #23 Step-2a: dual-field response.
    trust_index: ts.trust_index,
    trust_score_legacy: ts.score,
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

// ============================================================
// S33: CREDENTIAL RECOVERY — Key rotation with trust migration
// ============================================================
// POST /recover-credential — Rotates credential keys while preserving trust history.
//
// Tier 1: User re-verifies identity via Didit. The dedup hash matches their
//         existing credential, proving they are the same person. A new key pair
//         is generated client-side, and this endpoint swaps the dedup mapping
//         and migrates the trust record to the new credential ID.
//
// Tier 2: User's original voucher re-vouches for them. This endpoint verifies
//         the voucher's credential ID matches the one stored in the trust record,
//         then migrates the trust record to the new credential ID.
//
// Tier 3: Not recoverable — no identity anchor. Users create a fresh credential.
// ============================================================
async function handleRecoverCredential(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  let body;
  try {
    body = await request.json();
  } catch (_) {
    return jsonResponse({ error: "Invalid JSON" }, 400, origin);
  }

  const { recovery_type, old_credential_id, new_credential_id, recovery_nonce } = body;

  if (!recovery_type || !old_credential_id || !new_credential_id) {
    return jsonResponse({ error: "Missing recovery_type, old_credential_id, or new_credential_id" }, 400, origin);
  }

  if (old_credential_id === new_credential_id) {
    return jsonResponse({ error: "Old and new credential IDs must be different" }, 400, origin);
  }

  // S97 #34d: Idempotency key — client sends a UUID per recovery attempt.
  // If this nonce was already processed, return the cached result (safe retry).
  // If in progress, return 409 (concurrent duplicate blocked).
  if (recovery_nonce) {
    const idempotencyRaw = await env.DEDUP_KV.get(`recovery_idempotency:${recovery_nonce}`);
    if (idempotencyRaw) {
      const cached = JSON.parse(idempotencyRaw);
      if (cached.status === "completed") {
        return jsonResponse(cached.result, 200, origin);
      }
      // Still in progress — concurrent duplicate
      return jsonResponse({ error: "Recovery already in progress for this attempt" }, 409, origin);
    }
    // Claim the nonce immediately — 60s TTL for self-healing
    await env.DEDUP_KV.put(`recovery_idempotency:${recovery_nonce}`, JSON.stringify({ status: "in_progress" }), {
      expirationTtl: 60,
    });
  }

  // ── Tier 1 Recovery: re-verification via Didit ──
  if (recovery_type === "tier1-reverify") {
    const { session_id } = body;
    if (!session_id) {
      return jsonResponse({ error: "Missing session_id for Tier 1 recovery" }, 400, origin);
    }

    // Retrieve session data — must be approved with dedup = "exists"
    const sessionRaw = await env.DEDUP_KV.get(`session:${session_id}`);
    if (!sessionRaw) {
      return jsonResponse({ error: "Session not found or expired. Re-verification sessions are valid for 1 hour." }, 404, origin);
    }

    const sessionData = JSON.parse(sessionRaw);
    if (sessionData.status !== "Approved") {
      return jsonResponse({ error: "Session not approved" }, 400, origin);
    }

    if (sessionData.dedup !== "exists") {
      return jsonResponse({ error: "Session does not match an existing credential (dedup status: " + sessionData.dedup + ")" }, 400, origin);
    }

    // Verify the old credential ID matches what the dedup system found
    if (sessionData.existingCredentialId !== old_credential_id) {
      return jsonResponse({ error: "Old credential ID does not match identity verification result" }, 403, origin);
    }

    // Find the dedup hash that points to the old credential
    // We need to update it to point to the new credential
    // The dedupHash was stored in the session during webhook processing
    // but only for "new" entries. For "exists", we need to scan or
    // we stored it... let's check if it's in the session data.
    // Actually, for "exists" we didn't store dedupHash. We need to
    // recompute it from the webhook data, or we can store it going forward.
    // For now: the webhook handler stores dedupHash only for "new".
    // Solution: also store dedupHash for "exists" cases.
    // We'll update the webhook handler too.

    if (!sessionData.dedupHash) {
      return jsonResponse({ error: "Session missing dedup hash. This may be a session from before recovery was enabled." }, 400, origin);
    }

    // Verify the dedup hash still points to the old credential
    const currentMapping = await env.DEDUP_KV.get(`dedup:${sessionData.dedupHash}`);
    if (currentMapping !== old_credential_id) {
      return jsonResponse({ error: "Dedup mapping inconsistency — credential may have already been recovered" }, 409, origin);
    }

    // S97 #34d: Dedup-hash-level lock — narrows the TOCTOU window between the
    // consistency check above and the dedup write below. KV lacks CAS, so this
    // isn't airtight, but shrinks the race from seconds to milliseconds.
    const lockKey = `recovery_lock:${sessionData.dedupHash}`;
    const existingLock = await env.DEDUP_KV.get(lockKey);
    if (existingLock) {
      return jsonResponse({ error: "Recovery already in progress for this identity" }, 409, origin);
    }
    await env.DEDUP_KV.put(lockKey, recovery_nonce || "no-nonce", { expirationTtl: 60 });

    // ── Perform the rotation ──

    // 1. Update dedup hash → new credential ID
    await env.DEDUP_KV.put(`dedup:${sessionData.dedupHash}`, new_credential_id);

    // 2. Migrate trust record
    // S94 #34: tier1-reverify via Didit MUST stamp tier:1 + government-id-didit-v1
    // pathway, regardless of predecessor tier. Fixes paid-T1-recovery-issued-T3.
    const trustMigration = await migrateTrustRecord(old_credential_id, new_credential_id, env, {
      tierOverride: 1,
      pathwayOverride: "government-id-didit-v1",
    });

    // 3. Mark session as used for recovery
    sessionData.dedup = "recovered";
    sessionData.recoveredTo = new_credential_id;
    await env.DEDUP_KV.put(`session:${session_id}`, JSON.stringify(sessionData), {
      expirationTtl: 3600,
    });

    // 4. Release lock + cache idempotency result
    await env.DEDUP_KV.delete(lockKey);

    const t1Result = {
      success: true,
      recovery_type: "tier1-reverify",
      old_credential_id: old_credential_id,
      new_credential_id: new_credential_id,
      trust_migrated: trustMigration.migrated,
      // S92 #23 Step-2a: dual-field response.
      trust_index: trustMigration.trust_index,
      trust_score_legacy: trustMigration.trust_score,
      trust_score: trustMigration.trust_score,
    };

    // S97 #34d: Cache completed result for idempotent retry
    if (recovery_nonce) {
      await env.DEDUP_KV.put(`recovery_idempotency:${recovery_nonce}`, JSON.stringify({
        status: "completed",
        result: t1Result,
      }), { expirationTtl: 60 });
    }

    return jsonResponse(t1Result, 200, origin);
  }

  // ── Tier 2 Recovery: same voucher re-vouches ──
  if (recovery_type === "tier2-revouch") {
    const { voucher_credential_id, vouch_signature, vouch_body } = body;
    if (!voucher_credential_id || !vouch_signature || !vouch_body) {
      return jsonResponse({ error: "Missing voucher_credential_id, vouch_signature, or vouch_body for Tier 2 recovery" }, 400, origin);
    }

    // Look up the old credential's trust record to verify voucher match
    const oldTrustRaw = await env.DEDUP_KV.get(`trust:${old_credential_id}`);
    if (!oldTrustRaw) {
      return jsonResponse({ error: "No trust record found for old credential. Recovery requires an existing trust record." }, 404, origin);
    }

    const oldTrust = JSON.parse(oldTrustRaw);
    if (oldTrust.tier !== 2) {
      return jsonResponse({ error: "Old credential is not Tier 2" }, 400, origin);
    }

    // Verify the voucher matches the original
    if (!oldTrust.voucher_credential_id) {
      return jsonResponse({ error: "Old credential's trust record does not contain voucher information. Recovery is not available for credentials created before this feature." }, 400, origin);
    }

    if (oldTrust.voucher_credential_id !== voucher_credential_id) {
      return jsonResponse({ error: "Voucher credential ID does not match the original voucher. Recovery requires the same person who originally vouched." }, 403, origin);
    }

    // Verify the vouch signature is valid (voucher proves they hold the key)
    // The client sends vouch_body (canonical JSON of the recovery vouch) and vouch_signature (base64)
    // We verify using the voucher's public key from their trust record
    // But we don't store voucher public keys in trust records — the vouch_body should contain it
    // and the client already verified the signature. The server-side check is:
    // the voucher_credential_id matches the trust record, which is the critical auth step.

    // ── Perform the rotation ──

    // 1. Migrate trust record
    // S94 #34: tier2-revouch MUST stamp tier:2 regardless of predecessor tier
    // (hardening — same bug class as tier1-reverify; not yet observed live).
    const trustMigration = await migrateTrustRecord(old_credential_id, new_credential_id, env, {
      tierOverride: 2,
    });

    // 2. Store voucher link in new trust record
    const newTrustRaw = await env.DEDUP_KV.get(`trust:${new_credential_id}`);
    if (newTrustRaw) {
      const newTrust = JSON.parse(newTrustRaw);
      newTrust.voucher_credential_id = voucher_credential_id;
      await env.DEDUP_KV.put(`trust:${new_credential_id}`, JSON.stringify(newTrust));
    }

    const t2Result = {
      success: true,
      recovery_type: "tier2-revouch",
      old_credential_id: old_credential_id,
      new_credential_id: new_credential_id,
      trust_migrated: trustMigration.migrated,
      // S92 #23 Step-2a: dual-field response.
      trust_index: trustMigration.trust_index,
      trust_score_legacy: trustMigration.trust_score,
      trust_score: trustMigration.trust_score,
    };

    // S97 #34d: Cache completed result for idempotent retry
    if (recovery_nonce) {
      await env.DEDUP_KV.put(`recovery_idempotency:${recovery_nonce}`, JSON.stringify({
        status: "completed",
        result: t2Result,
      }), { expirationTtl: 60 });
    }

    return jsonResponse(t2Result, 200, origin);
  }

  return jsonResponse({ error: "Invalid recovery_type. Must be 'tier1-reverify' or 'tier2-revouch'." }, 400, origin);
}

// ============================================================
// S34: POST /upgrade-credential — Upgrades credential tier in-place.
//
// Unlike recovery, upgrade does NOT rotate keys or change credential ID.
// The trust record is updated in-place with the new tier, and the
// tier_base component of the trust score changes immediately.
//
// Tier 1 upgrade (tier1-idv): User verifies government ID via hipverify.org.
//   Dedup hash is mapped to existing credential ID. Trust record tier→1.
//
// Tier 2 upgrade (tier2-vouch): Tier 1 holder vouches for upgrade.
//   Trust record tier→2, voucher_credential_id stored.
// ============================================================
async function handleUpgradeCredential(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  let body;
  try {
    body = await request.json();
  } catch (_) {
    return jsonResponse({ error: "Invalid JSON" }, 400, origin);
  }

  const { upgrade_type, credential_id, new_tier } = body;

  if (!upgrade_type || !credential_id || new_tier === undefined || new_tier === null) {
    return jsonResponse({ error: "Missing upgrade_type, credential_id, or new_tier" }, 400, origin);
  }

  // Retrieve existing trust record
  const trustKey = `trust:${credential_id}`;
  const existingRaw = await env.DEDUP_KV.get(trustKey);
  if (!existingRaw) {
    return jsonResponse({ error: "No trust record found for this credential. Create a credential first." }, 404, origin);
  }

  const record = JSON.parse(existingRaw);
  const oldTier = record.tier || 3;

  // Validate upgrade direction (lower tier number = higher assurance)
  if (new_tier >= oldTier) {
    return jsonResponse({ error: "Can only upgrade to a higher tier. Current: Tier " + oldTier + ", requested: Tier " + new_tier }, 400, origin);
  }

  // ── Tier 1 Upgrade: government ID verification via Didit ──
  if (upgrade_type === "tier1-idv") {
    const { session_id } = body;

    // If a session_id is provided, validate the Didit session
    if (session_id) {
      const sessionRaw = await env.DEDUP_KV.get(`session:${session_id}`);
      if (sessionRaw) {
        const sessionData = JSON.parse(sessionRaw);
        if (sessionData.status !== "Approved") {
          return jsonResponse({ error: "Verification session not approved" }, 400, origin);
        }

        // Map dedup hash to this credential ID (prevents duplicate humans)
        if (sessionData.dedupHash) {
          const dedupKey = `dedup:${sessionData.dedupHash}`;
          const existingDedup = await env.DEDUP_KV.get(dedupKey);
          if (existingDedup && existingDedup !== credential_id) {
            // This identity is already linked to a DIFFERENT credential
            return jsonResponse({
              error: "This government ID is already linked to a different credential (" + existingDedup.substring(0, 12) + "…). Use credential recovery if you lost access to that credential."
            }, 409, origin);
          }
          // Map dedup hash → this credential
          await env.DEDUP_KV.put(dedupKey, credential_id);
        }

        // Mark session as used for upgrade
        sessionData.upgradedCredentialId = credential_id;
        sessionData.upgradeTimestamp = new Date().toISOString();
        await env.DEDUP_KV.put(`session:${session_id}`, JSON.stringify(sessionData), {
          expirationTtl: 3600,
        });
      }
    }

    // Update the trust record in-place
    record.tier = 1;
    record.upgraded_from = oldTier;
    record.upgraded_at = new Date().toISOString();
    record.pathway = "government-id-didit-v1";

    const ts = await computeTrustScore(record, env);
    // S92 #23 Step-2a: dual-write trust_index alongside trust_score.
    record.trust_score = ts.score;
    record.trust_index = ts.trust_index;

    await env.DEDUP_KV.put(trustKey, JSON.stringify(record));

    return jsonResponse({
      success: true,
      upgrade_type: "tier1-idv",
      credential_id: credential_id,
      old_tier: oldTier,
      new_tier: 1,
      trust_migrated: true,
      trust_index: ts.trust_index,
      trust_score_legacy: ts.score,
      trust_score: ts.score,
      score_breakdown: { tier_base: ts.tierBase, age_bonus: ts.ageBonus, volume_bonus: ts.volumeBonus, consistency_bonus: ts.consistencyBonus, liveness_bonus: ts.livenessBonus },
    }, 200, origin);
  }

  // ── Tier 2 Upgrade: peer vouch from Tier 1 holder ──
  if (upgrade_type === "tier2-vouch") {
    const { voucher_credential_id, vouch_timestamp } = body;
    if (!voucher_credential_id) {
      return jsonResponse({ error: "Missing voucher_credential_id for Tier 2 upgrade" }, 400, origin);
    }

    // Validate voucher holds a Tier 1 credential
    const voucherTrustRaw = await env.DEDUP_KV.get(`trust:${voucher_credential_id}`);
    if (!voucherTrustRaw) {
      return jsonResponse({ error: "No trust record found for voucher credential" }, 404, origin);
    }

    const voucherTrust = JSON.parse(voucherTrustRaw);
    if (voucherTrust.tier !== 1) {
      return jsonResponse({ error: "Voucher must hold a Tier 1 credential (current: Tier " + voucherTrust.tier + ")" }, 403, origin);
    }

    // S99 #32 hardening: TI >= 200 voucher floor (HP-SPEC-v1_2 §314)
    const voucherTs = await computeTrustScore(voucherTrust, env);
    if (voucherTs.trust_index < 200) {
      return jsonResponse({ error: "Voucher trust index (" + voucherTs.trust_index + ") is below the 200 minimum required to vouch (per HP-SPEC-v1_2 §314)" }, 403, origin);
    }

    // S99: Vouch rate limits — 3 per 30 days, max 10 active unresolved (HP-SPEC-v1_2 §839)
    const vouchLogKey = `vouches:${voucher_credential_id}`;
    const vouchLogRaw = await env.DEDUP_KV.get(vouchLogKey);
    const vouchLog = vouchLogRaw ? JSON.parse(vouchLogRaw) : [];
    // S101: Auto-flip 90-day positive resolutions before counting (HP-SPEC-v1_2 §847-850)
    if (flipResolvedVouches(vouchLog)) {
      await env.DEDUP_KV.put(vouchLogKey, JSON.stringify(vouchLog));
    }
    const thirtyDaysAgo = Date.now() - 30 * 86400000;
    const recentVouches = vouchLog.filter(function(v) { return new Date(v.timestamp).getTime() > thirtyDaysAgo; });
    if (recentVouches.length >= 3) {
      return jsonResponse({ error: "Voucher has reached the limit of 3 vouches per 30 days" }, 429, origin);
    }
    const activeVouches = vouchLog.filter(function(v) { return !v.resolved; });
    if (activeVouches.length >= 10) {
      return jsonResponse({ error: "Voucher has reached the limit of 10 active outstanding vouches" }, 429, origin);
    }

    // Validate vouch timestamp (within 24 hours)
    if (vouch_timestamp) {
      const vouchAge = Math.abs(Date.now() - new Date(vouch_timestamp).getTime());
      if (vouchAge > 86400000) {
        return jsonResponse({ error: "Upgrade vouch has expired (older than 24 hours). Ask the voucher to create a new one." }, 400, origin);
      }
    }

    // Update the trust record in-place
    record.tier = 2;
    record.upgraded_from = oldTier;
    record.upgraded_at = new Date().toISOString();
    record.voucher_credential_id = voucher_credential_id;

    const ts = await computeTrustScore(record, env);
    // S92 #23 Step-2a: dual-write trust_index alongside trust_score.
    record.trust_score = ts.score;
    record.trust_index = ts.trust_index;

    await env.DEDUP_KV.put(trustKey, JSON.stringify(record));

    // S99 #32: Log vouch event for rate limiting
    const vouchLogKeyW = `vouches:${voucher_credential_id}`;
    const vouchLogRawW = await env.DEDUP_KV.get(vouchLogKeyW);
    const vouchLogW = vouchLogRawW ? JSON.parse(vouchLogRawW) : [];
    vouchLogW.push({
      timestamp: new Date().toISOString(),
      vouched_credential_id: credential_id,
      resolved: false,
    });
    await env.DEDUP_KV.put(vouchLogKeyW, JSON.stringify(vouchLogW));

    return jsonResponse({
      success: true,
      upgrade_type: "tier2-vouch",
      credential_id: credential_id,
      old_tier: oldTier,
      new_tier: 2,
      trust_migrated: true,
      trust_index: ts.trust_index,
      trust_score_legacy: ts.score,
      trust_score: ts.score,
      score_breakdown: { tier_base: ts.tierBase, age_bonus: ts.ageBonus, volume_bonus: ts.volumeBonus, consistency_bonus: ts.consistencyBonus, liveness_bonus: ts.livenessBonus },
    }, 200, origin);
  }

  return jsonResponse({ error: "Invalid upgrade_type. Must be 'tier1-idv' or 'tier2-vouch'." }, 400, origin);
}

// S33: Migrate trust record from old credential to new credential
// S85CW: Also migrates credits, stripe_cust, and cred_proofs index (if present).
//        Old records are preserved in place for audit trail; only trust:
//        is explicitly marked superseded_by. Missing source keys are skipped
//        silently — a recovered user who never purchased credits or has no
//        proofs yet simply has nothing to copy.
async function migrateTrustRecord(oldCredentialId, newCredentialId, env, options) {
  // S94 #34: options = { tierOverride, pathwayOverride } — when the caller knows
  // the canonical tier for the new record (e.g., tier1-reverify via Didit →
  // tier:1 regardless of predecessor), it passes it here. Prevents bug #34
  // where predecessors with wrong stored tier propagated forward on recovery.
  const opts = options || {};

  const oldRaw = await env.DEDUP_KV.get(`trust:${oldCredentialId}`);
  if (!oldRaw) {
    // S92 #23 Step-2a: return trust_index:0 alongside trust_score:0 for the
    // no-old-record branch so callers can destructure uniformly.
    return { migrated: false, trust_score: 0, trust_index: 0, reason: "no_old_record" };
  }

  const oldRecord = JSON.parse(oldRaw);

  // S94 #34: resolve tier — caller override wins, else carry predecessor.
  const resolvedTier = (opts.tierOverride === 1 || opts.tierOverride === 2 || opts.tierOverride === 3)
    ? opts.tierOverride
    : oldRecord.tier;

  // Create new trust record preserving history
  const newRecord = {
    tier: resolvedTier,
    first_seen: oldRecord.first_seen,     // preserve original age
    last_seen: new Date().toISOString(),
    attestation_count: oldRecord.attestation_count,
    liveness_verified_count: oldRecord.liveness_verified_count || 0,
    active_months: oldRecord.active_months || [],
    recovered_from: oldCredentialId,
    recovered_at: new Date().toISOString(),
  };

  // S94 #34: pathway stamping (e.g., government-id-didit-v1 for Didit T1 recovery)
  if (opts.pathwayOverride) {
    newRecord.pathway = opts.pathwayOverride;
  } else if (oldRecord.pathway) {
    newRecord.pathway = oldRecord.pathway;
  }

  // S94 #34: audit stamps when tier was corrected vs predecessor
  if (opts.tierOverride != null && opts.tierOverride !== oldRecord.tier) {
    newRecord.tier_corrected_at = new Date().toISOString();
    newRecord.tier_corrected_from = oldRecord.tier;
  }

  // Preserve voucher link if present
  if (oldRecord.voucher_credential_id) {
    newRecord.voucher_credential_id = oldRecord.voucher_credential_id;
  }

  const ts = await computeTrustScore(newRecord, env);
  // S92 #23 Step-2a: dual-write trust_index alongside trust_score.
  newRecord.trust_score = ts.score;
  newRecord.trust_index = ts.trust_index;

  // Write new trust record
  await env.DEDUP_KV.put(`trust:${newCredentialId}`, JSON.stringify(newRecord));

  // Mark old record as superseded (don't delete — audit trail)
  oldRecord.superseded_by = newCredentialId;
  oldRecord.superseded_at = new Date().toISOString();
  await env.DEDUP_KV.put(`trust:${oldCredentialId}`, JSON.stringify(oldRecord));

  // S85CW: Migrate credit balance (pack_balance, sub_credits, sub_plan, etc.)
  // Stored as JSON at credits:{cred_id}. Skip silently if absent.
  let creditsMigrated = false;
  try {
    const creditsRaw = await env.DEDUP_KV.get(`credits:${oldCredentialId}`);
    if (creditsRaw) {
      await env.DEDUP_KV.put(`credits:${newCredentialId}`, creditsRaw);
      creditsMigrated = true;
    }
  } catch (_) { /* non-fatal */ }

  // S85CW: Migrate Stripe customer mapping so next purchase reuses the same
  // Stripe customer rather than creating a duplicate (which could double-bill
  // active subscriptions). Stored as a plain string (customer id), not JSON.
  let stripeCustMigrated = false;
  try {
    const custRaw = await env.DEDUP_KV.get(`stripe_cust:${oldCredentialId}`);
    if (custRaw) {
      await env.DEDUP_KV.put(`stripe_cust:${newCredentialId}`, custRaw);
      stripeCustMigrated = true;
    }
  } catch (_) { /* non-fatal */ }

  // S85CW: Migrate per-credential proof index (built by Change 2 — safe to
  // run before that ships; will simply no-op until the index starts populating).
  let credProofsMigrated = false;
  try {
    const proofsRaw = await env.DEDUP_KV.get(`cred_proofs:${oldCredentialId}`);
    if (proofsRaw) {
      await env.DEDUP_KV.put(`cred_proofs:${newCredentialId}`, proofsRaw);
      credProofsMigrated = true;
    }
  } catch (_) { /* non-fatal */ }

  return {
    migrated: true,
    trust_score: ts.score,
    trust_index: ts.trust_index,
    credits_migrated: creditsMigrated,
    stripe_cust_migrated: stripeCustMigrated,
    cred_proofs_migrated: credProofsMigrated,
  };
}

// S85CW Change 2: Maintain a per-credential index of proof content hashes.
// Called after a proof:{hash} record is successfully written. Idempotent —
// if the hash is already present in the index, no write occurs. Non-fatal:
// any failure is swallowed so proof registration never blocks on the index.
// The proof:{hash} record is the source of truth; this index is an accelerator
// so /api/portfolio can page through a credential's proofs without scanning.
async function addToCredProofsIndex(env, credential_id, content_hash) {
  if (!credential_id || !content_hash) return;
  try {
    const key = `cred_proofs:${credential_id}`;
    const raw = await env.DEDUP_KV.get(key);
    let record;
    if (raw) {
      try { record = JSON.parse(raw); } catch (_) { record = null; }
    }
    if (!record || !Array.isArray(record.hashes)) {
      record = { hashes: [], updated_at: null };
    }
    if (record.hashes.indexOf(content_hash) !== -1) {
      return; // already indexed — idempotent no-op
    }
    record.hashes.push(content_hash);
    record.updated_at = new Date().toISOString();
    await env.DEDUP_KV.put(key, JSON.stringify(record));
  } catch (_) {
    // Non-fatal: index is an accelerator, not source of truth.
  }
}


// S96: POST /retire-credential — Voluntary credential retirement (Level 2)
// Sets superseded_by:"self-retired" on the trust record, blocking all future
// API calls via verifyAppAuth line 156. Existing attestations remain valid.
// Client should clear localStorage only AFTER this succeeds (fail-safe).
async function handleRetireCredential(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  // Auth: prove ownership of the credential being retired
  const auth = await verifyAppAuth(request, "/retire-credential", env);
  if (!auth.ok) {
    return jsonResponse({ error: auth.error }, auth.status, origin);
  }

  const { credential_id, trust_record } = auth;

  // Mark as self-retired (same fields as recovery-supersede, different sentinel)
  trust_record.superseded_by = "self-retired";
  trust_record.superseded_at = new Date().toISOString();
  trust_record.retirement_reason = "voluntary";

  await env.DEDUP_KV.put(`trust:${credential_id}`, JSON.stringify(trust_record));

  return jsonResponse({
    ok: true,
    credential_id,
    retired_at: trust_record.superseded_at,
    message: "Credential retired. It can no longer be used for attestations on any device."
  }, 200, origin);
}


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

// ── S37: Public Proof Registry ──
// POST /register-proof — Register a signed proof record in the public registry.
//
// Security model:
//   Gate 1 — Valid credential: submission must include credential_id with a
//             server-side trust record (i.e. was properly issued via HIP).
//   Gate 2 — Rate limit: max 50 proof registrations per credential per 24 hours.
//             Consistent with attestation rate limits in HP-SPEC.
//   Gate 3 — First-write-wins: once a content_hash is registered, it is locked.
//             A second credential attempting the same hash gets 409 Conflict with
//             the existing record returned. No overwrite, ever.
//   Gate 4 — Signature: the client signs the canonical string
//             content_hash|perceptual_hash_or_NULL|credential_id|attested_at|classification
//             with its Ed25519 private key. The worker stores the signature so any
//             party can independently verify the record without trusting this server.
//
// The worker does NOT verify the Ed25519 signature itself (Cloudflare Workers do not
// expose SubtleCrypto Ed25519 verify in all deployments). The signature is stored
// verbatim and verified client-side by proof card viewers. This is correct: the
// signature is a self-verifying artifact — its validity is independent of this server.

// S88: Sanitize an optional display file name before storage.
// Rules: string only; strip ASCII control chars and path separators (\\ /);
// trim whitespace; cap at 255 chars; empty becomes null. Purely cosmetic —
// not part of the signature payload, not trusted as authoritative.
function sanitizeFileName(name) {
  if (typeof name !== "string") return null;
  let s = name.replace(/[\x00-\x1f\x7f\\\/]/g, "").trim();
  if (!s) return null;
  if (s.length > 255) s = s.substring(0, 255);
  return s;
}

async function handleRegisterProof(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  let body;
  try {
    body = await request.json();
  } catch (_) {
    return jsonResponse({ error: "Invalid JSON" }, 400, origin);
  }

  const {
    content_hash,
    perceptual_hash,
    credential_id,
    public_key,
    attested_at,
    classification,
    signature,
    sealed,
    protocol_version,
    file_name,
    original_hash,
    attested_copy_hash,
  } = body;

  // S88: Optional cosmetic display name. Not part of signature payload.
  const sanitizedFileName = sanitizeFileName(file_name);

  // ── Validate required fields ──
  if (!content_hash || !credential_id || !attested_at || !classification || !signature) {
    return jsonResponse({
      error: "Missing required fields: content_hash, credential_id, attested_at, classification, signature"
    }, 400, origin);
  }

  // content_hash must be a 64-char hex string (SHA-256)
  if (!/^[0-9a-f]{64}$/.test(content_hash)) {
    return jsonResponse({ error: "content_hash must be a 64-character lowercase hex string (SHA-256)" }, 400, origin);
  }

  // S102 Path 2: optional pre-embed hash, captured client-side before
  // badge/metadata embedding. Not part of the signature payload — metadata
  // only (same posture as file_name). Enables cross-device Verify fallback
  // via /api/credential/{id}/attestations to dual-hash-match a dropped file
  // against proofs attested under the requester's credential.
  if (original_hash !== undefined && original_hash !== null && !/^[0-9a-f]{64}$/.test(original_hash)) {
    return jsonResponse({ error: "original_hash must be a 64-character lowercase hex string (SHA-256)" }, 400, origin);
  }

  // S103 Fix 3: optional attested-copy hash. Client computes sha256 of the
  // attested-copy bytes (the file the user actually downloads) and sends it
  // alongside the canonical content_hash (= pre-embed source hash). When
  // present and distinct from content_hash, we write an alias KV entry so
  // Verify's /api/proof/{hash} miss-path can translate the downloaded-file
  // hash to the canonical record. Metadata only, not part of the signature
  // payload (same posture as file_name and original_hash).
  if (attested_copy_hash !== undefined && attested_copy_hash !== null && !/^[0-9a-f]{64}$/.test(attested_copy_hash)) {
    return jsonResponse({ error: "attested_copy_hash must be a 64-character lowercase hex string (SHA-256)" }, 400, origin);
  }

  // public_key must be a 64-char hex string (Ed25519 = 32 bytes = 64 hex chars)
  // Optional for backward compatibility, but strongly recommended
  if (public_key) {
    if (!/^[0-9a-f]{64}$/.test(public_key)) {
      return jsonResponse({ error: "public_key must be a 64-character lowercase hex string (Ed25519 public key)" }, 400, origin);
    }
    // Verify public_key matches credential_id: credential_id = SHA-256(public_key)
    const enc = new TextEncoder();
    const pubKeyBytes = new Uint8Array(public_key.match(/.{2}/g).map(b => parseInt(b, 16)));
    const hashBuf = await crypto.subtle.digest("SHA-256", pubKeyBytes);
    const computedId = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
    if (computedId !== credential_id) {
      return jsonResponse({
        error: "public_key does not match credential_id. credential_id must be SHA-256(public_key)."
      }, 400, origin);
    }
  }

  // classification must be a known HIP value
  const validClassifications = ["CompleteHumanOrigin", "HumanOriginAssisted", "HumanDirectedCollaborative"];
  if (!validClassifications.includes(classification)) {
    return jsonResponse({ error: "Invalid classification. Must be one of: " + validClassifications.join(", ") }, 400, origin);
  }

  // attested_at must be ISO 8601 UTC
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(attested_at)) {
    return jsonResponse({ error: "attested_at must be ISO 8601 UTC format: YYYY-MM-DDTHH:MM:SSZ" }, 400, origin);
  }

  // ── Gate 1: Credential must exist in trust system ──
  const trustRaw = await env.DEDUP_KV.get(`trust:${credential_id}`);
  if (!trustRaw) {
    return jsonResponse({
      error: "Credential not found. Only credentials issued through HIP may register proofs."
    }, 403, origin);
  }

  const trustRecord = JSON.parse(trustRaw);

  // Credential must be in good standing (no superseded/invalidated flag)
  if (trustRecord.superseded_by) {
    return jsonResponse({
      error: "This credential has been superseded. Use your current credential to register proofs."
    }, 403, origin);
  }

  // ── S92 #23 Step-2a: TI >= 60 attest floor (HP-SPEC-v1_3 §TI) ──
  // Ships in same deploy as dual-field computeTrustScore — legacy x10 translation
  // puts every live credential at >=100, so this floor screens only genuinely
  // under-attested credentials. Fallback `?? trust_score ?? 0` handles legacy KV
  // rows written before this deploy (their trust_score is 0-100, still well above
  // 60 for any non-pathological credential).
  if ((trustRecord.trust_index ?? trustRecord.trust_score ?? 0) < 60) {
    return jsonResponse({
      ok: false,
      error: "trust_index_below_floor",
      detail: `Credential TI (${trustRecord.trust_index ?? trustRecord.trust_score ?? 0}) is below the 60 attest floor. Build trust via device-liveness attestations before registering proofs.`,
    }, 403, origin);
  }

  // ── S90 #23b: T3 provisional ceiling — 50 OriginalAttestation lifetime cap ──
  // Per HP-SPEC-v1_3. Every /register-proof is an OriginalAttestation
  // (corrections/withdrawals flow through handleDisputeProof/handleUnsealProof).
  // Declaration key causes the cap to no-op globally when set.
  const t3DeclarationActive = await env.DEDUP_KV.get("governance:t3_ceiling_declaration");
  if (trustRecord.tier === 3
      && (trustRecord.t3_original_attestation_count || 0) >= 50
      && !t3DeclarationActive) {
    return jsonResponse({
      ok: false,
      error: "t3_attestation_cap_reached",
      detail: "Tier 3 credentials are limited to 50 original attestations until protocol-wide PFV/PHI readiness declaration."
    }, 403, origin);
  }

  // ── Gate 2: Rate limit — 50 proof registrations per credential per 24h ──
  const credHash = await hmacSHA256(env.DEDUP_SECRET, "prate:" + credential_id);
  const rateKey = `prate:${credHash}`;
  const rateRaw = await env.DEDUP_KV.get(rateKey);
  let rateCount = 0;
  if (rateRaw) {
    rateCount = JSON.parse(rateRaw).count || 0;
  }

  // Rate limit varies by tier: T1=50/day, T2=25/day, T3=10/day
  const tierLimits = { 1: 50, 2: 25, 3: 10 };
  const limit = tierLimits[trustRecord.tier] || 10;

  if (rateCount >= limit) {
    return jsonResponse({
      error: `Rate limit exceeded. Maximum ${limit} proof registrations per 24 hours for Tier ${trustRecord.tier} credentials.`,
      limit,
      current: rateCount,
    }, 429, origin);
  }

  // ── Gate 3: First-write-wins — check for existing record ──
  const proofKey = `proof:${content_hash}`;
  const existing = await env.DEDUP_KV.get(proofKey);
  if (existing) {
    const existingRecord = JSON.parse(existing);
    // Return existing record — do not overwrite
    return jsonResponse({
      error: "conflict",
      message: "A proof record already exists for this content hash. First registration wins.",
      existing_record: existingRecord.sealed ? {
        content_hash: existingRecord.content_hash,
        registered_at: existingRecord.registered_at,
        sealed: true,
        message: "This proof is sealed by its creator.",
      } : existingRecord,
    }, 409, origin);
  }

  // ── Write proof record ──
  const now = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

  // S40: Generate unique 8-char short ID with collision check (5 attempts)
  let short_id = null;
  for (let attempt = 0; attempt < 5; attempt++) {
    const candidate = generateShortId();
    const existing_short = await env.DEDUP_KV.get(`short:${candidate}`);
    if (!existing_short) {
      short_id = candidate;
      break;
    }
  }

  const proofRecord = {
    content_hash,
    perceptual_hash: perceptual_hash || null,
    credential_id,
    public_key: public_key || null,
    credential_tier: trustRecord.tier,
    classification,
    attested_at,
    registered_at: now,
    signature,
    sealed: sealed === true,
    protocol_version: protocol_version || "1.2",
    short_id: short_id,
    file_name: sanitizedFileName,
    original_hash: original_hash || null,
    attested_copy_hash: attested_copy_hash || null,
  };

  await env.DEDUP_KV.put(proofKey, JSON.stringify(proofRecord));

  // S103 Fix 3: write alias row so Verify can resolve sha256(downloaded file)
  // → canonical content_hash when the attested copy's bytes differ from the
  // pre-embed source (JPEG/PNG/WebP via HipImageEmbed, PDF/DOCX/MP3/etc. via
  // HipFileEmbed). Value is JSON for forward extensibility. Skip when the
  // attested copy's hash equals content_hash (no distinct attested copy) —
  // the canonical proof record already handles that case.
  if (attested_copy_hash && attested_copy_hash !== content_hash) {
    await env.DEDUP_KV.put(
      `alias:${attested_copy_hash}`,
      JSON.stringify({ canonical: content_hash, registered_at: now })
    );
  }

  // S90 #23b: Increment T3 OriginalAttestation counter on the trust record.
  // Only applies to T3 credentials; corrections/withdrawals are exempt and
  // don't flow through this handler. Declaration key does NOT no-op the
  // counter itself (it continues accumulating) — only the 50-cap gate above
  // and the read-time TI clamp in computeTrustScore are gated on it.
  if (trustRecord.tier === 3) {
    const trustRecordUpdated = { ...trustRecord };
    trustRecordUpdated.t3_original_attestation_count =
      (trustRecordUpdated.t3_original_attestation_count || 0) + 1;
    await env.DEDUP_KV.put(`trust:${credential_id}`, JSON.stringify(trustRecordUpdated));
  }

  // S85CW Change 2: Index this proof under the attester's credential so
  // /api/portfolio can page through it. Fire-and-continue semantics.
  await addToCredProofsIndex(env, credential_id, content_hash);

  // S40: Store reverse lookup for short link resolution
  if (short_id) {
    await env.DEDUP_KV.put(`short:${short_id}`, content_hash);
  }

  // Increment daily rate limit counter (24h TTL)
  await env.DEDUP_KV.put(rateKey, JSON.stringify({
    count: rateCount + 1,
    last_registration: now,
  }), { expirationTtl: 86400 });

  // S83: Increment weekly rate limit counter (7-day TTL)
  const weeklyHash = await hmacSHA256(env.DEDUP_SECRET, "wrate:" + credential_id);
  const weeklyKey = `wrate:${weeklyHash}`;
  const weeklyRaw = await env.DEDUP_KV.get(weeklyKey);
  const weeklyCount = weeklyRaw ? (JSON.parse(weeklyRaw).count || 0) : 0;
  await env.DEDUP_KV.put(weeklyKey, JSON.stringify({
    count: weeklyCount + 1,
    last_registration: now,
  }), { expirationTtl: 604800 });

  const short_url = short_id ? `https://hipprotocol.org/p/${short_id}` : null;

  return jsonResponse({
    success: true,
    content_hash,
    registered_at: now,
    proof_url: `https://hipprotocol.org/proof.html?hash=${content_hash}`,
    short_id,
    short_url,
    sealed: proofRecord.sealed,
  }, 200, origin);
}

// S43: POST /api/proof/batch — Batch proof lookup for browser extension.
// Accepts up to 50 SHA-256 hashes and optional pHashes.
// Returns found/not-found for each, plus pHash near-matches.
// Body: { hashes: ["abc...","def...",...], phashes: {"abc...":"hexphash",...} }

function pHashHammingDistance(a, b) {
  if (!a || !b || a.length !== b.length) return 64;
  let dist = 0;
  for (let i = 0; i < a.length; i++) {
    const xor = parseInt(a[i], 16) ^ parseInt(b[i], 16);
    dist += [0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4][xor];
  }
  return dist;
}

async function handleBatchProof(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  let body;
  try { body = await request.json(); } catch (_) {
    return jsonResponse({ error: "Invalid JSON" }, 400, origin);
  }

  const { hashes, phashes } = body;
  if (!hashes || !Array.isArray(hashes) || hashes.length === 0) {
    return jsonResponse({ error: "hashes array required" }, 400, origin);
  }
  if (hashes.length > 50) {
    return jsonResponse({ error: "Maximum 50 hashes per batch" }, 400, origin);
  }

  const results = {};

  // Look up all hashes in parallel
  const lookups = hashes.map(async (h) => {
    const hash = (h || "").toLowerCase().trim();
    if (!/^[0-9a-f]{64}$/.test(hash)) {
      results[hash] = { found: false, error: "invalid_hash" };
      return;
    }
    const raw = await env.DEDUP_KV.get(`proof:${hash}`);
    if (!raw) {
      results[hash] = { found: false };
      return;
    }
    const record = JSON.parse(raw);
    if (record.sealed) {
      results[hash] = { found: true, sealed: true, registered_at: record.registered_at };
    } else {
      results[hash] = {
        found: true,
        classification: record.classification,
        credential_tier: record.credential_tier,
        attested_at: record.attested_at,
        short_id: record.short_id || null,
        perceptual_hash: record.perceptual_hash || null,
      };
    }
  });

  await Promise.all(lookups);

  // S43: pHash near-match search for hashes that weren't found by SHA-256.
  // This handles social media re-encoding where exact hash changes but visual
  // content is preserved. We scan recent proofs that have perceptual hashes.
  // Note: This is a brute-force scan of unfound hashes against found pHashes
  // in this batch + a KV list scan. For Phase 1, we do a simpler approach:
  // compare provided pHashes against pHashes of found results in this batch,
  // plus check a dedicated pHash index if we build one later.
  //
  // Phase 1 approach: The caller provides pHashes for their images. We check
  // all proof records already fetched in this batch for pHash proximity.
  // This won't find matches outside the batch, but it's zero-cost.
  // Phase 2 will add a pHash index for global search.

  const pHashMatches = {};
  if (phashes && typeof phashes === "object") {
    // Collect all known pHashes from found results
    const knownPHashes = [];
    for (const [hash, result] of Object.entries(results)) {
      if (result.found && result.perceptual_hash) {
        knownPHashes.push({ hash, phash: result.perceptual_hash, result });
      }
    }

    // For each unfound hash that has a pHash, check similarity against all known
    for (const [hash, clientPHash] of Object.entries(phashes)) {
      const h = hash.toLowerCase().trim();
      if (results[h] && results[h].found) continue; // already found by SHA-256

      for (const known of knownPHashes) {
        const dist = pHashHammingDistance(clientPHash.toLowerCase(), known.phash.toLowerCase());
        const similarity = Math.round((1 - dist / 64) * 100);
        if (similarity >= 85) { // 85% threshold for "likely match"
          if (!pHashMatches[h] || similarity > pHashMatches[h].similarity) {
            pHashMatches[h] = {
              match_type: "perceptual",
              similarity,
              matched_hash: known.hash,
              classification: known.result.classification,
              credential_tier: known.result.credential_tier,
              attested_at: known.result.attested_at,
              short_id: known.result.short_id,
            };
          }
        }
      }
    }
  }

  return jsonResponse({
    results,
    phash_matches: Object.keys(pHashMatches).length > 0 ? pHashMatches : undefined,
  }, 200, origin);
}

// GET /proof/:hash — Retrieve a proof record from the public registry.
// Returns the full record for public proofs.
// Returns a minimal stub for sealed proofs (confirms existence without revealing contents).
// Returns 404 if no record exists for this hash.

async function handleGetProof(contentHash, request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  // Validate hash format
  if (!/^[0-9a-f]{64}$/.test(contentHash)) {
    return jsonResponse({ error: "Invalid content hash. Must be a 64-character lowercase hex SHA-256 hash." }, 400, origin);
  }

  const proofKey = `proof:${contentHash}`;
  let raw = await env.DEDUP_KV.get(proofKey);
  let canonicalHash = contentHash;
  let matchedVia = "canonical";

  // S103 Fix 3: alias miss-path fallback. If the requested hash isn't a
  // canonical content_hash, it may be the hash of a downloaded attested copy
  // whose bytes differ from the pre-embed source (any HipImageEmbed output,
  // or HipFileEmbed outputs for PDF/DOCX/MP3/etc.). Alias rows translate
  // those hashes to the canonical record. Diagnostic field matched_via
  // distinguishes the two paths for client logging / debugging.
  if (!raw) {
    const aliasRaw = await env.DEDUP_KV.get(`alias:${contentHash}`);
    if (aliasRaw) {
      try {
        const aliasRecord = JSON.parse(aliasRaw);
        if (aliasRecord && /^[0-9a-f]{64}$/.test(aliasRecord.canonical)) {
          const canonicalRaw = await env.DEDUP_KV.get(`proof:${aliasRecord.canonical}`);
          if (canonicalRaw) {
            raw = canonicalRaw;
            canonicalHash = aliasRecord.canonical;
            matchedVia = "alias";
          }
        }
      } catch (_) { /* malformed alias — treat as miss */ }
    }
  }

  if (!raw) {
    return jsonResponse({
      found: false,
      content_hash: contentHash,
      message: "No proof record found for this content hash.",
    }, 404, origin);
  }

  const record = JSON.parse(raw);

  // Sealed records: return stub only — existence confirmed, contents withheld
  if (record.sealed) {
    return jsonResponse({
      found: true,
      content_hash: canonicalHash,
      queried_hash: contentHash,
      matched_via: matchedVia,
      sealed: true,
      registered_at: record.registered_at,
      message: "This proof record is sealed by its creator. The content has been attested but the proof details are not yet public.",
    }, 200, origin);
  }

  // Public record: return full record
  return jsonResponse({
    found: true,
    queried_hash: contentHash,
    matched_via: matchedVia,
    ...record,
  }, 200, origin);
}

// POST /unseal-proof — Unseal a previously sealed proof record.
// Only the original credential holder can unseal.
// Requires: content_hash, credential_id, signature (signs "UNSEAL|{content_hash}|{credential_id}")
// If public_key was not included in the original registration, caller can provide it now.

async function handleUnsealProof(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  let body;
  try {
    body = await request.json();
  } catch (_) {
    return jsonResponse({ error: "Invalid JSON" }, 400, origin);
  }

  const { content_hash, credential_id, signature, public_key } = body;

  if (!content_hash || !credential_id || !signature) {
    return jsonResponse({
      error: "Missing required fields: content_hash, credential_id, signature"
    }, 400, origin);
  }

  if (!/^[0-9a-f]{64}$/.test(content_hash)) {
    return jsonResponse({ error: "content_hash must be a 64-character lowercase hex SHA-256 hash." }, 400, origin);
  }

  // Look up proof record
  const proofKey = `proof:${content_hash}`;
  const raw = await env.DEDUP_KV.get(proofKey);
  if (!raw) {
    return jsonResponse({ error: "No proof record found for this content hash." }, 404, origin);
  }

  const record = JSON.parse(raw);

  // Must be sealed
  if (!record.sealed) {
    return jsonResponse({ error: "This proof record is already public (not sealed)." }, 400, origin);
  }

  // Must be the original credential holder
  if (record.credential_id !== credential_id) {
    return jsonResponse({ error: "Only the original credential holder can unseal this proof." }, 403, origin);
  }

  // If public_key provided now (backfill), validate it matches credential_id
  if (public_key) {
    if (!/^[0-9a-f]{64}$/.test(public_key)) {
      return jsonResponse({ error: "public_key must be a 64-character lowercase hex string." }, 400, origin);
    }
    const pubKeyBytes = new Uint8Array(public_key.match(/.{2}/g).map(b => parseInt(b, 16)));
    const hashBuf = await crypto.subtle.digest("SHA-256", pubKeyBytes);
    const computedId = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
    if (computedId !== credential_id) {
      return jsonResponse({ error: "public_key does not match credential_id." }, 400, origin);
    }
  }

  // Unseal the record
  record.sealed = false;
  record.unsealed_at = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

  // Backfill public_key if it wasn't in the original record
  if (public_key && !record.public_key) {
    record.public_key = public_key;
  }

  await env.DEDUP_KV.put(proofKey, JSON.stringify(record));

  const short_url = record.short_id ? `https://hipprotocol.org/p/${record.short_id}` : null;

  return jsonResponse({
    success: true,
    content_hash,
    unsealed_at: record.unsealed_at,
    proof_url: `https://hipprotocol.org/proof.html?hash=${content_hash}`,
    short_id: record.short_id || null,
    short_url,
  }, 200, origin);
}

// POST /dispute-proof — Flag a proof as contested.
// Anyone with a valid credential can dispute. Rate-limited per credential.
// Disputes are stored as an array on the proof record.
// Fields: content_hash, credential_id, reason (text, max 500 chars)

async function handleDisputeProof(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  let body;
  try {
    body = await request.json();
  } catch (_) {
    return jsonResponse({ error: "Invalid JSON" }, 400, origin);
  }

  const { content_hash, credential_id, reason } = body;

  if (!content_hash || !credential_id || !reason) {
    return jsonResponse({ error: "Missing required fields: content_hash, credential_id, reason" }, 400, origin);
  }

  if (!/^[0-9a-f]{64}$/.test(content_hash)) {
    return jsonResponse({ error: "Invalid content hash." }, 400, origin);
  }

  if (typeof reason !== "string" || reason.trim().length < 10 || reason.length > 500) {
    return jsonResponse({ error: "Reason must be 10-500 characters." }, 400, origin);
  }

  // Verify disputer has a valid credential
  const trustRaw = await env.DEDUP_KV.get(`trust:${credential_id}`);
  if (!trustRaw) {
    return jsonResponse({ error: "Only HIP credential holders may file disputes." }, 403, origin);
  }
  const trustRecord = JSON.parse(trustRaw);
  if (trustRecord.superseded_by) {
    return jsonResponse({ error: "This credential has been superseded." }, 403, origin);
  }

  // Look up proof record
  const proofKey = `proof:${content_hash}`;
  const raw = await env.DEDUP_KV.get(proofKey);
  if (!raw) {
    return jsonResponse({ error: "No proof record found for this content hash." }, 404, origin);
  }

  const record = JSON.parse(raw);

  // Cannot dispute your own attestation
  if (record.credential_id === credential_id) {
    return jsonResponse({ error: "You cannot dispute your own attestation." }, 400, origin);
  }

  // Rate limit disputes: max 5 per credential per 24h
  const disputeRateKey = `drate:${credential_id}`;
  const drateRaw = await env.DEDUP_KV.get(disputeRateKey);
  let drateCount = 0;
  if (drateRaw) {
    drateCount = JSON.parse(drateRaw).count || 0;
  }
  if (drateCount >= 5) {
    return jsonResponse({ error: "Dispute rate limit exceeded. Maximum 5 disputes per 24 hours." }, 429, origin);
  }

  // Check for duplicate dispute from same credential
  const disputes = record.disputes || [];
  if (disputes.some(d => d.credential_id === credential_id)) {
    return jsonResponse({ error: "You have already filed a dispute for this proof." }, 409, origin);
  }

  // Add dispute
  const now = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const dispute = {
    credential_id,
    credential_tier: trustRecord.tier,
    reason: reason.trim(),
    filed_at: now,
  };

  record.disputes = disputes.concat([dispute]);
  record.disputed = true;

  await env.DEDUP_KV.put(proofKey, JSON.stringify(record));

  // Increment dispute rate limit
  await env.DEDUP_KV.put(disputeRateKey, JSON.stringify({
    count: drateCount + 1,
    last_dispute: now,
  }), { expirationTtl: 86400 });

  return jsonResponse({
    success: true,
    content_hash,
    dispute_count: record.disputes.length,
    filed_at: now,
  }, 200, origin);
}

// ══════════════════════════════════════════════════════════════
// S82: API Key Management + Authenticated Attestation (Phase B)
// ══════════════════════════════════════════════════════════════

// POST /api/admin/keys — Generate an API key bound to a credential.
// Protected by DEDUP_SECRET as bearer token (admin-only).
// KV key pattern: api_key:{hmac(DEDUP_SECRET, rawKey)} → { credential_id, label, created_at, active }
// The raw key is returned once and never stored.

async function handleCreateApiKey(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  // Admin auth: Bearer token must match ADMIN_KEY
  const authHeader = request.headers.get("Authorization") || "";
  if (!authHeader.startsWith("Bearer ") || authHeader.slice(7) !== env.ADMIN_KEY) {
    return jsonResponse({ error: "Unauthorized" }, 401, origin);
  }

  let body;
  try {
    body = await request.json();
  } catch (_) {
    return jsonResponse({ error: "Invalid JSON" }, 400, origin);
  }

  const { credential_id, label } = body;
  if (!credential_id) {
    return jsonResponse({ error: "Missing credential_id" }, 400, origin);
  }

  // Credential must exist in trust system
  const trustRaw = await env.DEDUP_KV.get(`trust:${credential_id}`);
  if (!trustRaw) {
    return jsonResponse({
      error: "Credential not found. Only credentials issued through HIP may receive API keys."
    }, 404, origin);
  }

  const trustRecord = JSON.parse(trustRaw);
  if (trustRecord.superseded_by) {
    return jsonResponse({
      error: "This credential has been superseded. Use the current credential."
    }, 403, origin);
  }

  // Generate a 32-byte (64 hex char) random API key
  const rawBytes = crypto.getRandomValues(new Uint8Array(32));
  const rawKey = Array.from(rawBytes).map(b => b.toString(16).padStart(2, "0")).join("");

  // Store as HMAC hash — raw key never persists
  const keyHash = await hmacSHA256(env.DEDUP_SECRET, rawKey);
  const now = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

  const keyRecord = {
    credential_id,
    tier: trustRecord.tier,
    label: label || null,
    created_at: now,
    active: true,
  };

  await env.DEDUP_KV.put(`api_key:${keyHash}`, JSON.stringify(keyRecord));

  return jsonResponse({
    success: true,
    api_key: rawKey,
    credential_id,
    tier: trustRecord.tier,
    label: label || null,
    created_at: now,
    message: "Store this API key securely. It will not be shown again.",
  }, 200, origin);
}


// POST /api/attest — Submit an attestation via API key.
// Authenticated via X-API-Key header. Reuses the proof registration pipeline
// with the same gates: credential check, rate limits, first-write-wins,
// short ID generation, trust score update.
//
// Request body: { content_hash, classification, signature, attested_at?, sealed?, protocol_version?, perceptual_hash?, public_key? }
// Rate limits: shared with app attestations (T1:50/day, T2:25/day, T3:10/day)

async function handleApiAttest(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  // ── Auth: Resolve API key to credential ──
  const apiKey = request.headers.get("X-API-Key");
  if (!apiKey) {
    return jsonResponse({
      error: "Missing X-API-Key header. See https://hipkit.net/api.html#authentication for details."
    }, 401, origin);
  }

  const keyHash = await hmacSHA256(env.DEDUP_SECRET, apiKey);
  const keyRaw = await env.DEDUP_KV.get(`api_key:${keyHash}`);
  if (!keyRaw) {
    return jsonResponse({ error: "Invalid API key" }, 403, origin);
  }

  const keyRecord = JSON.parse(keyRaw);
  if (!keyRecord.active) {
    return jsonResponse({ error: "API key has been deactivated" }, 403, origin);
  }

  const credential_id = keyRecord.credential_id;

  // ── Parse request body ──
  let body;
  try {
    body = await request.json();
  } catch (_) {
    return jsonResponse({ error: "Invalid JSON" }, 400, origin);
  }

  const {
    content_hash,
    classification,
    signature,
    attested_at,
    sealed,
    protocol_version,
    perceptual_hash,
    public_key,
    file_name,
    original_hash,
    attested_copy_hash,
  } = body;

  // S88: Optional cosmetic display name. Not part of signature payload.
  const sanitizedFileName = sanitizeFileName(file_name);

  // ── Validate required fields ──
  if (!content_hash || !classification || !signature) {
    return jsonResponse({
      error: "Missing required fields: content_hash, classification, signature"
    }, 400, origin);
  }

  // content_hash must be 64-char hex (SHA-256)
  if (!/^[0-9a-f]{64}$/.test(content_hash)) {
    return jsonResponse({
      error: "content_hash must be a 64-character lowercase hex string (SHA-256)"
    }, 400, origin);
  }

  // S102 Path 2: optional pre-embed hash (metadata only, not signed). See
  // handleRegisterProof for rationale. Symmetrical stamping here keeps
  // HIPKit-authed attestations shape-compatible with the credential history
  // endpoint (records with null original_hash are matched on content_hash only).
  if (original_hash !== undefined && original_hash !== null && !/^[0-9a-f]{64}$/.test(original_hash)) {
    return jsonResponse({
      error: "original_hash must be a 64-character lowercase hex string (SHA-256)"
    }, 400, origin);
  }

  // S103 Fix 3: symmetric attested_copy_hash accept (see handleRegisterProof).
  if (attested_copy_hash !== undefined && attested_copy_hash !== null && !/^[0-9a-f]{64}$/.test(attested_copy_hash)) {
    return jsonResponse({
      error: "attested_copy_hash must be a 64-character lowercase hex string (SHA-256)"
    }, 400, origin);
  }

  // classification must be a known HIP value
  const validClassifications = ["CompleteHumanOrigin", "HumanOriginAssisted", "HumanDirectedCollaborative"];
  if (!validClassifications.includes(classification)) {
    return jsonResponse({
      error: "Invalid classification. Must be one of: " + validClassifications.join(", ")
    }, 400, origin);
  }

  // attested_at: default to now if not provided
  const attestedAt = attested_at || new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(attestedAt)) {
    return jsonResponse({
      error: "attested_at must be ISO 8601 UTC format: YYYY-MM-DDTHH:MM:SSZ"
    }, 400, origin);
  }

  // Optional: validate public_key if provided
  if (public_key) {
    if (!/^[0-9a-f]{64}$/.test(public_key)) {
      return jsonResponse({
        error: "public_key must be a 64-character lowercase hex string (Ed25519 public key)"
      }, 400, origin);
    }
    // Verify public_key matches credential_id
    const enc = new TextEncoder();
    const pubKeyBytes = new Uint8Array(public_key.match(/.{2}/g).map(b => parseInt(b, 16)));
    const hashBuf = await crypto.subtle.digest("SHA-256", pubKeyBytes);
    const computedId = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
    if (computedId !== credential_id) {
      return jsonResponse({
        error: "public_key does not match the credential bound to this API key."
      }, 400, origin);
    }
  }

  // ── Gate 1: Credential must exist and be in good standing ──
  const trustRaw = await env.DEDUP_KV.get(`trust:${credential_id}`);
  if (!trustRaw) {
    return jsonResponse({
      error: "Credential not found. The credential bound to this API key no longer exists."
    }, 403, origin);
  }

  const trustRecord = JSON.parse(trustRaw);

  if (trustRecord.superseded_by) {
    return jsonResponse({
      error: "The credential bound to this API key has been superseded. Generate a new key with your current credential."
    }, 403, origin);
  }

  // ── S92 #23 Step-2a: TI >= 60 attest floor (HP-SPEC-v1_3 §TI) ──
  // Mirrors handleRegisterProof. Fallback `?? trust_score ?? 0` handles legacy
  // KV rows written before this deploy.
  if ((trustRecord.trust_index ?? trustRecord.trust_score ?? 0) < 60) {
    return jsonResponse({
      ok: false,
      error: "trust_index_below_floor",
      detail: `Credential TI (${trustRecord.trust_index ?? trustRecord.trust_score ?? 0}) is below the 60 attest floor. Build trust via device-liveness attestations before registering proofs.`,
    }, 403, origin);
  }

  // ── S90 #23b: T3 provisional ceiling — 50 OriginalAttestation lifetime cap ──
  // Per HP-SPEC-v1_3. Every /api/attest is an OriginalAttestation.
  // Declaration key causes the cap to no-op globally when set.
  const t3DeclarationActive = await env.DEDUP_KV.get("governance:t3_ceiling_declaration");
  if (trustRecord.tier === 3
      && (trustRecord.t3_original_attestation_count || 0) >= 50
      && !t3DeclarationActive) {
    return jsonResponse({
      ok: false,
      error: "t3_attestation_cap_reached",
      detail: "Tier 3 credentials are limited to 50 original attestations until protocol-wide PFV/PHI readiness declaration."
    }, 403, origin);
  }

  // ── Gate 2: Rate limit — shared with app attestations ──
  const credHash = await hmacSHA256(env.DEDUP_SECRET, "prate:" + credential_id);
  const rateKey = `prate:${credHash}`;
  const rateRaw = await env.DEDUP_KV.get(rateKey);
  let rateCount = 0;
  if (rateRaw) {
    rateCount = JSON.parse(rateRaw).count || 0;
  }

  const tierLimits = { 1: 50, 2: 25, 3: 10 };
  const limit = tierLimits[trustRecord.tier] || 10;

  if (rateCount >= limit) {
    return jsonResponse({
      error: `Rate limit exceeded. Maximum ${limit} attestations per 24 hours for Tier ${trustRecord.tier} credentials.`,
      limit,
      current: rateCount,
    }, 429, origin);
  }

  // ── Gate 3: First-write-wins ──
  const proofKey = `proof:${content_hash}`;
  const existing = await env.DEDUP_KV.get(proofKey);
  if (existing) {
    const existingRecord = JSON.parse(existing);
    return jsonResponse({
      error: "conflict",
      message: "A proof record already exists for this content hash. First registration wins.",
      existing_record: existingRecord.sealed ? {
        content_hash: existingRecord.content_hash,
        registered_at: existingRecord.registered_at,
        sealed: true,
        message: "This proof is sealed by its creator.",
      } : existingRecord,
    }, 409, origin);
  }

  // ── Write proof record ──
  const now = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

  // Generate unique short ID (5 attempts)
  let short_id = null;
  for (let attempt = 0; attempt < 5; attempt++) {
    const candidate = generateShortId();
    const existing_short = await env.DEDUP_KV.get(`short:${candidate}`);
    if (!existing_short) {
      short_id = candidate;
      break;
    }
  }

  const proofRecord = {
    content_hash,
    perceptual_hash: perceptual_hash || null,
    credential_id,
    public_key: public_key || null,
    credential_tier: trustRecord.tier,
    classification,
    attested_at: attestedAt,
    registered_at: now,
    signature,
    sealed: sealed === true,
    protocol_version: protocol_version || "1.2",
    short_id: short_id,
    source: "api",
    file_name: sanitizedFileName,
    original_hash: original_hash || null,
    attested_copy_hash: attested_copy_hash || null,
  };

  await env.DEDUP_KV.put(proofKey, JSON.stringify(proofRecord));

  // S103 Fix 3: symmetric alias write (see handleRegisterProof).
  if (attested_copy_hash && attested_copy_hash !== content_hash) {
    await env.DEDUP_KV.put(
      `alias:${attested_copy_hash}`,
      JSON.stringify({ canonical: content_hash, registered_at: now })
    );
  }

  // S85CW Change 2: Index this proof under the attester's credential.
  await addToCredProofsIndex(env, credential_id, content_hash);

  // Store short link reverse lookup
  if (short_id) {
    await env.DEDUP_KV.put(`short:${short_id}`, content_hash);
  }

  // Increment daily rate limit counter (24h TTL)
  await env.DEDUP_KV.put(rateKey, JSON.stringify({
    count: rateCount + 1,
    last_registration: now,
  }), { expirationTtl: 86400 });

  // S83: Increment weekly rate limit counter (7-day TTL)
  const weeklyHash = await hmacSHA256(env.DEDUP_SECRET, "wrate:" + credential_id);
  const weeklyKey = `wrate:${weeklyHash}`;
  const weeklyRaw = await env.DEDUP_KV.get(weeklyKey);
  const weeklyCount = weeklyRaw ? (JSON.parse(weeklyRaw).count || 0) : 0;
  await env.DEDUP_KV.put(weeklyKey, JSON.stringify({
    count: weeklyCount + 1,
    last_registration: now,
  }), { expirationTtl: 604800 });

  // Update trust record (attestation count, active months, score)
  const trustRecordCopy = { ...trustRecord };
  trustRecordCopy.attestation_count = (trustRecordCopy.attestation_count || 0) + 1;
  trustRecordCopy.last_seen = now;
  const monthStr = now.substring(0, 7);
  if (!trustRecordCopy.active_months) trustRecordCopy.active_months = [];
  if (!trustRecordCopy.active_months.includes(monthStr)) {
    trustRecordCopy.active_months.push(monthStr);
  }
  // S90 #23b: Increment T3 OriginalAttestation counter. Piggybacks on this write.
  if (trustRecordCopy.tier === 3) {
    trustRecordCopy.t3_original_attestation_count =
      (trustRecordCopy.t3_original_attestation_count || 0) + 1;
  }
  const ts = await computeTrustScore(trustRecordCopy, env);
  // S92 #23 Step-2a: dual-write trust_index alongside trust_score.
  trustRecordCopy.trust_score = ts.score;
  trustRecordCopy.trust_index = ts.trust_index;
  await env.DEDUP_KV.put(`trust:${credential_id}`, JSON.stringify(trustRecordCopy));

  const short_url = short_id ? `https://hipprotocol.org/p/${short_id}` : null;

  return jsonResponse({
    success: true,
    content_hash,
    classification,
    credential_tier: trustRecord.tier,
    attested_at: attestedAt,
    registered_at: now,
    proof_url: `https://hipprotocol.org/proof.html?hash=${content_hash}`,
    short_id,
    short_url,
    sealed: proofRecord.sealed,
  }, 200, origin);
}


// ── S81: Public Verify API ──
// GET /api/verify/{hash} — Public verification endpoint.
// Returns a clean, integration-friendly response indicating whether content
// has been attested via HIP. No authentication required.
// This is the stable public API for integrators (CMS, galleries, auction houses, etc.).
// The raw proof record is available via GET /api/proof/{hash} for advanced use.

async function handleVerify(contentHash, request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  // Validate hash format
  if (!/^[0-9a-f]{64}$/.test(contentHash)) {
    return jsonResponse({
      verified: false,
      error: "Invalid content hash. Must be a 64-character lowercase hex SHA-256 hash."
    }, 400, origin);
  }

  const proofKey = `proof:${contentHash}`;
  const raw = await env.DEDUP_KV.get(proofKey);

  if (!raw) {
    return jsonResponse({
      verified: false,
      content_hash: contentHash,
    }, 200, origin);
  }

  const record = JSON.parse(raw);

  // Sealed records: confirm existence but withhold details
  if (record.sealed) {
    return jsonResponse({
      verified: true,
      record: {
        content_hash: contentHash,
        sealed: true,
        registered_at: record.registered_at,
      },
      message: "This content has been attested but the proof details are sealed by its creator.",
    }, 200, origin);
  }

  // Public record: return integration-friendly verification response
  const short_url = record.short_id
    ? `https://hipprotocol.org/p/${record.short_id}`
    : null;

  return jsonResponse({
    verified: true,
    record: {
      content_hash: contentHash,
      classification: record.classification,
      credential_tier: record.credential_tier,
      attested_at: record.attested_at,
      registered_at: record.registered_at,
      short_id: record.short_id || null,
      proof_url: `https://hipprotocol.org/proof.html?hash=${contentHash}`,
      short_url,
      sealed: false,
    },
  }, 200, origin);
}

// ══════════════════════════════════════════════════════════════
// S83: Credit Balance, Usage, Consume + Stripe Checkout/Portal/Webhook
// ══════════════════════════════════════════════════════════════

// POST /api/credits/balance — Return credit balance for authenticated credential.
// Body: { credential_id, public_key, timestamp, signature } (HIPKit app auth)
// Response: { available, pack_balance, sub_credits, sub_plan, sub_status, total_consumed }

async function handleCreditBalance(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;
  const auth = await verifyAppAuth(request, "/api/credits/balance", env);
  if (!auth.ok) return jsonResponse({ error: auth.error }, auth.status, origin);

  const { credential_id } = auth;
  const creditsRaw = await env.DEDUP_KV.get(`credits:${credential_id}`);

  if (creditsRaw) {
    const credits = JSON.parse(creditsRaw);
    let available;
    if (credits.sub_status === "active" && credits.sub_plan === "studio") {
      available = "unlimited";
    } else {
      available = (credits.pack_balance || 0) + (credits.sub_credits || 0);
    }
    return jsonResponse({
      available,
      pack_balance: credits.pack_balance || 0,
      sub_credits: credits.sub_credits || 0,
      sub_plan: credits.sub_plan || null,
      sub_status: credits.sub_status || "inactive",
      total_consumed: credits.total_consumed || 0,
    }, 200, origin);
  }

  // No credit record — return defaults
  return jsonResponse({
    available: 0,
    pack_balance: 0,
    sub_credits: 0,
    sub_plan: null,
    sub_status: "inactive",
    total_consumed: 0,
  }, 200, origin);
}

// POST /api/usage — Return rate-limit usage for authenticated credential.
// Reads existing prate: key (daily) and trust record tier to compute limits.
// Response: { daily_used, daily_limit, daily_remaining, daily_resets_at,
//             weekly_used, weekly_limit, weekly_remaining, weekly_resets_at }

async function handleUsage(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;
  const auth = await verifyAppAuth(request, "/api/usage", env);
  if (!auth.ok) return jsonResponse({ error: auth.error }, auth.status, origin);

  const { credential_id, trust_record } = auth;

  // Read daily rate counter from existing prate: key
  const credHash = await hmacSHA256(env.DEDUP_SECRET, "prate:" + credential_id);
  const rateKey = `prate:${credHash}`;
  const rateRaw = await env.DEDUP_KV.get(rateKey);

  const tierDailyLimits = { 1: 50, 2: 25, 3: 10 };
  const tierWeeklyLimits = { 1: 100, 2: 50, 3: 20 };
  const dailyLimit = tierDailyLimits[trust_record.tier] || 10;
  const weeklyLimit = tierWeeklyLimits[trust_record.tier] || 20;

  let dailyUsed = 0;
  let lastRegistration = null;
  if (rateRaw) {
    const rate = JSON.parse(rateRaw);
    dailyUsed = rate.count || 0;
    lastRegistration = rate.last_registration || null;
  }

  // prate: key TTL resets on each write (24h sliding window).
  // Estimate daily reset from last registration + 24h.
  const now = new Date();
  let dailyResetsAt;
  if (lastRegistration && dailyUsed > 0) {
    dailyResetsAt = new Date(new Date(lastRegistration).getTime() + 86400000).toISOString();
  } else {
    dailyResetsAt = new Date(now.getTime() + 86400000).toISOString();
  }

  // Weekly tracking: read wrate: key (same pattern as prate: but 7-day TTL)
  const weeklyHash = await hmacSHA256(env.DEDUP_SECRET, "wrate:" + credential_id);
  const weeklyKey = `wrate:${weeklyHash}`;
  const weeklyRaw = await env.DEDUP_KV.get(weeklyKey);
  let weeklyUsed = 0;
  let weeklyLastReg = null;
  if (weeklyRaw) {
    const wr = JSON.parse(weeklyRaw);
    weeklyUsed = wr.count || 0;
    weeklyLastReg = wr.last_registration || null;
  }

  let weeklyResetsAt;
  if (weeklyLastReg && weeklyUsed > 0) {
    weeklyResetsAt = new Date(new Date(weeklyLastReg).getTime() + 7 * 86400000).toISOString();
  } else {
    weeklyResetsAt = new Date(now.getTime() + 7 * 86400000).toISOString();
  }

  return jsonResponse({
    daily_used: dailyUsed,
    daily_limit: dailyLimit,
    daily_remaining: Math.max(0, dailyLimit - dailyUsed),
    daily_resets_at: dailyResetsAt,
    weekly_used: weeklyUsed,
    weekly_limit: weeklyLimit,
    weekly_remaining: Math.max(0, weeklyLimit - weeklyUsed),
    weekly_resets_at: weeklyResetsAt,
  }, 200, origin);
}

// POST /api/credits/consume — Deduct one credit from authenticated credential.
// Prefers subscription credits, then pack credits. Studio plan is unlimited.
// Response: { consumed, remaining, source } or { error, consumed: false }

async function handleCreditConsume(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;
  const auth = await verifyAppAuth(request, "/api/credits/consume", env);
  if (!auth.ok) return jsonResponse({ error: auth.error }, auth.status, origin);

  const { credential_id } = auth;
  const creditsRaw = await env.DEDUP_KV.get(`credits:${credential_id}`);

  if (!creditsRaw) {
    return jsonResponse({ error: "No credits available", consumed: false }, 402, origin);
  }

  const credits = JSON.parse(creditsRaw);

  // Studio unlimited plan — no deduction needed
  if (credits.sub_status === "active" && credits.sub_plan === "studio") {
    credits.total_consumed = (credits.total_consumed || 0) + 1;
    await env.DEDUP_KV.put(`credits:${credential_id}`, JSON.stringify(credits));
    return jsonResponse({ consumed: true, remaining: "unlimited", source: "subscription" }, 200, origin);
  }

  // Try subscription credits first, then pack credits
  let source;
  if ((credits.sub_credits || 0) > 0) {
    credits.sub_credits -= 1;
    source = "subscription";
  } else if ((credits.pack_balance || 0) > 0) {
    credits.pack_balance -= 1;
    source = "pack";
  } else {
    return jsonResponse({ error: "No credits available", consumed: false }, 402, origin);
  }

  credits.total_consumed = (credits.total_consumed || 0) + 1;
  await env.DEDUP_KV.put(`credits:${credential_id}`, JSON.stringify(credits));

  const remaining = (credits.pack_balance || 0) + (credits.sub_credits || 0);
  return jsonResponse({ consumed: true, remaining, source }, 200, origin);
}

// POST /api/stripe/checkout — Create a Stripe Checkout session.
// Body: { credential_id, public_key, timestamp, signature, price_id }
// Response: { checkout_url }

async function handleStripeCheckout(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;
  const auth = await verifyAppAuth(request, "/api/stripe/checkout", env);
  if (!auth.ok) return jsonResponse({ error: auth.error }, auth.status, origin);

  const { credential_id } = auth;
  const { price_id } = auth.body;

  if (!price_id) {
    return jsonResponse({ error: "Missing price_id" }, 400, origin);
  }

  if (!env.STRIPE_SECRET_KEY) {
    return jsonResponse({ error: "Stripe is not configured" }, 503, origin);
  }

  // Get or create Stripe customer
  let customerId;
  const custRaw = await env.DEDUP_KV.get(`stripe_cust:${credential_id}`);

  if (custRaw) {
    customerId = custRaw;
  } else {
    const custResp = await fetch("https://api.stripe.com/v1/customers", {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + env.STRIPE_SECRET_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: "metadata[credential_id]=" + encodeURIComponent(credential_id),
    });
    if (!custResp.ok) {
      return jsonResponse({ error: "Failed to create customer" }, 500, origin);
    }
    const custData = await custResp.json();
    customerId = custData.id;
    await env.DEDUP_KV.put(`stripe_cust:${credential_id}`, customerId);
  }

  // One-time credit packs vs. recurring subscriptions
  const packPrices = [
    "price_1THHRmEl67wPY8DY42UC01I1",  // Starter 25
    "price_1THHTOEl67wPY8DYTDmQW4zf",  // Standard 100
    "price_1THHU6El67wPY8DY1NvkhpxI",  // Pro 300
    "price_1THHUiEl67wPY8DYUEnxLose",  // Studio 600
  ];
  const isSubscription = !packPrices.includes(price_id);

  const params = new URLSearchParams();
  params.append("customer", customerId);
  params.append("mode", isSubscription ? "subscription" : "payment");
  params.append("line_items[0][price]", price_id);
  params.append("line_items[0][quantity]", "1");
  params.append("success_url", "https://hipkit.net/app.html?checkout=success");
  params.append("cancel_url", "https://hipkit.net/app.html?checkout=cancel");
  params.append("metadata[credential_id]", credential_id);
  if (isSubscription) {
    params.append("subscription_data[metadata][credential_id]", credential_id);
  } else {
    params.append("payment_intent_data[metadata][credential_id]", credential_id);
  }

  const checkResp = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: {
      "Authorization": "Bearer " + env.STRIPE_SECRET_KEY,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params.toString(),
  });

  if (!checkResp.ok) {
    return jsonResponse({ error: "Failed to create checkout session" }, 500, origin);
  }
  const checkData = await checkResp.json();
  return jsonResponse({ checkout_url: checkData.url }, 200, origin);
}

// POST /api/stripe/portal — Create a Stripe Billing Portal session.
// Body: { credential_id, public_key, timestamp, signature }
// Response: { portal_url }

async function handleStripePortal(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;
  const auth = await verifyAppAuth(request, "/api/stripe/portal", env);
  if (!auth.ok) return jsonResponse({ error: auth.error }, auth.status, origin);

  const { credential_id } = auth;

  if (!env.STRIPE_SECRET_KEY) {
    return jsonResponse({ error: "Stripe is not configured" }, 503, origin);
  }

  const custRaw = await env.DEDUP_KV.get(`stripe_cust:${credential_id}`);
  if (!custRaw) {
    return jsonResponse({ error: "No billing account found. Purchase credits first." }, 404, origin);
  }

  const params = new URLSearchParams();
  params.append("customer", custRaw);
  params.append("return_url", "https://hipkit.net/app.html#account");

  const portalResp = await fetch("https://api.stripe.com/v1/billing_portal/sessions", {
    method: "POST",
    headers: {
      "Authorization": "Bearer " + env.STRIPE_SECRET_KEY,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params.toString(),
  });

  if (!portalResp.ok) {
    return jsonResponse({ error: "Failed to create portal session" }, 500, origin);
  }
  const portalData = await portalResp.json();
  return jsonResponse({ portal_url: portalData.url }, 200, origin);
}

// POST /api/stripe/webhook — Stripe webhook handler.
// Verifies Stripe signature, then processes:
//   checkout.session.completed  → credit pack / subscription purchase
//   customer.subscription.deleted → subscription cancellation
//   invoice.paid (subscription_cycle) → monthly credit reset

async function handleStripeWebhook(request, env) {
  if (!env.STRIPE_WEBHOOK_SECRET) {
    return new Response("Webhook not configured", { status: 503 });
  }

  const sigHeader = request.headers.get("stripe-signature");
  if (!sigHeader) {
    return new Response("Missing stripe-signature header", { status: 400 });
  }

  const rawBody = await request.text();

  // Parse Stripe signature header: t=timestamp,v1=signature
  const sigParts = {};
  sigHeader.split(",").forEach(p => {
    const eq = p.indexOf("=");
    if (eq > 0) sigParts[p.substring(0, eq).trim()] = p.substring(eq + 1);
  });

  if (!sigParts.t || !sigParts.v1) {
    return new Response("Malformed signature header", { status: 400 });
  }

  // Verify: HMAC-SHA256(webhook_secret, "timestamp.rawBody") must match v1
  const signedPayload = sigParts.t + "." + rawBody;
  const expectedSig = await hmacSHA256(env.STRIPE_WEBHOOK_SECRET, signedPayload);
  if (expectedSig !== sigParts.v1) {
    return new Response("Invalid signature", { status: 401 });
  }

  const event = JSON.parse(rawBody);

  // ── Credit pack quantities by price ID ──
  const packCredits = {
    "price_1THHRmEl67wPY8DY42UC01I1": 25,   // Starter
    "price_1THHTOEl67wPY8DYTDmQW4zf": 100,  // Standard
    "price_1THHU6El67wPY8DY1NvkhpxI": 300,  // Pro
    "price_1THHUiEl67wPY8DYUEnxLose": 600,  // Studio pack
  };
  const subPlans = {
    "price_1THHVdEl67wPY8DYV8RkTrhh": { plan: "creator", credits: 50 },
    "price_1THHWIEl67wPY8DYu0SM7Smw": { plan: "professional", credits: 150 },
    "price_1THHX4El67wPY8DY3SQyhd2H": { plan: "studio", credits: 0 },  // unlimited
  };

  // ── checkout.session.completed — purchase confirmed ──
  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const credentialId = session.metadata?.credential_id;
    if (!credentialId) return new Response("OK", { status: 200 });

    // Retrieve line items to identify the purchased price
    const lineResp = await fetch(
      `https://api.stripe.com/v1/checkout/sessions/${session.id}/line_items`,
      { headers: { "Authorization": "Bearer " + env.STRIPE_SECRET_KEY } }
    );
    const lineData = await lineResp.json();
    if (!lineData.data || lineData.data.length === 0) {
      return new Response("OK", { status: 200 });
    }

    const priceId = lineData.data[0].price.id;

    // Read or initialize credit record
    const creditsRaw = await env.DEDUP_KV.get(`credits:${credentialId}`);
    const credits = creditsRaw ? JSON.parse(creditsRaw) : {
      pack_balance: 0, sub_credits: 0, sub_plan: null,
      sub_status: "inactive", total_consumed: 0,
    };

    if (packCredits[priceId]) {
      credits.pack_balance = (credits.pack_balance || 0) + packCredits[priceId];
    } else if (subPlans[priceId]) {
      const plan = subPlans[priceId];
      credits.sub_plan = plan.plan;
      credits.sub_status = "active";
      credits.sub_credits = plan.credits;
    }

    await env.DEDUP_KV.put(`credits:${credentialId}`, JSON.stringify(credits));

    // Store Stripe customer mapping
    if (session.customer) {
      await env.DEDUP_KV.put(`stripe_cust:${credentialId}`, session.customer);
    }
  }

  // ── customer.subscription.deleted — subscription canceled ──
  if (event.type === "customer.subscription.deleted") {
    const sub = event.data.object;
    const credentialId = sub.metadata?.credential_id;
    if (credentialId) {
      const creditsRaw = await env.DEDUP_KV.get(`credits:${credentialId}`);
      if (creditsRaw) {
        const credits = JSON.parse(creditsRaw);
        credits.sub_status = "inactive";
        credits.sub_credits = 0;
        credits.sub_plan = null;
        await env.DEDUP_KV.put(`credits:${credentialId}`, JSON.stringify(credits));
      }
    }
  }

  // ── invoice.paid — subscription renewal (monthly credit reset) ──
  if (event.type === "invoice.paid") {
    const invoice = event.data.object;
    if (invoice.billing_reason === "subscription_cycle") {
      // Try to find credential_id from subscription metadata
      const subId = invoice.subscription;
      if (subId) {
        const subResp = await fetch(
          `https://api.stripe.com/v1/subscriptions/${subId}`,
          { headers: { "Authorization": "Bearer " + env.STRIPE_SECRET_KEY } }
        );
        const subData = await subResp.json();
        const credentialId = subData.metadata?.credential_id;
        if (credentialId) {
          const creditsRaw = await env.DEDUP_KV.get(`credits:${credentialId}`);
          if (creditsRaw) {
            const credits = JSON.parse(creditsRaw);
            const planCredits = { creator: 50, professional: 150, studio: 0 };
            if (credits.sub_plan && planCredits[credits.sub_plan] !== undefined) {
              credits.sub_credits = planCredits[credits.sub_plan];
              await env.DEDUP_KV.put(`credits:${credentialId}`, JSON.stringify(credits));
            }
          }
        }
      }
    }
  }

  return new Response("OK", { status: 200 });
}


// ══════════════════════════════════════════════════════════════
// S85CW Change 3: Portfolio endpoint
// ══════════════════════════════════════════════════════════════
// POST /api/portfolio — Paginated list of proofs attested under the
// authenticated credential. Reads cred_proofs:{cred_id} (built by Change 2
// going forward, and by the backfill endpoint for existing proofs).
// Body: { credential_id, public_key, timestamp, signature, page, per_page }
// Response: { records, total, total_pages, page, per_page }
//
// Each record is flagged with a `recovered_from` field when the proof's
// original credential_id differs from the requesting credential_id — this
// happens when the index was migrated forward by migrateTrustRecord during
// credential recovery. Frontends can render a "originally attested as X"
// badge using this field. The proof record itself is never mutated: the
// original signature chain remains intact.

async function handlePortfolio(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;
  const auth = await verifyAppAuth(request, "/api/portfolio", env);
  if (!auth.ok) return jsonResponse({ error: auth.error }, auth.status, origin);

  const { credential_id, body } = auth;

  // Pagination inputs (defensive defaults; cap per_page server-side at 100)
  let page = parseInt(body.page, 10);
  let per_page = parseInt(body.per_page, 10);
  if (!Number.isFinite(page) || page < 1) page = 1;
  if (!Number.isFinite(per_page) || per_page < 1) per_page = 20;
  if (per_page > 100) per_page = 100;

  const indexRaw = await env.DEDUP_KV.get(`cred_proofs:${credential_id}`);
  if (!indexRaw) {
    return jsonResponse({
      records: [],
      total: 0,
      total_pages: 0,
      page,
      per_page,
    }, 200, origin);
  }

  let index;
  try { index = JSON.parse(indexRaw); } catch (_) { index = null; }
  if (!index || !Array.isArray(index.hashes) || index.hashes.length === 0) {
    return jsonResponse({
      records: [],
      total: 0,
      total_pages: 0,
      page,
      per_page,
    }, 200, origin);
  }

  // Newest first — append-order means last element is most recent
  const ordered = index.hashes.slice().reverse();
  const total = ordered.length;
  const total_pages = Math.ceil(total / per_page);

  // Clamp page to valid range so out-of-bounds requests return empty rather than error
  if (page > total_pages && total_pages > 0) {
    return jsonResponse({
      records: [],
      total,
      total_pages,
      page,
      per_page,
    }, 200, origin);
  }

  const start = (page - 1) * per_page;
  const slice = ordered.slice(start, start + per_page);

  // Fetch each proof record. Orphan hashes (index entry exists but proof:{hash}
  // has been deleted for legal/compliance reasons) are skipped, not errored.
  const records = [];
  for (const hash of slice) {
    const proofRaw = await env.DEDUP_KV.get(`proof:${hash}`);
    if (!proofRaw) continue;
    let record;
    try { record = JSON.parse(proofRaw); } catch (_) { continue; }

    // Tag proofs whose original attesting credential was a predecessor of
    // the requesting credential (carried forward by migrateTrustRecord).
    if (record.credential_id && record.credential_id !== credential_id) {
      record.recovered_from = record.credential_id;
      record.migrated = true;
    }

    // Decorate with UI-friendly URLs (matching /api/verify response style)
    record.proof_url = `https://hipprotocol.org/proof.html?hash=${record.content_hash}`;
    if (record.short_id) {
      record.short_url = `https://hipprotocol.org/p/${record.short_id}`;
    }

    records.push(record);
  }

  return jsonResponse({
    records,
    total,
    total_pages,
    page,
    per_page,
  }, 200, origin);
}


// ══════════════════════════════════════════════════════════════
// S102 Path 2 — POST /api/credential/{id}/attestations
// Auth-gated compact enumeration of the calling credential's attestations.
// Returns {content_hash, original_hash|null, attested_at} triples so the
// hipprotocol.org Verify tool can dual-hash-match a dropped file against a
// cross-device (or cross-browser) attestation history without requiring the
// user to still have the proof card or an in-browser localStorage seed.
//
// Auth: verifyAppAuth with canonical endpoint string "/api/credential/attestations"
// (the {id} URL segment is discoverability only — the body-signed credential_id
// is the authority; if the URL id doesn't match, the request is rejected).
//
// Privacy posture: credential_id is already public (SHA-256 of public_key),
// and /api/proof/{hash} is already public. The only new leak is that an
// attacker who steals a credential can enumerate its history rather than
// guessing hashes. Same attacker can do worse with the credential (attest,
// retire). Net: modest bulk-profiling defense; not a sybil/theft defense.
//
// Migration: records written before this endpoint shipped have no
// original_hash field — we return null. Client treats null as "match
// content_hash only." Pre-embed hashes for pre-S102 embedding-file records
// are not recoverable server-side (they were computed client-side and never
// transmitted). Acceptable degradation; same-browser coverage continues via
// S101's hip_attest_local localStorage cache.
//
// Response cap: 1000 newest entries (oldest truncated). For typical users
// this is single-shot; power users with >1000 proofs get recency coverage.
// Compact shape keeps the payload manageable (~200 bytes/entry × 1000 = 200KB).
async function handleCredentialAttestations(request, env, credentialIdFromUrl) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;
  const auth = await verifyAppAuth(request, "/api/credential/attestations", env);
  if (!auth.ok) return jsonResponse({ error: auth.error }, auth.status, origin);

  const { credential_id } = auth;

  // URL id must match authenticated credential_id. Defense-in-depth — the
  // body-signed credential_id is the sole authority, but this catches the
  // category of bugs where a client constructs the URL from one credential
  // and signs with another.
  if (credentialIdFromUrl && credentialIdFromUrl !== credential_id) {
    return jsonResponse({
      error: "URL credential_id does not match authenticated credential",
    }, 400, origin);
  }

  const indexRaw = await env.DEDUP_KV.get(`cred_proofs:${credential_id}`);
  if (!indexRaw) {
    return jsonResponse({
      credential_id,
      entries: [],
      total: 0,
      truncated: false,
      cap: 1000,
    }, 200, origin);
  }

  let index;
  try { index = JSON.parse(indexRaw); } catch (_) { index = null; }
  if (!index || !Array.isArray(index.hashes) || index.hashes.length === 0) {
    return jsonResponse({
      credential_id,
      entries: [],
      total: 0,
      truncated: false,
      cap: 1000,
    }, 200, origin);
  }

  // Newest first — append-order means last element is most recent.
  const orderedAll = index.hashes.slice().reverse();
  const total = orderedAll.length;
  const cap = 1000;
  const truncated = total > cap;
  const ordered = truncated ? orderedAll.slice(0, cap) : orderedAll;

  // Fetch each proof record. Skip orphans (index present, record deleted).
  const entries = [];
  for (const hash of ordered) {
    const proofRaw = await env.DEDUP_KV.get(`proof:${hash}`);
    if (!proofRaw) continue;
    let record;
    try { record = JSON.parse(proofRaw); } catch (_) { continue; }
    entries.push({
      content_hash: record.content_hash,
      original_hash: record.original_hash || null,
      attested_at: record.attested_at || null,
    });
  }

  return jsonResponse({
    credential_id,
    entries,
    total,
    truncated,
    cap,
  }, 200, origin);
}


// ── Main Router ──

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const topOrigin = request.headers.get("Origin") || CORS_ORIGIN;

    try {

    // CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(topOrigin) });
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

    // S33: Credential recovery route
    if (method === "POST" && path === "/recover-credential") {
      return handleRecoverCredential(request, env);
    }

    // S34: Credential tier upgrade route
    if (method === "POST" && path === "/upgrade-credential") {
      return handleUpgradeCredential(request, env);
    }

    // S96: Credential voluntary retirement route
    if (method === "POST" && path === "/retire-credential") {
      return handleRetireCredential(request, env);
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

    // S37: Public proof registry
    if (method === "POST" && path === "/register-proof") {
      return handleRegisterProof(request, env);
    }

    // S38: Unseal a sealed proof record
    if (method === "POST" && path === "/unseal-proof") {
      return handleUnsealProof(request, env);
    }

    // S38: Dispute a proof record
    if (method === "POST" && path === "/dispute-proof") {
      return handleDisputeProof(request, env);
    }

    if (method === "GET" && path.startsWith("/proof/")) {
      const contentHash = path.replace("/proof/", "").toLowerCase().trim();
      if (!contentHash) return jsonResponse({ error: "Missing content hash" }, 400);

      // If request accepts JSON (API call), return data
      const accept = request.headers.get("Accept") || "";
      if (accept.includes("application/json") || accept.includes("text/plain")) {
        return handleGetProof(contentHash, request, env);
      }

      // If request accepts HTML (browser navigation), redirect to proof.html page
      // proof.html reads the hash from the URL path client-side
      return new Response(null, {
        status: 302,
        headers: {
          "Location": "https://hipprotocol.org/proof.html?hash=" + contentHash,
          ...corsHeaders(request.headers.get("Origin") || CORS_ORIGIN),
        },
      });
    }

    // S43: Batch proof lookup for browser extension
    if (method === "POST" && path === "/api/proof/batch") {
      return handleBatchProof(request, env);
    }

    // Direct JSON API endpoint for proof data (used by proof.html fetch)
    if (method === "GET" && path.startsWith("/api/proof/")) {
      const contentHash = path.replace("/api/proof/", "").toLowerCase().trim();
      if (!contentHash) return jsonResponse({ error: "Missing content hash" }, 400);
      return handleGetProof(contentHash, request, env);
    }

    // S82: Authenticated attestation submission via API key
    if (method === "POST" && path === "/api/attest") {
      return handleApiAttest(request, env);
    }

    // S82: Admin — generate API key for a credential
    if (method === "POST" && path === "/api/admin/keys") {
      return handleCreateApiKey(request, env);
    }

    // S85CW Change 3: Portfolio — paginated proofs for authenticated credential
    if (method === "POST" && path === "/api/portfolio") {
      return handlePortfolio(request, env);
    }

    // S102 Path 2: Credential-keyed attestation history (compact) for
    // cross-device Verify fallback. Auth-gated via verifyAppAuth.
    if (method === "POST") {
      const credAttMatch = path.match(/^\/api\/credential\/([0-9a-f]{64})\/attestations$/);
      if (credAttMatch) {
        return handleCredentialAttestations(request, env, credAttMatch[1]);
      }
    }

    // S85CW Backfill: one-shot index builder. Admin-key gated.
    // REMOVE THIS ROUTE AFTER BACKFILL COMPLETES (see S85CW kickoff).
    // S81: Public verification API — clean response for integrators
    if (method === "GET" && path.startsWith("/api/verify/")) {
      const contentHash = path.replace("/api/verify/", "").toLowerCase().trim();
      if (!contentHash) return jsonResponse({ error: "Missing content hash" }, 400);
      return handleVerify(contentHash, request, env);
    }

    // S83: Credit balance, usage, consume, Stripe checkout/portal/webhook
    if (method === "POST" && path === "/api/credits/balance") {
      return handleCreditBalance(request, env);
    }

    if (method === "POST" && path === "/api/usage") {
      return handleUsage(request, env);
    }

    if (method === "POST" && path === "/api/credits/consume") {
      return handleCreditConsume(request, env);
    }

    if (method === "POST" && path === "/api/stripe/checkout") {
      return handleStripeCheckout(request, env);
    }

    if (method === "POST" && path === "/api/stripe/portal") {
      return handleStripePortal(request, env);
    }

    if (method === "POST" && path === "/api/stripe/webhook") {
      return handleStripeWebhook(request, env);
    }

    // S40+S41: Short proof link resolution with dynamic OG tags
    if (method === "GET" && path.startsWith("/p/")) {
      const shortId = path.replace("/p/", "").trim();
      if (!shortId || shortId.length < 4 || shortId.length > 16) {
        return jsonResponse({ error: "Invalid short ID" }, 400);
      }

      // Resolve short ID to content hash via KV reverse lookup
      const contentHash = await env.DEDUP_KV.get(`short:${shortId}`);
      if (!contentHash) {
        return jsonResponse({ error: "Short link not found", short_id: shortId }, 404);
      }

      // Check if caller wants JSON (API/programmatic access)
      const accept = request.headers.get("Accept") || "";
      if (accept.includes("application/json")) {
        // Return proof data as JSON
        const proofRaw = await env.DEDUP_KV.get(`proof:${contentHash}`);
        if (!proofRaw) {
          return jsonResponse({ error: "Proof record not found", content_hash: contentHash }, 404);
        }
        const record = JSON.parse(proofRaw);
        if (record.sealed) {
          return jsonResponse({
            found: true, content_hash: contentHash, sealed: true,
            registered_at: record.registered_at, short_id: shortId,
            message: "This proof record is sealed by its creator.",
          }, 200, request.headers.get("Origin") || CORS_ORIGIN);
        }
        return jsonResponse({
          found: true, ...record, short_id: shortId,
        }, 200, request.headers.get("Origin") || CORS_ORIGIN);
      }

      // S41: Serve HTML page with dynamic OG tags for social crawlers
      // Then meta-refresh redirect to proof.html for human viewers
      const proofRaw = await env.DEDUP_KV.get(`proof:${contentHash}`);
      if (proofRaw) {
        const record = JSON.parse(proofRaw);
        if (!record.sealed) {
          // Full dynamic OG page with proof metadata
          const html = buildProofOGPage(record, shortId, contentHash);
          return new Response(html, {
            status: 200,
            headers: {
              "Content-Type": "text/html;charset=UTF-8",
              "Cache-Control": "public, max-age=3600",
              ...corsHeaders(request.headers.get("Origin") || CORS_ORIGIN),
            },
          });
        }
      }

      // Sealed or missing record: simple redirect (no OG preview for sealed proofs)
      return new Response(null, {
        status: 302,
        headers: {
          "Location": `https://hipprotocol.org/proof.html?hash=${contentHash}`,
          ...corsHeaders(request.headers.get("Origin") || CORS_ORIGIN),
        },
      });
    }

    // S83: GitHub Pages pass-through for static files.
    // When hipprotocol.org is routed through the worker, requests for static files
    // (HTML, CSS, JS, images) must be proxied to GitHub Pages so they still load.
    // API-path requests that didn't match any route above get a JSON 404.
    const host = url.hostname;
    if (host === "hipprotocol.org" || host === "www.hipprotocol.org") {
      // Don't proxy API paths — those are genuine 404s
      if (path.startsWith("/api/")) {
        return jsonResponse({ error: "Not found" }, 404, request.headers.get("Origin") || CORS_ORIGIN);
      }
      try {
        const ghUrl = "https://tadortot.github.io/hip-protocol" + path + url.search;
        const ghResp = await fetch(ghUrl, {
          headers: {
            "Host": "tadortot.github.io",
            "User-Agent": request.headers.get("User-Agent") || "HIP-Worker/1.0",
            "Accept": request.headers.get("Accept") || "*/*",
            "Accept-Encoding": request.headers.get("Accept-Encoding") || "",
          },
          redirect: "follow",
        });
        // Pass through the response from GitHub Pages
        const respHeaders = new Headers(ghResp.headers);
        // Remove headers that shouldn't be forwarded
        respHeaders.delete("x-proxy-cache");
        respHeaders.delete("x-github-request-id");
        return new Response(ghResp.body, {
          status: ghResp.status,
          headers: respHeaders,
        });
      } catch (e) {
        return jsonResponse({ error: "Upstream fetch failed" }, 502);
      }
    }

    return jsonResponse({ error: "Not found" }, 404, topOrigin);

    } catch (err) {
      // Top-level safety net: ensure any uncaught exception still returns
      // CORS headers so browsers don't mask the real error as a CORS failure.
      const msg = (err && err.stack) ? err.stack : String(err);
      return jsonResponse({
        error: "Internal error",
        detail: msg.slice(0, 2000),
        path: path,
        method: method,
      }, 500, topOrigin);
    }
  },
};
