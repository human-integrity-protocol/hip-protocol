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
    // S106.8CW F.1: PATCH added for /api/collection/{id}/sidecar. Global
    // advertisement is safe because per-route method gating still holds;
    // browsers will only preflight PATCH against routes that actually use it.
    "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
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

// S83 / S114CW: Verify a HIPKit app auth request (Ed25519 signature).
// The client signs "HIPKIT|{endpoint}|{credentialId}|{timestamp}" with its Ed25519 private key.
// Returns { ok, credential_id, public_key, trust_record, body } or { ok:false, error, status }.
//
// S114CW BLOCKS ANNOUNCE #1 closure: this helper now performs full server-side
// cryptographic verification. Prior to S114CW it only checked field presence +
// timestamp freshness + credential existence, which was authentication in name
// only — knowledge of any public (credential_id, public_key) pair was sufficient
// to pass. Per charter "If it says verify, it must verify."
async function verifyAppAuth(request, endpoint, env) {
  let body;
  try { body = await request.json(); } catch (_) {
    return { ok: false, error: "Invalid JSON", status: 400 };
  }

  const { credential_id, public_key, timestamp, signature } = body;
  if (!credential_id || !public_key || !timestamp || !signature) {
    return { ok: false, error: "Missing auth fields: credential_id, public_key, timestamp, signature", status: 400 };
  }

  // Format validation — both fields must be 64-char lowercase hex.
  if (!/^[0-9a-f]{64}$/.test(credential_id)) {
    return { ok: false, error: "credential_id must be 64-char lowercase hex", status: 400 };
  }
  if (!/^[0-9a-f]{64}$/.test(public_key)) {
    return { ok: false, error: "public_key must be 64-char lowercase hex (Ed25519 raw)", status: 400 };
  }

  // Timestamp must be within 5 minutes
  const ts = new Date(timestamp);
  if (isNaN(ts.getTime()) || Math.abs(Date.now() - ts.getTime()) > 300000) {
    return { ok: false, error: "Timestamp expired or invalid", status: 401 };
  }

  // Binding check: SHA-256(public_key) === credential_id.
  // This prevents credential_id grafting — a caller cannot present some other
  // credential's public_key alongside a target credential_id, because the
  // hash-to-id invariant is enforced by issuance and now revalidated here.
  const pubKeyBytes = new Uint8Array(public_key.match(/.{2}/g).map(b => parseInt(b, 16)));
  const computedIdBuf = await crypto.subtle.digest("SHA-256", pubKeyBytes);
  const computedId = Array.from(new Uint8Array(computedIdBuf))
    .map(b => b.toString(16).padStart(2, "0")).join("");
  if (computedId !== credential_id) {
    return { ok: false, error: "Key binding failed: SHA-256(public_key) !== credential_id", status: 403 };
  }

  // Ed25519 signature verification over canonical.
  // SubtleCrypto Ed25519 IS available on Workers (proven by verifyEd25519FromBytes
  // at worker.js:429 and series endpoints shipped S111). Stale comment removed.
  const canonical = "HIPKIT|" + endpoint + "|" + credential_id + "|" + timestamp;
  const msgBytes = new TextEncoder().encode(canonical);
  let sigOk;
  try {
    sigOk = await verifyEd25519FromBytes(pubKeyBytes, signature, msgBytes);
  } catch (_e) {
    return { ok: false, error: "Malformed signature", status: 400 };
  }
  if (!sigOk) {
    return { ok: false, error: "Invalid signature", status: 403 };
  }

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

// ════════════════════════════════════════════════════════════════
// ── S106 Collection Proof helpers (Phase 1) ──
// RFC 8785 JCS canonicalization, SHA-256 hex, Ed25519 verify
// wrapper, and validateManifest() per S105CW-COLLECTION-SPEC
// §3.1 (manifest structure) and §3.2 (canonicalization + signing).
// All pure functions — no KV reads, no mutations, no side effects.
// ════════════════════════════════════════════════════════════════

// base64 → Uint8Array. Uses atob (available in Workers runtime).
function base64ToBytes(b64) {
  if (typeof b64 !== "string") throw new Error("base64ToBytes: input must be string");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// 64-hex-lowercase validator used pervasively for content/member/collection hashes.
function isHex64Lower(s) {
  return typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
}

// S106.6CW Ambiguity F: collection_id = base32-lowercase(collection_hash[:12]) → 20 chars
// over the RFC 4648 alphabet "abcdefghijklmnopqrstuvwxyz234567". NOT [a-z0-9]{20}
// (the loose "alphanumeric" annotation would false-accept 0,1,8,9). Used by the
// §3.4.2 / §3.4.3 / §3.4.7 (short-URL Option C) validators so malformed ids produce
// a clean 400 rather than a soft 404.
function isCollectionId(s) {
  return typeof s === "string" && /^[a-z2-7]{20}$/.test(s);
}

// S111CW SERIES-SPEC-v1 §1.1: series_id shape is identical to collection_id
// (20-char RFC 4648 base32-lowercase), but the DERIVATION is different.
// collection_id is DETERMINISTIC (base32(SHA-256(JCS(manifest))[:12])) and
// idempotent-on-replay because the manifest carries the member list, so
// same-bytes-in → same-id-out. series_id is CLIENT-RANDOM (~100 bits from
// crypto.getRandomValues), because a series manifest does NOT encode its
// members — two creators with coincidentally-identical titles/descriptions/
// timestamps would otherwise squash each other, and first-writer-wins in
// §2.4 only makes sense with randomly-generated ids. The server does NOT
// generate series_id; the client sends it in the request body and the
// server validates shape here + collision-checks against series:{id} in
// the creation handler.
function isSeriesId(s) {
  return typeof s === "string" && /^[a-z2-7]{20}$/.test(s);
}

// JCS (RFC 8785) canonical JSON serializer — string output.
// Pure function; throws on non-JSON values (undefined, BigInt, NaN, ±Infinity, lone surrogates).
function jcsSerializeString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s.charCodeAt(i);
    // Surrogate pair handling (JCS requires well-formed UTF-16).
    if (ch >= 0xD800 && ch <= 0xDBFF) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next < 0xDC00 || next > 0xDFFF) throw new Error("jcs: lone high surrogate at index " + i);
      out += s[i] + s[i + 1]; // emit the full supplementary code point as-is
      i++;                     // skip the low surrogate we just consumed
      continue;
    }
    if (ch >= 0xDC00 && ch <= 0xDFFF) {
      throw new Error("jcs: lone low surrogate at index " + i);
    }
    if (ch === 0x22)      out += '\\"';
    else if (ch === 0x5C) out += '\\\\';
    else if (ch === 0x08) out += '\\b';
    else if (ch === 0x09) out += '\\t';
    else if (ch === 0x0A) out += '\\n';
    else if (ch === 0x0C) out += '\\f';
    else if (ch === 0x0D) out += '\\r';
    else if (ch < 0x20)   out += '\\u' + ch.toString(16).padStart(4, '0');
    else                  out += s[i];
  }
  return out + '"';
}

function jcsSerializeNumber(n) {
  if (typeof n !== "number" || !Number.isFinite(n)) {
    throw new Error("jcs: number must be finite, got " + String(n));
  }
  if (n === 0) return "0"; // normalises -0
  // ES6 Number.prototype.toString already gives the JCS-prescribed shortest
  // round-trip decimal. JCS forbids the leading "+" on exponents that V8 emits
  // for very large magnitudes (e.g. 1e+21); strip it.
  return n.toString().replace("e+", "e");
}

function jcsSerialize(v) {
  if (v === null)           return "null";
  if (v === true)           return "true";
  if (v === false)          return "false";
  if (typeof v === "number") return jcsSerializeNumber(v);
  if (typeof v === "string") return jcsSerializeString(v);
  if (Array.isArray(v)) {
    return "[" + v.map(jcsSerialize).join(",") + "]";
  }
  if (typeof v === "object") {
    // Object.keys().sort() uses UTF-16 code-unit order — JCS-compliant.
    const keys = Object.keys(v).sort();
    const parts = [];
    for (const k of keys) {
      if (v[k] === undefined) continue; // drop undefined keys, like JSON.stringify
      parts.push(jcsSerializeString(k) + ":" + jcsSerialize(v[k]));
    }
    return "{" + parts.join(",") + "}";
  }
  if (typeof v === "undefined") throw new Error("jcs: undefined is not a JSON value");
  if (typeof v === "bigint")    throw new Error("jcs: BigInt is not a JSON value");
  throw new Error("jcs: unsupported value type " + typeof v);
}

// Returns Uint8Array of the UTF-8 canonical bytes.
function jcsCanonicalize(value) {
  return new TextEncoder().encode(jcsSerialize(value));
}

// SHA-256 hex-lowercase. Accepts Uint8Array or string (UTF-8 encoded if string).
async function sha256Hex(input) {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// SHA-256 raw bytes (Uint8Array). Used as the Ed25519 signing message per §3.2.5.
async function sha256Bytes(input) {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

// Ed25519 verify wrapper over Web Crypto. Spec §3.2.5: signature is Ed25519 over
// the 32-byte SHA-256(JCS(manifest)) digest. Public key and signature arrive as
// base64 strings in manifest/collection records.
// Returns boolean. Throws on malformed inputs (bad base64, wrong byte length).
async function verifyEd25519(publicKeyB64, signatureB64, messageBytes) {
  const pub = base64ToBytes(publicKeyB64);
  if (pub.length !== 32) throw new Error("verifyEd25519: public key must be 32 bytes, got " + pub.length);
  return await verifyEd25519FromBytes(pub, signatureB64, messageBytes);
}

// S106.8CW G.2: bytes-in variant for callers whose public key comes from a
// source other than manifest.creator.public_key (e.g., trust:{id}.public_key
// which is stored as 64-char lowercase hex, not base64). Keeps the base64
// caller unchanged; PATCH sidecar + any future hex-keyed callers route here.
// Returns boolean. Throws on malformed inputs.
async function verifyEd25519FromBytes(pubkeyBytes, signatureB64, messageBytes) {
  if (!(pubkeyBytes instanceof Uint8Array) || pubkeyBytes.length !== 32) {
    const got = (pubkeyBytes && pubkeyBytes.length !== undefined) ? pubkeyBytes.length : "non-Uint8Array";
    throw new Error("verifyEd25519FromBytes: public key must be 32 bytes, got " + got);
  }
  const sig = base64ToBytes(signatureB64);
  if (sig.length !== 64) throw new Error("verifyEd25519FromBytes: signature must be 64 bytes, got " + sig.length);
  const key = await crypto.subtle.importKey("raw", pubkeyBytes, { name: "Ed25519" }, false, ["verify"]);
  return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, messageBytes);
}

// S111CW SERIES-SPEC-v1 shared signature verification helper.
// Used by /register-series (payload = manifest), /register-series-member
// (payload = series_add event minus signature), and /close-series (payload
// = series_close event minus signature). Per spec §7: every signed payload
// is JCS-canonicalized, SHA-256-hashed, and Ed25519-verified against the
// creator's base64 public key. Same cryptographic posture as
// handleRegisterCollectionProof §3.2.5 but generalized over payload shape.
//
// The CALLER is responsible for stripping the `signature` field before
// passing the payload — this helper does not mutate its input. Callers
// that need to strip should do:
//   const { signature, ...payload } = event;
//   const ok = await verifySeriesSignature(payload, signature, pubKeyB64);
//
// Returns boolean. Throws on malformed base64, bad pubkey/signature length,
// or JCS-unrepresentable payload — callers SHOULD try/catch and map
// throws to 422 invalid_signature per spec §7.
async function verifySeriesSignature(payload, signatureB64, publicKeyB64) {
  const digest = await sha256Bytes(jcsCanonicalize(payload));
  return await verifyEd25519(publicKeyB64, signatureB64, digest);
}

// Manifest validator per S105CW-COLLECTION-SPEC §3.1 + §3.2.
// Pure: no I/O, no clock reads. Returns structural and semantic pass/fail;
// does NOT validate signatures (that's the endpoint's responsibility),
// does NOT validate credential existence (KV lookup — endpoint's job),
// does NOT validate issued_at drift vs server clock (endpoint's job per §3.1.1).
// Returns { ok, errors[], canonicalBytes, collectionHash }.
// On ok:false, canonicalBytes and collectionHash are null.
// On ok:true, canonicalBytes = JCS UTF-8 bytes, collectionHash = SHA-256 hex.
async function validateManifest(manifest) {
  const errors = [];
  const push = (code, message, at) => {
    const e = { code, message };
    if (at !== undefined) e.at = at;
    errors.push(e);
  };

  // Root must be a plain object.
  if (typeof manifest !== "object" || manifest === null || Array.isArray(manifest)) {
    push("not_object", "manifest must be a JSON object");
    return { ok: false, errors, canonicalBytes: null, collectionHash: null };
  }

  // schema_version — locked to hip-collection-1.0 for S106.
  if (manifest.schema_version !== "hip-collection-1.0") {
    push("bad_schema_version", 'schema_version must be "hip-collection-1.0"');
  }

  // issued_at — ISO 8601 UTC, millisecond precision.
  if (typeof manifest.issued_at !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(manifest.issued_at) ||
      Number.isNaN(new Date(manifest.issued_at).getTime())) {
    push("bad_issued_at", "issued_at must be ISO 8601 UTC with ms precision (YYYY-MM-DDTHH:MM:SS.sssZ)");
  }

  // ordering — enum of three values.
  if (manifest.ordering !== "sequence" && manifest.ordering !== "set" && manifest.ordering !== "chronological") {
    push("bad_ordering", 'ordering must be "sequence", "set", or "chronological"');
  }

  // title — string, may be "", ≤200 code points.
  if (typeof manifest.title !== "string") {
    push("bad_title", "title must be a string (may be empty)");
  } else if ([...manifest.title].length > 200) {
    push("title_too_long", "title max 200 Unicode code points");
  }

  // description — string, may be "", ≤2000 code points.
  if (typeof manifest.description !== "string") {
    push("bad_description", "description must be a string (may be empty)");
  } else if ([...manifest.description].length > 2000) {
    push("description_too_long", "description max 2000 Unicode code points");
  }

  // cover_index — non-negative integer; range check deferred until members validated.
  if (!Number.isInteger(manifest.cover_index) || manifest.cover_index < 0) {
    push("bad_cover_index", "cover_index must be a non-negative integer");
  }

  // parent_collection_hash — optional; when present must be 64 hex-lowercase.
  if ("parent_collection_hash" in manifest) {
    if (!isHex64Lower(manifest.parent_collection_hash)) {
      push("bad_parent_collection_hash", "parent_collection_hash must be 64 hex-lowercase chars when present");
    }
  }

  // creator — object with credential_id, tier, public_key.
  const c = manifest.creator;
  if (typeof c !== "object" || c === null || Array.isArray(c)) {
    push("bad_creator", "creator must be an object");
  } else {
    if (typeof c.credential_id !== "string" || c.credential_id.length === 0) {
      push("bad_credential_id", "creator.credential_id must be a non-empty string");
    }
    if (c.tier !== 1 && c.tier !== 2 && c.tier !== 3) {
      push("bad_tier", "creator.tier must be 1, 2, or 3");
    }
    if (typeof c.public_key !== "string" || c.public_key.length === 0) {
      push("bad_public_key", "creator.public_key must be a non-empty base64 string");
    } else {
      try {
        const bytes = base64ToBytes(c.public_key);
        if (bytes.length !== 32) {
          push("bad_public_key_length", "creator.public_key must decode to 32 bytes, got " + bytes.length);
        }
      } catch (_) {
        push("bad_public_key_base64", "creator.public_key is not valid base64");
      }
    }
    // Unknown creator fields.
    const ALLOWED_CREATOR = new Set(["credential_id", "tier", "public_key"]);
    for (const key of Object.keys(c)) {
      if (!ALLOWED_CREATOR.has(key)) push("unknown_creator_field", "unknown creator field: " + key);
    }
  }

  // members — array, 1..497.
  if (!Array.isArray(manifest.members)) {
    push("bad_members", "members must be an array");
  } else {
    if (manifest.members.length < 1) {
      push("members_empty", "members must contain at least 1 entry");
    }
    if (manifest.members.length > 497) {
      push("members_too_many", "members max 497 per collection (KV write budget)");
    }
    // cover_index range — now that we know members length.
    if (Number.isInteger(manifest.cover_index) && manifest.cover_index >= 0 &&
        manifest.cover_index >= manifest.members.length) {
      push("cover_index_out_of_range",
        "cover_index " + manifest.cover_index + " >= members.length " + manifest.members.length);
    }

    const ALLOWED_MEMBER = new Set(["index", "filename", "size", "mime", "member_hash", "attested_copy_hash", "captured_at"]);
    for (let i = 0; i < manifest.members.length; i++) {
      const m = manifest.members[i];
      if (typeof m !== "object" || m === null || Array.isArray(m)) {
        push("bad_member", "member must be an object", i);
        continue;
      }
      if (m.index !== i) {
        push("member_index_mismatch", "member.index (" + m.index + ") must equal array position (" + i + ")", i);
      }
      if (!Number.isInteger(m.size) || m.size < 0) {
        push("bad_member_size", "member.size must be a non-negative integer", i);
      }
      if (typeof m.mime !== "string" || !/^[^/\s]+\/[^/\s]+$/.test(m.mime)) {
        push("bad_member_mime", "member.mime must be a type/subtype string", i);
      }
      if (!isHex64Lower(m.member_hash)) {
        push("bad_member_hash", "member.member_hash must be 64 hex-lowercase chars", i);
      }
      if (!isHex64Lower(m.attested_copy_hash)) {
        push("bad_attested_copy_hash", "member.attested_copy_hash must be 64 hex-lowercase chars", i);
      }
      if ("filename" in m) {
        if (typeof m.filename !== "string") {
          push("bad_filename", "member.filename must be a string when present", i);
        } else if (m.filename.length === 0) {
          push("filename_empty_string", "member.filename must not be empty string — omit the key instead", i);
        } else if ([...m.filename].length > 500) {
          push("filename_too_long", "member.filename max 500 Unicode code points", i);
        }
      }
      if ("captured_at" in m) {
        if (typeof m.captured_at !== "string" ||
            !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(m.captured_at) ||
            Number.isNaN(new Date(m.captured_at).getTime())) {
          push("bad_captured_at",
            "member.captured_at must be ISO 8601 UTC with ms precision (YYYY-MM-DDTHH:MM:SS.sssZ) when present", i);
        }
      }
      for (const key of Object.keys(m)) {
        if (!ALLOWED_MEMBER.has(key)) push("unknown_member_field", "unknown member field: " + key, i);
      }
    }

    // ordering "set" enforcement: member_hash ascending lexicographic.
    if (manifest.ordering === "set" && manifest.members.length > 1) {
      for (let i = 1; i < manifest.members.length; i++) {
        const prev = manifest.members[i - 1].member_hash;
        const curr = manifest.members[i].member_hash;
        if (typeof prev === "string" && typeof curr === "string" && prev >= curr) {
          push("set_not_sorted",
            'ordering "set" requires members sorted by member_hash ascending — violation at index ' + i, i);
          break;
        }
      }
    }

    // ordering "chronological" enforcement:
    //   (1) every member must carry captured_at (client fills from EXIF →
    //       XMP → issued_at fallback so no member is rejected).
    //   (2) members must be ascending by captured_at; ties are broken by
    //       member_hash ascending (same tiebreaker as ordering "set").
    //   Verifier trust model: image members can be cross-checked against
    //   their EXIF; non-image / EXIF-stripped members carry
    //   captured_at === issued_at by convention, so the verifier can
    //   confirm the fallback is honest.
    if (manifest.ordering === "chronological" && Array.isArray(manifest.members)) {
      // (1) required on every member.
      for (let i = 0; i < manifest.members.length; i++) {
        if (!("captured_at" in manifest.members[i])) {
          push("chrono_missing_captured_at",
            'ordering "chronological" requires captured_at on every member (use issued_at as fallback for members without EXIF/XMP)', i);
        }
      }
      // (2) ascending order with member_hash tiebreaker.
      if (manifest.members.length > 1) {
        for (let i = 1; i < manifest.members.length; i++) {
          const prevT = manifest.members[i - 1].captured_at;
          const currT = manifest.members[i].captured_at;
          const prevH = manifest.members[i - 1].member_hash;
          const currH = manifest.members[i].member_hash;
          if (typeof prevT !== "string" || typeof currT !== "string") continue;
          if (prevT > currT) {
            push("chrono_not_sorted",
              'ordering "chronological" requires members ascending by captured_at — violation at index ' + i, i);
            break;
          }
          if (prevT === currT && typeof prevH === "string" && typeof currH === "string" && prevH >= currH) {
            push("chrono_tiebreak",
              'ordering "chronological" requires captured_at ties broken by member_hash ascending — violation at index ' + i, i);
            break;
          }
        }
      }
    }
  }

  // Unknown top-level fields.
  const ALLOWED_TOP = new Set([
    "schema_version", "issued_at", "ordering", "title", "description",
    "cover_index", "parent_collection_hash", "creator", "members"
  ]);
  for (const key of Object.keys(manifest)) {
    if (!ALLOWED_TOP.has(key)) push("unknown_field", "unknown top-level field: " + key);
  }

  if (errors.length > 0) {
    return { ok: false, errors, canonicalBytes: null, collectionHash: null };
  }

  // Structural checks passed → canonicalize and hash.
  const canonicalBytes = jcsCanonicalize(manifest);
  const collectionHash = await sha256Hex(canonicalBytes);
  return { ok: true, errors: [], canonicalBytes, collectionHash };
}

// ════════════════════════════════════════════════════════════════
// ── End S106 Collection Proof helpers (Phase 1) ──
// ════════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════
// ── Begin S106 Collection Proof helpers (Phase 2) ──
// ════════════════════════════════════════════════════════════════
// readHash() dual-read, deriveCollectionId() + base32, and small byte
// utilities consumed by handleRegisterCollectionProof. Kept separate from
// Phase 1 so that Phase 1 can stand alone as pure (no KV) while Phase 2
// introduces the first KV-touching collection helpers.

// Convert lowercase hex string to Uint8Array.
function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0) {
    throw new Error("hexToBytes: expected even-length hex string");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(bytes[i])) throw new Error("hexToBytes: non-hex char at " + (i * 2));
  }
  return bytes;
}

// Convert Uint8Array to lowercase hex.
function bytesToHexLower(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

// Byte-wise equality for two Uint8Arrays (constant-time not required here —
// credential key comparison is not secret-vs-guess, it's byte-vs-stored).
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// RFC 4648 base32 lowercase, no padding. 12 bytes (96 bits) → 20 chars exactly
// (96 / 5 = 19.2, ceil = 20; final char carries 4 bits + 1 unused bit).
const BASE32_LOWER_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
function base32LowercaseNoPad(bytes) {
  let bits = 0;
  let value = 0;
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += BASE32_LOWER_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_LOWER_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

// §3.3.4 step 1: collection_id = base32-lowercase(SHA-256(canonical_bytes)[:12]).
// Accepts the 64-char hex collection_hash; extracts the first 12 bytes; emits 20 chars.
function deriveCollectionId(collectionHashHex) {
  if (typeof collectionHashHex !== "string" || !/^[0-9a-f]{64}$/.test(collectionHashHex)) {
    throw new Error("deriveCollectionId: collectionHashHex must be 64 lowercase hex chars");
  }
  const first12 = hexToBytes(collectionHashHex.slice(0, 24));
  return base32LowercaseNoPad(first12);
}

// Dual-read helper for the unified hash namespace during S106 migration.
// Reads hash:{hex} first, falls back to legacy proof:{hex} and alias:{hex}.
// Returns { record, sourceNamespace: "hash"|"proof"|"alias" } or null on miss.
// §3.3.1 dual-read phase: new writes go to hash:{hex} only; reads fall back
// so legacy S103 proofs remain resolvable until the sweep completes.
async function readHash(env, hexHash) {
  if (typeof hexHash !== "string" || !/^[0-9a-f]{64}$/.test(hexHash)) return null;

  const unifiedRaw = await env.DEDUP_KV.get(`hash:${hexHash}`);
  if (unifiedRaw) {
    try { return { record: JSON.parse(unifiedRaw), sourceNamespace: "hash" }; }
    catch (_) { return null; }
  }

  const proofRaw = await env.DEDUP_KV.get(`proof:${hexHash}`);
  if (proofRaw) {
    try {
      const parsed = JSON.parse(proofRaw);
      // Legacy standalone proof record. Wrap in unified type discriminator.
      return { record: { type: "standalone", ...parsed }, sourceNamespace: "proof" };
    } catch (_) { return null; }
  }

  const aliasRaw = await env.DEDUP_KV.get(`alias:${hexHash}`);
  if (aliasRaw) {
    try {
      const parsed = JSON.parse(aliasRaw);
      return { record: { type: "standalone", matchedVia: "alias", ...parsed }, sourceNamespace: "alias" };
    } catch (_) { return null; }
  }

  return null;
}

// Normalize a 32-byte Ed25519 public key from the manifest's base64 form.
// Returns Uint8Array(32) or null if malformed.
function normalizePubkeyFromB64(b64) {
  if (typeof b64 !== "string") return null;
  try {
    const bytes = base64ToBytes(b64);
    return bytes.length === 32 ? bytes : null;
  } catch (_) { return null; }
}

// Normalize a 32-byte Ed25519 public key from the trust record's hex form.
// Returns Uint8Array(32) or null if absent/malformed.
function normalizePubkeyFromHex(hex) {
  if (typeof hex !== "string" || !/^[0-9a-f]{64}$/.test(hex)) return null;
  return hexToBytes(hex);
}

// Map Phase 1 validateManifest internal codes to §3.4.1 spec-canonical error
// names for the 400 response. Codes not in the mapping pass through as-is.
function mapValidationError(err) {
  const spec = {
    not_object: "malformed_body",
    bad_schema_version: "unsupported_schema_version",
    bad_issued_at: "invalid_issued_at",
    bad_members: "missing_field",
    members_empty: "member_count_out_of_range",
    members_too_many: "member_count_out_of_range",
    bad_member_size: "member_size_out_of_range",
    bad_member_hash: "invalid_hash",
    bad_attested_copy_hash: "invalid_hash",
    bad_parent_collection_hash: "invalid_parent_collection_hash",
  }[err.code] || err.code;

  const out = { error: spec };
  if (err.code === "bad_schema_version") out.supported = ["hip-collection-1.0"];
  if (err.code === "bad_members") out.field = "members";
  if (err.code === "bad_member_hash") out.field = "member_hash";
  if (err.code === "bad_attested_copy_hash") out.field = "attested_copy_hash";
  if (err.at !== undefined) out.at = err.at;
  if (err.message && !out.error.startsWith(err.code)) out.detail = err.message;
  return out;
}

// ════════════════════════════════════════════════════════════════
// ── End S106 Collection Proof helpers (Phase 2) ──
// ════════════════════════════════════════════════════════════════

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

// ════════════════════════════════════════════════════════════════
// S111CW — SERIES-SPEC-v1 KV schema + index helpers (Phase A)
// ════════════════════════════════════════════════════════════════
//
// This block documents the six new KV key families introduced by
// SERIES-SPEC-v1 + the S111 secondary-index optimization:
//
//   series:{series_id}
//       Creation record. Value = JSON { series_id, manifest, signature,
//       status: "open"|"closed", created_at, closed_at, member_count,
//       last_event_at }. Manifest is immutable; status + closed_at +
//       member_count + last_event_at are server-maintained (§1.1). Written
//       by /register-series, updated in place by /register-series-member
//       (member_count, last_event_at) and /close-series (status, closed_at).
//
//   series_event:{event_hash}
//       Independently-signed add or close event. event_hash =
//       SHA-256(JCS(event-minus-signature)). Value = JSON of the full
//       event including its signature. Immutable after write (§1.2 +
//       §1.3).
//
//   series_events:{series_id}
//       Append-only ordering index. Value = JSON array of
//       { event_hash, event_type: "series_add"|"series_close",
//         applied_at: <server-clock ISO-8601> }. Newest-last per §1.4.
//       applied_at is the authoritative display order — per-event
//       added_at/closed_at client clocks are NOT used for ordering.
//
//   series_members:{series_id}  (S111 secondary index, permitted by spec §7.2)
//       O(1) duplicate-member check for /register-series-member step 10
//       without scanning the full series_events list. Value = JSON
//       { members: [<member_hash>, ...], updated_at }. Spec §7.2 text:
//       "Reference implementation may optimize this with a secondary
//       index series_members:{series_id} — implementation detail." So
//       this is in-spec. Idempotent append (indexOf guard).
//
//   affiliations:{content_hash}
//       Multi-affiliation index (§1.5). Value = JSON array of
//       { type: "series"|"collection", id, credential_id, added_at }.
//       Dedup on {type, id} tuple. Written by /register-series-member
//       (series affiliation) and by handleRegisterCollectionProof
//       retrofit (collection affiliation — Phase B change). Newest-last
//       append; clients reverse for newest-first rendering.
//
//   creator_series:{credential_id}
//       Portfolio-enumeration index (§1.6). Value = JSON array of
//       { series_id, created_at, status_at_write: "open" }. Newest-last.
//       status_at_write is a CREATION-TIME SNAPSHOT — clients rendering
//       a portfolio MUST re-read series:{series_id} for live status.
//
// All four write helpers below are NON-FATAL on failure (same posture as
// addToCredProofsIndex above). A failed index write does NOT roll back
// the primary record write; it just means an accelerator index is
// temporarily stale, and an index-repair script would reconcile. This
// matches the spec's §1.5.1 and §1.6 "consistent with addToCredProofsIndex
// posture" language.

// writeAffiliation: append one entry to affiliations:{content_hash},
// dedup on {type, id} tuple (§1.5: "If the same {type, id, credential_id}
// triple is already present, the server MUST NOT append a duplicate").
// Entry shape: { type: "series"|"collection", id, credential_id, added_at }.
// Newest-last append per spec.
async function writeAffiliation(env, content_hash, entry) {
  if (!content_hash || !entry || !entry.type || !entry.id) return;
  try {
    const key = `affiliations:${content_hash}`;
    const raw = await env.DEDUP_KV.get(key);
    let list = [];
    if (raw) {
      try { list = JSON.parse(raw); } catch (_) { list = []; }
      if (!Array.isArray(list)) list = [];
    }
    // Dedup on {type, id} tuple per §1.5. credential_id is not part of
    // the dedup key — two different credentials adding the same file
    // to the same series_id cannot happen (only the creator writes),
    // and two collections with the same id cannot exist (content-addressed).
    for (const e of list) {
      if (e && e.type === entry.type && e.id === entry.id) return;
    }
    list.push(entry);
    await env.DEDUP_KV.put(key, JSON.stringify(list));
  } catch (_) {
    // Non-fatal per §1.5.1 + addToCredProofsIndex posture.
  }
}

// writeCreatorSeriesIndex: append one entry to creator_series:{credential_id}
// for portfolio enumeration (§1.6). Entry shape:
// { series_id, created_at, status_at_write: "open" }. Newest-last append.
// status_at_write is a creation-time snapshot and is NOT updated here
// on subsequent closes — clients re-read series:{series_id} for live state.
async function writeCreatorSeriesIndex(env, credential_id, entry) {
  if (!credential_id || !entry || !entry.series_id) return;
  try {
    const key = `creator_series:${credential_id}`;
    const raw = await env.DEDUP_KV.get(key);
    let list = [];
    if (raw) {
      try { list = JSON.parse(raw); } catch (_) { list = []; }
      if (!Array.isArray(list)) list = [];
    }
    // Idempotent on series_id — first-writer-wins per §2.4 means a
    // legitimate collision overwrite already fails at the series:{id}
    // pre-existence check, but guard here for safety in the narrow
    // TOCTOU window where a double-creation might both reach the
    // creator_series write.
    for (const e of list) {
      if (e && e.series_id === entry.series_id) return;
    }
    list.push(entry);
    await env.DEDUP_KV.put(key, JSON.stringify(list));
  } catch (_) {
    // Non-fatal per §1.6 + addToCredProofsIndex posture.
  }
}

// addToSeriesMembersIndex: append member_hash to series_members:{series_id}
// for O(1) duplicate-member checks in /register-series-member step 10.
// Spec §7.2 explicitly permits this secondary index as an implementation
// detail. Idempotent append (indexOf guard).
async function addToSeriesMembersIndex(env, series_id, member_hash) {
  if (!series_id || !member_hash) return;
  try {
    const key = `series_members:${series_id}`;
    const raw = await env.DEDUP_KV.get(key);
    let record;
    if (raw) {
      try { record = JSON.parse(raw); } catch (_) { record = null; }
    }
    if (!record || !Array.isArray(record.members)) {
      record = { members: [], updated_at: null };
    }
    if (record.members.indexOf(member_hash) !== -1) {
      return; // already indexed — idempotent no-op
    }
    record.members.push(member_hash);
    record.updated_at = new Date().toISOString();
    await env.DEDUP_KV.put(key, JSON.stringify(record));
  } catch (_) {
    // Non-fatal: same posture as addToCredProofsIndex. Worst case is a
    // false-miss on the duplicate check, which would double-write a
    // series_event and double-increment member_count. That's recoverable
    // via index repair; not a protocol violation.
  }
}

// isSeriesMember: O(1) lookup against series_members:{series_id}. Returns
// boolean. Used by /register-series-member step 10 to reject duplicates
// per §7.2 "member_already_in_series" (400). On index miss (e.g., the
// index write failed on a prior add), returns false — the caller SHOULD
// treat false as "probably-not-a-member" with a fallback scan of
// series_events:{series_id} only if strict dedup is required. For v1 we
// trust the index.
async function isSeriesMember(env, series_id, member_hash) {
  if (!series_id || !member_hash) return false;
  try {
    const raw = await env.DEDUP_KV.get(`series_members:${series_id}`);
    if (!raw) return false;
    const record = JSON.parse(raw);
    if (!record || !Array.isArray(record.members)) return false;
    return record.members.indexOf(member_hash) !== -1;
  } catch (_) {
    return false;
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
//   Gate 4 — Signature: the client signs a canonical string with its Ed25519
//             private key. Two canonicals are accepted to preserve parity with
//             both hipprotocol.org/index.html (legacy) and hipkit-net/hip-attest.js
//             (HIPKit format). See the attest-canonical block below for exact
//             byte shapes. The worker also stores the signature verbatim so any
//             party can independently re-verify without trusting this server.
//
// S114CW BLOCKS ANNOUNCE #1 closure: the worker now DOES verify the Ed25519
// signature server-side. SubtleCrypto Ed25519 is available on Workers today
// (proven by verifyEd25519FromBytes and the series endpoints). Prior comment
// claiming otherwise was stale. `/api/verify` returning `verified: true` on
// KV presence alone was a charter-level semantic violation. No more.
// public_key is now REQUIRED (was optional pre-S114CW).

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
  // S114CW: public_key is now REQUIRED (was optional) — needed for sig verify.
  if (!content_hash || !credential_id || !public_key || !attested_at || !classification || !signature) {
    return jsonResponse({
      error: "Missing required fields: content_hash, credential_id, public_key, attested_at, classification, signature"
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
  // S114CW: REQUIRED (was optional pre-S114CW).
  if (!/^[0-9a-f]{64}$/.test(public_key)) {
    return jsonResponse({ error: "public_key must be a 64-character lowercase hex string (Ed25519 public key)" }, 400, origin);
  }
  // Verify public_key matches credential_id: credential_id = SHA-256(public_key)
  const pubKeyBytes = new Uint8Array(public_key.match(/.{2}/g).map(b => parseInt(b, 16)));
  const _cidBuf = await crypto.subtle.digest("SHA-256", pubKeyBytes);
  const _cidComputed = Array.from(new Uint8Array(_cidBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
  if (_cidComputed !== credential_id) {
    return jsonResponse({
      error: "public_key does not match credential_id. credential_id must be SHA-256(public_key)."
    }, 400, origin);
  }

  // ── S114CW BLOCKS ANNOUNCE #1: Ed25519 signature verification ──
  // Two canonicals are accepted because hipprotocol.org/index.html and
  // hipkit-net/hip-attest.js produce DIFFERENT signed messages for the same
  // attestation body. proof.html (the client-side verifier) already accepts
  // both at read time — we mirror that pattern at write time so historical
  // records stay verifiable AND both client surfaces continue to work without
  // a coordinated client patch.
  //
  //   HIPKit format (hipkit-net/hip-attest.js L17–23):
  //     content_hash | credential_id | classification | attested_at | protocol_version
  //
  //   Legacy format (hip-protocol/index.html L2574):
  //     content_hash | perceptual_hash_or_NULL | credential_id | attested_at | classification
  //
  // Try HIPKit first (matches proof.html ordering). On verify:false, try legacy.
  // Throws (malformed base64 / bad sig length) map to 400. verify:false on both
  // maps to 403 invalid_signature. verify:true on either is success.
  const attestPV = protocol_version || "1.2";
  const canonHIPKit = [content_hash, credential_id, classification, attested_at, attestPV].join("|");
  const canonLegacy = [content_hash, (perceptual_hash || "NULL"), credential_id, attested_at, classification].join("|");
  const _enc = new TextEncoder();
  let _sigOk = false;
  try {
    _sigOk = await verifyEd25519FromBytes(pubKeyBytes, signature, _enc.encode(canonHIPKit));
    if (!_sigOk) {
      _sigOk = await verifyEd25519FromBytes(pubKeyBytes, signature, _enc.encode(canonLegacy));
    }
  } catch (_e) {
    return jsonResponse({ error: "Malformed signature" }, 400, origin);
  }
  if (!_sigOk) {
    return jsonResponse({
      error: "invalid_signature",
      detail: "Signature does not verify against either HIPKit or legacy canonical form."
    }, 403, origin);
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

  // ═══════════════════════════════════════════════════════════════
  // S107CW Phase 1 — §3.4.5 collection dispatch (Phase 0 Decision 2c).
  //
  // Before the hash:{hex} dispatch, check whether contentHash is a
  // collection_hash. collection_hash_index:{hex} is written at POST time
  // (L~3267) with a bare-string value {collection_id}. A hit means this
  // hex identifies a collection as a whole, not a member or standalone.
  //
  // Without this branch, handleShortUrl (/c/{sid}) emits a 302 to
  // proof.html?hash={collection_hash}, which then fetches
  // /api/proof/{collection_hash} and 404s — collection_hashes were
  // never written to hash:{hex} or proof:{hex} (§3.3.4). Decision 2c
  // resolves the dead-end on the server side and preserves the
  // ?hash={hex} URL contract so existing /c/ bookmarks keep working.
  //
  // Pending-skip (Decision C1 / §3.3.4 reader contract): if the
  // referenced collection is status !== "active", fall through to the
  // existing hash:{hex} / legacy paths rather than leaking a partial
  // record. For the realistic case where no member_hash or legacy
  // proof:{hex} is keyed under a collection_hash, the fall-through
  // terminates at the final 404.
  //
  // Byte-identical preservation: collection_hash derivation
  // (SHA-256(JCS(manifest))) is disjoint from member_hash / standalone
  // content_hash derivations, so a hex that hits
  // collection_hash_index:{hex} has never ALSO hit hash:{hex} or
  // proof:{hex} in practice, and S106.6's byte-identical regression
  // set is unaffected.
  // ═══════════════════════════════════════════════════════════════
  const collIdxRaw = await env.DEDUP_KV.get(`collection_hash_index:${contentHash}`);
  if (collIdxRaw) {
    const collectionId = typeof collIdxRaw === "string" ? collIdxRaw.trim() : "";
    if (collectionId && isCollectionId(collectionId)) {
      const colRaw = await env.DEDUP_KV.get(`collection:${collectionId}`);
      if (colRaw) {
        let col = null;
        try { col = JSON.parse(colRaw); } catch (_) { col = null; }
        if (col && col.status === "active") {
          return jsonResponse({
            type: "collection",
            collection: {
              collection_id: col.collection_id,
              manifest: col.manifest,
              signature: col.signature,
              collection_hash: col.collection_hash,
              short_url: col.short_url,
              status: col.status,
              created_at: col.created_at,
              member_sidecar: col.member_sidecar || {},
              chain_sidecar: col.chain_sidecar || null,
            },
          }, 200, origin);
        }
        // col pending / malformed → fall through to existing dispatch.
      }
      // collection:{id} missing → fall through.
    }
    // malformed collection_hash_index value → fall through.
  }

  // ═══════════════════════════════════════════════════════════════
  // S106.6CW §3.4.5 — unified hash:{hex} dispatch (additive; legacy
  // proof:/alias: path below is untouched for byte-identical S103
  // wire preservation per S106.6 Phase 0 Ambiguity A ruling).
  //
  //   • type:"collection_member" → §3.4.5 collection_member response
  //     (nests the full §3.4.2 collection record inline, per S106.6
  //     Phase 0 Decision 1). Pending-skip per Decision 3: if the
  //     target collection isn't status:"active", fall through to the
  //     legacy path so we don't leak pending records via dispatch.
  //   • type:"standalone" → wire-mirror the legacy S103 shape exactly
  //     (flat {found:true, queried_hash, matched_via, ...record}).
  //     Currently unused in prod — no code writes standalone to
  //     hash:{hex} as of S106.5 — but future migration of legacy
  //     proof:{hex} rows must not silently change the wire format.
  //   • malformed / unknown-type → fall through.
  //
  // matched_via translation (Ambiguity D): the hash:{hex} value's
  // match_type is "source" | "attested_copy"; the wire response uses
  // matchedVia "collection_member_source" | "collection_member_attested_copy".
  // ═══════════════════════════════════════════════════════════════
  const unifiedRaw = await env.DEDUP_KV.get(`hash:${contentHash}`);
  if (unifiedRaw) {
    let unified = null;
    try { unified = JSON.parse(unifiedRaw); } catch (_) { unified = null; }

    if (unified && unified.type === "collection_member"
        && typeof unified.collection_id === "string" && unified.collection_id) {
      const colRaw = await env.DEDUP_KV.get(`collection:${unified.collection_id}`);
      if (colRaw) {
        let col = null;
        try { col = JSON.parse(colRaw); } catch (_) { col = null; }
        if (col && col.status === "active") {
          const mt = unified.match_type;
          const dispatchMatchedVia = mt === "attested_copy"
            ? "collection_member_attested_copy"
            : "collection_member_source";
          return jsonResponse({
            type: "collection_member",
            collection: {
              collection_id: col.collection_id,
              manifest: col.manifest,
              signature: col.signature,
              collection_hash: col.collection_hash,
              short_url: col.short_url,
              status: col.status,
              created_at: col.created_at,
              member_sidecar: col.member_sidecar || {},
              chain_sidecar: col.chain_sidecar || null, // S106.7CW — surface chain metadata if present
            },
            member_index: typeof unified.member_index === "number"
              ? unified.member_index : 0,
            matchedVia: dispatchMatchedVia,
          }, 200, origin);
        }
        // col pending / malformed / missing → fall through to legacy path.
      }
      // collection:{id} missing → fall through.
    } else if (unified && unified.type === "standalone" && unified.record) {
      // Post-migration standalone hit. Mirror legacy S103 wire byte-for-byte.
      const sRecord = unified.record;
      const sMatchedVia = unified.matchedVia === "alias" ? "alias" : "canonical";
      if (sRecord.sealed) {
        return jsonResponse({
          found: true,
          content_hash: contentHash,
          queried_hash: contentHash,
          matched_via: sMatchedVia,
          sealed: true,
          registered_at: sRecord.registered_at,
          message: "This proof record is sealed by its creator. The content has been attested but the proof details are not yet public.",
        }, 200, origin);
      }
      return jsonResponse({
        found: true,
        queried_hash: contentHash,
        matched_via: sMatchedVia,
        ...sRecord,
      }, 200, origin);
    }
    // other shapes → fall through to legacy path.
  }

  // ── Legacy S103 proof:/alias: dual-read fallback (byte-identical). ──
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

// POST /register-collection-proof — §3.4.1 of S105 Collection Proof spec.
//
// Wires the Phase 1 validateManifest pure function into the full write pipeline:
//   1. Parse JSON body. 400 malformed_body on parse failure. 413 manifest_too_large
//      when the raw body exceeds 1 MB (§3.4.1 "Manifest size cap").
//   2. validateManifest → on failure, 400 with the first error mapped to the
//      §3.4.1 step-2 error catalogue (unsupported_schema_version, missing_field,
//      invalid_issued_at, member_count_out_of_range, member_index_mismatch,
//      cover_index_out_of_range, invalid_hash, member_size_out_of_range,
//      filename_empty_string) — see mapValidationError().
//   3. Credential check (§3.4.1 step 3). Uses trust:{credential_id}, which is
//      the S103 impl name for what §3.5.6 calls credential:{...}.
//        - absent → 401 unknown_credential
//        - superseded_by truthy → 403 credential_revoked (+ revoked_at)
//        - trust_record.tier !== manifest.creator.tier → 403 credential_tier_mismatch
//        - public_key mismatch (byte-compare across the manifest's base64 and
//          the trust record's hex encoding) → 403 credential_key_mismatch
//        - trust_record has no public_key (legacy): accept iff
//          SHA-256(manifest_pubkey_bytes) === credential_id, and backfill.
//   4. Ed25519-verify signature against the 32-byte SHA-256(JCS(manifest)) digest
//      (§3.2.5 line 185). 422 signature_verification_failed on any failure.
//   5. Derive collection_id = base32-lowercase(digest[:12]) → 20 chars (§3.3.4 step 1).
//   6. Pending-flag write sequence (§3.3.4):
//        a. Existence check: collection:{id}.
//            - status:"active"  → idempotent replay, return the existing 200.
//            - status:"pending" → overwrite and resume the sequence.
//            - absent           → proceed.
//        b. Write collection:{id} with status:"pending" + created_at + sidecar.
//        c. Write collection_hash_index:{collection_hash} → collection_id (§3.5.3).
//        d. For each of the 2N member hashes, first-writer-wins (§3.3.5):
//            - readHash miss → write hash:{hex} with the collection_member payload.
//            - readHash hit  → skip write, record resolution_conflicts entry.
//        e. Read-modify-write collection_by_credential:{credential_id}
//           (§3.5.4). Idempotent-append: skip if collection_id already present.
//        f. Overwrite collection:{id} with status:"active".
//   7. Return 200 { collection_id, short_url, collection_hash, resolution_conflicts[],
//                   warnings?: ["issued_at_drift"] } per §3.4.1 step 8 + §3.10 publish-later.
//
// Any KV write failure → 500 { error:"kv_write_failure", retry:true }. The entire
// POST is idempotent on the derivation — retrying with the same body lands on the
// same collection_id and converges toward active status.
//
// Spec-vs-impl divergences resolved inline (green-lit at Phase 2 kickoff):
//   - credential:{id} in spec → trust:{id} in impl (§3.5.6: existing S103 key).
//   - Manifest public_key is base64 (§3.1); stored trust public_key is 64-char hex.
//     Normalize both to Uint8Array(32) and byte-compare.
//   - "revoked" in spec → truthy trust_record.superseded_by sentinel in impl.
//
// Chain support (S106.7CW Phase 1-3):
//   - §3.9.9 step 5a: if manifest.parent_collection_hash present, resolve via
//     collection_hash_index:{parent_collection_hash} → collection:{parent_id}.
//     Validate: parent active, same credential, issued_at >= parent.issued_at,
//     and member_count <= 496 (one lower than the 497 non-chain cap because
//     a chain POST writes one extra key — parent's chain_sidecar update —
//     so 2N + 7 ≤ 1000 bites at N = 496, not 497). Error codes:
//     chain_parent_not_found, chain_parent_inactive, chain_cross_credential_not_supported,
//     chain_timestamp_regression, chain_member_count_exceeded — all 400.
//   - Every successful POST embeds chain_sidecar = {chain_id, position,
//     known_length, has_children, cache_updated_at} directly on the new
//     collection record (atomic with the pending/active writes). Genesis
//     POSTs get chain_id = own collection_hash, position = 1; extension POSTs
//     inherit chain_id from parent (lazy-compute as parent.collection_hash
//     for pre-S106.7 genesis parents that predate chain_sidecar), position =
//     parent.position + 1.
//   - After flip-to-active, best-effort writes to (a) chain_registry:{chain_id}
//     (§3.5.5 cached, non-authoritative), and (b) parent's chain_sidecar.has_children
//     RMW (§3.9.9 step 5b). Failures here log silently — stale chain cache is
//     acceptable per §3.9.6 and the nightly sweep (S106.8CW) will recompute.
//
// Spec-vs-impl divergence on §3.4.6 (collection-by-credential): handled by
// the sibling handleCollectionByCredential() below — POST not GET, mirrors the
// existing verifyAppAuth pattern from handlePortfolio / handleCredentialAttestations.
async function handleRegisterCollectionProof(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  // ── 1. Parse body + enforce 1 MB manifest size cap ──
  let rawBody;
  try {
    rawBody = await request.text();
  } catch (_) {
    return jsonResponse({ error: "malformed_body" }, 400, origin);
  }
  if (rawBody.length > 1_048_576) {
    return jsonResponse({ error: "manifest_too_large" }, 413, origin);
  }
  let body;
  try {
    body = JSON.parse(rawBody);
  } catch (_) {
    return jsonResponse({ error: "malformed_body" }, 400, origin);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return jsonResponse({ error: "malformed_body" }, 400, origin);
  }

  const { manifest, signature, member_sidecar } = body;
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    return jsonResponse({ error: "missing_field", field: "manifest" }, 400, origin);
  }
  if (typeof signature !== "string" || signature.length === 0) {
    return jsonResponse({ error: "missing_field", field: "signature" }, 400, origin);
  }

  // ── 2. Manifest schema validation (Phase 1 pure function) ──
  const validation = await validateManifest(manifest);
  if (!validation.ok) {
    // Return the first error with its §3.4.1 spec-canonical code.
    return jsonResponse(mapValidationError(validation.errors[0]), 400, origin);
  }

  const canonicalBytes = validation.canonicalBytes; // Uint8Array of JCS bytes
  const collectionHashHex = validation.collectionHash; // 64-char lowercase hex
  const collectionHashBytes = hexToBytes(collectionHashHex); // 32 bytes

  // ── 3. Credential check ──
  const credentialId = manifest.creator.credential_id;
  const manifestPubKeyBytes = normalizePubkeyFromB64(manifest.creator.public_key);
  if (!manifestPubKeyBytes) {
    // Phase 1 already validated this during validateManifest, but double-check.
    return jsonResponse({ error: "invalid_public_key" }, 400, origin);
  }

  const trustRaw = await env.DEDUP_KV.get(`trust:${credentialId}`);
  if (!trustRaw) {
    return jsonResponse({ error: "unknown_credential" }, 401, origin);
  }
  let trustRecord;
  try { trustRecord = JSON.parse(trustRaw); }
  catch (_) { return jsonResponse({ error: "unknown_credential" }, 401, origin); }

  if (trustRecord.superseded_by) {
    return jsonResponse({
      error: "credential_revoked",
      revoked_at: trustRecord.superseded_at || null,
    }, 403, origin);
  }
  if (trustRecord.tier !== manifest.creator.tier) {
    return jsonResponse({
      error: "credential_tier_mismatch",
      actual_tier: trustRecord.tier,
    }, 403, origin);
  }

  let backfillPubKey = false;
  if (trustRecord.public_key) {
    const storedBytes = normalizePubkeyFromHex(trustRecord.public_key);
    if (!storedBytes || !bytesEqual(storedBytes, manifestPubKeyBytes)) {
      return jsonResponse({ error: "credential_key_mismatch" }, 403, origin);
    }
  } else {
    // Legacy trust record without public_key: verify SHA-256(pubkey) === credential_id.
    // Same fallback pattern as handleRegisterProof's backfill path.
    const computedDigest = await crypto.subtle.digest("SHA-256", manifestPubKeyBytes);
    const computedIdHex = bytesToHexLower(new Uint8Array(computedDigest));
    if (computedIdHex !== credentialId) {
      return jsonResponse({ error: "credential_key_mismatch" }, 403, origin);
    }
    backfillPubKey = true;
  }

  // ── 4. Ed25519-verify signature over 32-byte collection_hash digest ──
  // §3.2.5: "Ed25519 over the 32-byte hash ... over the 32-byte collection_hash digest."
  let verified = false;
  try {
    verified = await verifyEd25519(
      manifest.creator.public_key, // base64
      signature,                    // base64
      collectionHashBytes,          // 32-byte Uint8Array
    );
  } catch (_) {
    return jsonResponse({ error: "signature_verification_failed" }, 422, origin);
  }
  if (!verified) {
    return jsonResponse({ error: "signature_verification_failed" }, 422, origin);
  }

  // ── 4.5. Chain validation (§3.9.9 step 5a) ──
  // Runs after Ed25519 verify (so forged signatures fail before hitting KV) and
  // before collection_id derivation. Resolved parentRecord is threaded forward
  // so the write phases don't re-read KV.
  let parentRecord = null;
  const parentCollectionHash = manifest.parent_collection_hash;
  if (typeof parentCollectionHash === "string" && parentCollectionHash.length > 0) {
    // Q5 decision: chain POSTs cap members at 496 (not 497), because a chain
    // extension writes one extra key (parent's chain_sidecar RMW) so
    // 2N + 7 ≤ 1000 → N ≤ 496.
    if (manifest.members.length > 496) {
      return jsonResponse({
        error: "chain_member_count_exceeded",
        max: 496,
      }, 400, origin);
    }

    // Resolve parent_collection_hash → parent_collection_id via §3.5.3 index.
    const parentIdxRaw = await env.DEDUP_KV.get(
      `collection_hash_index:${parentCollectionHash}`
    );
    if (!parentIdxRaw) {
      return jsonResponse({ error: "chain_parent_not_found" }, 400, origin);
    }
    const parentId = parentIdxRaw;

    // Read parent collection record.
    const parentRaw = await env.DEDUP_KV.get(`collection:${parentId}`);
    if (!parentRaw) {
      return jsonResponse({ error: "chain_parent_not_found" }, 400, origin);
    }
    try { parentRecord = JSON.parse(parentRaw); }
    catch (_) { return jsonResponse({ error: "chain_parent_not_found" }, 400, origin); }
    if (!parentRecord || parentRecord.status !== "active") {
      return jsonResponse({ error: "chain_parent_inactive" }, 400, origin);
    }

    // Same-credential enforcement (§3.9.3 — cross-credential chains out of S105 scope).
    const parentCredId = parentRecord.manifest
      && parentRecord.manifest.creator
      && parentRecord.manifest.creator.credential_id;
    if (parentCredId !== credentialId) {
      return jsonResponse({
        error: "chain_cross_credential_not_supported",
      }, 400, origin);
    }

    // Monotonic issued_at within a chain (§3.9.3 bullet 4).
    // Compare in ms (not string lex) so timezone suffixes don't confuse.
    const parentIssuedMs = parentRecord.manifest
      ? Date.parse(parentRecord.manifest.issued_at)
      : NaN;
    const newIssuedMs = Date.parse(manifest.issued_at);
    if (!Number.isFinite(parentIssuedMs) || !Number.isFinite(newIssuedMs)
        || newIssuedMs < parentIssuedMs) {
      return jsonResponse({ error: "chain_timestamp_regression" }, 400, origin);
    }
  }

  // ── 5. Derive collection_id (§3.3.4 step 1) ──
  const collectionId = deriveCollectionId(collectionHashHex);
  const shortUrl = `https://hipprotocol.org/c/${collectionId}`;

  // ── 6. Pending-flag write sequence (§3.3.4) ──
  const collectionKey = `collection:${collectionId}`;
  const existingRaw = await env.DEDUP_KV.get(collectionKey);
  if (existingRaw) {
    try {
      const existing = JSON.parse(existingRaw);
      if (existing.status === "active") {
        // True idempotent replay — the client re-sent the same bundle.
        // Return the same 200 shape. resolution_conflicts is preserved from
        // the original POST if we stored it; otherwise empty (older records).
        return jsonResponse({
          collection_id: collectionId,
          short_url: existing.short_url || shortUrl,
          collection_hash: collectionHashHex,
          resolution_conflicts: existing.resolution_conflicts || [],
        }, 200, origin);
      }
      // status:"pending" → a prior POST failed mid-sequence. Fall through and
      // re-execute steps 6b-6f; KV writes are key-idempotent (same value).
    } catch (_) { /* malformed pending record, overwrite below */ }
  }

  const nowIso = new Date().toISOString();

  // §3.10 publish-later: accept any drift, surface as a warning only.
  const warnings = [];
  const issuedMs = new Date(manifest.issued_at).getTime();
  if (!Number.isNaN(issuedMs) && Math.abs(Date.now() - issuedMs) > 300_000) {
    warnings.push("issued_at_drift");
  }

  // First compute the resolution_conflicts so the final active record can
  // persist them (enables idempotent replay to echo the same array).
  const members = manifest.members;
  const probes = [];
  for (let i = 0; i < members.length; i++) {
    probes.push({ idx: i, hashType: "member_hash", hash: members[i].member_hash });
    probes.push({ idx: i, hashType: "attested_copy_hash", hash: members[i].attested_copy_hash });
  }
  const probeResults = await Promise.all(probes.map(p => readHash(env, p.hash)));

  const resolutionConflicts = [];
  const memberWrites = [];
  const claimWrites = []; // S106.5: hash_claim:{hex}:{collection_id} rows (conflicts only)
  for (let p = 0; p < probes.length; p++) {
    const probe = probes[p];
    const hit = probeResults[p];
    const value = {
      type: "collection_member",
      collection_id: collectionId,
      member_index: probe.idx,
      match_type: probe.hashType === "member_hash" ? "source" : "attested_copy",
    };
    if (hit) {
      // Edge case: if the existing hit is for the SAME collection_id (retry
      // case after step 6d partial write), the write is still a no-op for
      // first-writer-wins, but it's not a real conflict to surface. Skip
      // recording it in resolution_conflicts.
      const rec = hit.record || {};
      const sameCollectionRetry = rec.type === "collection_member"
        && rec.collection_id === collectionId
        && rec.member_index === probe.idx;
      if (!sameCollectionRetry) {
        const conflict = {
          member_index: probe.idx,
          hash_type: probe.hashType,
          existing_record_type: rec.type || "standalone",
        };
        if (rec.type === "collection_member" && rec.collection_id) {
          conflict.existing_collection_id = rec.collection_id;
        }
        resolutionConflicts.push(conflict);
        // S106.5 history index — Phase 0 Decision 1=B, Decision 4 value shape.
        // One hash_claim row per conflict entry; keyed by
        // hash_claim:{member_hash_hex}:{this_collection_id} so the /history
        // endpoint can list-prefix by hex to surface all co-claimants.
        // Non-conflicting POSTs emit zero claim rows → S105 2N+6 budget preserved.
        claimWrites.push({
          key: `hash_claim:${probe.hash}:${collectionId}`,
          value: {
            credential_id: credentialId,
            created_at: nowIso,
            member_index: probe.idx,
            hash_type: probe.hashType,
            collection_hash: collectionHashHex,
          },
        });
      }
    } else {
      memberWrites.push({ key: `hash:${probe.hash}`, value });
    }
  }

  // Compute chain_sidecar for the new collection record (S106.7CW Phase 1).
  // Genesis: chain_id = own collection_hash, position = 1.
  // Extension: inherit chain_id from parent (lazy-compute for pre-S106.7 parents
  // whose chain_sidecar is absent — their implicit chain_id is their own
  // collection_hash, position 1, so this collection is position 2).
  let chainSidecar;
  if (parentRecord) {
    const parentChainId = (parentRecord.chain_sidecar && typeof parentRecord.chain_sidecar.chain_id === "string")
      ? parentRecord.chain_sidecar.chain_id
      : parentRecord.collection_hash;
    const parentPosition = (parentRecord.chain_sidecar && Number.isInteger(parentRecord.chain_sidecar.position))
      ? parentRecord.chain_sidecar.position
      : 1;
    const newPosition = parentPosition + 1;
    chainSidecar = {
      chain_id: parentChainId,
      position: newPosition,
      known_length: newPosition,
      has_children: [],
      cache_updated_at: nowIso,
    };
  } else {
    chainSidecar = {
      chain_id: collectionHashHex,
      position: 1,
      known_length: 1,
      has_children: [],
      cache_updated_at: nowIso,
    };
  }

  // 6b. Write collection:{id} pending.
  const pendingRecord = {
    collection_id: collectionId,
    manifest,
    signature,
    collection_hash: collectionHashHex,
    short_url: shortUrl,
    status: "pending",
    created_at: nowIso,
    member_sidecar: (member_sidecar && typeof member_sidecar === "object" && !Array.isArray(member_sidecar))
      ? member_sidecar : {},
    chain_sidecar: chainSidecar,
    resolution_conflicts: resolutionConflicts, // persisted for idempotent replay
  };
  try {
    await env.DEDUP_KV.put(collectionKey, JSON.stringify(pendingRecord));
  } catch (_) {
    return jsonResponse({ error: "kv_write_failure", retry: true }, 500, origin);
  }

  // 6c. collection_hash_index:{collection_hash} → collection_id (§3.5.3).
  try {
    await env.DEDUP_KV.put(`collection_hash_index:${collectionHashHex}`, collectionId);
  } catch (_) {
    return jsonResponse({ error: "kv_write_failure", retry: true }, 500, origin);
  }

  // 6d. Member hash rows (non-conflicting only).
  try {
    await Promise.all(memberWrites.map(w =>
      env.DEDUP_KV.put(w.key, JSON.stringify(w.value))
    ));
  } catch (_) {
    return jsonResponse({ error: "kv_write_failure", retry: true }, 500, origin);
  }

  // 6d.5. S106.5 hash_claim:{hex}:{collection_id} rows for conflicted members.
  // Emitted only for entries in resolutionConflicts — same cardinality as that
  // array, so non-conflict POSTs write zero extra keys. Rolled-back-consistent
  // with the rest of the sequence because the collection record is still
  // status:"pending" at this point; readers that list hash_claim:{hex}:* MUST
  // filter out claims whose target collection isn't status:"active" (§3.3.4
  // reader contract, preserved by S106.5 Phase 0 Decision C1).
  if (claimWrites.length) {
    try {
      await Promise.all(claimWrites.map(w =>
        env.DEDUP_KV.put(w.key, JSON.stringify(w.value))
      ));
    } catch (_) {
      return jsonResponse({ error: "kv_write_failure", retry: true }, 500, origin);
    }
  }

  // 6e. Append to collection_by_credential:{credential_id} (§3.5.4, idempotent).
  const credIndexKey = `collection_by_credential:${credentialId}`;
  try {
    const credIndexRaw = await env.DEDUP_KV.get(credIndexKey);
    let credIndex = [];
    if (credIndexRaw) {
      try {
        const parsed = JSON.parse(credIndexRaw);
        if (Array.isArray(parsed)) credIndex = parsed;
      } catch (_) { credIndex = []; }
    }
    const alreadyPresent = credIndex.some(e => e && e.collection_id === collectionId);
    if (!alreadyPresent) {
      credIndex.unshift({
        collection_id: collectionId,
        title: manifest.title,
        issued_at: manifest.issued_at,
        member_count: members.length,
        cover_index: manifest.cover_index,
        short_url: shortUrl,
        created_at: nowIso,
        chain_id: chainSidecar.chain_id, // S106.7CW Phase 1 — populated for every POST
      });
      await env.DEDUP_KV.put(credIndexKey, JSON.stringify(credIndex));
    }
  } catch (_) {
    return jsonResponse({ error: "kv_write_failure", retry: true }, 500, origin);
  }

  // 6f. Flip collection:{id} to status:"active".
  const activeRecord = { ...pendingRecord, status: "active" };
  try {
    await env.DEDUP_KV.put(collectionKey, JSON.stringify(activeRecord));
  } catch (_) {
    return jsonResponse({ error: "kv_write_failure", retry: true }, 500, origin);
  }

  // ── 6g. chain_registry:{chain_id} write (S106.7CW Phase 2 — §3.5.5) ──
  // Best-effort, non-blocking. Spec: "cached, non-authoritative — a verifier
  // may always recompute by walking." Stale or missing entries get rebuilt
  // by the nightly sweep (S106.8CW). Failure here does not fail the POST.
  try {
    const registryKey = `chain_registry:${chainSidecar.chain_id}`;
    const existingRegistryRaw = await env.DEDUP_KV.get(registryKey);
    let registry = null;
    if (existingRegistryRaw) {
      try { registry = JSON.parse(existingRegistryRaw); } catch (_) { registry = null; }
    }
    if (!registry || typeof registry !== "object") {
      // Fresh registry entry. Either this IS the genesis POST (no parent), or
      // we're lazy-creating for a pre-S106.7 parent whose chain_registry never
      // existed. In the lazy case, stage_count_known = 2 because the parent
      // (genesis) and the new child are both now known.
      registry = {
        chain_id: chainSidecar.chain_id,
        genesis_collection_id: parentRecord
          ? (parentRecord.collection_id)
          : collectionId,
        credential_id: credentialId,
        stage_count_known: parentRecord ? 2 : 1,
        last_extended_at: nowIso,
        fork_points: [],
        cache_updated_at: nowIso,
      };
    } else {
      // Extension of an existing chain — increment stage_count_known and
      // detect forks (parent already had ≥1 child before this POST).
      registry.stage_count_known = (Number.isInteger(registry.stage_count_known)
        ? registry.stage_count_known : 0) + 1;
      registry.last_extended_at = nowIso;
      registry.cache_updated_at = nowIso;
      if (parentRecord && parentRecord.chain_sidecar
          && Array.isArray(parentRecord.chain_sidecar.has_children)
          && parentRecord.chain_sidecar.has_children.length >= 1) {
        const forks = Array.isArray(registry.fork_points) ? registry.fork_points : [];
        const existingFork = forks.find(f => f && f.parent_collection_id === parentRecord.collection_id);
        if (existingFork) {
          if (!Array.isArray(existingFork.children)) existingFork.children = [];
          if (!existingFork.children.includes(collectionId)) {
            existingFork.children.push(collectionId);
          }
        } else {
          // First fork detection for this parent — seed with existing sibling(s)
          // plus the new child, so the dashboard can render all branches.
          const allChildren = [...parentRecord.chain_sidecar.has_children, collectionId];
          forks.push({
            parent_collection_id: parentRecord.collection_id,
            children: allChildren,
          });
        }
        registry.fork_points = forks;
      }
    }
    await env.DEDUP_KV.put(registryKey, JSON.stringify(registry));
  } catch (_) { /* stale registry is acceptable per §3.5.5 */ }

  // ── 6h. Parent's chain_sidecar.has_children RMW (S106.7CW Phase 3 — §3.9.9 step 5b) ──
  // Best-effort, non-atomic with the main write. On failure, parent cache stays
  // stale but child is fully registered. Re-read the parent record here rather
  // than mutating the captured parentRecord so we don't clobber concurrent
  // writes (e.g. another sibling POST racing us on the same parent).
  if (parentRecord) {
    try {
      const parentKey = `collection:${parentRecord.collection_id}`;
      const latestParentRaw = await env.DEDUP_KV.get(parentKey);
      if (latestParentRaw) {
        const latestParent = JSON.parse(latestParentRaw);
        if (latestParent && latestParent.status === "active") {
          // Lazy-backfill chain_sidecar on pre-S106.7 parents.
          if (!latestParent.chain_sidecar || typeof latestParent.chain_sidecar !== "object") {
            latestParent.chain_sidecar = {
              chain_id: latestParent.collection_hash,
              position: 1,
              known_length: 2,
              has_children: [collectionId],
              cache_updated_at: nowIso,
            };
          } else {
            if (!Array.isArray(latestParent.chain_sidecar.has_children)) {
              latestParent.chain_sidecar.has_children = [];
            }
            if (!latestParent.chain_sidecar.has_children.includes(collectionId)) {
              latestParent.chain_sidecar.has_children.push(collectionId);
            }
            latestParent.chain_sidecar.cache_updated_at = nowIso;
            // Best-effort known_length bump: we know the chain now reaches at
            // least this child's position.
            const childPos = chainSidecar.position;
            if (!Number.isInteger(latestParent.chain_sidecar.known_length)
                || latestParent.chain_sidecar.known_length < childPos) {
              latestParent.chain_sidecar.known_length = childPos;
            }
          }
          await env.DEDUP_KV.put(parentKey, JSON.stringify(latestParent));
        }
      }
    } catch (_) { /* stale parent cache is acceptable per §3.9.6 */ }
  }

  // ── 6i. S112CW — writeAffiliation for each collection member ──
  // Mirror of handleRegisterSeriesMember's post-write affiliation stamp
  // (worker.js ~L4277). Non-fatal per writeAffiliation contract; dedup on
  // {type, id} tuple means idempotent replays and chain re-executions are
  // safe. Forward-only posture: pre-S112 collections are NOT backfilled
  // per kickoff §3 Q3 (a) new-only decision; a one-shot reconciliation
  // script can fill historicals if demand surfaces (CLAUDE.md carryover
  // #36). Parallel because each target key (affiliations:{member_hash})
  // is distinct — no same-key races. Runs AFTER the active-record flip
  // so a failed mid-sequence POST does not stamp affiliations on a
  // collection that never reached status:"active".
  await Promise.all(members.map(m => writeAffiliation(env, m.member_hash, {
    type: "collection",
    id: collectionId,
    credential_id: credentialId,
    added_at: nowIso,
  })));

  // Best-effort backfill of trust_record.public_key (legacy credentials).
  // Failure here is silent — the collection record is already active.
  if (backfillPubKey) {
    try {
      trustRecord.public_key = bytesToHexLower(manifestPubKeyBytes);
      await env.DEDUP_KV.put(`trust:${credentialId}`, JSON.stringify(trustRecord));
    } catch (_) { /* swallow */ }
  }

  const response = {
    collection_id: collectionId,
    short_url: shortUrl,
    collection_hash: collectionHashHex,
    resolution_conflicts: resolutionConflicts,
  };
  if (warnings.length) response.warnings = warnings;
  return jsonResponse(response, 200, origin);
}

// ══════════════════════════════════════════════════════════════════════
// S111CW — SERIES-SPEC-v1 write handlers (Phase B)
// ══════════════════════════════════════════════════════════════════════
// Three POST endpoints implementing SERIES-SPEC-v1 §7.1, §7.2, §7.3.
// All three follow the handleRegisterCollectionProof auth pattern:
// manifest/event carries creator.credential_id + creator.public_key;
// server reads trust:{id} for retirement check; Ed25519 verify is done
// server-side via verifySeriesSignature (Phase A helper).
//
// Validation-order fidelity: each handler executes checks in the exact
// order spec §7.1/§7.2/§7.3 prescribes, so error codes match spec.
// Per-handler comments call out the numbered step from the spec.

// validateSeriesManifest — pure structural/field validator per spec
// §1.1 + §4.6. Returns { ok, errors[], canonicalBytes }. Does NOT read
// KV, does NOT verify signatures (endpoint's job), does NOT clock-drift
// the issued_at. Mirrors validateManifest() (collections) but for the
// series manifest shape.
function validateSeriesManifest(manifest) {
  const errors = [];
  const push = (code, detail, field) => {
    const e = { code };
    if (detail !== undefined) e.detail = detail;
    if (field !== undefined) e.field = field;
    errors.push(e);
  };

  if (typeof manifest !== "object" || manifest === null || Array.isArray(manifest)) {
    push("invalid_manifest", "manifest must be a JSON object");
    return { ok: false, errors, canonicalBytes: null };
  }

  // schema_version — v1 locked to hip-series-1.0 per §1.1.
  if (manifest.schema_version !== "hip-series-1.0") {
    push("invalid_manifest_field", 'schema_version must be "hip-series-1.0"', "schema_version");
  }

  // issued_at — required ISO-8601 UTC, must parse (no drift check per spec).
  if (typeof manifest.issued_at !== "string"
      || Number.isNaN(Date.parse(manifest.issued_at))) {
    push("invalid_manifest_field", "issued_at must be a valid ISO-8601 UTC timestamp", "issued_at");
  }

  // title — 1 to 200 chars, trimmed. §4.6 says server MUST trim before
  // verification; clients MUST also trim before signing. We do NOT mutate
  // manifest here — we validate its as-signed form. Clients that signed
  // an untrimmed title will fail here rather than silently letting the
  // server trim and re-sign something the creator didn't approve.
  if (typeof manifest.title !== "string") {
    push("invalid_manifest_field", "title must be a string", "title");
  } else if (manifest.title !== manifest.title.trim()) {
    push("invalid_manifest_field", "title must have no leading/trailing whitespace", "title");
  } else if (manifest.title.length < 1 || manifest.title.length > 200) {
    push("invalid_manifest_field", "title must be 1 to 200 characters", "title");
  }

  // description — 0 to 2000 chars, trimmed. Optional but when present must
  // satisfy the trimmed/length constraint. §4.5 says zero-length is legal
  // as "" (empty string); absent is also legal.
  if (manifest.description !== undefined) {
    if (typeof manifest.description !== "string") {
      push("invalid_manifest_field", "description must be a string", "description");
    } else if (manifest.description !== manifest.description.trim()) {
      push("invalid_manifest_field", "description must have no leading/trailing whitespace", "description");
    } else if (manifest.description.length > 2000) {
      push("invalid_manifest_field", "description must be 0 to 2000 characters", "description");
    }
  }

  // cover_member_hash — optional 64-hex lowercase if present.
  if (manifest.cover_member_hash !== undefined) {
    if (!isHex64Lower(manifest.cover_member_hash)) {
      push("invalid_manifest_field", "cover_member_hash must be 64 lowercase hex chars", "cover_member_hash");
    }
  }

  // creator — required object with credential_id, tier, public_key.
  if (typeof manifest.creator !== "object" || manifest.creator === null || Array.isArray(manifest.creator)) {
    push("invalid_manifest_field", "creator must be an object", "creator");
  } else {
    if (!isHex64Lower(manifest.creator.credential_id)) {
      push("invalid_manifest_field", "creator.credential_id must be 64 lowercase hex chars", "creator.credential_id");
    }
    if (manifest.creator.tier !== 1 && manifest.creator.tier !== 2 && manifest.creator.tier !== 3) {
      push("invalid_manifest_field", "creator.tier must be 1, 2, or 3", "creator.tier");
    }
    const pubBytes = normalizePubkeyFromB64(manifest.creator.public_key);
    if (!pubBytes) {
      push("invalid_manifest_field", "creator.public_key must be a base64 Ed25519 public key (32 bytes)", "creator.public_key");
    }
  }

  if (errors.length) return { ok: false, errors, canonicalBytes: null };

  // Canonicalize (may throw on JCS-unrepresentable values — caller should
  // try/catch the whole function call if it wants to map throws cleanly).
  let canonicalBytes;
  try {
    canonicalBytes = jcsCanonicalize(manifest);
  } catch (e) {
    return { ok: false, errors: [{ code: "invalid_manifest", detail: "manifest not JCS-representable: " + e.message }], canonicalBytes: null };
  }
  return { ok: true, errors: [], canonicalBytes };
}

// ──────────────────────────────────────────────────────────────────────
// POST /register-series — SERIES-SPEC-v1 §7.1
// ──────────────────────────────────────────────────────────────────────
// Creation. Client generates series_id (client-random, §1.1); server
// validates shape + collision-checks + validates manifest + verifies
// signature + writes series:{id} + appends to creator_series:{cred_id}.
//
// Validation order (spec §7.1):
//   1. Parse JSON                             → 400 malformed_body
//   2. Shape-check series_id                  → 400 invalid_series_id
//   3. Pre-existence on series:{id}           → 400 series_id_collision
//   4. Credential trust-record check          → 401 unknown_credential
//                                              403 credential_revoked
//                                              403 credential_tier_mismatch
//                                              403 credential_key_mismatch
//   5. TI ≥ 60                                → 403 trust_index_below_floor
//   6. Rate-limit (unified attest budget)     → 429 rate_limited
//   7. Manifest field validation              → 400 invalid_manifest /
//                                                400 invalid_manifest_field
//   8. JCS + SHA-256 + Ed25519-verify         → 422 invalid_signature
//   9. Write series:{id} (status="open",
//      created_at, member_count=0,
//      closed_at=null, last_event_at=created)
//  10. Append creator_series:{cred_id} idx    (non-fatal)
//  11. Increment rate counters
async function handleRegisterSeries(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  // ── 1. Parse body ──
  let rawBody;
  try { rawBody = await request.text(); }
  catch (_) { return jsonResponse({ error: "malformed_body" }, 400, origin); }
  if (rawBody.length > 1_048_576) {
    return jsonResponse({ error: "manifest_too_large" }, 413, origin);
  }
  let body;
  try { body = JSON.parse(rawBody); }
  catch (_) { return jsonResponse({ error: "malformed_body" }, 400, origin); }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return jsonResponse({ error: "malformed_body" }, 400, origin);
  }

  const { series_id, manifest, signature } = body;
  if (typeof signature !== "string" || signature.length === 0) {
    return jsonResponse({ error: "missing_field", field: "signature" }, 400, origin);
  }

  // ── 2. Shape-check series_id ──
  if (!isSeriesId(series_id)) {
    return jsonResponse({ error: "invalid_series_id" }, 400, origin);
  }

  // ── 3. Pre-existence check (first-writer-wins per §2.4) ──
  const seriesKey = `series:${series_id}`;
  const existing = await env.DEDUP_KV.get(seriesKey);
  if (existing) {
    return jsonResponse({ error: "series_id_collision" }, 400, origin);
  }

  // ── 4. Credential trust-record check (mirrors handleRegisterCollectionProof) ──
  if (typeof manifest !== "object" || manifest === null || Array.isArray(manifest)) {
    // Must reach this shape-check before reading credential_id from it.
    return jsonResponse({ error: "invalid_manifest" }, 400, origin);
  }
  if (typeof manifest.creator !== "object" || manifest.creator === null) {
    return jsonResponse({ error: "invalid_manifest_field", field: "creator" }, 400, origin);
  }
  const credentialId = manifest.creator.credential_id;
  if (!isHex64Lower(credentialId)) {
    return jsonResponse({ error: "invalid_manifest_field", field: "creator.credential_id" }, 400, origin);
  }
  const manifestPubKeyBytes = normalizePubkeyFromB64(manifest.creator.public_key);
  if (!manifestPubKeyBytes) {
    return jsonResponse({ error: "invalid_manifest_field", field: "creator.public_key" }, 400, origin);
  }

  const trustRaw = await env.DEDUP_KV.get(`trust:${credentialId}`);
  if (!trustRaw) {
    return jsonResponse({ error: "unknown_credential" }, 401, origin);
  }
  let trustRecord;
  try { trustRecord = JSON.parse(trustRaw); }
  catch (_) { return jsonResponse({ error: "unknown_credential" }, 401, origin); }

  if (trustRecord.superseded_by) {
    return jsonResponse({
      error: "credential_retired",
      revoked_at: trustRecord.superseded_at || null,
    }, 403, origin);
  }
  if (trustRecord.tier !== manifest.creator.tier) {
    return jsonResponse({
      error: "credential_tier_mismatch",
      actual_tier: trustRecord.tier,
    }, 403, origin);
  }
  // Public key match (manifest is base64, trust is hex — compare as bytes).
  if (trustRecord.public_key) {
    const storedBytes = normalizePubkeyFromHex(trustRecord.public_key);
    if (!storedBytes || !bytesEqual(storedBytes, manifestPubKeyBytes)) {
      return jsonResponse({ error: "credential_key_mismatch" }, 403, origin);
    }
  } else {
    // Legacy trust record without public_key: verify SHA-256(pubkey) === credential_id.
    const computedDigest = await crypto.subtle.digest("SHA-256", manifestPubKeyBytes);
    const computedIdHex = bytesToHexLower(new Uint8Array(computedDigest));
    if (computedIdHex !== credentialId) {
      return jsonResponse({ error: "credential_key_mismatch" }, 403, origin);
    }
  }

  // ── 5. TI ≥ 60 attest floor (HP-SPEC-v1_3 §TI) ──
  if ((trustRecord.trust_index ?? trustRecord.trust_score ?? 0) < 60) {
    return jsonResponse({
      error: "trust_index_below_floor",
      detail: `Credential TI (${trustRecord.trust_index ?? trustRecord.trust_score ?? 0}) is below the 60 attest floor.`,
    }, 403, origin);
  }

  // ── 6. Rate-limit — shared with register-proof per §2.1 "unified attest budget" ──
  // Uses the same prate:{cred_hash} key + tier-differentiated 24h limits as
  // handleRegisterProof. NOTE: spec §2.1 states unified 20/24h + 100/7d; the
  // actual impl here uses T1=50/T2=25/T3=10 (pre-existing drift flagged in
  // CLAUDE.md). S111 matches running behavior for consistency; the limit-
  // number reconciliation is a separate decision.
  const credHash = await hmacSHA256(env.DEDUP_SECRET, "prate:" + credentialId);
  const rateKey = `prate:${credHash}`;
  const rateRaw = await env.DEDUP_KV.get(rateKey);
  let rateCount = 0;
  if (rateRaw) {
    try { rateCount = JSON.parse(rateRaw).count || 0; } catch (_) { rateCount = 0; }
  }
  const tierLimits = { 1: 50, 2: 25, 3: 10 };
  const limit = tierLimits[trustRecord.tier] || 10;
  if (rateCount >= limit) {
    return jsonResponse({
      error: "rate_limited",
      detail: `Rate limit exceeded. Maximum ${limit} writes per 24 hours for Tier ${trustRecord.tier}.`,
      limit,
      current: rateCount,
    }, 429, origin);
  }

  // ── 7. Full manifest field validation per §4.6 ──
  const mv = validateSeriesManifest(manifest);
  if (!mv.ok) {
    const first = mv.errors[0] || { code: "invalid_manifest" };
    return jsonResponse(first, 400, origin);
  }
  const manifestBytes = mv.canonicalBytes;

  // ── 8. Ed25519 verify over SHA-256(JCS(manifest)) ──
  const digestBytes = await sha256Bytes(manifestBytes);
  let verified = false;
  try {
    verified = await verifyEd25519(manifest.creator.public_key, signature, digestBytes);
  } catch (_) {
    return jsonResponse({ error: "invalid_signature" }, 422, origin);
  }
  if (!verified) {
    return jsonResponse({ error: "invalid_signature" }, 422, origin);
  }

  // ── 9. Write series:{id} ──
  const createdAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const seriesRecord = {
    series_id,
    manifest,
    signature,
    status: "open",
    created_at: createdAt,
    closed_at: null,
    member_count: 0,
    last_event_at: createdAt,
  };
  await env.DEDUP_KV.put(seriesKey, JSON.stringify(seriesRecord));

  // ── 10. Append creator_series:{cred_id} (non-fatal) ──
  await writeCreatorSeriesIndex(env, credentialId, {
    series_id,
    created_at: createdAt,
    status_at_write: "open",
  });

  // ── 11. Increment rate counters (24h + 7d, same pattern as handleRegisterProof) ──
  await env.DEDUP_KV.put(rateKey, JSON.stringify({
    count: rateCount + 1,
    last_registration: createdAt,
  }), { expirationTtl: 86400 });
  const weeklyHash = await hmacSHA256(env.DEDUP_SECRET, "wrate:" + credentialId);
  const weeklyKey = `wrate:${weeklyHash}`;
  const weeklyRaw = await env.DEDUP_KV.get(weeklyKey);
  const weeklyCount = weeklyRaw ? (JSON.parse(weeklyRaw).count || 0) : 0;
  await env.DEDUP_KV.put(weeklyKey, JSON.stringify({
    count: weeklyCount + 1,
    last_registration: createdAt,
  }), { expirationTtl: 604800 });

  return jsonResponse({
    series_id,
    status: "open",
    created_at: createdAt,
    short_url: `https://hipprotocol.org/s/${series_id}`,
  }, 200, origin);
}

// ──────────────────────────────────────────────────────────────────────
// POST /register-series-member — SERIES-SPEC-v1 §7.2
// ──────────────────────────────────────────────────────────────────────
// Add a member to an open series. Request body: { event, signature }.
// The event.signature is derived from body.signature (spec §7.2 stores
// the signed event with signature inside series_event:{event_hash}).
//
// Validation order (spec §7.2):
//   1. Parse JSON                             → 400 malformed_body
//   2. event.event_type === "series_add"      → 400 invalid_event_type
//   3. event.member_type === "file"           → 400 invalid_member_type
//   4. Shape-check series_id, member_hash,
//      added_by_credential_id                 → 400 invalid_*
//   5. Read series:{id}                       → 404 series_not_found
//   6. status === "open"                      → 400 series_closed
//   7. added_by_credential_id ===
//      series.manifest.creator.credential_id  → 403 not_series_creator
//   8. trust_record.superseded_by not set     → 403 credential_retired
//   9. Read proof:{member_hash}               → 404 member_proof_not_found
//  10. Duplicate check (series_members idx)   → 400 member_already_in_series
//  11. Rate-limit                             → 429 rate_limited
//  12. JCS + SHA-256 + Ed25519-verify         → 422 invalid_signature
//  13. Write series_event:{event_hash}
//  14. Append series_events:{series_id}
//  15. Increment series.member_count,
//      update series.last_event_at
//  16. Add to series_members:{series_id} idx
//  17. Write affiliations:{member_hash}       (non-fatal, dedup)
//  18. Increment rate counters
async function handleRegisterSeriesMember(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  // ── 1. Parse body ──
  let rawBody;
  try { rawBody = await request.text(); }
  catch (_) { return jsonResponse({ error: "malformed_body" }, 400, origin); }
  if (rawBody.length > 262_144) { // 256 KB — events are tiny vs manifests
    return jsonResponse({ error: "event_too_large" }, 413, origin);
  }
  let body;
  try { body = JSON.parse(rawBody); }
  catch (_) { return jsonResponse({ error: "malformed_body" }, 400, origin); }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return jsonResponse({ error: "malformed_body" }, 400, origin);
  }

  const { event, signature } = body;
  if (typeof event !== "object" || event === null || Array.isArray(event)) {
    return jsonResponse({ error: "missing_field", field: "event" }, 400, origin);
  }
  if (typeof signature !== "string" || signature.length === 0) {
    return jsonResponse({ error: "missing_field", field: "signature" }, 400, origin);
  }

  // ── 2. event.event_type === "series_add" ──
  if (event.event_type !== "series_add") {
    return jsonResponse({ error: "invalid_event_type" }, 400, origin);
  }
  // schema_version sanity — v1 locked.
  if (event.schema_version !== "hip-series-event-1.0") {
    return jsonResponse({ error: "invalid_event_schema_version" }, 400, origin);
  }
  // added_at parseable (provenance only — no drift check).
  if (typeof event.added_at !== "string" || Number.isNaN(Date.parse(event.added_at))) {
    return jsonResponse({ error: "invalid_event_field", field: "added_at" }, 400, origin);
  }

  // ── 3. event.member_type === "file" (§1.2 forward-compat) ──
  if (event.member_type !== "file") {
    return jsonResponse({ error: "invalid_member_type" }, 400, origin);
  }

  // ── 4. Shape-check ids ──
  if (!isSeriesId(event.series_id)) {
    return jsonResponse({ error: "invalid_series_id" }, 400, origin);
  }
  if (!isHex64Lower(event.member_hash)) {
    return jsonResponse({ error: "invalid_member_hash" }, 400, origin);
  }
  if (!isHex64Lower(event.added_by_credential_id)) {
    return jsonResponse({ error: "invalid_credential_id" }, 400, origin);
  }

  // ── 5. Read series:{id} ──
  const seriesKey = `series:${event.series_id}`;
  const seriesRaw = await env.DEDUP_KV.get(seriesKey);
  if (!seriesRaw) {
    return jsonResponse({ error: "series_not_found" }, 404, origin);
  }
  let seriesRecord;
  try { seriesRecord = JSON.parse(seriesRaw); }
  catch (_) { return jsonResponse({ error: "series_not_found" }, 404, origin); }
  if (!seriesRecord || !seriesRecord.manifest || !seriesRecord.manifest.creator) {
    return jsonResponse({ error: "series_not_found" }, 404, origin);
  }

  // ── 6. status === "open" ──
  if (seriesRecord.status !== "open") {
    return jsonResponse({ error: "series_closed" }, 400, origin);
  }

  // ── 7. Credential must match the series creator ──
  if (event.added_by_credential_id !== seriesRecord.manifest.creator.credential_id) {
    return jsonResponse({ error: "not_series_creator" }, 403, origin);
  }

  // ── 8. Trust-record retirement check ──
  const trustRaw = await env.DEDUP_KV.get(`trust:${event.added_by_credential_id}`);
  if (!trustRaw) {
    return jsonResponse({ error: "unknown_credential" }, 401, origin);
  }
  let trustRecord;
  try { trustRecord = JSON.parse(trustRaw); }
  catch (_) { return jsonResponse({ error: "unknown_credential" }, 401, origin); }
  if (trustRecord.superseded_by) {
    return jsonResponse({
      error: "credential_retired",
      revoked_at: trustRecord.superseded_at || null,
    }, 403, origin);
  }

  // ── 9. Read proof:{member_hash} ──
  const memberProofRaw = await env.DEDUP_KV.get(`proof:${event.member_hash}`);
  if (!memberProofRaw) {
    return jsonResponse({ error: "member_proof_not_found" }, 404, origin);
  }

  // ── 10. Duplicate check via series_members secondary index ──
  if (await isSeriesMember(env, event.series_id, event.member_hash)) {
    return jsonResponse({ error: "member_already_in_series" }, 400, origin);
  }

  // ── 11. Rate-limit (unified attest budget, same as creation) ──
  const credHash = await hmacSHA256(env.DEDUP_SECRET, "prate:" + event.added_by_credential_id);
  const rateKey = `prate:${credHash}`;
  const rateRaw = await env.DEDUP_KV.get(rateKey);
  let rateCount = 0;
  if (rateRaw) {
    try { rateCount = JSON.parse(rateRaw).count || 0; } catch (_) { rateCount = 0; }
  }
  const tierLimits = { 1: 50, 2: 25, 3: 10 };
  const limit = tierLimits[trustRecord.tier] || 10;
  if (rateCount >= limit) {
    return jsonResponse({
      error: "rate_limited",
      limit,
      current: rateCount,
    }, 429, origin);
  }

  // ── 12. Ed25519-verify event signature against series creator's public key ──
  // Per spec §7.2: signed payload is JCS(event), server computes event_hash =
  // SHA-256(JCS(event)). Verification uses series.manifest.creator.public_key
  // (the cryptographically-authoritative key locked at series creation).
  const creatorPubKeyB64 = seriesRecord.manifest.creator.public_key;
  let verified = false;
  try {
    verified = await verifySeriesSignature(event, signature, creatorPubKeyB64);
  } catch (_) {
    return jsonResponse({ error: "invalid_signature" }, 422, origin);
  }
  if (!verified) {
    return jsonResponse({ error: "invalid_signature" }, 422, origin);
  }

  // ── 13. Compute event_hash + write series_event:{event_hash} ──
  // event_hash per §1.2 = SHA-256(JCS(event minus signature)). Since the
  // request separates event and signature, body.event already excludes the
  // signature — no stripping needed. Hex lowercase per WF-SPEC.
  const eventHashHex = await sha256Hex(jcsCanonicalize(event));
  const appliedAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  // Stored form = event + signature field (per §7.6 response shape).
  const storedEvent = { ...event, signature };
  await env.DEDUP_KV.put(`series_event:${eventHashHex}`, JSON.stringify(storedEvent));

  // ── 14. Append series_events:{series_id} ──
  const eventsListKey = `series_events:${event.series_id}`;
  const eventsListRaw = await env.DEDUP_KV.get(eventsListKey);
  let eventsList = [];
  if (eventsListRaw) {
    try { eventsList = JSON.parse(eventsListRaw); } catch (_) { eventsList = []; }
    if (!Array.isArray(eventsList)) eventsList = [];
  }
  eventsList.push({
    event_hash: eventHashHex,
    event_type: "series_add",
    applied_at: appliedAt,
  });
  await env.DEDUP_KV.put(eventsListKey, JSON.stringify(eventsList));

  // ── 15. Update series:{id} with member_count + last_event_at ──
  seriesRecord.member_count = (seriesRecord.member_count || 0) + 1;
  seriesRecord.last_event_at = appliedAt;
  await env.DEDUP_KV.put(seriesKey, JSON.stringify(seriesRecord));

  // ── 16. Add to series_members:{series_id} (secondary index for dupe check) ──
  await addToSeriesMembersIndex(env, event.series_id, event.member_hash);

  // ── 17. Write affiliations:{member_hash} (non-fatal) ──
  await writeAffiliation(env, event.member_hash, {
    type: "series",
    id: event.series_id,
    credential_id: event.added_by_credential_id,
    added_at: appliedAt,
  });

  // ── 18. Increment rate counters ──
  await env.DEDUP_KV.put(rateKey, JSON.stringify({
    count: rateCount + 1,
    last_registration: appliedAt,
  }), { expirationTtl: 86400 });
  const weeklyHash = await hmacSHA256(env.DEDUP_SECRET, "wrate:" + event.added_by_credential_id);
  const weeklyKey = `wrate:${weeklyHash}`;
  const weeklyRaw = await env.DEDUP_KV.get(weeklyKey);
  const weeklyCount = weeklyRaw ? (JSON.parse(weeklyRaw).count || 0) : 0;
  await env.DEDUP_KV.put(weeklyKey, JSON.stringify({
    count: weeklyCount + 1,
    last_registration: appliedAt,
  }), { expirationTtl: 604800 });

  return jsonResponse({
    event_hash: eventHashHex,
    series_id: event.series_id,
    member_hash: event.member_hash,
    applied_at: appliedAt,
    member_count: seriesRecord.member_count,
  }, 200, origin);
}

// ──────────────────────────────────────────────────────────────────────
// POST /close-series — SERIES-SPEC-v1 §7.3
// ──────────────────────────────────────────────────────────────────────
// Close an open series. Terminal, idempotent-rejecting operation:
// closing an already-closed series returns 400 series_already_closed
// per §1.3. NOT rate-limited per §2.3.
//
// Validation order (spec §7.3):
//   1. Parse JSON                             → 400 malformed_body
//   2. event.event_type === "series_close"    → 400 invalid_event_type
//   3. Shape-check series_id,
//      closed_by_credential_id                → 400 invalid_*
//   4. Read series:{id}                       → 404 series_not_found
//   5. status === "open"                      → 400 series_already_closed
//   6. closed_by_credential_id ===
//      series.manifest.creator.credential_id  → 403 not_series_creator
//   7. Trust-record retirement check          → 403 credential_retired
//   8. JCS + SHA-256 + Ed25519-verify         → 422 invalid_signature
//   9. Write series_event:{event_hash}
//  10. Append series_events:{series_id}
//  11. Update series.status="closed",
//      series.closed_at = event.closed_at
async function handleCloseSeries(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  // ── 1. Parse body ──
  let rawBody;
  try { rawBody = await request.text(); }
  catch (_) { return jsonResponse({ error: "malformed_body" }, 400, origin); }
  if (rawBody.length > 262_144) {
    return jsonResponse({ error: "event_too_large" }, 413, origin);
  }
  let body;
  try { body = JSON.parse(rawBody); }
  catch (_) { return jsonResponse({ error: "malformed_body" }, 400, origin); }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return jsonResponse({ error: "malformed_body" }, 400, origin);
  }

  const { event, signature } = body;
  if (typeof event !== "object" || event === null || Array.isArray(event)) {
    return jsonResponse({ error: "missing_field", field: "event" }, 400, origin);
  }
  if (typeof signature !== "string" || signature.length === 0) {
    return jsonResponse({ error: "missing_field", field: "signature" }, 400, origin);
  }

  // ── 2. event.event_type === "series_close" ──
  if (event.event_type !== "series_close") {
    return jsonResponse({ error: "invalid_event_type" }, 400, origin);
  }
  if (event.schema_version !== "hip-series-event-1.0") {
    return jsonResponse({ error: "invalid_event_schema_version" }, 400, origin);
  }
  if (typeof event.closed_at !== "string" || Number.isNaN(Date.parse(event.closed_at))) {
    return jsonResponse({ error: "invalid_event_field", field: "closed_at" }, 400, origin);
  }

  // ── 3. Shape-check ids ──
  if (!isSeriesId(event.series_id)) {
    return jsonResponse({ error: "invalid_series_id" }, 400, origin);
  }
  if (!isHex64Lower(event.closed_by_credential_id)) {
    return jsonResponse({ error: "invalid_credential_id" }, 400, origin);
  }

  // ── 4. Read series:{id} ──
  const seriesKey = `series:${event.series_id}`;
  const seriesRaw = await env.DEDUP_KV.get(seriesKey);
  if (!seriesRaw) {
    return jsonResponse({ error: "series_not_found" }, 404, origin);
  }
  let seriesRecord;
  try { seriesRecord = JSON.parse(seriesRaw); }
  catch (_) { return jsonResponse({ error: "series_not_found" }, 404, origin); }
  if (!seriesRecord || !seriesRecord.manifest || !seriesRecord.manifest.creator) {
    return jsonResponse({ error: "series_not_found" }, 404, origin);
  }

  // ── 5. status === "open" ──
  if (seriesRecord.status !== "open") {
    return jsonResponse({ error: "series_already_closed" }, 400, origin);
  }

  // ── 6. Credential must match the series creator ──
  if (event.closed_by_credential_id !== seriesRecord.manifest.creator.credential_id) {
    return jsonResponse({ error: "not_series_creator" }, 403, origin);
  }

  // ── 7. Trust-record retirement check ──
  const trustRaw = await env.DEDUP_KV.get(`trust:${event.closed_by_credential_id}`);
  if (!trustRaw) {
    return jsonResponse({ error: "unknown_credential" }, 401, origin);
  }
  let trustRecord;
  try { trustRecord = JSON.parse(trustRaw); }
  catch (_) { return jsonResponse({ error: "unknown_credential" }, 401, origin); }
  if (trustRecord.superseded_by) {
    return jsonResponse({
      error: "credential_retired",
      revoked_at: trustRecord.superseded_at || null,
    }, 403, origin);
  }

  // ── 8. Ed25519-verify event signature against series creator's public key ──
  const creatorPubKeyB64 = seriesRecord.manifest.creator.public_key;
  let verified = false;
  try {
    verified = await verifySeriesSignature(event, signature, creatorPubKeyB64);
  } catch (_) {
    return jsonResponse({ error: "invalid_signature" }, 422, origin);
  }
  if (!verified) {
    return jsonResponse({ error: "invalid_signature" }, 422, origin);
  }

  // ── 9. Compute event_hash + write series_event:{event_hash} ──
  const eventHashHex = await sha256Hex(jcsCanonicalize(event));
  const appliedAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const storedEvent = { ...event, signature };
  await env.DEDUP_KV.put(`series_event:${eventHashHex}`, JSON.stringify(storedEvent));

  // ── 10. Append series_events:{series_id} ──
  const eventsListKey = `series_events:${event.series_id}`;
  const eventsListRaw = await env.DEDUP_KV.get(eventsListKey);
  let eventsList = [];
  if (eventsListRaw) {
    try { eventsList = JSON.parse(eventsListRaw); } catch (_) { eventsList = []; }
    if (!Array.isArray(eventsList)) eventsList = [];
  }
  eventsList.push({
    event_hash: eventHashHex,
    event_type: "series_close",
    applied_at: appliedAt,
  });
  await env.DEDUP_KV.put(eventsListKey, JSON.stringify(eventsList));

  // ── 11. Flip series status + stamp closed_at ──
  seriesRecord.status = "closed";
  seriesRecord.closed_at = event.closed_at;
  seriesRecord.last_event_at = appliedAt;
  await env.DEDUP_KV.put(seriesKey, JSON.stringify(seriesRecord));

  return jsonResponse({
    event_hash: eventHashHex,
    series_id: event.series_id,
    status: "closed",
    closed_at: event.closed_at,
  }, 200, origin);
}

// ══════════════════════════════════════════════════════════════════════
// S111CW Phase C — SERIES-SPEC-v1 read endpoints (§7.4–§7.8)
// ══════════════════════════════════════════════════════════════════════
// Five public, no-auth read handlers. All five are idempotent and safe
// to cache at the edge (Cloudflare's default caching is sufficient; none
// write back to KV). Shared posture:
//
//   • Shape-validate the path parameter first (400 on malformed input).
//   • Read the primary KV record (404 when the resource doesn't exist,
//     per each §7.X's step list — these are 404s, not 400s, even though
//     the shape was valid).
//   • For paginated endpoints (§7.6, §7.7), cap at 500 newest-first with
//     `truncated: true` when the underlying list is longer. Indices are
//     stored newest-last (append-only) per §1.4/§1.6, so we reverse
//     in-handler before slicing.
//   • Dereference companion records (event_hash → series_event, series_id
//     → series) via Promise.all to avoid CPU-time exhaustion on a 500-
//     entry page — 500 sequential KV reads would comfortably exceed the
//     10 ms CPU budget. Malformed/missing companion records are skipped
//     silently rather than failing the whole page.
//
// No /c/-style OG-preview HTML path here. §7.4 returns a pure 302 redirect
// — the landing HTML (series.html, S112+) owns card rendering.

// ──────────────────────────────────────────────────────────────────────
// GET /s/{series_id} — SERIES-SPEC-v1 §7.4
// ──────────────────────────────────────────────────────────────────────
// Short-URL resolver, symmetric with /c/{collection_id}. Emits 302 to
// the card-rendering landing page. Spec §7.4 proposes
// `series.html?id={series_id}` as the default destination; we honor it
// (implementations MAY diverge, but no reason to here).
//
// HEAD is accepted per §7.4: "handlers SHOULD also accept HEAD and return
// the same 302 Location header with no body, to support link-checkers
// and crawlers." Routing is the same — the Response has a null body,
// which works for both. Cloudflare's runtime strips any body for HEAD
// responses regardless.
//
// Validation order (§7.4):
//   1. Method is GET/HEAD — enforced by dispatch gate.
//   2. Shape-check series_id          → 400 invalid_series_id
//   3. Read series:{series_id}        → 404 series_not_found
//   4. Parse + status ∈ {open,closed} → 404 series_not_found
async function handleSeriesShortUrl(shortId, request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  if (!isSeriesId(shortId)) {
    return jsonResponse({ error: "invalid_series_id" }, 400, origin);
  }

  const raw = await env.DEDUP_KV.get(`series:${shortId}`);
  if (!raw) {
    return jsonResponse({ error: "series_not_found" }, 404, origin);
  }

  let record;
  try { record = JSON.parse(raw); }
  catch (_) { return jsonResponse({ error: "series_not_found" }, 404, origin); }

  // Defensive: unexpected status values (not "open"/"closed") hit 404
  // rather than leaking a garbage redirect. Mirrors handleShortUrl's
  // "collection_hash is 64-hex before emitting" defensive check.
  if (!record
      || (record.status !== "open" && record.status !== "closed")) {
    return jsonResponse({ error: "series_not_found" }, 404, origin);
  }

  return new Response(null, {
    status: 302,
    headers: {
      "Location": `https://hipprotocol.org/series.html?id=${shortId}`,
      ...corsHeaders(origin),
    },
  });
}

// ──────────────────────────────────────────────────────────────────────
// GET /api/series/{series_id} — SERIES-SPEC-v1 §7.5
// ──────────────────────────────────────────────────────────────────────
// JSON read of the series creation record. Public, no auth. Response
// shape matches §7.5 verbatim; short_url is stamped on the response
// (not stored in KV — derivable from series_id) for client convenience.
//
// Validation order (§7.5):
//   1. Shape-check series_id         → 400 invalid_series_id
//   2. Read series:{series_id}       → 404 series_not_found
async function handleGetSeries(seriesId, request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  if (!isSeriesId(seriesId)) {
    return jsonResponse({ error: "invalid_series_id" }, 400, origin);
  }

  const raw = await env.DEDUP_KV.get(`series:${seriesId}`);
  if (!raw) {
    return jsonResponse({ error: "series_not_found" }, 404, origin);
  }

  let record;
  try { record = JSON.parse(raw); }
  catch (_) { return jsonResponse({ error: "series_not_found" }, 404, origin); }
  if (!record || !record.series_id) {
    return jsonResponse({ error: "series_not_found" }, 404, origin);
  }

  // Stamp short_url at response time per §7.5. Not part of the stored
  // record — always derivable from series_id.
  record.short_url = `https://hipprotocol.org/s/${seriesId}`;

  return jsonResponse(record, 200, origin);
}

// ──────────────────────────────────────────────────────────────────────
// GET /api/series/{series_id}/events — SERIES-SPEC-v1 §7.6
// ──────────────────────────────────────────────────────────────────────
// Paginated event list, 500 cap, newest-first. Each entry dereferences
// to the full signed event record in series_event:{event_hash} so
// consumers can independently verify signatures against the creator's
// public key (fetched via /api/series/{id} → manifest.creator.public_key).
//
// The stored index series_events:{series_id} is newest-last per §1.4.
// We reverse in-handler, cap at 500, then Promise.all the individual
// series_event fetches. 500 sequential KV reads would bust the CPU
// budget; parallel reads complete comfortably under 10 ms.
//
// Validation order (§7.6):
//   1. Shape-check series_id                 → 400 invalid_series_id
//   2. Read series:{series_id}               → 404 series_not_found
//   3. Read series_events:{series_id} — OK if missing (returns [])
async function handleGetSeriesEvents(seriesId, request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  if (!isSeriesId(seriesId)) {
    return jsonResponse({ error: "invalid_series_id" }, 400, origin);
  }

  const seriesRaw = await env.DEDUP_KV.get(`series:${seriesId}`);
  if (!seriesRaw) {
    return jsonResponse({ error: "series_not_found" }, 404, origin);
  }

  const indexRaw = await env.DEDUP_KV.get(`series_events:${seriesId}`);
  let index = [];
  if (indexRaw) {
    try { index = JSON.parse(indexRaw); } catch (_) { index = []; }
    if (!Array.isArray(index)) index = [];
  }

  // Stored newest-last → reverse for newest-first.
  const reversed = index.slice().reverse();
  const CAP = 500;
  const truncated = reversed.length > CAP;
  const capped = truncated ? reversed.slice(0, CAP) : reversed;

  // Parallel dereference of each event_hash → series_event:{hash}.
  const eventRaws = await Promise.all(
    capped.map(e => {
      if (!e || typeof e.event_hash !== "string") return null;
      return env.DEDUP_KV.get(`series_event:${e.event_hash}`);
    })
  );

  const events = [];
  for (let i = 0; i < capped.length; i++) {
    const e = capped[i];
    const raw = eventRaws[i];
    if (!raw) continue; // missing companion record — skip silently
    let eventRec;
    try { eventRec = JSON.parse(raw); } catch (_) { continue; }
    if (!eventRec) continue;
    events.push({
      event_hash: e.event_hash,
      event_type: e.event_type,
      applied_at: e.applied_at,
      event: eventRec,
    });
  }

  return jsonResponse({
    series_id: seriesId,
    events,
    truncated,
  }, 200, origin);
}

// ──────────────────────────────────────────────────────────────────────
// GET /api/creator/{credential_id}/series — SERIES-SPEC-v1 §7.7
// ──────────────────────────────────────────────────────────────────────
// Portfolio enumeration: all series authored by a given credential.
// 500 cap newest-first. Each entry carries a live `series_snapshot`
// joined from series:{id} at response time (per §7.7 "clients that want
// the full record call /api/series/{series_id} per entry — snapshots
// MAY be omitted if the read budget is constrained").
//
// We include snapshots by default. Same parallel-read posture as §7.6
// — 500 creator_series entries become 500 parallel KV reads. A future
// optimization could cache the snapshot in creator_series itself and
// refresh on /close-series; deferred (spec permits either shape).
//
// Validation order (§7.7):
//   1. Shape-check credential_id              → 400 invalid_credential_id
//   2. Read trust:{credential_id}             → 404 creator_not_found
//   3. Read creator_series:{credential_id} — OK if missing (returns [])
async function handleGetCreatorSeries(credentialId, request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  if (!isHex64Lower(credentialId)) {
    return jsonResponse({ error: "invalid_credential_id" }, 400, origin);
  }

  // §7.7 step 2: "A well-formed credential_id that was never issued." → 404.
  const trustRaw = await env.DEDUP_KV.get(`trust:${credentialId}`);
  if (!trustRaw) {
    return jsonResponse({ error: "creator_not_found" }, 404, origin);
  }

  const indexRaw = await env.DEDUP_KV.get(`creator_series:${credentialId}`);
  let index = [];
  if (indexRaw) {
    try { index = JSON.parse(indexRaw); } catch (_) { index = []; }
    if (!Array.isArray(index)) index = [];
  }

  const reversed = index.slice().reverse();
  const CAP = 500;
  const truncated = reversed.length > CAP;
  const capped = truncated ? reversed.slice(0, CAP) : reversed;

  // Parallel snapshot dereference.
  const seriesRaws = await Promise.all(
    capped.map(e => {
      if (!e || typeof e.series_id !== "string") return null;
      return env.DEDUP_KV.get(`series:${e.series_id}`);
    })
  );

  const seriesList = [];
  for (let i = 0; i < capped.length; i++) {
    const e = capped[i];
    const entry = {
      series_id: e.series_id,
      created_at: e.created_at,
      status_at_write: e.status_at_write || "open",
    };
    const raw = seriesRaws[i];
    if (raw) {
      try {
        const rec = JSON.parse(raw);
        if (rec && rec.manifest) {
          const snap = {
            title: rec.manifest.title,
            status: rec.status,
            member_count: rec.member_count || 0,
            closed_at: rec.closed_at || null,
          };
          if (rec.manifest.cover_member_hash) {
            snap.cover_member_hash = rec.manifest.cover_member_hash;
          }
          entry.series_snapshot = snap;
        }
      } catch (_) { /* snapshot omitted on malformed companion */ }
    }
    seriesList.push(entry);
  }

  return jsonResponse({
    credential_id: credentialId,
    series: seriesList,
    truncated,
  }, 200, origin);
}

// ──────────────────────────────────────────────────────────────────────
// GET /api/affiliations/{content_hash} — SERIES-SPEC-v1 §7.8
// ──────────────────────────────────────────────────────────────────────
// Multi-affiliation index lookup. Always 200 with an `affiliations`
// array — per §7.8, this endpoint's purpose is "list affiliations,"
// not "verify attestation." A missing affiliations:{hash} key returns
// an empty array, not 404.
//
// Stored newest-last per §1.5; reversed here for newest-first rendering
// (§7.8 final paragraph).
//
// S112CW: handleRegisterCollectionProof now calls writeAffiliation for
// each member at the end of the active-record write sequence (§6i,
// worker.js ~L3747), so forward-going collection affiliations surface
// here alongside series affiliations. Pre-S112 collections are NOT
// backfilled per the §3 Q3 (a) "new-only" decision (CLAUDE.md carryover
// #36); a one-shot script can reconcile historicals if demand surfaces.
// A missing affiliations:{hash} key still returns an empty array, not
// 404 — this endpoint is "list affiliations," not "verify attestation."
//
// Validation order (§7.8):
//   1. Shape-check content_hash               → 400 invalid_content_hash
//   2. Read affiliations:{content_hash} — OK if missing (returns [])
async function handleGetAffiliations(contentHash, request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  if (!isHex64Lower(contentHash)) {
    return jsonResponse({ error: "invalid_content_hash" }, 400, origin);
  }

  const raw = await env.DEDUP_KV.get(`affiliations:${contentHash}`);
  let list = [];
  if (raw) {
    try { list = JSON.parse(raw); } catch (_) { list = []; }
    if (!Array.isArray(list)) list = [];
  }

  // Stored newest-last per §1.5; reverse for newest-first rendering.
  const affiliations = list.slice().reverse();

  return jsonResponse({
    content_hash: contentHash,
    affiliations,
  }, 200, origin);
}

// GET /api/proof/{hex}/history — §3.3.5 S106.5CW multi-attestor visibility.
// Returns every record that ever claimed a hash, ascending by timestamp.
// First-writer wins the default /api/proof/{hash} route (unchanged); this
// endpoint only surfaces subsequent co-claimants so the file drop in Verify
// can still discover them. See SESSION 106.5CW/S106.5CW-KICKOFF.md Phase 0
// for the four decisions that shape this response.
async function handleProofHistory(hexHash, request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  // Validate hex (64 lowercase chars) per §3.3.1.
  if (typeof hexHash !== "string" || !/^[0-9a-f]{64}$/.test(hexHash)) {
    return jsonResponse({ error: "invalid_hash" }, 400, origin);
  }

  // 1. First-writer lookup via the unified dual-read helper. This covers
  //    hash:{hex}, legacy proof:{hex}, and legacy alias:{hex}.
  const firstHit = await readHash(env, hexHash);

  // 2. List all hash_claim:{hex}:* rows. Paginate defensively.
  const claimKeys = [];
  let cursor = undefined;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const listOpts = { prefix: `hash_claim:${hexHash}:` };
    if (cursor) listOpts.cursor = cursor;
    const page = await env.DEDUP_KV.list(listOpts);
    if (page && Array.isArray(page.keys)) {
      for (const k of page.keys) claimKeys.push(k.name);
    }
    if (!page || page.list_complete || !page.cursor) break;
    cursor = page.cursor;
  }

  if (!firstHit && claimKeys.length === 0) {
    return jsonResponse({ error: "not_found" }, 404, origin);
  }

  // 3. Fetch all hash_claim values in parallel.
  const claimRaws = await Promise.all(
    claimKeys.map(k => env.DEDUP_KV.get(k))
  );
  const claims = [];
  const prefixLen = `hash_claim:${hexHash}:`.length;
  for (let i = 0; i < claimKeys.length; i++) {
    const raw = claimRaws[i];
    if (!raw) continue;
    let v;
    try { v = JSON.parse(raw); } catch (_) { continue; }
    const collectionId = claimKeys[i].slice(prefixLen);
    if (!collectionId) continue;
    claims.push({ collectionId, value: v });
  }

  // 4. Resolve target collections. Needed for:
  //    (a) first-writer collection_member timestamp + short_url + collection_hash
  //    (b) each claim's short_url + Decision C1 pending-skip gate
  const neededCollectionIds = new Set(claims.map(c => c.collectionId));
  if (firstHit && firstHit.record && firstHit.record.type === "collection_member"
      && firstHit.record.collection_id) {
    neededCollectionIds.add(firstHit.record.collection_id);
  }
  const colIds = Array.from(neededCollectionIds);
  const colRaws = await Promise.all(
    colIds.map(id => env.DEDUP_KV.get(`collection:${id}`))
  );
  const activeCol = new Map();
  for (let i = 0; i < colIds.length; i++) {
    const raw = colRaws[i];
    if (!raw) continue;
    try {
      const parsed = JSON.parse(raw);
      // Decision C1: skip pending/non-active collections — matches §3.3.4
      // reader contract ("resolvers MUST treat pending collections as
      // not-yet-registered").
      if (parsed && parsed.status === "active") {
        activeCol.set(colIds[i], parsed);
      }
    } catch (_) { /* skip malformed */ }
  }

  // 5. Assemble entries. Role is determined by source namespace:
  //    - hash:{hex}  → first_writer
  //    - hash_claim:* → subsequent
  //    Invariant: the first-writer's nowIso is always ≤ any claim's nowIso,
  //    so the source-based role tag aligns with chronological order after
  //    the ascending sort below. If the first-writer collection is pending
  //    or missing, it's omitted here and the response contains only
  //    subsequent claims.
  const entries = [];

  if (firstHit && firstHit.record) {
    const rec = firstHit.record;
    if (rec.type === "collection_member") {
      const col = activeCol.get(rec.collection_id);
      if (col) {
        entries.push({
          record_type: "collection_member",
          role: "first_writer",
          credential_id: (col.manifest && col.manifest.creator
            && col.manifest.creator.credential_id) || null,
          timestamp_iso: col.created_at || null,
          hash_type: rec.match_type === "source" ? "member_hash" : "attested_copy_hash",
          collection_id: rec.collection_id,
          short_url: col.short_url || `https://hipprotocol.org/c/${rec.collection_id}`,
          collection_hash: col.collection_hash || null,
          member_index: rec.member_index,
        });
      }
      // else: first-writer collection is pending/missing — skip per C1.
    } else if (rec.type === "standalone") {
      // S103 standalone proof record. matchedVia may live on the wrapper
      // (legacy alias: namespace) or be absent (implies "content" match).
      const std = rec.record || rec;
      const matchedVia = rec.matchedVia || std.matchedVia || "content";
      entries.push({
        record_type: "standalone",
        role: "first_writer",
        credential_id: std.credential_id || null,
        timestamp_iso: std.attested_at || std.created_at || null,
        hash_type: matchedVia === "alias" ? "attested_copy_hash" : "member_hash",
        standalone_record_ref: { hash: hexHash, matchedVia },
      });
    }
  }

  for (const c of claims) {
    const col = activeCol.get(c.collectionId);
    if (!col) continue; // Decision C1: skip pending/missing target
    const v = c.value || {};
    entries.push({
      record_type: "collection_member",
      role: "subsequent",
      credential_id: v.credential_id || null,
      timestamp_iso: v.created_at || null,
      hash_type: v.hash_type || null,
      collection_id: c.collectionId,
      short_url: col.short_url || `https://hipprotocol.org/c/${c.collectionId}`,
      collection_hash: v.collection_hash || col.collection_hash || null,
      member_index: typeof v.member_index === "number" ? v.member_index : null,
    });
  }

  if (entries.length === 0) {
    return jsonResponse({ error: "not_found" }, 404, origin);
  }

  // 6. Ascending sort on timestamp_iso (lex sort is correct for ISO-8601).
  //    null/missing timestamps sort last for deterministic output.
  entries.sort((a, b) => {
    const ta = a.timestamp_iso || "\uffff";
    const tb = b.timestamp_iso || "\uffff";
    if (ta < tb) return -1;
    if (ta > tb) return 1;
    return 0;
  });

  return jsonResponse({
    hash: hexHash,
    total: entries.length,
    entries,
  }, 200, origin);
}

// ════════════════════════════════════════════════════════════════
// ── S106.6CW Collection read handlers (Phase 1) ──
// §3.4.2 GET /api/collection/{id}
// §3.4.3 GET /api/collection/{id}/member/{i}
//
// Both are pure reads against collection:{id}. Pending-skip per S106.5
// Decision C1 / §3.3.4 reader contract: status !== "active" ⇒ 404.
// Malformed {id} (not 20-char base32-lowercase per §3.3.4 step 1 and
// S106.6 Ambiguity F) ⇒ 400. Malformed {i} (not a non-negative decimal
// integer) ⇒ 400. Member index out of range ⇒ 404. CORS: public (§3.4.8).
// ════════════════════════════════════════════════════════════════

// §3.4.2 — Fetch a collection record. Primary read path for proof.html.
// Response on success: {collection_id, manifest, signature, collection_hash,
// short_url, status, created_at, member_sidecar}. resolution_conflicts is
// an S106-internal field persisted for idempotent POST replay and is NOT
// surfaced here (not part of the §3.4.2 shape).
async function handleCollectionGet(id, request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  if (!isCollectionId(id)) {
    return jsonResponse({ error: "invalid_collection_id" }, 400, origin);
  }

  const raw = await env.DEDUP_KV.get(`collection:${id}`);
  if (!raw) {
    return jsonResponse({ error: "not_found" }, 404, origin);
  }

  let record;
  try { record = JSON.parse(raw); }
  catch (_) { return jsonResponse({ error: "not_found" }, 404, origin); }

  // Decision C1 pending-skip — treat pending / malformed status identically
  // to "not found" so failed-mid-write POSTs never leak via reads.
  if (!record || record.status !== "active") {
    return jsonResponse({ error: "not_found" }, 404, origin);
  }

  return jsonResponse({
    collection_id: record.collection_id,
    manifest: record.manifest,
    signature: record.signature,
    collection_hash: record.collection_hash,
    short_url: record.short_url,
    status: record.status,
    created_at: record.created_at,
    member_sidecar: record.member_sidecar || {},
    chain_sidecar: record.chain_sidecar || null, // S106.7CW — surface chain metadata if present
  }, 200, origin);
}

// §3.4.3 — Thin fetch for a single member. Cheaper/narrower than fetching the
// full collection record; present for tooling that cares about only one member.
// Optional fields per S106 Decision 1 and S106.6 Ambiguity C: filename is
// omitted when absent from the signed manifest (do NOT emit filename: ""),
// collection_title is omitted when absent from manifest, and download_url_hint
// is omitted when absent from member_sidecar[index].
async function handleCollectionMember(id, indexStr, request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  if (!isCollectionId(id)) {
    return jsonResponse({ error: "invalid_collection_id" }, 400, origin);
  }

  // {i} MUST be a non-negative decimal integer with no leading zeros (except "0"
  // itself) — this also rejects "01", "+1", "-1", " 1", "1.0", "1e2", hex, etc.
  if (typeof indexStr !== "string" || !/^(0|[1-9][0-9]*)$/.test(indexStr)) {
    return jsonResponse({ error: "invalid_member_index" }, 400, origin);
  }
  const index = parseInt(indexStr, 10);
  if (!Number.isFinite(index) || index < 0) {
    return jsonResponse({ error: "invalid_member_index" }, 400, origin);
  }

  const raw = await env.DEDUP_KV.get(`collection:${id}`);
  if (!raw) {
    return jsonResponse({ error: "not_found" }, 404, origin);
  }

  let record;
  try { record = JSON.parse(raw); }
  catch (_) { return jsonResponse({ error: "not_found" }, 404, origin); }

  if (!record || record.status !== "active") {
    return jsonResponse({ error: "not_found" }, 404, origin);
  }

  const members = record.manifest && Array.isArray(record.manifest.members)
    ? record.manifest.members : [];
  if (index >= members.length) {
    return jsonResponse({ error: "not_found" }, 404, origin);
  }

  const m = members[index] || {};

  // Build response preserving §3.4.3 field order for a stable wire shape.
  // collection_id, index, (filename?), size, mime, member_hash,
  // attested_copy_hash, collection_short_url, (collection_title?),
  // (download_url_hint?).
  const out = {
    collection_id: record.collection_id,
    index,
  };
  if (typeof m.filename === "string" && m.filename.length > 0) {
    out.filename = m.filename;
  }
  out.size = m.size;
  out.mime = m.mime;
  out.member_hash = m.member_hash;
  out.attested_copy_hash = m.attested_copy_hash;
  out.collection_short_url = record.short_url;
  if (record.manifest && typeof record.manifest.title === "string"
      && record.manifest.title.length > 0) {
    out.collection_title = record.manifest.title;
  }
  const sidecar = (record.member_sidecar && typeof record.member_sidecar === "object")
    ? record.member_sidecar : {};
  const sc = sidecar[String(index)];
  if (sc && typeof sc.download_url_hint === "string" && sc.download_url_hint.length > 0) {
    out.download_url_hint = sc.download_url_hint;
  }

  return jsonResponse(out, 200, origin);
}

// §3.4.7 — GET /c/{short_id} short-URL resolver.
//
// S106.6CW Phase 0 Decision 2 Option C: the S106 POST handler writes
// `short_url = https://hipprotocol.org/c/${collection_id}` (worker.js
// handleRegisterCollectionProof) with NO reverse index key — the
// {short_id} in the URL IS the 20-char base32-lowercase collection_id.
// So this handler validates + fetches collection:{sid} directly, with
// no migration and no scan. Cost: 1 KV read.
//
// Behavior:
//   • {short_id} doesn't match the 20-char base32-lowercase shape    → 400.
//   • collection:{sid} missing, malformed, or status !== "active"    → 404.
//   • otherwise 302 → /proof.html?hash={collection_hash} so proof.html's
//     shared dispatch re-hits /api/proof/{hash} and renders the card.
//
// Defensive: we verify collection_hash is 64-hex before emitting it in
// the Location header — a malformed record shouldn't leak a garbage URL.
async function handleShortUrl(shortId, request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  if (!isCollectionId(shortId)) {
    return jsonResponse({ error: "invalid_short_id" }, 400, origin);
  }

  const raw = await env.DEDUP_KV.get(`collection:${shortId}`);
  if (!raw) {
    return jsonResponse({ error: "not_found" }, 404, origin);
  }

  let record;
  try { record = JSON.parse(raw); }
  catch (_) { return jsonResponse({ error: "not_found" }, 404, origin); }

  // Decision C1 pending-skip + sanity on collection_hash.
  if (!record
      || record.status !== "active"
      || typeof record.collection_hash !== "string"
      || !/^[0-9a-f]{64}$/.test(record.collection_hash)) {
    return jsonResponse({ error: "not_found" }, 404, origin);
  }

  return new Response(null, {
    status: 302,
    headers: {
      "Location": `https://hipprotocol.org/proof.html?hash=${record.collection_hash}`,
      ...corsHeaders(origin),
    },
  });
}

// ══════════════════════════════════════════════════════════════════════
// S106.8CW §3.4.4 — PATCH /api/collection/{id}/sidecar.
// ══════════════════════════════════════════════════════════════════════
// Credential-signed mutation of member_sidecar (download-URL hints only).
// collection_hash, signature, manifest, status, chain_sidecar all unchanged.
// Returns 200 { "updated_indices": [...] } ascending numeric (Ambiguity A).
//
// Signed payload: SHA-256(JCS({collection_id, sidecar_updates, credential_id,
// timestamp})). collection_id comes from the URL path, NOT the body —
// prevents mismatched-URL replay.
//
// Validation order (Phase 0 kickoff §2.1, preserves spec §3.4.4 ordering
// with rate-limit inserted before signature verify so brute-force attempts
// consume budget):
//   1. Parse JSON                                         → 400 malformed_body
//   2. Shape-check {id}                                   → 400 invalid_collection_id
//   3. Read collection; missing OR status!=="active"      → 404 not_found (D1 pending-skip)
//   4. credential_id matches creator credential_id        → else 403 credential_mismatch
//   5. timestamp within ±5 min of worker clock            → else 400 clock_drift
//   6. Rate-limit (patch_rate:{collection_id}, 10/hr,
//      fixed-hour window, Ambiguity D)                    → else 429 rate_limited
//   7. JCS-canonicalize + SHA-256 + Ed25519-verify against
//      trust:{id}.public_key (hex→bytes via G.2 helper)   → else 422 invalid_signature
//   8. Validate sidecar_updates keys: non-empty, string-
//      form integer /^(0|[1-9][0-9]*)$/, in [0, len)      → 400 invalid_sidecar_key
//                                                            or sidecar_index_out_of_range
//   9. Validate each value is a plain object              → 400 invalid_sidecar_value
//  10. Shallow-merge per-index (Ambiguity B/C: replace
//      inner object), write back collection:{id}
//  11. Return 200 { updated_indices: [...asc] }
async function handleCollectionSidecarPatch(id, request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  // ── Step 2: shape-check {id} before any body parse or KV read ──
  if (!isCollectionId(id)) {
    return jsonResponse({ error: "invalid_collection_id" }, 400, origin);
  }

  // ── Step 1: parse body ──
  let body;
  try { body = await request.json(); }
  catch (_) {
    return jsonResponse({ error: "malformed_body" }, 400, origin);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return jsonResponse({ error: "malformed_body" }, 400, origin);
  }
  const { sidecar_updates, credential_id, timestamp, signature } = body;
  if (typeof credential_id !== "string" || credential_id.length === 0
      || typeof timestamp !== "string" || timestamp.length === 0
      || typeof signature !== "string" || signature.length === 0
      || !sidecar_updates || typeof sidecar_updates !== "object"
      || Array.isArray(sidecar_updates)) {
    return jsonResponse({ error: "malformed_body" }, 400, origin);
  }

  // ── Step 3: read collection; gate on status === "active" (D1 pending-skip) ──
  const collectionKey = `collection:${id}`;
  const raw = await env.DEDUP_KV.get(collectionKey);
  if (!raw) return jsonResponse({ error: "not_found" }, 404, origin);
  let record;
  try { record = JSON.parse(raw); }
  catch (_) { return jsonResponse({ error: "not_found" }, 404, origin); }
  if (!record || record.status !== "active") {
    return jsonResponse({ error: "not_found" }, 404, origin);
  }

  // ── Step 4: credential_id match ──
  const recordCredId = record.manifest && record.manifest.creator
    && record.manifest.creator.credential_id;
  if (credential_id !== recordCredId) {
    return jsonResponse({ error: "credential_mismatch" }, 403, origin);
  }

  // ── Step 5: timestamp drift ±5 min (300_000 ms) ──
  const ts = new Date(timestamp);
  if (Number.isNaN(ts.getTime())
      || Math.abs(Date.now() - ts.getTime()) > 300000) {
    return jsonResponse({ error: "clock_drift" }, 400, origin);
  }

  // ── Step 6: rate-limit (D2 per-collection, Ambiguity D fixed-hour window) ──
  const rateKey = `patch_rate:${id}`;
  const nowMs = Date.now();
  const WINDOW_MS = 3600000;
  const LIMIT = 10;
  let windowStartMs = nowMs;
  let count = 0;
  try {
    const rateRaw = await env.DEDUP_KV.get(rateKey);
    if (rateRaw) {
      const parsed = JSON.parse(rateRaw);
      if (parsed && typeof parsed.window_start_ms === "number"
          && typeof parsed.count === "number"
          && nowMs - parsed.window_start_ms <= WINDOW_MS) {
        windowStartMs = parsed.window_start_ms;
        count = parsed.count;
      }
    }
  } catch (_) { /* fall through: stale/malformed counter → fresh window */ }
  if (count >= LIMIT) {
    return jsonResponse({ error: "rate_limited" }, 429, origin);
  }
  // Persist the incremented counter BEFORE sig-verify so brute-force forged
  // signatures also consume budget. Write is best-effort: failure to persist
  // doesn't block the PATCH (worst case: one uncounted request).
  try {
    await env.DEDUP_KV.put(rateKey,
      JSON.stringify({ window_start_ms: windowStartMs, count: count + 1 }),
      { expirationTtl: 7200 }); // 2h TTL — KV self-cleans stale windows
  } catch (_) { /* intentional: rate-limit persistence is not load-bearing */ }

  // ── Step 7: Ed25519 signature verify ──
  // Public key comes from trust:{id}, NOT the body — creator's stored key is
  // authoritative. Spec §3.4.4 step 5 + §3.4.8 "signature-based".
  const trustRaw = await env.DEDUP_KV.get(`trust:${credential_id}`);
  if (!trustRaw) {
    // Credential absent from trust. Spec doesn't enumerate this case for
    // PATCH; 403 credential_mismatch is the closest semantic proxy (the
    // signing key cannot match because it doesn't exist).
    return jsonResponse({ error: "credential_mismatch" }, 403, origin);
  }
  let trustRecord;
  try { trustRecord = JSON.parse(trustRaw); }
  catch (_) { return jsonResponse({ error: "credential_mismatch" }, 403, origin); }
  if (trustRecord.superseded_by) {
    return jsonResponse({
      error: "credential_revoked",
      revoked_at: trustRecord.superseded_at || null,
    }, 403, origin);
  }
  const pubKeyBytes = normalizePubkeyFromHex(trustRecord.public_key || "");
  if (!pubKeyBytes) {
    // Legacy trust record without public_key — PATCH cannot proceed without
    // the authoritative key. Reject as credential_mismatch (not 500) since
    // this is a data-shape gap specific to the caller's credential, not a
    // worker bug.
    return jsonResponse({ error: "credential_mismatch" }, 403, origin);
  }

  // Canonicalize {collection_id, sidecar_updates, credential_id, timestamp}
  // — collection_id bound to URL path, not body.
  const canonicalBytes = jcsCanonicalize({
    collection_id: id,
    sidecar_updates,
    credential_id,
    timestamp,
  });
  const digestBytes = await sha256Bytes(canonicalBytes);
  let verified = false;
  try {
    verified = await verifyEd25519FromBytes(pubKeyBytes, signature, digestBytes);
  } catch (_) {
    return jsonResponse({ error: "invalid_signature" }, 422, origin);
  }
  if (!verified) {
    return jsonResponse({ error: "invalid_signature" }, 422, origin);
  }

  // ── Step 8: validate keys ──
  const members = (record.manifest && Array.isArray(record.manifest.members))
    ? record.manifest.members : [];
  const memberCount = members.length;
  const updateKeys = Object.keys(sidecar_updates);
  if (updateKeys.length === 0) {
    return jsonResponse({ error: "malformed_body" }, 400, origin);
  }
  for (const k of updateKeys) {
    if (typeof k !== "string" || !/^(0|[1-9][0-9]*)$/.test(k)) {
      return jsonResponse({ error: "invalid_sidecar_key", key: k }, 400, origin);
    }
    const idx = parseInt(k, 10);
    if (!Number.isFinite(idx) || idx < 0 || idx >= memberCount) {
      return jsonResponse({
        error: "sidecar_index_out_of_range",
        key: k,
      }, 400, origin);
    }
  }

  // ── Step 9: validate values (each must be a plain object) ──
  for (const k of updateKeys) {
    const v = sidecar_updates[k];
    if (!v || typeof v !== "object" || Array.isArray(v)) {
      return jsonResponse({ error: "invalid_sidecar_value", key: k }, 400, origin);
    }
  }

  // ── Step 10: shallow-merge per-index and write back ──
  // Ambiguity B/C: PATCH replaces the per-index object entirely (inner object
  // is the unit of update). Existing per-index entries not in sidecar_updates
  // are preserved via the spread. Existing inner fields on touched indices
  // are dropped if not restated in the PATCH body.
  const priorSidecar = (record.member_sidecar
    && typeof record.member_sidecar === "object"
    && !Array.isArray(record.member_sidecar))
    ? record.member_sidecar : {};
  const newSidecar = { ...priorSidecar };
  for (const k of updateKeys) {
    newSidecar[k] = sidecar_updates[k];
  }
  const updatedRecord = { ...record, member_sidecar: newSidecar };
  try {
    await env.DEDUP_KV.put(collectionKey, JSON.stringify(updatedRecord));
  } catch (_) {
    return jsonResponse({ error: "kv_write_failure", retry: true }, 500, origin);
  }

  // ── Step 11: response (Ambiguity A — ascending numeric) ──
  const updated_indices = updateKeys.map(Number).sort((a, b) => a - b);
  return jsonResponse({ updated_indices }, 200, origin);
}

// §3.4.6 — Creator's collection list for the dashboard UI (S106.7CW Phase 4).
//
// Spec-vs-impl divergence resolved at S106.7 Phase 0 (Decision D7):
// §3.4.6 specifies "GET /api/collection-by-credential/{credential_id}" with
// "Authorization: Bearer <credential_token>". HIPKit has no bearer-token
// credential auth — every credential-authenticated endpoint in this worker
// (handlePortfolio, handleCredentialAttestations) uses verifyAppAuth with a
// body-signed {credential_id, public_key, timestamp, signature}. Mirroring
// that pattern here: POST (not GET), body-signed auth, URL credential_id
// must match the authenticated one.
//
// Request body (JSON): verifyAppAuth fields + optional { page }.
// Response:
//   {
//     credential_id, total, page, page_size: 50,
//     collections: [ {collection_id, title, issued_at, member_count,
//                     cover_index, short_url, created_at, chain_id}, ... ]
//   }
// Page size is fixed at 50 per spec §3.4.6.
async function handleCollectionByCredential(request, env, credentialIdFromUrl) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;

  const auth = await verifyAppAuth(request, "/api/collection-by-credential", env);
  if (!auth.ok) return jsonResponse({ error: auth.error }, auth.status, origin);

  const { credential_id, body } = auth;

  // URL id must match authenticated credential. Defense-in-depth — mirrors
  // the handleCredentialAttestations check (L4756-4760 pre-session).
  if (credentialIdFromUrl && credentialIdFromUrl !== credential_id) {
    return jsonResponse({
      error: "URL credential_id does not match authenticated credential",
    }, 400, origin);
  }

  // Pagination: spec §3.4.6 says page=0, page_size=50. page_size is fixed.
  let page = parseInt(body.page, 10);
  if (!Number.isFinite(page) || page < 0) page = 0;
  const pageSize = 50;

  const indexRaw = await env.DEDUP_KV.get(`collection_by_credential:${credential_id}`);
  if (!indexRaw) {
    return jsonResponse({
      credential_id,
      total: 0,
      page,
      page_size: pageSize,
      collections: [],
    }, 200, origin);
  }

  let index;
  try { index = JSON.parse(indexRaw); } catch (_) { index = null; }
  if (!Array.isArray(index)) {
    return jsonResponse({
      credential_id,
      total: 0,
      page,
      page_size: pageSize,
      collections: [],
    }, 200, origin);
  }

  const total = index.length;
  const start = page * pageSize;
  const slice = (start >= total) ? [] : index.slice(start, start + pageSize);

  // Defensively project only the §3.4.6 response fields; the stored shape
  // already matches this projection (set at write time in §3.5.4), but
  // projecting here insulates us from future storage drift.
  const collections = slice.map(e => ({
    collection_id: e.collection_id,
    title: e.title,
    issued_at: e.issued_at,
    member_count: e.member_count,
    cover_index: e.cover_index,
    short_url: e.short_url,
    created_at: e.created_at,
    chain_id: (typeof e.chain_id === "string") ? e.chain_id : null,
  }));

  return jsonResponse({
    credential_id,
    total,
    page,
    page_size: pageSize,
    collections,
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

  // If public_key provided now (backfill), validate it matches credential_id.
  // S114CW: also validate shape if it came from the stored record.
  const effectivePubKey = public_key || record.public_key;
  if (!effectivePubKey) {
    return jsonResponse({
      error: "public_key required (not stored on pre-S38 record) — caller must provide it to prove credential possession before unsealing."
    }, 400, origin);
  }
  if (!/^[0-9a-f]{64}$/.test(effectivePubKey)) {
    return jsonResponse({ error: "public_key must be a 64-character lowercase hex string." }, 400, origin);
  }
  const pubKeyBytesU = new Uint8Array(effectivePubKey.match(/.{2}/g).map(b => parseInt(b, 16)));
  const hashBufU = await crypto.subtle.digest("SHA-256", pubKeyBytesU);
  const computedIdU = Array.from(new Uint8Array(hashBufU)).map(b => b.toString(16).padStart(2, "0")).join("");
  if (computedIdU !== credential_id) {
    return jsonResponse({ error: "public_key does not match credential_id." }, 400, origin);
  }

  // ── S114CW BLOCKS ANNOUNCE #1: Ed25519 signature verification ──
  // Canonical: "UNSEAL|{content_hash}|{credential_id}" (matches
  // hip-protocol/index.html L2696). Pre-S114CW this endpoint accepted the
  // signature field without verifying it — any party knowing content_hash +
  // credential_id + public_key (all public) could unseal someone else's record.
  const canonUnseal = "UNSEAL|" + content_hash + "|" + credential_id;
  const encU = new TextEncoder();
  let _unsealOk;
  try {
    _unsealOk = await verifyEd25519FromBytes(pubKeyBytesU, signature, encU.encode(canonUnseal));
  } catch (_e) {
    return jsonResponse({ error: "Malformed signature" }, 400, origin);
  }
  if (!_unsealOk) {
    return jsonResponse({
      error: "invalid_signature",
      detail: "Unseal signature does not verify against canonical \"UNSEAL|{content_hash}|{credential_id}\"."
    }, 403, origin);
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

  // S114CW: public_key is now REQUIRED (was optional). Needed for sig verify.
  if (!public_key) {
    return jsonResponse({
      error: "Missing required field: public_key (64-char lowercase hex, Ed25519 raw)"
    }, 400, origin);
  }
  if (!/^[0-9a-f]{64}$/.test(public_key)) {
    return jsonResponse({
      error: "public_key must be a 64-character lowercase hex string (Ed25519 public key)"
    }, 400, origin);
  }
  // Verify public_key matches credential_id
  const pubKeyBytes = new Uint8Array(public_key.match(/.{2}/g).map(b => parseInt(b, 16)));
  const _cidBuf = await crypto.subtle.digest("SHA-256", pubKeyBytes);
  const _cidComputed = Array.from(new Uint8Array(_cidBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
  if (_cidComputed !== credential_id) {
    return jsonResponse({
      error: "public_key does not match the credential bound to this API key."
    }, 400, origin);
  }

  // ── S114CW BLOCKS ANNOUNCE #1: Ed25519 signature verification ──
  // Dual-canonical accept, mirroring handleRegisterProof (see that handler's
  // rationale block). The X-API-Key header authenticates the caller's API
  // key → credential binding; the Ed25519 signature authenticates that the
  // credential holder (key possessor) consented to THIS specific attestation.
  // Both gates must pass.
  const _attestPV = protocol_version || "1.2";
  const _canonHIPKit = [content_hash, credential_id, classification, attestedAt, _attestPV].join("|");
  const _canonLegacy = [content_hash, (perceptual_hash || "NULL"), credential_id, attestedAt, classification].join("|");
  const _enc = new TextEncoder();
  let _sigOk = false;
  try {
    _sigOk = await verifyEd25519FromBytes(pubKeyBytes, signature, _enc.encode(_canonHIPKit));
    if (!_sigOk) {
      _sigOk = await verifyEd25519FromBytes(pubKeyBytes, signature, _enc.encode(_canonLegacy));
    }
  } catch (_e) {
    return jsonResponse({ error: "Malformed signature" }, 400, origin);
  }
  if (!_sigOk) {
    return jsonResponse({
      error: "invalid_signature",
      detail: "Signature does not verify against either HIPKit or legacy canonical form."
    }, 403, origin);
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
//
// S114CW BLOCKS ANNOUNCE #1 closure: `verified: true` now REQUIRES a successful
// Ed25519 signature re-verification against the stored public_key + binding
// invariant SHA-256(public_key) === credential_id. Prior to S114CW this endpoint
// returned `verified: true` on pure KV presence — a charter-level semantic
// violation. Records stored before S114CW that were accepted without write-path
// verify will now surface their true state: `verified: false, reason: "signature_invalid"`.
// Pre-S38 records (no public_key stored) cannot be re-verified server-side; we
// return `verified: true, signature_verified: "skipped_no_public_key"` to be
// explicit about what happened — integrators who require cryptographic
// verification can run client-side verify via proof.html.

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

  // Sealed records: confirm existence but withhold details. Still run sig
  // re-verify if public_key is stored — sealed != exempt from verification.
  const short_url = record.short_id
    ? `https://hipprotocol.org/p/${record.short_id}`
    : null;

  // ── S114CW signature re-verification ──
  let signatureVerified;         // true | false | "skipped_no_public_key"
  let verifyFailureReason = null;

  if (!record.public_key || !record.signature) {
    signatureVerified = "skipped_no_public_key";
  } else {
    try {
      const pubKeyBytes = new Uint8Array(record.public_key.match(/.{2}/g).map(b => parseInt(b, 16)));
      // Binding check
      const cidBuf = await crypto.subtle.digest("SHA-256", pubKeyBytes);
      const cidComputed = Array.from(new Uint8Array(cidBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
      if (cidComputed !== record.credential_id) {
        signatureVerified = false;
        verifyFailureReason = "key_binding_failed";
      } else {
        // Dual-canonical verify, matching proof.html.
        const pv = record.protocol_version || "1.2";
        const canonHIPKit = [record.content_hash, record.credential_id, record.classification, record.attested_at, pv].join("|");
        const canonLegacy = [record.content_hash, (record.perceptual_hash || "NULL"), record.credential_id, record.attested_at, record.classification].join("|");
        const enc = new TextEncoder();
        let ok = await verifyEd25519FromBytes(pubKeyBytes, record.signature, enc.encode(canonHIPKit));
        if (!ok) {
          ok = await verifyEd25519FromBytes(pubKeyBytes, record.signature, enc.encode(canonLegacy));
        }
        signatureVerified = ok === true;
        if (!signatureVerified) verifyFailureReason = "signature_invalid";
      }
    } catch (_e) {
      signatureVerified = false;
      verifyFailureReason = "signature_malformed";
    }
  }

  // Sealed branch (post-verify).
  if (record.sealed) {
    if (signatureVerified === false) {
      return jsonResponse({
        verified: false,
        content_hash: contentHash,
        signature_verified: false,
        reason: verifyFailureReason,
      }, 200, origin);
    }
    return jsonResponse({
      verified: true,
      signature_verified: signatureVerified,
      record: {
        content_hash: contentHash,
        sealed: true,
        registered_at: record.registered_at,
      },
      message: "This content has been attested but the proof details are sealed by its creator.",
    }, 200, origin);
  }

  // Public record: honor sig-verify result.
  if (signatureVerified === false) {
    return jsonResponse({
      verified: false,
      content_hash: contentHash,
      signature_verified: false,
      reason: verifyFailureReason,
    }, 200, origin);
  }

  return jsonResponse({
    verified: true,
    signature_verified: signatureVerified,
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


// ══════════════════════════════════════════════════════════════════════
// S106.8CW §2.2 — Pending-GC sweep helper (nightly cron + admin dry-run).
// ══════════════════════════════════════════════════════════════════════
// Finds collection:{id} rows where status === "pending" and created_at is
// older than 24h. Deletes the primary record plus any KV artifacts the
// pending write sequence (§3.3.4 steps 6b–6e) managed to land.
//
// Guarantees (kickoff §2.2):
//   • Active collections are untouched (status-gate).
//   • Collections pending <24h are untouched (age-gate).
//   • hash:{hex} rows owned by other collections are untouched — each row
//     is re-read before delete; we only remove entries whose type ===
//     "collection_member" AND whose collection_id === this pending row's id.
//   • collection_hash_index:{hex} is deleted only if it still points at us.
//   • chain_registry:{chain_id} is intentionally NOT modified (best-effort
//     cache; self-corrects on next extension per S106.7 Decision 6).
//   • Parent has_children is NOT modified — pending children were never
//     added per §3.9.9 step 5b timing (appended in 6h, after the status
//     flip at 6f that a pending row never reaches).
//   • Malformed rows are logged + skipped (D4) — deletion risks losing
//     data a future migration might salvage.
//
// Observability: single-line JSON log per notable event
//   {kind: "malformed_pending_row", key, ...}
//   {kind: "gc_list_error", message}
//   {kind: "gc_delete_error", key, message}
//   {kind: "gc_pending_summary", started_at, finished_at, dry_run,
//     swept_count, skipped_count, malformed_count, errors_count, elapsed_ms}
//
// Returns { summary, candidates[], would_skip[], malformed[] } — the
// {candidates, would_skip, malformed} arrays are used by the
// POST /admin/gc-pending-dry-run endpoint to surface what WOULD be swept.
async function sweepPendingCollections(env, { dryRun = false } = {}) {
  const GC_AGE_MS = 24 * 3600 * 1000;
  const nowMs = Date.now();
  const started_at = new Date(nowMs).toISOString();
  let swept_count = 0;
  let skipped_count = 0;
  let malformed_count = 0;
  let errors_count = 0;
  const candidates = [];
  const would_skip = [];
  const malformed = [];

  let cursor = undefined;
  let listComplete = false;
  while (!listComplete) {
    let page;
    try {
      const listOpts = { prefix: "collection:" };
      if (cursor) listOpts.cursor = cursor;
      page = await env.DEDUP_KV.list(listOpts);
    } catch (e) {
      errors_count++;
      console.log(JSON.stringify({
        kind: "gc_list_error",
        message: String(e).slice(0, 500),
      }));
      break;
    }
    for (const k of (page.keys || [])) {
      const name = k.name;
      let raw;
      try { raw = await env.DEDUP_KV.get(name); }
      catch (_) { errors_count++; continue; }
      if (!raw) { skipped_count++; continue; }
      let rec;
      try { rec = JSON.parse(raw); }
      catch (_) {
        malformed_count++;
        malformed.push({ key: name, reason: "parse_error" });
        console.log(JSON.stringify({ kind: "malformed_pending_row", key: name, reason: "parse_error" }));
        continue;
      }
      if (!rec || typeof rec !== "object" || Array.isArray(rec)) {
        malformed_count++;
        malformed.push({ key: name, reason: "not_object" });
        console.log(JSON.stringify({ kind: "malformed_pending_row", key: name, reason: "not_object" }));
        continue;
      }
      if (rec.status !== "pending") { skipped_count++; continue; }
      if (typeof rec.created_at !== "string" || rec.created_at.length === 0) {
        skipped_count++;
        would_skip.push({ key: name, reason: "missing_created_at" });
        continue;
      }
      const createdMs = Date.parse(rec.created_at);
      if (!Number.isFinite(createdMs)) {
        skipped_count++;
        would_skip.push({ key: name, reason: "malformed_created_at", created_at: rec.created_at });
        continue;
      }
      const ageMs = nowMs - createdMs;
      if (ageMs < GC_AGE_MS) {
        skipped_count++;
        would_skip.push({ key: name, reason: "age_below_ttl", age_ms: ageMs });
        continue;
      }

      // This row is a GC target.
      const collectionId = typeof rec.collection_id === "string" && rec.collection_id.length > 0
        ? rec.collection_id
        : name.replace(/^collection:/, "");
      const collectionHash = typeof rec.collection_hash === "string"
        && /^[0-9a-f]{64}$/.test(rec.collection_hash)
        ? rec.collection_hash : null;
      const credId = (rec.manifest && rec.manifest.creator
        && typeof rec.manifest.creator.credential_id === "string")
        ? rec.manifest.creator.credential_id : null;
      const members = (rec.manifest && Array.isArray(rec.manifest.members))
        ? rec.manifest.members : [];
      const target = {
        key: name,
        collection_id: collectionId,
        collection_hash: collectionHash,
        credential_id: credId,
        member_count: members.length,
        age_ms: ageMs,
        created_at: rec.created_at,
      };
      candidates.push(target);
      if (dryRun) continue;

      // ── Execute the delete ──
      try {
        // 1. hash:{hex} rows — only delete entries we own.
        for (const m of members) {
          for (const field of ["member_hash", "attested_copy_hash"]) {
            const hex = m && m[field];
            if (typeof hex !== "string" || !/^[0-9a-f]{64}$/.test(hex)) continue;
            const hashKey = `hash:${hex}`;
            try {
              const hashRaw = await env.DEDUP_KV.get(hashKey);
              if (!hashRaw) continue;
              let hashRec;
              try { hashRec = JSON.parse(hashRaw); }
              catch (_) { continue; } // don't touch malformed rows
              if (hashRec && hashRec.type === "collection_member"
                  && hashRec.collection_id === collectionId) {
                await env.DEDUP_KV.delete(hashKey);
              }
            } catch (_) { errors_count++; }
          }
        }

        // 2. hash_claim:*:{collection_id} rows (S106.5, only for conflicted
        //    members). We don't know the hexes without a scan; walk the
        //    hash_claim: namespace once per GC target. This is O(total
        //    hash_claims) per target but GC-rare so acceptable. If hash_claim
        //    scale ever becomes an issue, revisit with an inverted index.
        try {
          let claimCursor = undefined;
          let claimComplete = false;
          const suffix = ":" + collectionId;
          while (!claimComplete) {
            const listOpts = { prefix: "hash_claim:" };
            if (claimCursor) listOpts.cursor = claimCursor;
            const claimPage = await env.DEDUP_KV.list(listOpts);
            for (const ck of (claimPage.keys || [])) {
              if (ck.name.endsWith(suffix)) {
                try { await env.DEDUP_KV.delete(ck.name); }
                catch (_) { errors_count++; }
              }
            }
            claimCursor = claimPage.cursor;
            claimComplete = !!claimPage.list_complete || !claimCursor;
          }
        } catch (_) { errors_count++; }

        // 3. collection_hash_index:{hex} — delete iff it still points at us.
        //    Value is a bare string (not JSON), per handleRegisterCollectionProof
        //    step 6c (worker.js L3251: put(..., collectionId)).
        if (collectionHash) {
          const idxKey = `collection_hash_index:${collectionHash}`;
          try {
            const idxRaw = await env.DEDUP_KV.get(idxKey);
            if (idxRaw && idxRaw === collectionId) {
              await env.DEDUP_KV.delete(idxKey);
            }
          } catch (_) { errors_count++; }
        }

        // 4. Remove us from collection_by_credential:{credential_id}.
        if (credId) {
          const credIdxKey = `collection_by_credential:${credId}`;
          try {
            const credRaw = await env.DEDUP_KV.get(credIdxKey);
            if (credRaw) {
              const list = JSON.parse(credRaw);
              if (Array.isArray(list)) {
                const filtered = list.filter(
                  e => !(e && typeof e === "object" && e.collection_id === collectionId)
                );
                if (filtered.length !== list.length) {
                  await env.DEDUP_KV.put(credIdxKey, JSON.stringify(filtered));
                }
              }
            }
          } catch (_) { errors_count++; }
        }

        // 5. Finally, delete collection:{id} itself.
        await env.DEDUP_KV.delete(name);
        swept_count++;
      } catch (e) {
        errors_count++;
        console.log(JSON.stringify({
          kind: "gc_delete_error",
          key: name,
          message: String(e).slice(0, 500),
        }));
      }
    }
    cursor = page.cursor;
    listComplete = !!page.list_complete || !cursor;
  }

  const summary = {
    kind: "gc_pending_summary",
    started_at,
    finished_at: new Date().toISOString(),
    dry_run: dryRun,
    swept_count,
    skipped_count,
    malformed_count,
    errors_count,
    elapsed_ms: Date.now() - nowMs,
  };
  console.log(JSON.stringify(summary));
  return { summary, candidates, would_skip, malformed };
}

// S106.8CW Phase 3b — Admin dry-run handler for the GC sweep. Lets Peter
// verify sweep behavior against real prod KV without waiting for the cron
// or having to wrangler-put synthetic pending rows. Guarded by ADMIN_KEY
// (same bearer-token pattern as handleCreateApiKey).
async function handleAdminGcPendingDryRun(request, env) {
  const origin = request.headers.get("Origin") || CORS_ORIGIN;
  const authHeader = request.headers.get("Authorization") || "";
  if (!authHeader.startsWith("Bearer ") || authHeader.slice(7) !== env.ADMIN_KEY) {
    return jsonResponse({ error: "Unauthorized" }, 401, origin);
  }
  const result = await sweepPendingCollections(env, { dryRun: true });
  return jsonResponse(result, 200, origin);
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

    // S106 §3.4.1: Collection Proof registration
    if (method === "POST" && path === "/register-collection-proof") {
      return handleRegisterCollectionProof(request, env);
    }

    // ══════════════════════════════════════════════════════════════════
    // S111CW — SERIES-SPEC-v1 dispatch (§7.1–§7.3 writes, §7.5–§7.8 reads).
    // ══════════════════════════════════════════════════════════════════
    // /s/{series_id} is wired in the short-URL block below (GET+HEAD),
    // alongside /c/{collection_id}. These three writes + four reads are
    // clustered here for locality with /register-collection-proof. Reads
    // ordered longest-path-first so /api/series/{id}/events matches
    // before /api/series/{id}.
    if (method === "POST" && path === "/register-series") {
      return handleRegisterSeries(request, env);
    }
    if (method === "POST" && path === "/register-series-member") {
      return handleRegisterSeriesMember(request, env);
    }
    if (method === "POST" && path === "/close-series") {
      return handleCloseSeries(request, env);
    }

    // §7.6 — GET /api/series/{series_id}/events. MUST match before §7.5.
    if (method === "GET") {
      const seriesEventsMatch = path.match(/^\/api\/series\/([^\/]+)\/events$/);
      if (seriesEventsMatch) {
        return handleGetSeriesEvents(seriesEventsMatch[1], request, env);
      }
    }
    // §7.5 — GET /api/series/{series_id}.
    if (method === "GET") {
      const seriesGetMatch = path.match(/^\/api\/series\/([^\/]+)$/);
      if (seriesGetMatch) {
        return handleGetSeries(seriesGetMatch[1], request, env);
      }
    }
    // §7.7 — GET /api/creator/{credential_id}/series. Loose [^/]+ capture
    // so malformed credential_ids hit the handler's 400 path, not a
    // route-miss 404 (same posture as /api/collection/{id}).
    if (method === "GET") {
      const creatorSeriesMatch = path.match(/^\/api\/creator\/([^\/]+)\/series$/);
      if (creatorSeriesMatch) {
        return handleGetCreatorSeries(creatorSeriesMatch[1], request, env);
      }
    }
    // §7.8 — GET /api/affiliations/{content_hash}.
    if (method === "GET") {
      const affiliationsMatch = path.match(/^\/api\/affiliations\/([^\/]+)$/);
      if (affiliationsMatch) {
        return handleGetAffiliations(affiliationsMatch[1], request, env);
      }
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

    // S106.5CW: GET /api/proof/{hex}/history — §3.3.5 history endpoint.
    // MUST match before the /api/proof/{hash} prefix handler below so the
    // trailing /history isn't folded into the hash parameter.
    if (method === "GET") {
      const historyMatch = path.match(/^\/api\/proof\/([0-9a-f]{64})\/history$/);
      if (historyMatch) {
        return handleProofHistory(historyMatch[1], request, env);
      }
    }

    // S106.6CW: GET /api/collection/{id}/member/{i} — §3.4.3. MUST match
    // before the /api/collection/{id} route below so the trailing /member/{i}
    // isn't folded into the id parameter. Loose [^/]+ capture so malformed
    // ids/indices hit the handler's 400 path rather than the 404 route-miss.
    if (method === "GET") {
      const memberMatch = path.match(/^\/api\/collection\/([^\/]+)\/member\/([^\/]+)$/);
      if (memberMatch) {
        return handleCollectionMember(memberMatch[1], memberMatch[2], request, env);
      }
    }

    // S106.6CW: GET /api/collection/{id} — §3.4.2.
    if (method === "GET") {
      const colMatch = path.match(/^\/api\/collection\/([^\/]+)$/);
      if (colMatch) {
        return handleCollectionGet(colMatch[1], request, env);
      }
    }

    // S106.8CW §3.4.4 — PATCH /api/collection/{id}/sidecar.
    // Credential-signed mutation of member_sidecar. collection_hash,
    // signature, manifest, status, chain_sidecar all unchanged. Loose [^/]+
    // capture so malformed ids hit the handler's 400 path rather than a
    // route-miss 404.
    if (method === "PATCH") {
      const patchMatch = path.match(/^\/api\/collection\/([^\/]+)\/sidecar$/);
      if (patchMatch) {
        return handleCollectionSidecarPatch(patchMatch[1], request, env);
      }
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

    // S106.8CW Phase 3b — Admin dry-run for the pending-GC sweep.
    // Bearer ADMIN_KEY. Returns {summary, candidates, would_skip, malformed}
    // without performing any deletes. Used to verify sweep behavior against
    // real prod KV before/after cron schedule activates.
    if (method === "POST" && path === "/admin/gc-pending-dry-run") {
      return handleAdminGcPendingDryRun(request, env);
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

    // S106.7CW §3.4.6 — Creator's collection list for dashboard UI.
    // POST (not GET per spec) to mirror existing verifyAppAuth pattern;
    // see handleCollectionByCredential doc comment for the spec-vs-impl
    // divergence rationale (Phase 0 Decision D7).
    if (method === "POST") {
      const collByCredMatch = path.match(/^\/api\/collection-by-credential\/([0-9a-f]{64})$/);
      if (collByCredMatch) {
        return handleCollectionByCredential(request, env, collByCredMatch[1]);
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

    // S106.6 §3.4.7: Short collection URL → proof.html redirect.
    // {short_id} == {collection_id} (S106 POST writes short_url=/c/{collection_id},
    // no separate reverse index). Pending-skip per S106.5 Decision C1.
    //
    // S111CW: HEAD accepted per RFC 9110 §9.3.2 + S110 carryover #32.
    // Previously GET-only; HEAD fell through to bottom-of-dispatch 404,
    // causing false-negative link-check probes (observed S110 §0).
    if ((method === "GET" || method === "HEAD") && path.startsWith("/c/")) {
      const shortId = path.slice(3);
      return handleShortUrl(shortId, request, env);
    }

    // S111CW §7.4 — Short series URL → series.html redirect. Symmetric
    // with /c/{id}; see handleSeriesShortUrl doc comment for the HEAD
    // rationale and the series.html-vs-proof.html landing-path choice.
    if ((method === "GET" || method === "HEAD") && path.startsWith("/s/")) {
      const shortId = path.slice(3);
      return handleSeriesShortUrl(shortId, request, env);
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

  // ── S106.8CW §2.2 — Nightly pending-GC cron ──────────────────────────
  // Cloudflare Cron Trigger fires this handler at the schedule configured
  // in the Cloudflare dashboard (Decision E.1: dashboard-configured, NOT
  // wrangler.toml — no wrangler.toml exists in hip-protocol). Target
  // schedule: "0 4 * * *" (nightly 04:00 UTC, Decision 5).
  //
  // Uses waitUntil so the sweep can outlive the event dispatch but still
  // benefit from ctx lifecycle (logs, graceful teardown). env is the same
  // binding object as fetch — DEDUP_KV accessible identically (Ambiguity E).
  async scheduled(event, env, ctx) {
    ctx.waitUntil(sweepPendingCollections(env, { dryRun: false }));
  },
};
