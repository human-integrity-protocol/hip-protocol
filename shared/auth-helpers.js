/**
 * shared/auth-helpers.js — source of truth for shared auth/crypto/index helpers
 *
 * This module is the single source of truth for helpers used by BOTH the public
 * `hip-protocol/worker.js` AND the future private `hipkit-net/worker.js` (S144
 * sub-task D, per S141CW privacy-flip Phase 2 plan).
 *
 * Helpers currently DUPLICATED inline in `hip-protocol/worker.js`. The duplication
 * is verified byte-identical via `tools/verify-helpers-sync.mjs`. Run:
 *
 *   node tools/verify-helpers-sync.mjs
 *
 * before any commit that touches either file. The verifier extracts each helper's
 * function body from both locations and reports drift.
 *
 * S144 (HIPKit private worker creation) will seed `hipkit-net/worker.js` by copying
 * these helpers verbatim from this module. After S144 the verifier covers both
 * workers.
 *
 * S143 sub-task C decision (Option C-refined / "Option B-zero"):
 * - Worker.js bytes UNCHANGED this session (no Cloudflare Dashboard deploy needed)
 * - This file is the architectural seam: source-of-truth lives here
 * - Drift detection is automated via the sync verifier
 * - If a future session decides to use literal ES module imports (Option A) or
 *   build-time concat (Option B), this file becomes the literal import target
 *
 * Helpers exported (18 total, in worker.js source order):
 *   1.  CORS_ORIGIN             constant   — worker.js line 79
 *   2.  corsHeaders             function   — worker.js line 83-107
 *   3.  jsonResponse            function   — worker.js line 108-118
 *   4.  hmacSHA256              async fn   — worker.js line 119-136
 *   5.  verifyAppAuth           async fn   — worker.js line 137-204
 *   6.  base64ToBytes           function   — worker.js line 330-338
 *   7.  isHex64Lower            function   — worker.js line 339-347
 *   8.  isCollectionId          function   — worker.js line 348-363
 *   9.  isSeriesId              function   — worker.js line 364-369
 *   10. jcsSerializeString      function   — worker.js line 370-397
 *   11. jcsSerializeNumber      function   — worker.js line 398-408
 *   12. jcsSerialize            function   — worker.js line 409-433
 *   13. jcsCanonicalize         function   — worker.js line 434-438
 *   14. sha256Hex               async fn   — worker.js line 439-445
 *   15. sha256Bytes             async fn   — worker.js line 446-454
 *   16. verifyEd25519           async fn   — worker.js line 455-465
 *   17. verifyEd25519FromBytes  async fn   — worker.js line 466-493
 *   18. addToCredProofsIndex    async fn   — worker.js line 2318-2345
 *   19. addToCredApiKeysIndex   async fn   — worker.js line 2346-2367
 *
 * Helpers explicitly NOT included (protocol-only or HIPVerify-only, stay in worker.js):
 *   - writeAffiliation, writeCreatorSeriesIndex, addToSeriesMembersIndex, isSeriesMember
 *     (series/collection-only, called only from protocol-side handlers)
 *   - verifySeriesSignature, validateManifest, validateSeriesManifest
 *     (series/collection only)
 *   - migrateTrustRecord, flipResolvedVouches, computeTrustScore (trust ops)
 *   - verifyWebhookSignatureV2, verifyWebhookSignatureSimple, computeDedupHash,
 *     shortenFloats, sortKeysDeep (HIPVerify Didit webhook — Carryover #78
 *     deferred to post-launch)
 *   - generateShortId, buildProofOGPage, hexToBytes, bytesToHexLower, bytesEqual,
 *     base32LowercaseNoPad, deriveCollectionId, readHash, normalizePubkeyFromB64,
 *     normalizePubkeyFromHex, mapValidationError, sanitizeFileName, pHashHammingDistance
 *     (handler-specific or protocol-only utilities)
 *
 * Created S143CW per S141CW-LOCKED-DECISIONS.md Phase 2 sub-task C.
 */

export const CORS_ORIGIN = "https://hipprotocol.org";

// === corsHeaders === (worker.js line 83-107)
export function corsHeaders(origin) {
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

// === jsonResponse === (worker.js line 108-118)
export function jsonResponse(data, status = 200, origin = CORS_ORIGIN) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders(origin),
    },
  });
}

// === hmacSHA256 === (worker.js line 119-136)
// HMAC-SHA-256 for dedup hash and webhook signature verification
export async function hmacSHA256(key, data) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// === verifyAppAuth === (worker.js line 137-204)
// S83 / S114CW: Verify a HIPKit app auth request (Ed25519 signature).
// The client signs "HIPKIT|{endpoint}|{credentialId}|{timestamp}" with its Ed25519 private key.
// Returns { ok, credential_id, public_key, trust_record, body } or { ok:false, error, status }.
//
// S114CW BLOCKS ANNOUNCE #1 closure: this helper now performs full server-side
// cryptographic verification. Prior to S114CW it only checked field presence +
// timestamp freshness + credential existence, which was authentication in name
// only — knowledge of any public (credential_id, public_key) pair was sufficient
// to pass. Per charter "If it says verify, it must verify."
export async function verifyAppAuth(request, endpoint, env) {
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

// === base64ToBytes === (worker.js line 330-338)
export function base64ToBytes(b64) {
  if (typeof b64 !== "string") throw new Error("base64ToBytes: input must be string");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// === isHex64Lower === (worker.js line 339-347)
// 64-hex-lowercase validator used pervasively for content/member/collection hashes.
export function isHex64Lower(s) {
  return typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
}

// === isCollectionId === (worker.js line 348-363)
// S106.6CW Ambiguity F: collection_id = base32-lowercase(collection_hash[:12]) → 20 chars
// over the RFC 4648 alphabet "abcdefghijklmnopqrstuvwxyz234567". NOT [a-z0-9]{20}
// (the loose "alphanumeric" annotation would false-accept 0,1,8,9). Used by the
// §3.4.2 / §3.4.3 / §3.4.7 (short-URL Option C) validators so malformed ids produce
// a clean 400 rather than a soft 404.
export function isCollectionId(s) {
  return typeof s === "string" && /^[a-z2-7]{20}$/.test(s);
}

// === isSeriesId === (worker.js line 364-369)
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
export function isSeriesId(s) {
  return typeof s === "string" && /^[a-z2-7]{20}$/.test(s);
}

// === jcsSerializeString === (worker.js line 370-397)
// JCS (RFC 8785) canonical JSON serializer — string output.
// Pure function; throws on non-JSON values (undefined, BigInt, NaN, ±Infinity, lone surrogates).
export function jcsSerializeString(s) {
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

// === jcsSerializeNumber === (worker.js line 398-408)
export function jcsSerializeNumber(n) {
  if (typeof n !== "number" || !Number.isFinite(n)) {
    throw new Error("jcs: number must be finite, got " + String(n));
  }
  if (n === 0) return "0"; // normalises -0
  // ES6 Number.prototype.toString already gives the JCS-prescribed shortest
  // round-trip decimal. JCS forbids the leading "+" on exponents that V8 emits
  // for very large magnitudes (e.g. 1e+21); strip it.
  return n.toString().replace("e+", "e");
}

// === jcsSerialize === (worker.js line 409-433)
export function jcsSerialize(v) {
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

// === jcsCanonicalize === (worker.js line 434-438)
// Returns Uint8Array of the UTF-8 canonical bytes.
export function jcsCanonicalize(value) {
  return new TextEncoder().encode(jcsSerialize(value));
}

// === sha256Hex === (worker.js line 439-445)
// SHA-256 hex-lowercase. Accepts Uint8Array or string (UTF-8 encoded if string).
export async function sha256Hex(input) {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// === sha256Bytes === (worker.js line 446-454)
// SHA-256 raw bytes (Uint8Array). Used as the Ed25519 signing message per §3.2.5.
export async function sha256Bytes(input) {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

// === verifyEd25519 === (worker.js line 455-465)
// Ed25519 verify wrapper over Web Crypto. Spec §3.2.5: signature is Ed25519 over
// the 32-byte SHA-256(JCS(manifest)) digest. Public key and signature arrive as
// base64 strings in manifest/collection records.
// Returns boolean. Throws on malformed inputs (bad base64, wrong byte length).
export async function verifyEd25519(publicKeyB64, signatureB64, messageBytes) {
  const pub = base64ToBytes(publicKeyB64);
  if (pub.length !== 32) throw new Error("verifyEd25519: public key must be 32 bytes, got " + pub.length);
  return await verifyEd25519FromBytes(pub, signatureB64, messageBytes);
}

// === verifyEd25519FromBytes === (worker.js line 466-493)
// S106.8CW G.2: bytes-in variant for callers whose public key comes from a
// source other than manifest.creator.public_key (e.g., trust:{id}.public_key
// which is stored as 64-char lowercase hex, not base64). Keeps the base64
// caller unchanged; PATCH sidecar + any future hex-keyed callers route here.
// Returns boolean. Throws on malformed inputs.
export async function verifyEd25519FromBytes(pubkeyBytes, signatureB64, messageBytes) {
  if (!(pubkeyBytes instanceof Uint8Array) || pubkeyBytes.length !== 32) {
    const got = (pubkeyBytes && pubkeyBytes.length !== undefined) ? pubkeyBytes.length : "non-Uint8Array";
    throw new Error("verifyEd25519FromBytes: public key must be 32 bytes, got " + got);
  }
  const sig = base64ToBytes(signatureB64);
  if (sig.length !== 64) throw new Error("verifyEd25519FromBytes: signature must be 64 bytes, got " + sig.length);
  const key = await crypto.subtle.importKey("raw", pubkeyBytes, { name: "Ed25519" }, false, ["verify"]);
  return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, messageBytes);
}

// === addToCredProofsIndex === (worker.js line 2318-2345)
export async function addToCredProofsIndex(env, credential_id, content_hash) {
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

// === addToCredApiKeysIndex === (worker.js line 2346-2367)
// S116CW: reverse index cred_api_keys:{credential_id} — enables /api/keys/list
// to enumerate a credential's API keys without a KV scan. Same non-fatal
// posture as addToCredProofsIndex. The primary record is api_key:{keyHash};
// this index is an accelerator. Reads of api_key:{keyHash} remain the source
// of truth for a key's existence, active state, and metadata.
export async function addToCredApiKeysIndex(env, credential_id, key_hash) {
  if (!credential_id || !key_hash) return;
  try {
    const key = `cred_api_keys:${credential_id}`;
    const raw = await env.DEDUP_KV.get(key);
    let record;
    if (raw) {
      try { record = JSON.parse(raw); } catch (_) { record = null; }
    }
    if (!record || !Array.isArray(record.key_hashes)) {
      record = { key_hashes: [], updated_at: null };
    }
    if (record.key_hashes.indexOf(key_hash) !== -1) {
      return; // already indexed — idempotent no-op
    }
    record.key_hashes.push(key_hash);
    record.updated_at = new Date().toISOString();
    await env.DEDUP_KV.put(key, JSON.stringify(record));
  } catch (_) {
    // Non-fatal: index is an accelerator, not source of truth.
  }
}
