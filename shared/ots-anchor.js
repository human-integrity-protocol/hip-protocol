/**
 * shared/ots-anchor.js — source of truth for OpenTimestamps + Bitcoin
 *                        durability anchor helpers
 *
 * Per S151CW Path A architectural lock + S152CW Path 2 deploy-tooling preservation:
 *   - Strategy: OpenTimestamps + Bitcoin (LOCKED S151CW via charter constraints)
 *     Charter alignment: $0 operator cost (calendars are public good); permanent
 *     (Bitcoin); ledger-based (literal Bitcoin); trustless verification (anyone
 *     can verify via Bitcoin block explorer); durable client verifier.
 *   - Approach: hand-rolled minimal protocol implementation
 *     Rejected: bundling @lacrypta/typescript-opentimestamps because the library
 *     has runtime imports of @noble/hashes, which conflict with single-file
 *     Cloudflare Dashboard Quick Editor paste workflow. Hand-roll mirrors S150
 *     arweave-anchor.js precedent (also hand-rolled with SubtleCrypto).
 *   - Workflow: single-file Cloudflare Dashboard Quick Editor paste preserved
 *   - Dependencies: NONE beyond Workers' built-in globalThis.crypto + fetch
 *
 * Schema field on records (server-stamped only; clients cannot submit):
 *
 *   ledger_proof: null    // initial state on write (synchronous return)
 *
 * After successful stamp (Phase 1, fire-and-forget via ctx.waitUntil):
 *
 *   ledger_proof: {
 *     status: "pending",
 *     ots_b64: "<base64 of full .ots binary; downloadable as proof file>",
 *     stamped_at: "<ISO8601>",
 *     calendar: "<calendar URL used>",
 *     upgrade_msg_hex: "<32-byte hex; the message to query at upgrade time>",
 *     upgrade_url:  "<URL to GET for upgrade>"
 *   }
 *
 * After successful upgrade to Bitcoin-confirmed (Phase 2, on-demand at read-time):
 *
 *   ledger_proof: {
 *     status: "confirmed",
 *     ots_b64: "<base64 of full .ots binary, now with Bitcoin attestation>",
 *     stamped_at: "<ISO8601>",
 *     upgraded_at: "<ISO8601>",
 *     calendar: "...",
 *     upgrade_msg_hex: "...",
 *     upgrade_url: "...",
 *     bitcoin_block_height: <number>
 *   }
 *
 * Pattern: this module is the single source of truth for helpers used by BOTH:
 *   - public  hip-protocol/worker.js (handles register-proof, register-series,
 *     register-series-member, register-collection-proof, close-series)
 *   - private hipkit-net/worker.js  (handles api-attest)
 *
 * Helpers stay INLINE in each consumer worker (zero deploy risk on Cloudflare
 * Dashboard Quick Editor flows); drift is detected via tools/verify-helpers-sync.mjs
 * which compares each function body byte-for-byte across consumers. Run:
 *
 *   node tools/verify-helpers-sync.mjs
 *
 * before any commit that touches this file or any consumer worker.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * Helpers exported (16 functions + 5 constants = 21 items, source order):
 *   1.  OTS_CALENDAR_URL        constant — primary calendar (Alice)
 *   2.  OTS_HEADER_MAGIC        constant — .ots file magic header (31 bytes)
 *   3.  OTS_LEAFHDR_PENDING_HEX constant — pending attestation header (hex)
 *   4.  OTS_LEAFHDR_BITCOIN_HEX constant — Bitcoin attestation header (hex)
 *   5.  OTS_STAMP_TIMEOUT_MS    constant — calendar POST timeout
 *   6.  otsB64UrlEncode         function — base64-url encode Uint8Array (no padding)
 *   7.  otsB64UrlDecode         function — base64-url decode to Uint8Array
 *   8.  otsBytesToHex           function — Uint8Array → lowercase hex
 *   9.  otsHexToBytes           function — hex → Uint8Array
 *   10. otsConcatBytes          function — concat Uint8Arrays
 *   11. otsSha256               function — SubtleCrypto SHA-256 wrapper
 *   12. otsReadVarint           function — read OTS varint (returns {value, nextIdx})
 *   13. otsApplyOp              function — apply OTS op to message bytes
 *   14. otsParsePathToLeaves    function — walk tree, return leaves with messages
 *   15. otsBuildFileBytes       function — assemble full .ots file from response
 *   16. otsSubmitDigest         function — POST hash to calendar's /digest endpoint
 *   17. otsRequestUpgrade       function — GET {calendar}/timestamp/{msg-hex}
 *   18. otsExtractStatus        function — scan ots bytes for leaf type
 *   19. otsExtractFirstPending  function — find first pending leaf {url, msgHex}
 *   20. otsStamp                function — Phase 1 fire-and-forget entry point
 *   21. otsUpgradeIfPending     function — Phase 2 on-demand upgrade entry point
 *
 * Helpers explicitly NOT included (out of v1 scope):
 *   - Multi-calendar submission with tree merging (single-calendar v1 sufficient)
 *   - Fudge nonce / privacy mixing (content hashes are already public via
 *     /api/proof/{hash}; calendars learning content hashes is moot)
 *   - REVERSE / HEXLIFY ops (calendars don't emit these in current protocol)
 *   - SHA1 / RIPEMD160 / KECCAK256 ops (Bitcoin path uses SHA256 only)
 *   - Litecoin / Ethereum attestations (we only care about Bitcoin)
 *   - Local cryptographic verification of upgraded proofs (handled client-side
 *     via OpenTimestamps web verifier + Bitcoin block explorer)
 *   - Backfill (~500 pre-S152 records get ledger_proof: null; backfill is a
 *     one-shot S153+ tool, not part of the live read/write path)
 *
 * Protocol references:
 *   - https://opentimestamps.org/
 *   - https://github.com/opentimestamps/python-opentimestamps (reference impl)
 *   - https://github.com/lacrypta/typescript-opentimestamps (browser impl;
 *     used at S152 §1A spike to validate protocol shape; not bundled into
 *     the worker per Quick Editor paste workflow constraint)
 *   - El Salvador government adopted OpenTimestamps for official document
 *     anchoring 2024-2025 (production-grade endorsement at scale)
 */

// ============================================================================
// Constants
// ============================================================================

/**
 * Primary calendar for stamping. Single-calendar v1 (multi-calendar deferred).
 * Alice is the OpenTimestamps reference calendar; runs as public-good service.
 */
export const OTS_CALENDAR_URL = "https://alice.btc.calendar.opentimestamps.org";

/**
 * .ots file magic header (31 bytes). Required prefix for any valid .ots file.
 *
 * Decodes to: \x00 + "OpenTimestamps\x00\x00Proof\x00" + magic constant.
 */
export const OTS_HEADER_MAGIC = new Uint8Array([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
  0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);

/**
 * Pending attestation leaf header (8 bytes hex). Indicates the leaf is awaiting
 * Bitcoin block confirmation; the leaf's body contains the calendar URL to
 * query for upgrade.
 */
export const OTS_LEAFHDR_PENDING_HEX = "83dfe30d2ef90c8e";

/**
 * Bitcoin attestation leaf header (8 bytes hex). Indicates the leaf is
 * confirmed in a Bitcoin block; the leaf's body contains the block height
 * (as varint).
 */
export const OTS_LEAFHDR_BITCOIN_HEX = "0588960d73d71901";

/**
 * Calendar POST timeout. Calendars typically respond within 1-2s.
 */
export const OTS_STAMP_TIMEOUT_MS = 8000;

// ============================================================================
// Encoding helpers
// ============================================================================

/**
 * base64-url encode (no padding, URL-safe). Mirrors arweave-anchor's pattern.
 */
export function otsB64UrlEncode(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * base64-url decode → Uint8Array. Tolerates standard base64 too.
 */
export function otsB64UrlDecode(str) {
  const std = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = std.length % 4 === 0 ? "" : "=".repeat(4 - (std.length % 4));
  const bin = atob(std + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Uint8Array → lowercase hex string.
 */
export function otsBytesToHex(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Lowercase hex string → Uint8Array. Throws on odd length or non-hex chars.
 */
export function otsHexToBytes(str) {
  if (typeof str !== "string" || str.length % 2 !== 0) {
    throw new Error("ots: hex must be even-length string");
  }
  const out = new Uint8Array(str.length / 2);
  for (let i = 0; i < str.length; i += 2) {
    const b = parseInt(str.slice(i, i + 2), 16);
    if (Number.isNaN(b)) throw new Error("ots: invalid hex character");
    out[i / 2] = b;
  }
  return out;
}

/**
 * Concat any number of Uint8Arrays into a single Uint8Array.
 */
export function otsConcatBytes(...arrs) {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/**
 * SubtleCrypto SHA-256 wrapper. Returns Uint8Array.
 */
export async function otsSha256(bytes) {
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
}

// ============================================================================
// OTS binary protocol — minimal parser
// ============================================================================

/**
 * Read an OTS varint (variable-length integer, little-endian, 7-bit groups
 * with high bit = continuation flag). Returns {value, nextIdx}.
 *
 * Used for op operand lengths and Bitcoin block heights.
 *
 * Throws if more than 8 bytes consumed (safety bound; real OTS values are tiny).
 */
export function otsReadVarint(data, idx) {
  let value = 0;
  let shift = 0;
  let cur = idx;
  let bytesRead = 0;
  while (cur < data.length) {
    const b = data[cur++];
    bytesRead++;
    value |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) {
      return { value, nextIdx: cur };
    }
    shift += 7;
    if (bytesRead > 8) throw new Error("ots: varint too long");
  }
  throw new Error("ots: unexpected EOF reading varint");
}

/**
 * Apply an OTS op to a message. Returns the new message Uint8Array.
 *
 * Tags handled:
 *   0x08 SHA256       — msg = SHA256(msg)
 *   0xf0 APPEND       — msg = msg || operand
 *   0xf1 PREPEND      — msg = operand || msg
 *
 * Other tags (SHA1, RIPEMD160, KECCAK256, REVERSE, HEXLIFY) throw — out of
 * scope for v1 (Bitcoin path uses SHA256 only).
 */
export async function otsApplyOp(msg, opTag, operand) {
  if (opTag === 0x08) {
    return await otsSha256(msg);
  }
  if (opTag === 0xf0) {
    if (!operand) throw new Error("ots: APPEND missing operand");
    return otsConcatBytes(msg, operand);
  }
  if (opTag === 0xf1) {
    if (!operand) throw new Error("ots: PREPEND missing operand");
    return otsConcatBytes(operand, msg);
  }
  throw new Error("ots: unsupported op tag 0x" + opTag.toString(16));
}

/**
 * Parse an OTS tree from `data` starting at `idx`, with starting message
 * `msg`, and return all leaves found with their accumulated message values.
 *
 * Tree format (per OTS spec; mirrors python-opentimestamps + lacrypta):
 *
 *   Tree         := (NonFinal Edge)* FinalEdge
 *   NonFinal     := 0xff
 *   FinalEdge    := Edge
 *   Edge         := Op Tree    |    Leaf
 *   Op           := UnaryTag                       // 0x02 0x03 0x08 0x67 0xf2 0xf3
 *                 | BinaryTag varint(opLen) bytes  // 0xf0 APPEND, 0xf1 PREPEND
 *   Leaf         := 0x00 LeafHeader[8] varint(payloadLen) payload[payloadLen]
 *
 *   Pending leaf payload = varint(urlLen) urlBytes[urlLen]
 *   Bitcoin leaf payload = varint(blockHeight)
 *
 * Returns {leaves: Array<{type, messageHex, ...data}>, nextIdx: number}.
 */
export async function otsParsePathToLeaves(data, idx, msg) {
  const leaves = [];
  let cur = idx;

  // Read [0xff Edge]* FinalEdge — all non-last edges are 0xff-prefixed.
  while (data[cur] === 0xff) {
    cur++;
    const er = await otsParseEdge_(data, cur, msg);
    for (const l of er.leaves) leaves.push(l);
    cur = er.nextIdx;
  }
  // Read FinalEdge (no 0xff prefix).
  const er = await otsParseEdge_(data, cur, msg);
  for (const l of er.leaves) leaves.push(l);
  cur = er.nextIdx;

  return { leaves, nextIdx: cur };
}

/**
 * Parse a single Edge (Op-then-Tree, or Leaf). Internal helper.
 */
async function otsParseEdge_(data, idx, msg) {
  let cur = idx;
  if (cur >= data.length) {
    throw new Error("ots: unexpected EOF at edge start");
  }
  const tag = data[cur++];

  if (tag === 0x00) {
    // Leaf
    if (cur + 8 > data.length) {
      throw new Error("ots: unexpected EOF reading leaf header");
    }
    const headerHex = otsBytesToHex(data.slice(cur, cur + 8));
    cur += 8;

    // payload = varint(payloadLen) + payloadBytes
    const payloadLen = otsReadVarint(data, cur);
    cur = payloadLen.nextIdx;
    const payload = data.slice(cur, cur + payloadLen.value);
    cur += payloadLen.value;

    if (headerHex === OTS_LEAFHDR_PENDING_HEX) {
      // pending payload = varint(urlLen) + urlBytes
      const urlLen = otsReadVarint(payload, 0);
      const urlBytes = payload.slice(urlLen.nextIdx, urlLen.nextIdx + urlLen.value);
      const url = new TextDecoder().decode(urlBytes);
      return {
        leaves: [{ type: "pending", url, messageHex: otsBytesToHex(msg) }],
        nextIdx: cur,
      };
    }
    if (headerHex === OTS_LEAFHDR_BITCOIN_HEX) {
      // bitcoin payload = varint(blockHeight)
      const heightRead = otsReadVarint(payload, 0);
      return {
        leaves: [{ type: "bitcoin", height: heightRead.value, messageHex: otsBytesToHex(msg) }],
        nextIdx: cur,
      };
    }
    // Unknown / litecoin / ethereum — treat as opaque
    return {
      leaves: [{ type: "unknown", headerHex, messageHex: otsBytesToHex(msg) }],
      nextIdx: cur,
    };
  }

  // Op — read operand if APPEND/PREPEND, then recurse into subtree
  let operand = null;
  if (tag === 0xf0 || tag === 0xf1) {
    const opLen = otsReadVarint(data, cur);
    operand = data.slice(opLen.nextIdx, opLen.nextIdx + opLen.value);
    cur = opLen.nextIdx + opLen.value;
  }
  const newMsg = await otsApplyOp(msg, tag, operand);
  const sub = await otsParsePathToLeaves(data, cur, newMsg);
  return { leaves: sub.leaves, nextIdx: sub.nextIdx };
}

/**
 * Assemble a full .ots file from a content_hash and a calendar response tree.
 *
 * Layout:
 *   OTS_HEADER_MAGIC (31 bytes)
 *   OTS_VERSION      (1 byte = 0x01)
 *   file_hash_alg    (1 byte = 0x08 for SHA256)
 *   file_hash_bytes  (32 bytes for SHA256)
 *   tree_bytes       (calendar response, verbatim)
 *
 * Note: this assumes no fudge ops were applied client-side (we submit the
 * content_hash directly to the calendar; the resulting tree starts from
 * content_hash, no APPEND+SHA256 prefix needed).
 */
export function otsBuildFileBytes(contentHashBytes, treeBytes) {
  if (!(contentHashBytes instanceof Uint8Array) || contentHashBytes.length !== 32) {
    throw new Error("ots: content_hash must be 32-byte Uint8Array");
  }
  return otsConcatBytes(
    OTS_HEADER_MAGIC,
    new Uint8Array([0x01]), // version
    new Uint8Array([0x08]), // SHA-256 algorithm tag
    contentHashBytes,
    treeBytes
  );
}

// ============================================================================
// Calendar HTTP transport
// ============================================================================

/**
 * Submit a 32-byte digest to a calendar's /digest endpoint. Returns the raw
 * binary response (the OTS tree starting from the submitted digest).
 *
 * Throws on HTTP error or timeout.
 */
export async function otsSubmitDigest(digestBytes, calendarUrl) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), OTS_STAMP_TIMEOUT_MS);
  try {
    const resp = await fetch(calendarUrl + "/digest", {
      method: "POST",
      body: digestBytes,
      headers: {
        "Content-Type": "application/octet-stream",
        "Accept": "application/octet-stream",
        "User-Agent": "hip-ots-anchor/1.0",
      },
      signal: ctrl.signal,
    });
    if (!resp.ok) {
      const txt = await resp.text().catch(() => "");
      throw new Error("ots: calendar /digest HTTP " + resp.status + ": " + txt.slice(0, 200));
    }
    const buf = await resp.arrayBuffer();
    return new Uint8Array(buf);
  } finally {
    clearTimeout(t);
  }
}

/**
 * Query a calendar's upgrade endpoint with a message hex. Returns the raw
 * binary response (the OTS tree from that pending point onward, hopefully
 * now including a Bitcoin attestation).
 *
 * If the Bitcoin block hasn't been mined yet, the calendar returns the same
 * pending tree (or HTTP 404). Caller should check status of returned tree.
 */
export async function otsRequestUpgrade(calendarUrl, msgHex) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), OTS_STAMP_TIMEOUT_MS);
  try {
    const resp = await fetch(calendarUrl + "/timestamp/" + msgHex, {
      method: "GET",
      headers: {
        "Accept": "application/octet-stream",
        "User-Agent": "hip-ots-anchor/1.0",
      },
      signal: ctrl.signal,
    });
    if (resp.status === 404) {
      // Not yet mined. Caller treats as no-op.
      return null;
    }
    if (!resp.ok) {
      throw new Error("ots: calendar upgrade HTTP " + resp.status);
    }
    const buf = await resp.arrayBuffer();
    return new Uint8Array(buf);
  } finally {
    clearTimeout(t);
  }
}

// ============================================================================
// Status detection + leaf extraction
// ============================================================================

/**
 * Scan ots binary bytes for a Bitcoin attestation leaf. Returns "confirmed" if
 * found (any Bitcoin leaf), "pending" otherwise.
 *
 * Uses the parser (otsParsePathToLeaves) for accuracy. Falls back to byte-scan
 * if parsing fails (defensive against malformed inputs).
 */
export async function otsExtractStatus(otsBytes) {
  // Skip header + version + algorithm + 32-byte file_hash
  // = 31 + 1 + 1 + 32 = 65 bytes
  const treeStart = OTS_HEADER_MAGIC.length + 2 + 32;
  if (otsBytes.length < treeStart) return "pending";
  const fileHash = otsBytes.slice(OTS_HEADER_MAGIC.length + 2, treeStart);
  try {
    const result = await otsParsePathToLeaves(otsBytes, treeStart, fileHash);
    for (const leaf of result.leaves) {
      if (leaf.type === "bitcoin") return "confirmed";
    }
    return "pending";
  } catch (_e) {
    // Defensive byte-scan fallback
    const bitcoinHeader = otsHexToBytes(OTS_LEAFHDR_BITCOIN_HEX);
    for (let i = 0; i < otsBytes.length - 9; i++) {
      if (otsBytes[i] !== 0x00) continue;
      let match = true;
      for (let j = 0; j < 8; j++) {
        if (otsBytes[i + 1 + j] !== bitcoinHeader[j]) { match = false; break; }
      }
      if (match) return "confirmed";
    }
    return "pending";
  }
}

/**
 * Extract the first pending leaf from a calendar /digest response.
 *
 * `treeBytes` is the calendar response (NOT the full .ots file). `digestBytes`
 * is the 32-byte hash that was submitted.
 *
 * Returns {url, msgHex} for the pending leaf, or null if no pending leaf found.
 */
export async function otsExtractFirstPending(treeBytes, digestBytes) {
  const result = await otsParsePathToLeaves(treeBytes, 0, digestBytes);
  for (const leaf of result.leaves) {
    if (leaf.type === "pending") {
      return { url: leaf.url, msgHex: leaf.messageHex };
    }
  }
  return null;
}

// ============================================================================
// Phase 1: Stamp (fire-and-forget, called via ctx.waitUntil)
// ============================================================================

/**
 * Stamp a record with an OpenTimestamps + Bitcoin durability anchor.
 *
 * This is a best-effort fire-and-forget operation — the caller wraps in
 * ctx.waitUntil() so the anchor completes in the post-response window without
 * blocking the user. Failures are logged but don't propagate to the user.
 *
 * Steps:
 *   1. Read the just-written record from KV (race-clean re-read)
 *   2. Submit content hash to calendar
 *   3. Parse response; extract pending leaf URL + upgrade message hex
 *   4. Build full .ots file (header + version + alg tag + content_hash + tree)
 *   5. Merge ledger_proof into record
 *   6. Re-write record (KV last-write-wins; race-clean against any concurrent updates)
 */
export async function otsStamp(env, ctx, recordType, recordKey, recordValue) {
  const logPrefix = "[ots-anchor " + recordType + " " + recordKey + "]";
  try {
    if (!env || !env.DEDUP_KV) {
      console.warn(logPrefix + " no DEDUP_KV binding; skipping");
      return;
    }

    // Determine what hash to submit (per record type).
    let hashHex = null;
    if (recordType === "proof") {
      hashHex = recordValue && recordValue.content_hash;
    } else if (recordType === "collection" || recordType === "series") {
      // Use record's signed-manifest digest; fall back to KV key suffix.
      hashHex = (recordValue && recordValue.manifest_digest) ||
                (recordKey.includes(":") ? recordKey.split(":").slice(1).join(":") : recordKey);
    } else if (recordType === "series_event") {
      hashHex = (recordValue && recordValue.event_hash) ||
                (recordKey.includes(":") ? recordKey.split(":").slice(1).join(":") : recordKey);
    } else {
      console.warn(logPrefix + " unknown record type; skipping");
      return;
    }

    if (typeof hashHex !== "string" || !/^[0-9a-f]{64}$/i.test(hashHex)) {
      console.warn(logPrefix + " hashHex not 64-char hex; skipping (got " + (typeof hashHex) + ")");
      return;
    }

    const digestBytes = otsHexToBytes(hashHex.toLowerCase());

    // Phase 1a: submit to calendar
    let treeBytes;
    try {
      treeBytes = await otsSubmitDigest(digestBytes, OTS_CALENDAR_URL);
    } catch (e) {
      console.error(logPrefix + " calendar submit failed: " + e.message);
      return;
    }

    // Phase 1b: extract pending leaf
    let pending;
    try {
      pending = await otsExtractFirstPending(treeBytes, digestBytes);
    } catch (e) {
      console.error(logPrefix + " parse calendar response failed: " + e.message);
      return;
    }
    if (!pending) {
      console.warn(logPrefix + " no pending leaf in calendar response; skipping");
      return;
    }

    // Phase 1c: build full .ots file
    const otsBytes = otsBuildFileBytes(digestBytes, treeBytes);

    // Phase 1d: re-read record (race-clean against concurrent updates)
    const cur = await env.DEDUP_KV.get(recordKey, { type: "json" });
    if (!cur) {
      console.warn(logPrefix + " record vanished between write and stamp; skipping");
      return;
    }
    if (cur.ledger_proof && cur.ledger_proof.status === "confirmed") {
      console.warn(logPrefix + " record already confirmed; skipping");
      return;
    }

    // Phase 1e: merge ledger_proof and re-write
    cur.ledger_proof = {
      status: "pending",
      ots_b64: otsB64UrlEncode(otsBytes),
      stamped_at: new Date().toISOString(),
      calendar: OTS_CALENDAR_URL,
      upgrade_msg_hex: pending.msgHex,
      upgrade_url: pending.url,
    };
    await env.DEDUP_KV.put(recordKey, JSON.stringify(cur));
    console.log(logPrefix + " stamped pending; ots " + otsBytes.length + " bytes");
  } catch (e) {
    console.error(logPrefix + " unhandled error: " + (e && e.message ? e.message : e));
  }
}

// ============================================================================
// Phase 2: On-demand upgrade at read-time
// ============================================================================

/**
 * If the record's ledger_proof is pending, attempt to upgrade it via the
 * calendar's /timestamp/{msg-hex} endpoint. On success, persist the upgraded
 * record back to KV and return the upgraded record. On failure or no-op,
 * return the original record unchanged.
 *
 * This is non-fatal: any failure leaves status: "pending" unchanged; next
 * read attempt will retry.
 *
 * Caller is responsible for env binding + KV access. Pass record by value
 * (not by reference); this function returns the (possibly upgraded) record.
 */
export async function otsUpgradeIfPending(env, recordKey, record) {
  const lp = record && record.ledger_proof;
  if (!lp || lp.status !== "pending") return record;
  if (!lp.upgrade_url || !lp.upgrade_msg_hex) return record;
  if (!env || !env.DEDUP_KV) return record;

  const logPrefix = "[ots-upgrade " + recordKey + "]";

  try {
    const upgradeBytes = await otsRequestUpgrade(lp.upgrade_url, lp.upgrade_msg_hex);
    if (!upgradeBytes) {
      // 404 — not yet mined. Leave pending.
      return record;
    }

    // Parse upgrade response. If it contains a Bitcoin leaf, replace pending
    // section in stored ots_b64 with the new tree.
    // Strategy for v1: scan upgrade response for Bitcoin attestation; if found,
    // replace the entire suffix of ots_b64 starting at the pending leaf with
    // the new tree. (More precise tree-merging deferred to v2.)

    // Quick check: does upgrade response contain a Bitcoin leaf?
    const bitcoinHdr = otsHexToBytes(OTS_LEAFHDR_BITCOIN_HEX);
    let hasBitcoin = false;
    for (let i = 0; i < upgradeBytes.length - 9; i++) {
      if (upgradeBytes[i] !== 0x00) continue;
      let match = true;
      for (let j = 0; j < 8; j++) {
        if (upgradeBytes[i + 1 + j] !== bitcoinHdr[j]) { match = false; break; }
      }
      if (match) { hasBitcoin = true; break; }
    }

    if (!hasBitcoin) {
      // Calendar responded but not yet Bitcoin-anchored. Leave pending.
      return record;
    }

    // Rebuild .ots file: original prefix (header + version + alg + hash) + ops to
    // pending point + upgrade response. For our simple (no-fudge, single-leaf)
    // case, the pending tree from the calendar /digest response was the final
    // suffix of the .ots file. The upgrade response is the replacement suffix
    // starting from the same digest position.
    //
    // Concretely: in our stamp flow, we built ots_b64 = HEADER + VERSION + ALG
    // + HASH + calendar_response_tree. The pending leaf is at the end of
    // calendar_response_tree. The upgrade response IS the new calendar_response_tree
    // (containing path from digest to Bitcoin attestation).
    //
    // So new ots_b64 = HEADER + VERSION + ALG + HASH + upgrade_bytes.
    //
    // Note: this only works because we submit content_hash directly (no fudge).
    // If we later add fudge ops, the rebuild becomes more complex.

    if (lp.ots_b64) {
      const oldOts = otsB64UrlDecode(lp.ots_b64);
      // Validate prefix matches (defense in depth)
      const prefixLen = OTS_HEADER_MAGIC.length + 2 + 32;
      if (oldOts.length < prefixLen) {
        console.warn(logPrefix + " stored ots_b64 too short; skipping");
        return record;
      }
      const prefix = oldOts.slice(0, prefixLen);
      const newOts = otsConcatBytes(prefix, upgradeBytes);

      // Extract block height from upgrade response.
      let blockHeight = null;
      try {
        const fileHash = oldOts.slice(OTS_HEADER_MAGIC.length + 2, prefixLen);
        const parsed = await otsParsePathToLeaves(upgradeBytes, 0, fileHash);
        for (const leaf of parsed.leaves) {
          if (leaf.type === "bitcoin") {
            blockHeight = leaf.height;
            break;
          }
        }
      } catch (_e) {
        // parsing failed but we know hasBitcoin = true. Leave height null.
      }

      // Re-read current record (race-clean) before overwriting.
      const cur = await env.DEDUP_KV.get(recordKey, { type: "json" });
      if (!cur) return record;
      if (cur.ledger_proof && cur.ledger_proof.status === "confirmed") {
        // Some other read-handler upgraded concurrently; defer to its result.
        return cur;
      }

      cur.ledger_proof = {
        status: "confirmed",
        ots_b64: otsB64UrlEncode(newOts),
        stamped_at: lp.stamped_at,
        upgraded_at: new Date().toISOString(),
        calendar: lp.calendar,
        upgrade_msg_hex: lp.upgrade_msg_hex,
        upgrade_url: lp.upgrade_url,
        bitcoin_block_height: blockHeight,
      };

      await env.DEDUP_KV.put(recordKey, JSON.stringify(cur));
      console.log(logPrefix + " upgraded to confirmed; block " + blockHeight);
      return cur;
    }

    return record;
  } catch (e) {
    console.error(logPrefix + " unhandled error: " + (e && e.message ? e.message : e));
    return record;
  }
}
