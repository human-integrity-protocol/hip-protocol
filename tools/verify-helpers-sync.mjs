#!/usr/bin/env node
/**
 * tools/verify-helpers-sync.mjs — drift detection between shared modules and
 * inline duplicates in one or more consumer worker files.
 *
 * Per S143CW Phase 2 sub-task C (S141CW privacy-flip plan): shared/auth-helpers.js
 * is the source of truth for helpers used by worker scripts that handle Auth/JCS/
 * Ed25519/etc. The helpers stay INLINE in each consumer worker (zero deploy risk
 * on Cloudflare Dashboard Quick Editor flows); this tool verifies byte-identity
 * between the source-of-truth file and every consumer's inline copy so drift is
 * immediately visible.
 *
 * S144CW extension:
 *   - Added two more dual-side helpers (generateShortId, sanitizeFileName).
 *     HELPER_NAMES list grew from 18 to 20.
 *   - Added second consumer: hipkit-net/worker.js (sibling repo, private, S144).
 *   - WORKERS array drives the per-consumer loop. Single tool, single command,
 *     reports per-consumer + aggregated PASS/FAIL.
 *
 * S150CW extension (Carryover #84 — Arweave durability anchor; later RETIRED):
 *   - Refactored from single SHARED_PATH to SHARED_MODULES array. Each module
 *     declares its own path + helper list + constants list.
 *   - Added shared/arweave-anchor.js as second module: 16 functions + 5
 *     constants (gateway URL, app name/version, retry budget).
 *   - Verifier loops per consumer × per module. Aggregate report covers
 *     all (module, consumer, helper) tuples.
 *
 * S152CW extension (Carryover #84 — OpenTimestamps + Bitcoin durability anchor;
 * supersedes Arweave per S151CW charter-cost re-lock):
 *   - shared/arweave-anchor.js REMOVED from SHARED_MODULES (file deleted in
 *     same commit; S150 code retired).
 *   - shared/ots-anchor.js ADDED as second module: 17 functions (16 exported
 *     + 1 internal otsParseEdge_) + 5 constants (calendar URL, file magic,
 *     leaf header constants, timeout). Hand-rolled minimal protocol impl
 *     (no @noble/hashes runtime dep) to preserve single-file Cloudflare
 *     Dashboard Quick Editor paste workflow.
 *
 * Usage:
 *   node tools/verify-helpers-sync.mjs
 *
 * Exits 0 on PASS (every consumer's inline copies of every module are byte-
 * identical to the corresponding shared/<module>.js after stripping `export `
 * prefix). Exits 1 on FAIL — prints offending (module, consumer, item) and
 * a diff hint.
 *
 * Created S143CW. Extended S144CW to cover hipkit-net/worker.js. Extended
 * S150CW to cover shared/arweave-anchor.js (multi-module support).
 * Replaced arweave-anchor with ots-anchor S152CW per S151CW strategy lock.
 * Run pre-commit when any shared/<module>.js OR any consumer worker is touched.
 */

import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");

// ──────────────────────────────────────────────────────────────────────────
// Shared modules — each is a source-of-truth file expected to have inline
// byte-identical copies in every consumer worker. Add new modules here.
// ──────────────────────────────────────────────────────────────────────────

const SHARED_MODULES = [
  {
    name: "shared/auth-helpers.js",
    path: resolve(REPO_ROOT, "shared/auth-helpers.js"),
    // 20 functions + 1 constant (CORS_ORIGIN). Source order matches file.
    helpers: [
      "corsHeaders",
      "jsonResponse",
      "hmacSHA256",
      "verifyAppAuth",
      "generateShortId",         // added S144CW
      "base64ToBytes",
      "isHex64Lower",
      "isCollectionId",
      "isSeriesId",
      "jcsSerializeString",
      "jcsSerializeNumber",
      "jcsSerialize",
      "jcsCanonicalize",
      "sha256Hex",
      "sha256Bytes",
      "verifyEd25519",
      "verifyEd25519FromBytes",
      "addToCredProofsIndex",
      "addToCredApiKeysIndex",
      "sanitizeFileName",        // added S144CW
    ],
    constants: [
      { name: "CORS_ORIGIN", expected: '"https://hipprotocol.org"' },
    ],
  },
  {
    name: "shared/ots-anchor.js",
    path: resolve(REPO_ROOT, "shared/ots-anchor.js"),
    // 16 exported functions + 1 internal helper (otsParseEdge_) + 5 constants.
    // Per S151CW lock: OpenTimestamps + Bitcoin (charter-aligned: $0 operator
    // cost, permanent via Bitcoin, trustless verification via block explorer).
    // Per S152CW lock: hand-rolled minimal protocol implementation (no library
    // bundling) to preserve single-file Cloudflare Dashboard Quick Editor paste.
    helpers: [
      "otsB64UrlEncode",
      "otsB64UrlDecode",
      "otsBytesToHex",
      "otsHexToBytes",
      "otsConcatBytes",
      "otsSha256",
      "otsReadVarint",
      "otsApplyOp",
      "otsParsePathToLeaves",
      "otsParseEdge_",            // internal helper; still must be byte-identical
      "otsBuildFileBytes",
      "otsSubmitDigest",
      "otsRequestUpgrade",
      "otsExtractStatus",
      "otsExtractFirstPending",
      "otsStamp",
      "otsUpgradeIfPending",
    ],
    constants: [
      { name: "OTS_CALENDAR_URL", expected: '"https://alice.btc.calendar.opentimestamps.org"' },
      { name: "OTS_HEADER_MAGIC", expected: null },        // multi-line Uint8Array literal
      { name: "OTS_LEAFHDR_PENDING_HEX", expected: '"83dfe30d2ef90c8e"' },
      { name: "OTS_LEAFHDR_BITCOIN_HEX", expected: '"0588960d73d71901"' },
      { name: "OTS_STAMP_TIMEOUT_MS", expected: "8000" },
    ],
  },
];

// ──────────────────────────────────────────────────────────────────────────
// Consumer workers — each must contain inline byte-identical copies of every
// helper from every module above. Add new consumers here as they ship.
// ──────────────────────────────────────────────────────────────────────────

const WORKERS = [
  {
    name: "hip-protocol/worker.js",
    path: resolve(REPO_ROOT, "worker.js"),
  },
  {
    name: "hipkit-net/worker.js",
    path: resolve(REPO_ROOT, "../hipkit-net/worker.js"),
  },
];

/**
 * Extract a top-level function declaration's full text from a source string.
 * Matches `(export )?(async )?function NAME(...)` and walks balanced braces.
 * Returns the text from `function NAME(` through the matching closing `}`,
 * inclusive. Returns null if not found.
 *
 * Naive brace matching: assumes function bodies don't contain `{` or `}` inside
 * strings/comments/regex literals. Verified true for all extracted helpers in
 * this codebase. If a future helper violates this, swap for a proper JS parser.
 */
function extractFunctionBody(source, name) {
  const declRegex = new RegExp(
    "(^|\\n)(export\\s+)?(async\\s+)?function\\s+" + name + "\\s*\\(",
    "g"
  );
  const m = declRegex.exec(source);
  if (!m) return null;

  const matchedSpan = m[0];
  const offsetInSpan =
    matchedSpan.indexOf("async function ") !== -1
      ? matchedSpan.indexOf("async function ")
      : matchedSpan.indexOf("function ");
  const startIdx = m.index + offsetInSpan;

  let i = startIdx;
  while (i < source.length && source[i] !== "{") i++;
  if (i >= source.length) return null;
  const openBraceIdx = i;

  let depth = 0;
  for (let j = openBraceIdx; j < source.length; j++) {
    const ch = source[j];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) {
        return source.substring(startIdx, j + 1);
      }
    }
  }
  return null;
}

/**
 * Extract a top-level `const NAME = VALUE;` declaration's value text.
 * Matches `(export )?const NAME = ` through the next semicolon.
 * Returns the VALUE text (semicolon excluded), or null if not found.
 */
function extractConstValue(source, name) {
  const declRegex = new RegExp(
    "(^|\\n)(export\\s+)?const\\s+" + name + "\\s*=\\s*",
    "g"
  );
  const m = declRegex.exec(source);
  if (!m) return null;
  const matchedSpan = m[0];
  const startIdx = m.index + matchedSpan.length;
  const semiIdx = source.indexOf(";", startIdx);
  if (semiIdx === -1) return null;
  return source.substring(startIdx, semiIdx).trim();
}

/**
 * Verify one consumer's inline copies of one shared module against the
 * source-of-truth. Returns a result object with passed/failed lists.
 */
function verifyConsumerAgainstModule(module, consumer, sharedSrc, consumerSrc) {
  const result = {
    moduleName: module.name,
    consumerName: consumer.name,
    passed: [],
    failed: [],
  };

  // Constants.
  for (const c of module.constants) {
    const sharedVal = extractConstValue(sharedSrc, c.name);
    const consumerVal = extractConstValue(consumerSrc, c.name);
    if (sharedVal === null) {
      result.failed.push(`${c.name} (constant): not found in ${module.name}`);
      continue;
    }
    if (consumerVal === null) {
      result.failed.push(`${c.name} (constant): not found in ${consumer.name}`);
      continue;
    }
    if (consumerVal !== sharedVal) {
      result.failed.push(
        `${c.name} (constant): value mismatch — ${consumer.name}: ${consumerVal} | ${module.name}: ${sharedVal}`
      );
      continue;
    }
    if (c.expected !== null && c.expected !== undefined && consumerVal !== c.expected) {
      result.failed.push(
        `${c.name} (constant): drift from spec ${c.expected} — found ${consumerVal}`
      );
      continue;
    }
    result.passed.push(`${c.name} (constant)`);
  }

  // Functions.
  for (const name of module.helpers) {
    const consumerBody = extractFunctionBody(consumerSrc, name);
    const sharedBody = extractFunctionBody(sharedSrc, name);

    if (sharedBody === null) {
      result.failed.push(`${name}: not found in ${module.name}`);
      continue;
    }
    if (consumerBody === null) {
      result.failed.push(`${name}: not found in ${consumer.name}`);
      continue;
    }
    if (consumerBody !== sharedBody) {
      const cLines = consumerBody.split("\n");
      const sLines = sharedBody.split("\n");
      const maxLen = Math.max(cLines.length, sLines.length);
      let firstDivergent = -1;
      for (let i = 0; i < maxLen; i++) {
        if (cLines[i] !== sLines[i]) { firstDivergent = i + 1; break; }
      }
      result.failed.push(
        `${name}: bytes differ — first divergent line ${firstDivergent} | ${consumer.name}: ${JSON.stringify(cLines[firstDivergent - 1])} | ${module.name}: ${JSON.stringify(sLines[firstDivergent - 1])}`
      );
      continue;
    }
    result.passed.push(`${name} (${consumerBody.length} bytes)`);
  }

  return result;
}

function main() {
  // Load each shared module's source up front.
  const moduleSources = new Map();
  for (const mod of SHARED_MODULES) {
    if (!existsSync(mod.path)) {
      console.error(`FATAL: ${mod.name} not found at ${mod.path}`);
      process.exit(1);
    }
    moduleSources.set(mod.name, readFileSync(mod.path, "utf8"));
  }

  // Load each consumer's source. Missing files = FAIL (treated as zero pass).
  const consumerSources = new Map();
  const consumerMissing = new Map();
  for (const c of WORKERS) {
    if (!existsSync(c.path)) {
      consumerMissing.set(c.name, c.path);
      continue;
    }
    consumerSources.set(c.name, readFileSync(c.path, "utf8"));
  }

  // Run every (module, consumer) pair.
  const results = [];
  for (const c of WORKERS) {
    if (consumerMissing.has(c.name)) {
      results.push({
        consumerName: c.name,
        missing: true,
        moduleResults: [],
      });
      continue;
    }
    const consumerSrc = consumerSources.get(c.name);
    const moduleResults = [];
    for (const mod of SHARED_MODULES) {
      const sharedSrc = moduleSources.get(mod.name);
      moduleResults.push(verifyConsumerAgainstModule(mod, c, sharedSrc, consumerSrc));
    }
    results.push({ consumerName: c.name, missing: false, moduleResults });
  }

  // Aggregate counts.
  let totalPass = 0;
  let totalFail = 0;
  let perConsumerExpected = 0;
  for (const mod of SHARED_MODULES) {
    perConsumerExpected += mod.helpers.length + mod.constants.length;
  }

  console.log("");
  console.log("=".repeat(64));
  console.log(`Shared modules: ${SHARED_MODULES.length}  (${SHARED_MODULES.map((m) => m.name).join(", ")})`);
  console.log(`Consumers: ${WORKERS.length}  (${WORKERS.map((w) => w.name).join(", ")})`);
  console.log(`Items per consumer: ${perConsumerExpected}  (sum across all modules)`);
  console.log("=".repeat(64));
  console.log("");

  for (const r of results) {
    console.log(`Consumer: ${r.consumerName}`);
    if (r.missing) {
      console.log(`  SKIPPED — file not found at ${consumerMissing.get(r.consumerName)} (treated as FAIL).`);
      totalFail += perConsumerExpected;
      continue;
    }
    let consumerPass = 0;
    let consumerFail = 0;
    for (const mr of r.moduleResults) {
      consumerPass += mr.passed.length;
      consumerFail += mr.failed.length;
      if (mr.failed.length > 0) {
        console.log(`  Module: ${mr.moduleName}  PASS:${mr.passed.length}  FAIL:${mr.failed.length}`);
        for (const f of mr.failed) console.log(`    FAIL  ${f}`);
      } else {
        console.log(`  Module: ${mr.moduleName}  PASS:${mr.passed.length}  FAIL:0`);
      }
    }
    console.log(`  Consumer total: PASS:${consumerPass}  FAIL:${consumerFail}`);
    console.log("");
    totalPass += consumerPass;
    totalFail += consumerFail;
  }

  console.log("=".repeat(64));
  console.log(`Aggregate across ${WORKERS.length} consumers × ${SHARED_MODULES.length} modules`);
  console.log(`Total PASS: ${totalPass}`);
  console.log(`Total FAIL: ${totalFail}`);
  console.log("=".repeat(64));

  if (totalFail > 0) {
    console.log("");
    console.log("DRIFT DETECTED. Reconcile shared/<module>.js with consumer(s) above before commit.");
    process.exit(1);
  }

  console.log("");
  console.log("ALL HELPERS BYTE-IDENTICAL ACROSS ALL CONSUMERS — sync verified.");
  console.log("");
  process.exit(0);
}

main();
