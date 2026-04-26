#!/usr/bin/env node
/**
 * tools/verify-helpers-sync.mjs — drift detection between shared/auth-helpers.js
 * and inline duplicates in one or more consumer worker files.
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
 *     HELPER_NAMES list grows from 18 to 20.
 *   - Added second consumer: hipkit-net/worker.js (sibling repo, private, S144).
 *   - WORKERS array drives the per-consumer loop. Single tool, single command,
 *     reports per-consumer + aggregated PASS/FAIL.
 *
 * Usage:
 *   node tools/verify-helpers-sync.mjs
 *
 * Exits 0 on PASS (every consumer's inline copies are byte-identical to
 * shared/auth-helpers.js after stripping `export ` prefix).
 * Exits 1 on FAIL — prints the offending consumer + helper(s) and a diff hint.
 *
 * Created S143CW. Extended S144CW to cover hipkit-net/worker.js.
 * Run pre-commit when shared/auth-helpers.js OR any consumer worker is touched.
 */

import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");
const SHARED_PATH = resolve(REPO_ROOT, "shared/auth-helpers.js");

// Consumer workers — each must contain inline byte-identical copies of every
// helper in HELPER_NAMES (with `export ` prefix stripped). Add new consumers
// here as they ship.
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

// Helpers expected to be byte-identical between shared/auth-helpers.js and every
// consumer worker. Order matches shared/auth-helpers.js source order. Updates to
// this list must propagate to (a) shared/auth-helpers.js, (b) every consumer
// worker's inline copy, AND (c) the header comment block in shared/auth-helpers.js.
const HELPER_NAMES = [
  "corsHeaders",
  "jsonResponse",
  "hmacSHA256",
  "verifyAppAuth",
  "generateShortId",         // added S144CW (dual-side: handleRegisterProof + handleApiAttest)
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
  "sanitizeFileName",        // added S144CW (dual-side: handleRegisterProof + handleApiAttest)
];

// Constant expected to be present (with same value) in shared and every consumer.
const CONST_NAME = "CORS_ORIGIN";
const CONST_EXPECTED_VALUE = '"https://hipprotocol.org"';

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
 * Verify one consumer worker against shared/auth-helpers.js.
 * Returns { name, passed: [], failed: [], missingFile: bool }.
 */
function verifyConsumer(consumer, sharedSrc, sharedConst) {
  const result = {
    name: consumer.name,
    passed: [],
    failed: [],
    missingFile: false,
  };

  if (!existsSync(consumer.path)) {
    result.missingFile = true;
    result.failed.push(`${consumer.name}: file does not exist at ${consumer.path}`);
    return result;
  }

  const consumerSrc = readFileSync(consumer.path, "utf8");

  // Constant.
  const consumerConst = extractConstValue(consumerSrc, CONST_NAME);
  if (consumerConst === null) {
    result.failed.push(`${CONST_NAME} (constant): not found in ${consumer.name}`);
  } else if (consumerConst !== sharedConst) {
    result.failed.push(
      `${CONST_NAME} (constant): value mismatch — ${consumer.name}: ${consumerConst} | shared: ${sharedConst}`
    );
  } else if (consumerConst !== CONST_EXPECTED_VALUE) {
    result.failed.push(
      `${CONST_NAME} (constant): drift from spec ${CONST_EXPECTED_VALUE} — found ${consumerConst}`
    );
  } else {
    result.passed.push(`${CONST_NAME} (constant)`);
  }

  // Functions.
  for (const name of HELPER_NAMES) {
    const consumerBody = extractFunctionBody(consumerSrc, name);
    const sharedBody = extractFunctionBody(sharedSrc, name);

    if (sharedBody === null) {
      result.failed.push(`${name}: not found in shared/auth-helpers.js`);
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
        `${name}: bytes differ — first divergent line ${firstDivergent} | ${consumer.name}: ${JSON.stringify(cLines[firstDivergent - 1])} | shared: ${JSON.stringify(sLines[firstDivergent - 1])}`
      );
      continue;
    }
    result.passed.push(`${name} (${consumerBody.length} bytes)`);
  }

  return result;
}

function main() {
  if (!existsSync(SHARED_PATH)) {
    console.error(`FATAL: shared/auth-helpers.js not found at ${SHARED_PATH}`);
    process.exit(1);
  }
  const sharedSrc = readFileSync(SHARED_PATH, "utf8");
  const sharedConst = extractConstValue(sharedSrc, CONST_NAME);

  const totalItems = HELPER_NAMES.length + 1;
  const results = WORKERS.map((c) => verifyConsumer(c, sharedSrc, sharedConst));

  let totalFail = 0;
  let totalPass = 0;

  console.log("");
  for (const r of results) {
    console.log(`Consumer: ${r.name}`);
    if (r.missingFile) {
      console.log(`  SKIPPED — file not found (treated as FAIL).`);
      totalFail += totalItems;
      continue;
    }
    console.log(`  Items checked: ${totalItems}`);
    console.log(`  PASS: ${r.passed.length}`);
    console.log(`  FAIL: ${r.failed.length}`);
    if (r.failed.length > 0) {
      console.log("");
      for (const f of r.failed) console.log(`    FAIL  ${f}`);
    }
    console.log("");
    totalPass += r.passed.length;
    totalFail += r.failed.length;
  }

  console.log("=".repeat(60));
  console.log(`Aggregate across ${WORKERS.length} consumers`);
  console.log(`Items per consumer: ${totalItems}  (${HELPER_NAMES.length} functions + 1 constant)`);
  console.log(`Total PASS: ${totalPass}`);
  console.log(`Total FAIL: ${totalFail}`);

  if (totalFail > 0) {
    console.log("");
    console.log("DRIFT DETECTED. Reconcile shared/auth-helpers.js with consumer(s) above before commit.");
    process.exit(1);
  }

  console.log("");
  console.log("ALL HELPERS BYTE-IDENTICAL ACROSS ALL CONSUMERS — sync verified.");
  console.log("");

  // Per-consumer detail (lighter than S143's verbose detail; per-consumer summary above).
  for (const r of results) {
    console.log(`Detail (${r.name}):`);
    for (const p of r.passed) console.log("  PASS  " + p);
    console.log("");
  }

  process.exit(0);
}

main();
