#!/usr/bin/env node
/**
 * tools/verify-helpers-sync.mjs — drift detection between shared/auth-helpers.js
 * and worker.js inline duplicates.
 *
 * Per S143CW Phase 2 sub-task C (S141CW privacy-flip plan): shared/auth-helpers.js
 * is the source of truth for helpers used by both hip-protocol/worker.js (current)
 * and hipkit-net/worker.js (S144 sub-task D). For S143 the helpers stay INLINE in
 * worker.js (zero deploy risk on first worker.js touch in 16 sessions); this tool
 * verifies byte-identity between the two locations so drift is immediately visible.
 *
 * Usage:
 *   node tools/verify-helpers-sync.mjs
 *
 * Exits 0 on PASS (all 18 helpers byte-identical between worker.js and
 * shared/auth-helpers.js after stripping `export ` prefix from the shared side).
 * Exits 1 on FAIL (drift detected) and prints the offending helper(s).
 *
 * Created S143CW. Run pre-commit when either file is touched.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");
const WORKER_PATH = resolve(REPO_ROOT, "worker.js");
const SHARED_PATH = resolve(REPO_ROOT, "shared/auth-helpers.js");

// Helpers expected to be byte-identical between the two files.
// Order doesn't matter for verification; preserved for readability.
const HELPER_NAMES = [
  "corsHeaders",
  "jsonResponse",
  "hmacSHA256",
  "verifyAppAuth",
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
];

// Constant expected to be present (with same value) in both files.
const CONST_NAME = "CORS_ORIGIN";
const CONST_EXPECTED_VALUE = '"https://hipprotocol.org"';

/**
 * Extract a top-level function declaration's full text from a source string.
 * Matches `(export )?(async )?function NAME(...)` and walks balanced braces.
 * Returns the text from `function NAME(` through the matching closing `}`,
 * inclusive. Returns null if not found.
 *
 * Naive brace matching: assumes function bodies don't contain `{` or `}` inside
 * strings/comments/regex literals. Verified true for all 18 helpers in this
 * codebase. If a future helper violates this, swap for a proper JS parser.
 */
function extractFunctionBody(source, name) {
  // Match `(export )?(async )?function NAME(` — capture from `function` onward.
  // Use a regex that finds the function declaration; we'll trim `export ` after.
  const declRegex = new RegExp(
    "(^|\\n)(export\\s+)?(async\\s+)?function\\s+" + name + "\\s*\\(",
    "g"
  );
  const m = declRegex.exec(source);
  if (!m) return null;

  // Start of `function NAME(` (skip optional `export ` and any leading newline).
  // m.index points at the start of the match (which may be a leading newline).
  // The actual function declaration start is at m.index + match-of-leading-newline-and-keywords.
  // Simpler: locate the literal "function " or "async function " within the matched span.
  const matchedSpan = m[0];
  const offsetInSpan =
    matchedSpan.indexOf("async function ") !== -1
      ? matchedSpan.indexOf("async function ")
      : matchedSpan.indexOf("function ");
  const startIdx = m.index + offsetInSpan;

  // Find the function's opening brace.
  let i = startIdx;
  while (i < source.length && source[i] !== "{") i++;
  if (i >= source.length) return null;
  const openBraceIdx = i;

  // Walk balanced braces.
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
  return null; // unbalanced braces — should not happen
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
  // Find the start of the value (after the `= ` part).
  const matchedSpan = m[0];
  const startIdx = m.index + matchedSpan.length;
  // Find the terminating semicolon (assumes value doesn't span multiple statements).
  const semiIdx = source.indexOf(";", startIdx);
  if (semiIdx === -1) return null;
  return source.substring(startIdx, semiIdx).trim();
}

function main() {
  const workerSrc = readFileSync(WORKER_PATH, "utf8");
  const sharedSrc = readFileSync(SHARED_PATH, "utf8");

  let failures = 0;
  const passed = [];

  // Verify the CORS_ORIGIN constant first.
  const workerConst = extractConstValue(workerSrc, CONST_NAME);
  const sharedConst = extractConstValue(sharedSrc, CONST_NAME);
  if (workerConst === null) {
    console.error(`FAIL: const ${CONST_NAME} not found in worker.js`);
    failures++;
  } else if (sharedConst === null) {
    console.error(`FAIL: const ${CONST_NAME} not found in shared/auth-helpers.js`);
    failures++;
  } else if (workerConst !== sharedConst) {
    console.error(
      `FAIL: const ${CONST_NAME} value mismatch:\n  worker.js: ${workerConst}\n  shared:    ${sharedConst}`
    );
    failures++;
  } else if (workerConst !== CONST_EXPECTED_VALUE) {
    console.error(
      `FAIL: const ${CONST_NAME} value drift from spec (${CONST_EXPECTED_VALUE}):\n  found: ${workerConst}`
    );
    failures++;
  } else {
    passed.push(`${CONST_NAME} (constant)`);
  }

  // Verify each function helper.
  for (const name of HELPER_NAMES) {
    const workerBody = extractFunctionBody(workerSrc, name);
    const sharedBody = extractFunctionBody(sharedSrc, name);

    if (workerBody === null) {
      console.error(`FAIL: function ${name} not found in worker.js`);
      failures++;
      continue;
    }
    if (sharedBody === null) {
      console.error(`FAIL: function ${name} not found in shared/auth-helpers.js`);
      failures++;
      continue;
    }
    if (workerBody !== sharedBody) {
      console.error(`FAIL: function ${name} bytes differ between worker.js and shared/auth-helpers.js`);
      // Print a minimal diff hint: first differing line index.
      const wLines = workerBody.split("\n");
      const sLines = sharedBody.split("\n");
      const maxLen = Math.max(wLines.length, sLines.length);
      for (let i = 0; i < maxLen; i++) {
        if (wLines[i] !== sLines[i]) {
          console.error(`  first divergent line (relative to function start): ${i + 1}`);
          console.error(`    worker.js: ${JSON.stringify(wLines[i])}`);
          console.error(`    shared:    ${JSON.stringify(sLines[i])}`);
          break;
        }
      }
      failures++;
      continue;
    }
    passed.push(`${name} (${workerBody.length} bytes)`);
  }

  // Summary.
  console.log("");
  console.log(
    `Helpers checked: ${HELPER_NAMES.length} functions + 1 constant = ${HELPER_NAMES.length + 1} items`
  );
  console.log(`PASS: ${passed.length}`);
  console.log(`FAIL: ${failures}`);
  if (failures > 0) {
    console.log("");
    console.log("DRIFT DETECTED. Reconcile worker.js and shared/auth-helpers.js before commit.");
    process.exit(1);
  }
  console.log("");
  console.log("ALL HELPERS BYTE-IDENTICAL — sync verified.");
  console.log("");
  console.log("Detail:");
  for (const p of passed) console.log("  PASS  " + p);
  process.exit(0);
}

main();
