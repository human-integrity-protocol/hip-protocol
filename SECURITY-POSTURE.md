# SECURITY-POSTURE.md

> Standing artifact. One block per auth-gated endpoint. Every session that touches
> an auth-gated endpoint updates this file. No session is CLOSED until this file
> matches reality for every endpoint in scope.
>
> **Charter principle — "If it says verify, it must verify."** Any gap between
> what an endpoint's name/response-shape *claims* and what it actually verifies
> is a **BLOCKS ANNOUNCE** condition.

**Last updated:** S143CW — 2026-04-25
**Worker.js HEAD at update:** UNCHANGED at S131CW commit `bbfbdfd` (`worker.js` 8097 lines). S143CW Phase 2 sub-task C added a parallel source-of-truth file `shared/auth-helpers.js` for the privacy-flip launch plan; worker.js bytes are byte-identical to S131CW (sync verified 19/19 PASS via `tools/verify-helpers-sync.mjs`). See change log below.

---

## Cryptographic primitives (unchanged baseline)

- **Ed25519 raw keys**: 32-byte public, 64-byte signature, hex-encoded public_key on the wire, base64-encoded signature.
- **Key binding invariant**: `credential_id = lower(hex(SHA-256(public_key_32_bytes)))`. Every endpoint that accepts both fields MUST enforce this.
- **`verifyEd25519FromBytes(pubKeyBytes, sigB64, msgBytes)`** at worker.js:429 — the canonical verify helper. Returns boolean. Throws on malformed inputs (bad base64 / wrong byte length).
- **SubtleCrypto Ed25519 IS available on Cloudflare Workers** (proven by series endpoints S111+ running in production). Prior comments in the codebase claiming otherwise were stale.

## Two attest canonicals accepted on write-path

Historical reality: two client surfaces produce **different signed messages** for the same attestation body. Both are in live production today. `proof.html` (the client-side verifier) already accepts both at read time. The S114CW write-path fix mirrors that pattern. No client migration required.

- **HIPKit format** (hipkit-net/hip-attest.js): `content_hash | credential_id | classification | attested_at | protocol_version`
- **Legacy format** (hip-protocol/index.html L2574): `content_hash | (perceptual_hash || "NULL") | credential_id | attested_at | classification`

`handleRegisterProof`, `handleApiAttest`, and `handleVerify` all implement dual-canonical accept: try HIPKit first, fall back to legacy, fail on both.

---

## Endpoint blocks

### 1. `verifyAppAuth` helper — worker.js:129

- **Used by**: `/retire-credential`, `/api/collections/by-credential`, `/api/portfolio`, `/api/credential/{id}/attestations`, `/api/credits/balance`, `/api/credits/usage`, `/api/credits/consume`, `/api/stripe/checkout`, `/api/stripe/portal`, `/api/keys/create`, `/api/keys/list`, `/api/keys/deactivate` (S116CW).
- **Canonical**: `"HIPKIT|" + endpoint + "|" + credential_id + "|" + timestamp`
- **(a) field-presence checks**: credential_id, public_key, timestamp, signature. Hex-shape validation on credential_id + public_key. Timestamp ±5 min.
- **(b) crypto verification** (S114CW): ✅ Ed25519 signature verified over canonical. ✅ Binding check SHA-256(public_key) === credential_id. ✅ Trust record existence. ✅ Superseded-by guard.
- **(c) claim**: AppAuth = "credential holder consents to this endpoint call at this timestamp."
- **Gap?**: **NONE.** Closed S114CW. Pre-S114CW gap logged as BLOCKS ANNOUNCE #1.

### 2. `handleRegisterProof` — worker.js ~2624

- **Body fields**: content_hash, perceptual_hash?, credential_id, public_key (NOW REQUIRED), attested_at, classification, signature, sealed?, protocol_version?, file_name?, original_hash?, attested_copy_hash?, thumbnail?.
- **Canonical**: dual — HIPKit format OR legacy format.
- **(a) field-presence checks**: all required. Hex-shape on content_hash, public_key, original_hash, attested_copy_hash. Classification enum. ISO 8601 on attested_at.
- **(b) crypto verification** (S114CW): ✅ Binding check SHA-256(public_key) === credential_id. ✅ Ed25519 dual-canonical verify. Trust record existence + superseded guard + TI≥60 + T3 cap + rate limit. First-writer-wins.
- **(c) claim**: "Register a signed, tier-bound attestation over `content_hash`."
- **S131CW addendum** (Carryover #69 closure): optional `thumbnail` body field accepted — a data URL image string for Portfolio rendering. Validation: non-string → 400; >68000 chars → 400; not starting with `data:image/` → 400 (defensive, catches buggy/adversarial clients since the value ends up rendered as `<img src>` in Portfolio). NOT inside the signature payload — metadata only, same field-presence-only posture as `file_name` (S88), `original_hash` (S102), `attested_copy_hash` (S103). Persisted on `proof:{hash}` records as `thumbnail: thumbnail || null`. Pre-S131CW records stay `thumbnail: null` (forward-only migration; hipkit-net's S130 client-side `hip_thumb_cache_v1` localStorage cache continues to hydrate pre-S131 records on the same device via the non-destructive `if (!r.thumbnail …)` merge gate at hip-ui.js `loadPortfolio`).
- **Gap?**: **NONE.** Closed S114CW. S131CW addition is field-presence-only — no verification gate added, weakened, or removed.

### 3. `handleApiAttest` — worker.js ~5699

- **Auth**: `X-API-Key` header → resolves to credential_id via `api_key:{hmac(apiKey)}` KV.
- **Body fields**: content_hash, classification, signature, public_key (NOW REQUIRED), attested_at?, sealed?, protocol_version?, perceptual_hash?, file_name?, original_hash?, attested_copy_hash?, thumbnail?.
- **Canonical**: dual — HIPKit format OR legacy format.
- **(a) field-presence checks**: identical to `handleRegisterProof` plus API key lookup.
- **(b) crypto verification** (S114CW): ✅ Binding check. ✅ Ed25519 dual-canonical verify. Trust + TI≥60 + T3 cap + rate limit. First-writer-wins.
- **(c) claim**: "Programmatic attestation from a HIPKit API customer, signed by their bound credential."
- **S131CW addendum** (Carryover #69 closure): symmetric `thumbnail` acceptance with `handleRegisterProof` — same three-stage validation (non-string / >68000 chars / missing `data:image/` prefix → 400), same field-presence-only posture, same persistence (`thumbnail: thumbnail || null` on `proof:{hash}` records). Keeps API-keyed and web-signed attestation records shape-compatible for Portfolio cross-device rendering.
- **Gap?**: **NONE.** Closed S114CW. S131CW addition is field-presence-only — no verification gate added, weakened, or removed.

### 4. `handleVerify` — worker.js ~6105 (`GET /api/verify/{hash}`)

- **Auth**: None (public endpoint).
- **Before S114CW**: returned `verified: true` on KV presence alone — charter-level semantic violation.
- **After S114CW**:
  - Pre-S38 records (no `public_key` stored) → `verified: true, signature_verified: "skipped_no_public_key"` with explicit disclaimer. Integrators who require cryptographic verification can run client-side verify via proof.html.
  - Modern records → Ed25519 re-verify server-side against stored `public_key` + binding check. `verified: true` iff signature verifies.
  - Records with invalid signature (pre-S114CW records written under the verify-less path) → `verified: false, signature_verified: false, reason: "signature_invalid" | "key_binding_failed" | "signature_malformed"`.
- **(c) claim**: "Cryptographic verification of content attestation."
- **Gap?**: **NONE.** Closed S114CW. Legacy-response-shape integrators should not break — `verified: true` now means what it says. Pre-S114CW forged records will flip to `verified: false` — correct behavior.

### 5. `handleUnsealProof` — worker.js ~5515 (`POST /unseal-proof`)

- **Canonical**: `"UNSEAL|" + content_hash + "|" + credential_id`
- **Body fields**: content_hash, credential_id, signature, public_key? (optional backfill for pre-S38 records).
- **Before S114CW**: binding check existed when `public_key` was provided, but the signature was **never verified**. Anyone who knew `content_hash + credential_id + public_key` (all public) could unseal a target record.
- **After S114CW**: ✅ public_key now required (from body or stored record). ✅ Binding check. ✅ Ed25519 verify over canonical.
- **Gap?**: **NONE.** Closed S114CW.

### 6. `handleRegisterCollectionProof` — worker.js ~3265 (`POST /register-collection-proof`)

- **Canonical**: `JCS(manifest)` → SHA-256 → Ed25519 verify.
- **Crypto verification**: ✅ Already correct pre-S114CW. `verifyEd25519(manifest.creator.public_key, signature, collectionHashBytes)` at ~L3357. Binding backfill at ~L3345.
- **Gap?**: **NONE.** Unchanged.

### 7. `handleCollectionSidecarPatch` — worker.js ~5163 (`POST /api/collections/{id}/sidecar-patch`)

- **Canonical**: `JCS({collection_id, sidecar_updates, credential_id, timestamp})` → SHA-256 → Ed25519 verify against trust:{id}.public_key (hex) via `verifyEd25519FromBytes`.
- **Crypto verification**: ✅ Already correct (shipped S106.8CW). Binding-by-construction (public_key fetched from trust record, which was seeded with the same hex key at issuance).
- **Gap?**: **NONE.** Unchanged.

### 8. `/register-series` (series creation) — worker.js via `verifySeriesSignature`

- **Canonical**: `JCS(manifest)` → SHA-256 → Ed25519 verify against `manifest.creator.public_key`.
- **Crypto verification**: ✅ Already correct (shipped S111CW). TI≥60 floor. Superseded-by guard. First-writer-wins on series_id.
- **S122CW addendum**: optional `hipkit_originated` boolean body field accepted (rejected with `invalid_field` if non-boolean). NOT inside the signed manifest — metadata-only routing flag, same posture as `original_hash` (S102), `attested_copy_hash` (S103), `file_name` (S88). Stamped on the persisted `series:{id}` record only when strictly `true` (conditional spread; absent otherwise to keep protocol-default record shape pristine). Verifier-side semantic correctness unchanged.
- **Gap?**: **NONE.** Field-presence-only addition; no verification gate added, weakened, or removed.

### 9. `/register-series-member` — same helper as #8

- **Canonical**: `JCS(event_minus_signature)` → SHA-256 → Ed25519 verify.
- **Crypto verification**: ✅ Already correct. Creator-match enforcement. `member_proof_not_found` gate. Superseded-by guard.
- **S122CW addendum**: optional `hipkit_originated` boolean body field accepted (rejected with `invalid_field` if non-boolean). NOT inside the signed event — metadata only. Stamped on the persisted `series_event:{event_hash}` record only when strictly `true`. Independent of the parent series' flag (a HIPKit-side add to a hipprotocol-originated series flags the event, not the series; vice versa).
- **Gap?**: **NONE.** Field-presence-only addition.

### 10. `/close-series` — same helper as #8

- **Canonical**: `JCS(event_minus_signature)` → SHA-256 → Ed25519 verify.
- **Crypto verification**: ✅ Already correct. Creator-match. Terminal-transition gate.
- **Gap?**: **NONE.** Unchanged.

### 11. `handleRetireCredential` — worker.js ~2540 (`POST /retire-credential`)

- **Auth**: routes through `verifyAppAuth` with canonical `"HIPKIT|/retire-credential|{credId}|{ts}"`.
- **Effect**: writes `superseded_by: "self-retired"` on trust record. Any subsequent AppAuth call with this credential will fail.
- **S118CW cascade**: after the trust write succeeds, reads `cred_api_keys:{credential_id}` and flips `active:false` + stamps `deactivated_at` + `deactivated_reason:"credential_retired"` on every still-active `api_key:{keyHash}` record owned by this credential. Already-deactivated keys are skipped (existing `deactivated_reason` preserved). Per-key failures are non-fatal (logged via `cascaded_keys: {total, deactivated}` counters in the response). Defense-in-depth: cascade skips any record whose stored `credential_id` does not match. Cost: 1 + N reads + M writes (M ≤ N ≤ 100 per the S116 hard cap). Pre-S118CW retired credentials are NOT backfilled (forward-only, by design).
- **Gap?**: **NONE** (cascade is data hygiene, not a new auth gate; no verification weakened on any endpoint).

### 12. `handleCollectionByCredential` — worker.js ~5365 (`POST /api/collections/by-credential`)

- **Auth**: `verifyAppAuth` with `"HIPKIT|/api/collections/by-credential|{credId}|{ts}"`. Additionally enforces URL `{id}` === body `credential_id`.
- **Gap?**: **NONE** (post-S114CW).

### 13. `handlePortfolio` — worker.js ~6499 (`POST /api/portfolio`)

- **Auth**: `verifyAppAuth` with `"HIPKIT|/api/portfolio|{credId}|{ts}"`.
- **Gap?**: **NONE** (post-S114CW).

### 14. `handleCredentialAttestations` — worker.js ~6618 (`POST /api/credential/{id}/attestations`)

- **Auth**: `verifyAppAuth` with the **static** canonical `"HIPKIT|/api/credential/attestations|{credId}|{ts}"` (URL-embedded {id} NOT in canonical — by S102 design). URL `{id}` must match body `credential_id`.
- **Gap?**: **NONE** (post-S114CW).

### 15. `handleCreditBalance` — worker.js ~6170 (`POST /api/credits/balance`)

- **Auth**: `verifyAppAuth` with `"HIPKIT|/api/credits/balance|{credId}|{ts}"`.
- **Gap?**: **NONE** (post-S114CW).

### 16. `handleUsage` — worker.js ~6110 (`POST /api/credits/usage`)

- **Auth**: `verifyAppAuth` with `"HIPKIT|/api/credits/usage|{credId}|{ts}"`.
- **Gap?**: **NONE** (post-S114CW).

### 17. `handleCreditConsume` — worker.js ~6180 (`POST /api/credits/consume`)

- **Auth**: `verifyAppAuth` with `"HIPKIT|/api/credits/consume|{credId}|{ts}"`.
- **Exposure pre-S114CW**: credit-drain attack — anyone who had observed a victim's (credential_id, public_key) pair (both public in any proof record) could spend that credential's credits. **Closed S114CW.**
- **Gap?**: **NONE** (post-S114CW).

### 18. `handleStripeCheckout` — worker.js ~6224 (`POST /api/stripe/checkout`)

- **Auth**: `verifyAppAuth`.
- **Gap?**: **NONE** (post-S114CW).

### 19. `handleStripePortal` — worker.js ~6306 (`POST /api/stripe/portal`)

- **Auth**: `verifyAppAuth`.
- **Gap?**: **NONE** (post-S114CW).

### 20. `handleTrustInitialize` — worker.js (`POST /trust/initialize`)

- **Auth model**: Didit session verification (for T1), T1 voucher cryptographic check (for T2), WebAuthn attestation check (for T3). NOT signature-authed — this is the bootstrap endpoint that CREATES the credential.
- **Gap?**: **NONE.** Correct by design (can't sign with a key you haven't yet bound). S97CW #34c/d fixes (Didit session gate + recovery idempotency) are live.

### 21. `handleUpgradeCredential` — worker.js ~1976 (`POST /upgrade-credential`)

- **Auth model**: Same as #20 (Didit/voucher/WebAuthn). NOT signature-authed — this is a pathway-re-establishment flow.
- **Gap?**: **NONE.** Correct by design.

### 22. `handleDisputeProof` — worker.js ~5622 (`POST /dispute-proof`)

- **Canonical**: `"DISPUTE|" + content_hash + "|" + credential_id + "|" + reason_hash + "|" + timestamp` where `reason_hash = lowercase hex SHA-256(reason.trim())` and `timestamp` is ISO 8601 (±5 min freshness).
- **Body fields**: content_hash (hex64), credential_id (hex64), public_key (hex64 — NOW REQUIRED), reason (10–500 chars), signature (b64), timestamp (ISO 8601).
- **Before S115CW**: credential existence check ONLY. NO signature required. Any party knowing a victim's credential_id (public) could impersonate a dispute filing against any proof, up to the 5/24h rate limit and per-credential dedupe.
- **After S115CW** (BLOCKS ANNOUNCE #2 closure):
  - ✅ Presence + hex-shape on content_hash, credential_id, public_key.
  - ✅ Timestamp freshness ±5 min.
  - ✅ Binding check: SHA-256(public_key) === credential_id.
  - ✅ Ed25519 signature verified over canonical before any state mutation or proof-record KV read.
  - ✅ Reason_hash binds the specific claim text to the signature — a captured signature cannot be replayed against the same (hash, cred) with a different reason.
  - Business logic preserved: superseded_by guard, 5/24h rate limit, per-credential dedupe, own-attestation block.
- **(c) claim**: "Credential X formally disputes attestation of content Y on the grounds of reason Z at time T."
- **Gap?**: **NONE.** Closed S115CW. No legacy-unsigned fallback — `proof.html`'s `submitDispute` ships atomically with the worker as the only client surface.

### 23. `handleUserCreateApiKey` — worker.js ~5916 (`POST /api/keys/create`)

- **Auth**: `verifyAppAuth` with `"HIPKIT|/api/keys/create|{credId}|{ts}"`.
- **Body fields** (beyond AppAuth): `label?` (string, ≤60 chars, sanitized to trimmed slice).
- **Effect**: generates a 32-byte random `rawKey` (64 hex), stores `api_key:{hmac(DEDUP_SECRET, rawKey)}` with `{credential_id, tier, label, created_at, active:true, last_used:null}`, appends the keyHash to `cred_api_keys:{credential_id}`, increments `kcrate:{hmac(cred_id)}` (10/24h rate limit).
- **Hard cap**: 100 keys per credential (index length check). 409 `key_limit_reached` when exceeded — user must deactivate before creating.
- **Rate limit**: 10 creates / 24h per credential. 429 `rate_limited` when exceeded.
- **Returns**: `api_key` (rawKey, ONCE ONLY) + `key_id` (first 8 hex chars of keyHash, the display handle).
- **(c) claim**: "Credential holder creates a new API key for programmatic use, bound to their credential."
- **Gap?**: **NONE.** AppAuth inheritance — full Ed25519 + binding + superseded-by + trust existence. Rate limit sized for real workflow (rotations, labeling), low enough to contain spam. Raw key never persists.

### 24. `handleListApiKeys` — worker.js ~6002 (`POST /api/keys/list`)

- **Auth**: `verifyAppAuth` with `"HIPKIT|/api/keys/list|{credId}|{ts}"`.
- **Effect**: reads `cred_api_keys:{credential_id}`, fetches every `api_key:{keyHash}` record in parallel, returns `{key_id, label, created_at, last_used, active}` tuples newest-first.
- **Defense-in-depth**: any key record whose stored `credential_id` doesn't match the authenticated caller is filtered out (null) even if its hash appears in the index.
- **Never returns** the raw key (unrecoverable from hmac anyway). `key_id` leak is acceptable — 8 hex of HMAC output is useless without the full key.
- **(c) claim**: "Enumerate the authenticated credential's API keys and their metadata."
- **Gap?**: **NONE.** AppAuth inheritance.

### 25. `handleDeactivateApiKey` — worker.js ~6057 (`POST /api/keys/deactivate`)

- **Auth**: `verifyAppAuth` with `"HIPKIT|/api/keys/deactivate|{credId}|{ts}"`.
- **Body fields** (beyond AppAuth): `key_id` (8-char lowercase hex prefix from `/api/keys/list`).
- **Effect**: resolves `key_id` prefix → full `keyHash` by scanning ONLY the authenticated credential's `cred_api_keys` index (never a global scan). If the resolved `api_key:{keyHash}` record's `credential_id` doesn't match the authenticated caller, returns 403 `key_not_owned_by_credential`. On match, flips `active:false`, stamps `deactivated_at`, writes back.
- **Idempotency**: already-deactivated returns 200 with `already_deactivated:true` (no-op).
- **Ambiguity**: multiple keyHashes sharing the 8-char prefix → 409 `ambiguous_key_id` (practically impossible at realistic key counts; defended anyway).
- **(c) claim**: "Credential holder deactivates one of their own API keys. Deactivation is permanent (no reactivate)."
- **Gap?**: **NONE.** AppAuth inheritance + per-credential index scope + credential_id match check on the key record itself (defense-in-depth against any hypothetical cross-credential KV leak).

---

## Change log

- **S143CW — 2026-04-25.** Phase 2 sub-task C of S141CW privacy-flip launch plan: created `hip-protocol/shared/auth-helpers.js` as the parallel source of truth for 18 helpers + 1 constant (`CORS_ORIGIN`) shared between the public protocol worker and the future private HIPKit worker (S144 sub-task D). Helpers extracted (named exports): `corsHeaders`, `jsonResponse`, `hmacSHA256`, `verifyAppAuth`, `base64ToBytes`, `isHex64Lower`, `isCollectionId`, `isSeriesId`, `jcsSerializeString`, `jcsSerializeNumber`, `jcsSerialize`, `jcsCanonicalize`, `sha256Hex`, `sha256Bytes`, `verifyEd25519`, `verifyEd25519FromBytes`, `addToCredProofsIndex`, `addToCredApiKeysIndex`. Per Option C-refined module strategy decision (recorded in `WEBSITE-TOOLS-HK/SESSION 143CW/S143CW-DELIVERIES.md`): **worker.js bytes UNCHANGED this session** — helpers continue to live inline in worker.js *and* the parallel source-of-truth lives in `shared/auth-helpers.js`. Drift detection automated via `tools/verify-helpers-sync.mjs` (run pre-commit when either file is touched). 19/19 byte-identical PASS verified at session close. **No verification logic changed; only mirrored to a parallel source-of-truth file.** No endpoint added, weakened, or removed. **Gap NONE preserved on every endpoint block above.** No Cloudflare Dashboard deploy required (worker.js byte-identical to live deploy `bbfbdfd`). S144 (HIPKit private worker creation) will seed `hipkit-net/worker.js` by copying these helpers verbatim from `shared/auth-helpers.js`; the verifier extends to cover both workers thereafter. Three rejected alternatives, in order of consideration: Option A (multi-file ES modules with literal `import`) — feasible since worker.js already deploys in Modules format, but introduces deploy-time uncertainty in Peter's Cloudflare Dashboard Quick Editor flow on the first worker.js touch in 16 sessions; deferred. Option B (build-time concat) — adds new tooling and a deploy-bundle artifact distinct from source-controlled `worker.js`; deferred. Option C as originally framed (inline copy + sync test, highest drift risk) — refined to "Option C-refined" above by treating `shared/auth-helpers.js` as a true source-of-truth file rather than an undocumented duplicate, with automated drift detection via `verify-helpers-sync.mjs`. The "extract" goal is met architecturally (single source-of-truth + reusable across both workers) without code movement, which provably eliminates behavior-change risk on the highest-stakes worker.js touch since S131.
- **S131CW — 2026-04-24.** Optional `thumbnail` body field added to `/register-proof` and `/api/attest` (Carryover #69 closure; supersedes long-standing Carryover #5). Field is a data URL image string for Portfolio cross-device rendering. Validation: non-string → 400 `thumbnail must be a string (data URL) or null`; length >68000 chars → 400 (mirror of client guard at hipkit-net/hip-ui.js L815); missing `data:image/` prefix → 400 (defensive — the value ends up rendered as `<img src>` in Portfolio views, so MIME shape matters at the display layer even though the worker doesn't consume the value). NOT inside the signature payload — metadata only, identical posture to `file_name` (S88), `original_hash` (S102), `attested_copy_hash` (S103). Persisted on `proof:{hash}` records as `thumbnail: thumbnail || null`; pre-S131CW records stay `null` (forward-only migration). S130CW's client-side `hip_thumb_cache_v1` localStorage cache on hipkit.net continues to hydrate pre-S131CW records on the same device via the non-destructive `if (!r.thumbnail …)` merge gate at hip-ui.js `loadPortfolio` — as E1 propagates, worker-returned truth wins automatically and the cache degrades to same-device only. No verification gate added, weakened, or removed. No client migration required (hipkit-net/hip-attest.js L41 was already sending `thumbnail: fileEntry.thumbnail || null` since S63; the field was silently dropped by the worker until S131CW). worker.js +46 lines (8051 → 8097). Single atomic Cloudflare Dashboard deploy.
- **S122CW — 2026-04-23.** Optional `hipkit_originated` boolean body field added to `/register-series` and `/register-series-member` (Carryover #40 design pass; HIPKIT-SERIES-DESIGN.md §4). Field is metadata-only: stamped on the persisted record when strictly `true`, absent otherwise (conditional spread keeps protocol-default record shape unchanged for hipprotocol.org-originated writes). NOT inside the signed manifest/event — same posture as `original_hash`, `attested_copy_hash`, `file_name`. Validation: `undefined | true | false` accepted; non-boolean rejected with `invalid_field`. Verifier-side semantic correctness identical (both `series.html` read path and `/api/series/{id}` ignore the flag entirely; HIPKit-side surfaces filter on it for the portfolio Series tab and downstream cert/3D integrations). No verification gate added, weakened, or removed on any endpoint. worker.js +24 lines (8027 → 8051). Single atomic Cloudflare Dashboard deploy. No client migration required (legacy clients omit the field; record shape unchanged).
- **S118CW — 2026-04-23.** API key retirement cascade (Carryover #48). `handleRetireCredential` now reads `cred_api_keys:{credential_id}` after the trust-record write and parallel-deactivates every still-active `api_key:{keyHash}` belonging to the credential, stamping `deactivated_reason:"credential_retired"` and `deactivated_at` (= retirement timestamp). Already-deactivated keys are preserved untouched (their existing `deactivated_reason` — typically `"user_revoked"` — is not clobbered). Per-key failures non-fatal; retirement succeeds even if every cascade write fails. Response augmented with `cascaded_keys: {total, deactivated}`. `handleListApiKeys` response shape extended with additive `deactivated_at` + `deactivated_reason` fields (null on still-active keys). `handleDeactivateApiKey` now stamps `deactivated_reason:"user_revoked"` for symmetry. No verification weakened on any endpoint; cascade is data hygiene that closes the audit-shape inconsistency surfaced in S116CW Carryover #48. No client migration required for the worker change (additive fields, idempotent cascade). hipkit.net Keys panel updated in same session to render "Revoked · credential retired" vs plain "Revoked" based on `deactivated_reason`.
- **S116CW — 2026-04-22.** BLOCKS SCALE #1 worker-side: three AppAuth-gated endpoints for user-facing API key management — `POST /api/keys/create`, `POST /api/keys/list`, `POST /api/keys/deactivate`. New KV shapes `cred_api_keys:{credential_id}` (reverse index) and `kcrate:{hmac(cred_id)}` (24h TTL rate limit at 10 creates/day). `api_key:{keyHash}` record extended with optional `last_used` (stamped by `handleApiAttest` on each authenticated auth pass; non-fatal) and optional `deactivated_at` (stamped on deactivation). Admin endpoint `POST /api/admin/keys` retained as escape hatch. No existing endpoints modified in scope/behavior beyond the `last_used` stamp. No client surface touched this session — hipkit.net Keys panel UX deferred to S117CW.
- **S115CW — 2026-04-22.** BLOCKS ANNOUNCE #2 closure: `handleDisputeProof` now requires server-side Ed25519 signature verification over `"DISPUTE|{content_hash}|{credential_id}|{reason_hash}|{timestamp}"`. `public_key` is a required body field; binding check (SHA-256(public_key) === credential_id) enforced. Timestamp freshness ±5 min matches `verifyAppAuth` posture. Client-side: `proof.html` `submitDispute` rewritten to import PKCS8 private key, compute `reason_hash = SHA-256(reason.trim())` and ISO 8601 timestamp, sign canonical, and send signature + public_key + timestamp alongside the existing body. No dual-canonical fallback — `proof.html` is the only client that POSTs `/dispute-proof`; worker + client ship atomically.
- **S114CW — 2026-04-22.** BLOCKS ANNOUNCE #1 closure: server-side Ed25519 verification added to `verifyAppAuth`, `handleRegisterProof`, `handleApiAttest`, `handleVerify`, `handleUnsealProof`. Binding check (SHA-256(public_key) === credential_id) enforced on every endpoint that accepts both fields. Dual-canonical accept for `/register-proof` and `/api/attest` to preserve parity with both live client surfaces. `/api/verify` now returns `signature_verified: true | false | "skipped_no_public_key"` honestly. Deployed as a single atomic worker.js push.
