# SECURITY-POSTURE.md

> Standing artifact. One block per auth-gated endpoint. Every session that touches
> an auth-gated endpoint updates this file. No session is CLOSED until this file
> matches reality for every endpoint in scope.
>
> **Charter principle — "If it says verify, it must verify."** Any gap between
> what an endpoint's name/response-shape *claims* and what it actually verifies
> is a **BLOCKS ANNOUNCE** condition.

**Last updated:** S115CW — 2026-04-22
**Worker.js HEAD at update:** post-S115CW BLOCKS ANNOUNCE #2 closure deploy (`worker.js` ~7645 lines)

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

- **Used by**: `/retire-credential`, `/api/collections/by-credential`, `/api/portfolio`, `/api/credential/{id}/attestations`, `/api/credits/balance`, `/api/credits/usage`, `/api/credits/consume`, `/api/stripe/checkout`, `/api/stripe/portal`.
- **Canonical**: `"HIPKIT|" + endpoint + "|" + credential_id + "|" + timestamp`
- **(a) field-presence checks**: credential_id, public_key, timestamp, signature. Hex-shape validation on credential_id + public_key. Timestamp ±5 min.
- **(b) crypto verification** (S114CW): ✅ Ed25519 signature verified over canonical. ✅ Binding check SHA-256(public_key) === credential_id. ✅ Trust record existence. ✅ Superseded-by guard.
- **(c) claim**: AppAuth = "credential holder consents to this endpoint call at this timestamp."
- **Gap?**: **NONE.** Closed S114CW. Pre-S114CW gap logged as BLOCKS ANNOUNCE #1.

### 2. `handleRegisterProof` — worker.js ~2624

- **Body fields**: content_hash, perceptual_hash?, credential_id, public_key (NOW REQUIRED), attested_at, classification, signature, sealed?, protocol_version?, file_name?, original_hash?, attested_copy_hash?.
- **Canonical**: dual — HIPKit format OR legacy format.
- **(a) field-presence checks**: all required. Hex-shape on content_hash, public_key, original_hash, attested_copy_hash. Classification enum. ISO 8601 on attested_at.
- **(b) crypto verification** (S114CW): ✅ Binding check SHA-256(public_key) === credential_id. ✅ Ed25519 dual-canonical verify. Trust record existence + superseded guard + TI≥60 + T3 cap + rate limit. First-writer-wins.
- **(c) claim**: "Register a signed, tier-bound attestation over `content_hash`."
- **Gap?**: **NONE.** Closed S114CW.

### 3. `handleApiAttest` — worker.js ~5699

- **Auth**: `X-API-Key` header → resolves to credential_id via `api_key:{hmac(apiKey)}` KV.
- **Body fields**: content_hash, classification, signature, public_key (NOW REQUIRED), attested_at?, sealed?, protocol_version?, perceptual_hash?, file_name?, original_hash?, attested_copy_hash?.
- **Canonical**: dual — HIPKit format OR legacy format.
- **(a) field-presence checks**: identical to `handleRegisterProof` plus API key lookup.
- **(b) crypto verification** (S114CW): ✅ Binding check. ✅ Ed25519 dual-canonical verify. Trust + TI≥60 + T3 cap + rate limit. First-writer-wins.
- **(c) claim**: "Programmatic attestation from a HIPKit API customer, signed by their bound credential."
- **Gap?**: **NONE.** Closed S114CW.

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
- **Gap?**: **NONE.** Unchanged.

### 9. `/register-series-member` — same helper as #8

- **Canonical**: `JCS(event_minus_signature)` → SHA-256 → Ed25519 verify.
- **Crypto verification**: ✅ Already correct. Creator-match enforcement. `member_proof_not_found` gate. Superseded-by guard.
- **Gap?**: **NONE.** Unchanged.

### 10. `/close-series` — same helper as #8

- **Canonical**: `JCS(event_minus_signature)` → SHA-256 → Ed25519 verify.
- **Crypto verification**: ✅ Already correct. Creator-match. Terminal-transition gate.
- **Gap?**: **NONE.** Unchanged.

### 11. `handleRetireCredential` — worker.js ~2475 (`POST /retire-credential`)

- **Auth**: routes through `verifyAppAuth` with canonical `"HIPKIT|/retire-credential|{credId}|{ts}"`.
- **Effect**: writes `superseded_by: "self-retired"` on trust record. Any subsequent AppAuth call with this credential will fail.
- **Gap?**: **NONE** (post-S114CW — inherits from `verifyAppAuth` fix).

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

---

## Change log

- **S115CW — 2026-04-22.** BLOCKS ANNOUNCE #2 closure: `handleDisputeProof` now requires server-side Ed25519 signature verification over `"DISPUTE|{content_hash}|{credential_id}|{reason_hash}|{timestamp}"`. `public_key` is a required body field; binding check (SHA-256(public_key) === credential_id) enforced. Timestamp freshness ±5 min matches `verifyAppAuth` posture. Client-side: `proof.html` `submitDispute` rewritten to import PKCS8 private key, compute `reason_hash = SHA-256(reason.trim())` and ISO 8601 timestamp, sign canonical, and send signature + public_key + timestamp alongside the existing body. No dual-canonical fallback — `proof.html` is the only client that POSTs `/dispute-proof`; worker + client ship atomically.
- **S114CW — 2026-04-22.** BLOCKS ANNOUNCE #1 closure: server-side Ed25519 verification added to `verifyAppAuth`, `handleRegisterProof`, `handleApiAttest`, `handleVerify`, `handleUnsealProof`. Binding check (SHA-256(public_key) === credential_id) enforced on every endpoint that accepts both fields. Dual-canonical accept for `/register-proof` and `/api/attest` to preserve parity with both live client surfaces. `/api/verify` now returns `signature_verified: true | false | "skipped_no_public_key"` honestly. Deployed as a single atomic worker.js push.
