# S104CW DELIVERIES

Running log of UX-polish changes shipped this session and of in-session decisions that the next embed-payload touch needs to act on.

---

## Phase 0 — Cleanup

### 0.1 — Dead `readHipExif` / `readHipPng` removed

Both pre-S41 walkers were superseded by `HipImageRead` in S103 (~L623). Call-sites in the Attest `handleFile` (JPEG branch and PNG branch) migrated to `HipImageRead.read` + `HipImageRead.extractContentHash`, which reads the post-S41 XMP payload on JPEG/WebP and the `HIP:Proof` iTXt chunk on PNG. The legacy walkers looked for pre-S41 artefacts (EXIF UserComment with `HIP-Protocol:attested` on JPEG; `HIP-Protocol` iTXt keyword on PNG) that the current `HipImageEmbed` writer no longer produces, so this also fixes a latent bug where a file attested post-S41 was not recognised as "already attested" on re-upload and the user was silently allowed to re-attest it.

Also removed: the `HIP_EXIF_MARKER` constant (only referenced inside `readHipExif`) and the `readHipMeta(fname, dataOrBytes)` wrapper (no callers remained after the two walkers were deleted).

Net delta to `index.html`: −67 lines.

### 0.2 — `short_url`-in-XMP — PARKED (no code change)

**Tradeoff.** Today the post-attest XMP / iTXt / PDF-Info / OOXML-custom payload written by `HipImageEmbed` and `HipFileEmbed` derives the `proof_url` at read time from the embedded `content_hash` — it serialises the canonical long form `https://hipprotocol.org/proof.html?hash={content_hash}` rather than the server-issued `short_url`. This is deliberate post-Fix-3: the attested copy must be byte-stable *before* the `/register-proof` POST so its `attested_copy_hash` can be sent to the worker in the same request and seeded into the alias table atomically. Adding `hip:ShortURL="{short_url}"` to the embedded payload after the fact is not possible without a second download step, which negates the one-POST pattern.

The open question is whether the benefit of offline-viewable `short_url` provenance (user can see the branded short link inside the file even without a network round-trip) is worth the XMP payload bloat and the schema-migration cost. Per-field cost in XMP is ~35 bytes; iTXt/PDF-Info are similar. Multiply across every attested image in circulation, the aggregate is not large. The real cost is that adding it means a second-pass embed (post-POST), which doubles the client-side write cost for the attested copy on large files, and means the alias seed would need to be re-keyed from the second-pass bytes or the first-pass bytes would need to be discarded — neither is free.

**Decision parked** until the next touch that already has to rewrite the embed payload (e.g. a schema version bump to 1.3, or a move to COSE envelopes). At that point, revisit and decide: (a) serialise short_url with the other hip:* attributes and accept the second-pass embed cost, (b) keep the long form only and consider a side-channel (e.g. HTTP redirect table) instead, or (c) embed both and let readers prefer whichever resolves.

**Until decided: do not add new fields to the XMP / iTXt / PDF-Info / OOXML-custom payloads.** The Fix-3 `content_hash = pre-embed-source` invariant and the `attested_copy_hash`-in-alias-table pattern depend on the payload being byte-stable across the POST.

### 0.3 — Fix-3-aware `CANONICAL COPY MATCHED` copy

Updated QuickVerify's positive-result header to map each `matchedVia` to copy that distinguishes "canonical pre-embed source" from "attested copy" under Fix-3 semantics:

- `matchedVia === "xmp"` (Tier 0, `HipImageRead` picked up the `hip:ContentHash` claim inside the dropped file's embedded metadata) → `ATTESTED — XMP CLAIM VERIFIED`
- `matchedVia === "content"` (Tier 1, dropped file's SHA-256 equals `content_hash` — which under Fix 3 is the pre-embed source hash) → `ATTESTED — CANONICAL SOURCE MATCHED`
- `matchedVia === "alias"` (Tier 1 with the worker translating a dropped attested-copy hash to its canonical record via the alias table seeded at publish time) → `ATTESTED — ATTESTED COPY RECOGNIZED`
- `matchedVia === "attested_copy"` (same-browser localStorage dual-hash match where the dropped file is the attested copy) → `ATTESTED — ATTESTED COPY RECOGNIZED`
- `matchedVia === "original"` (Tier 2/3 S101/S102 phrasing — the dropped file is the pre-embed source and the server record was resolved via localStorage or `/api/credential/{id}/attestations` history) → `ATTESTED — PRE-EMBED SOURCE RECOGNIZED` (unchanged)

Also updated the explanatory sub-block for `content` so it no longer conflates the dropped file with "the HIP-embedded copy that the signature covers" — post-Fix-3, a `content` match means the dropped file IS the canonical pre-embed source whose hash the signature covers. Added a short explanatory sub-block for `xmp` so users know the dropped file's embedded metadata was the match trigger and not the file bytes themselves.

---

## Phase 1 — Local label / copy fixes

### 1.1 — Liveness row gated on T3 + WebAuthn

At the Proof Card render (~L2789), the Liveness row now renders only when `cred.tier===3 && cred.webauthn && cred.webauthn.credentialId` — matching the gate at `waLiveness` (~L2500) that controls whether liveness is even attempted. For T1/T2 the row is omitted entirely instead of showing `Not verified`, which was misleading because those tiers never take the WebAuthn liveness path in the first place.

### 1.2 — "Save Attested Copy" button copy

Button copy rewritten from feature-forward to benefit-forward:

- Label: `Download your attested version` (replaces `↓ Save {fname}`)
- Subline: `Signed copy you can share anywhere` (replaces the prior long-form technical caption)

The section-heading `SAVE ATTESTED COPY` is retained so the affordance is still discoverable by users scanning for it.

---

## Phase 2 — Publish-flow structural fixes

### 2.1 — Pre-publish "Save Attested {fname}" button deleted

The pre-publish download surface (~L2800–2803) embedded `content_hash: "pending"` as a literal string and offered the resulting file as a download. Any downstream tool that reads it would see an unverifiable placeholder — a UX trap that provided nothing legitimate and confused users into thinking the attestation was finalised before publish. Removed entirely along with its `ToolAlert` and caption.

Verified that no non-`publishProof` code path depended on the deleted `<a>` element. The `publishProof` pre-compute at ~L2569 still runs its own in-flow embed for `attested_copy_hash` derivation; `embeddedBytes` is still consumed there as a `sourceBytes` fallback.

### 2.2 — "Save Proof Card" button styling

Switched from the orange `btnDl`/`btnG` conditional (which read as primary-adjacent on the post-publish screen because both the Proof Card button and the Save Attested Copy button were derived from the same hue) to an always-neutral secondary style — transparent background, neutral border, muted text. Hierarchy on the post-publish screen now reads as intended: primary = Save Attested Copy (solid green), secondary = Save Proof Card (neutral outline).

### 2.3 — Autoscroll on publish success

Added `id="publish-success"` to the post-publish block (the `<div>` wrapping the `ToolAlert("success", …)`, the copy-able proof URL, the optional Unseal button, and the Save Attested Copy block). In the `/register-proof` 200 success branch, after `setProofUrl` and `setAttestedCopyURL`, a `setTimeout(..., 80)` calls `document.getElementById("publish-success").scrollIntoView({behavior:"smooth", block:"start"})`. The 80 ms delay gives React time to commit the state update and paint the post-publish block before the scroll runs.

Because Phase 2.1 removed the pre-publish `Save Attested {fname}` button, there is no ambiguity about the scroll target — the only Save Attested Copy surface in the DOM is the post-publish one.

---

## Phase 3 — Navigation affordance polish

### 3.1 — Bolder tab active state

Tool-drawer tab active state (`~L3331-3344`) rewritten from subtle-tint to solid-fill:

- Background: `active?gg:"transparent"` (old — `gg` = `rgba(224,90,0,0.04)`, barely visible) → `active?go:"transparent"` (new — `go` = `#E05A00`, solid orange).
- Color: `active?go:t2` → `active?"#fff":t2`. White text on orange reads as unambiguously active.
- Font weight: `active?600:400` → `active?700:400`.
- Added `boxShadow: active?"0 0 12px rgba(224,90,0,0.28)":"none"` for a soft glow so the active tab visually lifts off the row.

Hover-vs-active interaction: the prior `className:active?"":"hip-tab-btn"` trick (apply the hover class only to inactive tabs) was replaced by a single `className:"hip-tab-btn"` plus `data-active={"true"|"false"}`. The hover rule was retargeted to `.hip-tab-btn:not([data-active="true"]):hover`. This keeps a single class on every tab button, which makes the Phase 4 mobile override (below) apply uniformly regardless of active state — otherwise the active tab's inline `padding` / `fontSize` / `letterSpacing` would have escaped the mobile CSS tightening since it had no shared class to anchor the media-query selector to.

### 3.2 — Credential tab first-view affordance (state only, visual reverted)

**Round-1 review outcome**: the corner-dot badge implementation read to Peter as a misaligned notification indicator, not as a subtle first-view hint. Specifically, the dot's `position:absolute; top:4; right:6` placement made the Credential button look visually asymmetric relative to Attest/Verify — breaking the uniform tab-row alignment the Phase 3.1 work just established. Dot removed.

The `credSeen` state scaffolding is retained in `index.html`:
- `useState` slot `s8` with lazy localStorage initializer reading `hip_cred_tab_seen_v1`.
- onClick hook on the Credential tab button (persists seen-flag on direct click).
- Deep-link useEffect branch that marks seen on `#tier1|#tier2|#tier3|#vouch|#vouch-recipient|#hip-import=` arrivals.

This lets a different, less-intrusive affordance form be wired later (candidates: a tab-row banner above the row saying "Start here →", auto-opening the Credential panel on a user's very first drawer open, or a one-time tooltip) without re-threading the state machinery.

**Original implementation notes (for reference, not shipped)**: added a pulsing 6px orange dot at `position:absolute; top:4; right:6` inside the Credential tab button.

State: `credSeen` (useState, new slot `s8`). Initialized synchronously from `localStorage.getItem("hip_cred_tab_seen_v1") === "1"` inside the useState lazy-initializer — not via useEffect — so the first render already has the correct value and the dot doesn't flash on for users who dismissed it in a prior session.

Render gate: `showDot = tab==="credential" && !credSeen && toolTab!=="credential"`. The `toolTab!=="credential"` clause means the dot never appears on the tab the user is currently viewing — so on the default-open state (toolTab defaults to `"credential"` in `s5`), no dot; the dot appears only if the user navigates to Attest/Verify without having ever actively selected Credential.

Dismissal: three triggers mark the tab as seen and persist to localStorage:
1. Direct click on the Credential tab button (inline onClick, before `setToolTab`).
2. Any tier-deep-link arrival (`#tier1`, `#tier2`, `#tier3`, `#vouch`, `#vouch-recipient`) — these auto-select the credential tab, so the user effectively "sees" it.
3. Arrival via `#hip-import=` sync link (`HIP_IMPORT_RESULT`) — same rationale.

The "scoped to credential_id" hint in the kickoff was dropped in favor of a single global key `hip_cred_tab_seen_v1`. On app reinstall / site-data clear, localStorage is wiped along with the credential, so the re-install-clears-it property is satisfied by the simpler scheme. A per-credential-id scope would have required re-showing the dot every time the user created or imported a new credential even if they immediately landed on the Credential tab — not the intended UX.

CSS (reverted in Round-1 follow-up): `@keyframes hipDotPulse` and `.hip-cred-dot` class removed when the dot span was removed.

Accessibility: moot — no visual element to screen-read.

---

## Phase 4 — Information density / mobile pass

### 4.1 — Mobile drawer tightening + very-narrow breakpoint

Pedro's TEST PEDRO 1 screenshots surfaced two classes of mobile issue, most of which were already neutralised by earlier phases: dual competing green CTAs (fixed in 2.1/2.2 — pre-publish Save Attested deleted, Save Proof Card restyled to neutral-secondary), and primary actions buried below the fold on success (fixed in 2.3 autoscroll). What remained was vertical-rhythm and tab-nav density on narrow widths.

Two targeted CSS additions at the `@media(max-width:480px)` breakpoint:

- `.hip-drawer-inner{padding:16px 12px!important;margin:0 4px!important}` — tightens from the 768px default of `padding:20px 16px, margin:0 8px`. Reclaims ~16px of horizontal real estate on phones under 480px, which matters because the drawer inner content (drop zones, proof-card grids, button rows) already has its own padding stack.
- `.hip-tab-btn{padding:9px 6px!important;letter-spacing:0.25px!important;font-size:10px!important}` — tab row now fits "Credential / Attest / Verify" without wrapping or clipping on iPhone SE / narrow Android widths. Letter-spacing reduced from 0.5px (inline) to 0.25px, font-size from 11px to 10px, horizontal padding from 12px to 6px. These target `!important` because the inline React styles would otherwise win.

### 4.2 — Not executed

No further structural changes this session. The Verify tab's Quick Verify / Full Verify / Content Matching section stack (visible in screenshot 6.23.01) remains dense but distinct — the green `QUICK VERIFY` header vs. orange `FULL VERIFY` header is by-design color-coded per the S89 wizard taxonomy, not ambient visual noise. Collapsing Full Verify to an expandable disclosure was considered but deferred: it touches the VerifyWizard component structure and the S103 Fix-3 test-plan assumes both paths are directly reachable from the tab. Revisit with the next wizard-structure touch, not as part of a UX polish session.

---

## Round 1 review — post-Phase-3 bug surfaced

### R1.1 — `setToolTab("cred")` typo on "GET A CREDENTIAL" CTA

Peter's Round-1 screenshot (`SESSION 104CW/Round 1/Screenshot 2026-04-18 at 8.20.28 PM.png`) showed the tool drawer open with **all three tab buttons rendering in inactive state** — no tab visually selected and no panel content below the tab row.

Root cause: line 3433's "GET A CREDENTIAL" CTA onClick set `toolTab` to the string `"cred"` (a legacy typo carried forward from a pre-S33 scaffold). The three tab buttons' `active = toolTab === tab` check is against `["credential","attest","verify"]` — `"cred"` matches none of them, so all three tabs rendered inactive. Likewise the three panel-render gates (`toolTab==="credential" && ...`) all evaluated false, leaving the drawer with an empty body.

This bug has been in the code since S33 but was not visually obvious pre-S104 because the old active-state styling (`background:gg` where `gg = rgba(224,90,0,0.04)`) was barely distinguishable from inactive. Phase 3.1's solid-orange active state made the absence of any active tab glaringly obvious — which is how Peter caught it.

Two-part fix:
1. **Direct fix** at line 3433: `setToolTab("cred")` → `setToolTab("credential")`.
2. **Defensive normalisation** in the tab-row map and panel-render lines: any `toolTab` value outside `{"credential","attest","verify"}` now falls through to `"credential"` (both for active-state styling and for panel rendering). This ensures a future typo in the same pattern can't silently break the drawer again — worst case, the user lands on the Credential tab instead of a broken empty drawer.

### R1.2 — Corner-dot affordance (Phase 3.2 original form) reverted

See 3.2 section above — same Round 1. Peter's first Round-1 screenshot read the dot as a misaligned notification badge breaking tab-row uniformity. Reverted; `credSeen` state scaffolding retained for a future non-intrusive affordance form.

---

## Deliverables

- `index.html`: 4054 → 4046 lines (−8 net across session). Phase 0.1 removed 67 lines of dead code; Phase 2.1 removed ~10 lines of pre-publish UX-trap button; Phase 2.3 and Phase 3.2 each added small amounts of state/effect logic; Phase 3.1 added `data-active` plumbing and boxShadow; Phase 4.1 added 4 lines of mobile CSS.
- `SESSION 104CW/S104CW-DELIVERIES.md`: this file.
- Snapshot: `SESSION 104CW/snapshots/index.html` (final session state).
- Commit target: `index.html: S104 UX polish (dead-code cleanup + Fix-3-aware copy + publish-flow fixes + nav polish + mobile density)`.
