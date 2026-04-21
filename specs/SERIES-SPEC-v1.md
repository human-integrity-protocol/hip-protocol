# HIP — Human Integrity Protocol
## SERIES-SPEC-v1: Series Mechanics Specification
### v1.0 DRAFT | 2026-04-21 | all 8 sections drafted, pending full-doc review

---

## Authority and Status

This specification derives its authority from and must remain consistent with:

- **HIP Genesis Covenant Charter v1.0** — the governing covenant document, in
  particular **DP-5 (Permissionless Proliferation)**, **DP-7 (Zero Institutional
  Cost)**, and **DP-8 (Protocol, Not Entity)**
- **HP-SPEC-v1.2** — HUMAN-PROOF Credential Mechanics, which defines credential
  identity, Trust Index, lifecycle state, retirement, and rate-limit
  architecture. SERIES-SPEC-v1 does not redefine any of these concepts; it
  references them.
- **WF-SPEC-v1** — Proof Bundle wire format. SERIES-SPEC-v1 uses the same
  canonicalization (RFC 8785 JCS), hash (SHA-256), and signature (Ed25519 per
  CRYPTO-SPEC-v1_1) primitives, but defines new record and event types.

In any conflict between this specification and the documents listed above, the
parent document controls. SERIES-SPEC-v1 may not introduce principles that
contradict those documents.

This specification is a companion document. It is not part of the Genesis
inscription. Its evolution does not require Charter amendment and does not
trigger fork conditions. It is versioned separately and updated as the
implementation landscape evolves.

---

## Purpose

SERIES-SPEC-v1 defines the mechanics of the **series** construct: an open,
append-only, creator-bound stream of attested content. A series is a
creator-asserted grouping that complements but does not replace the **collection**
construct defined elsewhere in the HIP implementation reference.

Where a collection is closed at sign time, atomic, and carries a single
signature binding its members at a fixed point in time, a series is open,
incremental, and accumulates signed affiliation events over time. A series
identifies *the creator's ongoing intent* to group content under a shared
heading; it does not re-attest the underlying content, which is already
covered by the member's existing `proof:{content_hash}` record.

---

## Scope

This specification covers:

- The `series` creation record schema and its persistence key
- The `series_add` and `series_close` event schemas and their persistence keys
- The `affiliations:{content_hash}` multi-affiliation index used by client
  surfaces to render affiliation chips at drop time
- Write authority rules: who may create a series, who may add members, who may
  close a series, and how credential retirement interacts with each
- Series lifecycle states and transitions
- Metadata immutability posture
- The credit model for series operations on HIPKit and hipprotocol surfaces
- Discovery mechanics (creator-portfolio only; no server-side directory)
- Wire format of the three new endpoints and the one new index-read endpoint
- Relationship to the collection construct

This specification explicitly defers:

- Client rendering details for series cards, affiliation chips, and portfolio
  tabs — these belong to implementation-surface documentation, not to the
  protocol spec
- Long-term series archival, compaction, or pruning policies — out of scope
  for v1
- Migration of existing collection member files into a series — out of scope
  for v1; creators who want this today publish a new series and add members
  one at a time
- Cross-series reference or linking semantics — out of scope for v1
- Member-type discriminator for collection-as-series-member — see §1.2
  Forward Compatibility. Files only in v1.

---

## §1 Data model

SERIES-SPEC-v1 introduces three new record types persisted in the primary KV
namespace (`DEDUP_KV` in the reference implementation), and one new index.

### §1.1 `series` creation record

**KV key:** `series:{series_id}`

**Value:** JSON object.

**`series_id` format:** 20-character lowercase base32 string, same alphabet
and shape as `collection_id` in the collection construct (see the collection
reference-implementation helper `isCollectionId`). Client-generated using a
cryptographically secure random source. The 20-char, 32-symbol alphabet yields
~100 bits of entropy, which is sufficient for creator-asserted volume and
makes the id short enough for human-visible URLs (`/s/{series_id}`).

**Record shape:**

```json
{
  "series_id": "<20-char base32-lowercase>",
  "manifest": {
    "schema_version": "hip-series-1.0",
    "issued_at": "<ISO-8601 UTC from client>",
    "title": "<string, 1–200 characters, required>",
    "description": "<string, 0–2000 characters, optional>",
    "cover_member_hash": "<64-hex SHA-256, optional>",
    "creator": {
      "credential_id": "<64-hex>",
      "tier": 1 | 2 | 3,
      "public_key": "<base64 Ed25519 public key>"
    }
  },
  "signature": "<base64 Ed25519 signature over SHA-256(JCS(manifest))>",
  "status": "open" | "closed",
  "created_at": "<ISO-8601 UTC from worker clock>",
  "closed_at": null | "<ISO-8601 UTC>",
  "member_count": <integer, ≥ 0>,
  "last_event_at": "<ISO-8601 UTC>"
}
```

**Immutability posture.** The entire `manifest` object is immutable after
creation: the server MUST reject any attempt to modify `title`, `description`,
`cover_member_hash`, or `creator` fields. The out-of-manifest fields
(`status`, `closed_at`, `member_count`, `last_event_at`) are server-maintained
and are updated by the `series_close` event (status, closed_at) or by each
successful `series_add` event (member_count, last_event_at). Because the
signature covers only the manifest, server-side updates to the out-of-manifest
fields do not invalidate the creation signature.

**`cover_member_hash` rule.** If present, it MUST equal the `member_hash`
(content SHA-256) of a file that is later added via `series_add`. The spec
does not require the cover member to be added at creation time — the creator
may declare an intended cover ahead of its addition, in which case the client
renders a placeholder until the matching `series_add` arrives. Implementations
MAY additionally reject creation with a cover_member_hash that is not present
as a `proof:{content_hash}` record at creation time if they wish a stricter
posture; the spec leaves this as an implementation choice.

### §1.2 `series_add` event

**KV key:** `series_event:{event_hash}` where `event_hash = SHA-256(JCS(event minus signature))`

**Persistence also:** append the event_hash to the ordered list at
`series_events:{series_id}`.

**Event shape:**

```json
{
  "event_type": "series_add",
  "schema_version": "hip-series-event-1.0",
  "series_id": "<20-char base32-lowercase>",
  "member_hash": "<64-hex SHA-256>",
  "member_type": "file",
  "added_at": "<ISO-8601 UTC from client>",
  "added_by_credential_id": "<64-hex>",
  "signature": "<base64 Ed25519 over SHA-256(JCS(event minus signature))>"
}
```

**Reference semantics.** A `series_add` event does NOT contain the member's
content or attestation. It references a pre-existing `proof:{content_hash}`
record by hash. The server MUST reject a `series_add` whose `member_hash`
does not resolve to an existing `proof:{member_hash}` record (404 /
`member_proof_not_found`). This enforces the "indexing, not re-attestation"
posture: adding to a series is a metadata event over already-attested content.

**Forward compatibility: `member_type`.** In v1, `member_type` MUST be the
string `"file"`. The field is reserved so that future versions of this
specification may introduce `"collection"` (or other member types) without
a record-format break. Servers SHOULD reject any value other than `"file"`
as `invalid_member_type`; clients MUST emit `"file"`. Allowing
`"collection"` members is explicitly deferred to a future spec version.

### §1.3 `series_close` event

**KV key:** `series_event:{event_hash}` where `event_hash = SHA-256(JCS(event minus signature))`

**Persistence also:** append the event_hash to `series_events:{series_id}`.

**Event shape:**

```json
{
  "event_type": "series_close",
  "schema_version": "hip-series-event-1.0",
  "series_id": "<20-char base32-lowercase>",
  "closed_at": "<ISO-8601 UTC from client>",
  "closed_by_credential_id": "<64-hex>",
  "signature": "<base64 Ed25519 over SHA-256(JCS(event minus signature))>"
}
```

**Side effect.** On successful acceptance, the server MUST update the
`series:{series_id}` record: set `status = "closed"` and `closed_at =` the
event's `closed_at`. The original manifest is untouched, preserving signature
integrity.

**Idempotency.** A `series_close` event for an already-closed series MUST
return 400 `series_already_closed` rather than silently succeeding. Clients
that observe this error after a network retry MAY treat it as "already done."

### §1.4 `series_events:{series_id}` — event ordering index

**KV key:** `series_events:{series_id}`

**Value:** JSON array of objects, append-only, ordered by server-side
`applied_at` (the worker clock at the time of acceptance):

```json
[
  { "event_hash": "<64-hex>", "event_type": "series_add" | "series_close",
    "applied_at": "<ISO-8601 UTC>" },
  ...
]
```

**Ordering.** `applied_at` (server clock) is authoritative for display. The
per-event `added_at` / `closed_at` (client clock) is retained in the event
record for provenance but MUST NOT be used by the reference client for
member ordering, as client clocks are not trusted for ordering within a
series.

**Capacity note.** The list is append-only with no hard cap in v1. A series
with more than ~10,000 events will require pagination on the read side;
pagination semantics are part of §7 Wire Format and are not specified in §1.

### §1.5 `affiliations:{content_hash}` — multi-affiliation index

**KV key:** `affiliations:{content_hash}` where `content_hash` is the file's
attested content hash (64-hex SHA-256).

**Value:** JSON array of objects:

```json
[
  {
    "type": "series" | "collection",
    "id": "<20-char base32-lowercase series_id or collection_id>",
    "credential_id": "<64-hex of the adder / collection creator>",
    "added_at": "<ISO-8601 UTC, server clock>"
  },
  ...
]
```

**Write path.** Each successful `series_add` event appends an entry to this
index. Additionally, `handleRegisterCollectionProof` (the collection-creation
handler) MUST be retrofitted to append one entry per collection member at
collection-creation time, so that a file's full affiliation history
(collections + series) is surfaced in a single read. See Implementation Note
§1.5.1.

**Ordering.** Newest-last (append). Clients that need newest-first for
rendering MAY reverse the array client-side.

**Idempotency.** If the same `{type, id, credential_id}` triple is already
present, the server MUST NOT append a duplicate. This handles the
application-layer retry case where a client sends a `series_add` that
was already applied server-side.

#### §1.5.1 Implementation Note — collection retrofit

At the time SERIES-SPEC-v1 is drafted, the collection-creation handler
(`handleRegisterCollectionProof` in the reference implementation) does not
write `affiliations:{member_hash}` entries. Shipping SERIES-SPEC-v1 requires
adding one KV write per member at collection creation, guarded so that
re-runs of the handler (e.g., a retry after a partial write) do not create
duplicates. The write is non-fatal to the collection-creation critical path
— a failure to write an affiliation entry MUST NOT roll back the collection
itself, consistent with the existing `addToCredProofsIndex` posture.

### §1.6 `creator_series:{credential_id}` — creator-to-series index

**KV key:** `creator_series:{credential_id}`

**Value:** JSON array of objects, append-only:

```json
[
  {
    "series_id": "<20-char base32-lowercase>",
    "created_at": "<ISO-8601 UTC, server clock>",
    "status_at_write": "open"
  },
  ...
]
```

**Write path.** Appended as a side-effect of the series creation handler,
within the same request that writes `series:{series_id}`. Non-fatal: a
failure to append this index entry MUST NOT roll back the series creation
itself, consistent with the existing `addToCredProofsIndex` posture and
with the §1.5.1 affiliations retrofit. A partial write simply means the
series will not appear in the creator's portfolio until an index-repair
script runs (out of scope for v1; acceptable degradation).

**Ordering.** Newest-last (append). Clients that need newest-first for
rendering MAY reverse client-side.

**Staleness note.** `status_at_write` is a creation-time snapshot and does
NOT track subsequent status changes. A series closed via `series_close`
after its creation will still read `status_at_write: "open"` in this
index. Clients rendering a portfolio MUST re-read each
`series:{series_id}` record for its current `status`, `closed_at`,
`member_count`, and `last_event_at`. The index exists for enumeration,
not for state.

**Rationale.** Enables portfolio-level reads of the form "list all series
by credential X" without a full KV prefix-scan on `series:`. Symmetrical
with `cred_proofs:{credential_id}` for attestations, which has been the
working pattern since S50 in the reference implementation.

**Capacity.** A creator credential may author an unbounded number of
series over its lifetime (subject to rate limits per §2.1). Pagination
of a creator-series index is deferred to §7 Wire Format; for v1, a hard
cap of ~1000 entries with a `truncated: true` sentinel on the read
response is sufficient for the expected volume of series per credential.
T1 creators who exceed 1000 are an acceptable degradation — they can
retire the oldest series (close them) and the client can filter the
display.

---

## §2 Write authority

### §2.1 Series creation

- The requesting credential MUST be active on the ledger. The server uses the
  existing `verifyAppAuth` gate (reference implementation: worker.js ~L126)
  which checks `trust_record.superseded_by` and rejects retired credentials.
- The requesting credential's Trust Index MUST be ≥ 60, the same floor used
  for `register-proof` per HP-SPEC-v1.2. Below-floor credentials receive 403
  `trust_index_below_floor`.
- The creation signature MUST verify against the credential's Ed25519 public
  key, where the signed payload is `SHA-256(JCS(manifest))`. Signature
  verification failure returns 422 `invalid_signature`.
- The `series_id` MUST match the shape check in §1.1. Shape failure returns
  400 `invalid_series_id`.
- Rate-limit: series creation counts against the unified credential attest
  rate budget defined in HP-SPEC-v1.2 (20/24h, 100/7d). No separate
  series-creation budget in v1.

### §2.2 Series adds

- The event's `added_by_credential_id` MUST equal the series' `manifest.creator.credential_id`.
  Mismatch returns 403 `not_series_creator`.
- The signing credential MUST be active (not retired). Retired-credential
  `series_add` returns 403 `credential_retired` via `verifyAppAuth`.
- The target `series:{series_id}` record MUST exist and have `status === "open"`.
  Missing series returns 404 `series_not_found`. Closed series returns 400
  `series_closed`.
- The `member_hash` MUST resolve to an existing `proof:{member_hash}` record.
  Missing member-proof returns 404 `member_proof_not_found`.
- The event signature MUST verify against the credential's Ed25519 public
  key, where the signed payload is `SHA-256(JCS(event minus signature))`.
  Verification failure returns 422 `invalid_signature`.
- The `member_hash` MUST NOT already be a member of this series. Duplicate
  add returns 400 `member_already_in_series`. (The creator may remove and
  re-add semantics are out of scope for v1 — there is no remove.)
- Rate-limit: series-add events count against the unified credential attest
  rate budget defined in HP-SPEC-v1.2. Implementations MAY adopt a more
  permissive per-operation budget in a future spec version; v1 uses the
  unified budget to minimize operational surface area.

### §2.3 Series close

- Same authority rules as §2.2: `closed_by_credential_id` MUST equal the
  series creator, signing credential MUST be active, the series MUST exist
  and be `open`, and the signature MUST verify against the credential's
  public key over `SHA-256(JCS(event minus signature))`.
- Rate-limit: series-close events are idempotent terminal operations and
  are exempt from rate limiting. (The worst case is a single close per
  series, so there is no abuse surface.)

### §2.4 First-writer rule

For `series:{series_id}`, the first valid creation request to reach the
server wins. A subsequent creation request with the same `series_id` returns
400 `series_id_collision` regardless of whether the creator credential matches.

The reference-implementation pattern is:

1. Read `series:{series_id}` — if present, return 400 `series_id_collision`.
2. Perform all validation (signature, TI, shape, rate-limit).
3. Write `series:{series_id}` with `status: "open"`, `member_count: 0`.

There is a narrow TOCTOU window between step 1 and step 3 where two
simultaneous creations can both pass the collision check. The reference
implementation accepts this narrow window — an adversary cannot exploit it
to any effect, since the two requests would each need to present valid
signatures over the same `series_id`, which the adversary cannot forge
without the creator's private key. If the same legitimate creator
accidentally races two creation requests, the second write simply
overwrites the first — functionally a no-op, because both requests
carried identical manifest content.

### §2.5 Continuation across credential rotation

The HIP credential lifecycle already supports key rotation via the
`recovered_from` chain (HP-SPEC-v1.2 §credential portability, reference
implementation stamps `recovered_from: <predecessor credential_id>` on the
new trust record). SERIES-SPEC-v1 does not introduce a new field for
series continuation.

A creator whose credential is retired cannot write to any series they
previously created (per §2.2: retired-credential writes fail). To continue
the stream, they publish a new series under their new credential. The new
series's card MAY render a link "continues from: `/s/{predecessor_series_id}`"
if and only if:

- Both series exist and have valid creation records,
- The new series's `manifest.creator.credential_id` chains to the
  predecessor's `manifest.creator.credential_id` via `recovered_from`
  (zero or more hops), AND
- The creator has asserted the continuation through an out-of-band
  mechanism (e.g., a client-side UI affordance or a manual URL the
  creator shares). The spec does NOT require the server to infer
  continuation links; they are a render-time convenience.

No new endpoint is required for the render-time check. The client (or the
card HTML generator on the server) walks the `recovered_from` chain by
reading trust records directly.

---

## §3 Lifecycle

### §3.1 States

A series has exactly two explicit states plus one implicit state:

| State | Explicit? | How reached | Write behavior |
|---|---|---|---|
| `open` | yes, `status: "open"` | on successful creation | accepts `series_add`, accepts `series_close` |
| `closed` | yes, `status: "closed"` | on successful `series_close` event | rejects `series_add` (400 `series_closed`), rejects `series_close` (400 `series_already_closed`) |
| `frozen` | no explicit flag | creator credential is retired | all writes rejected by `verifyAppAuth` (403 `credential_retired`) |

`frozen` is not a persisted state on the series record. It is derived at
request time: if the creator credential's trust record has `superseded_by`
set, any write bearing that credential is rejected before it reaches the
series-specific logic. Card UI MAY render a "frozen since {retirement_date}"
badge by reading the creator's retirement metadata. The series record itself
retains `status: "open"`, which is accurate — the series is not deliberately
closed, it is merely unwritable.

### §3.2 Transitions

```
          create
           │
           ▼
       ┌───────┐        series_close (signed, by creator)
       │ open  │ ─────────────────────────────────────────►  closed
       └───────┘
           │
           │ creator credential retired
           ▼
      (frozen — implicit)
```

- `open → open`: each successful `series_add` increments `member_count`,
  updates `last_event_at`. No state transition.
- `open → closed`: via signed `series_close` event. Irreversible.
- `open → frozen`: implicit on creator credential retirement. Reversible
  only in the sense that credential recovery (new credential via
  `recovered_from`) allows the creator to publish a **new** series and
  render continuation — the original series stays frozen forever.
- `closed → *`: no transition. A closed series cannot be reopened. If the
  creator wants to add more content under the same brand, they publish a
  new series and MAY render a client-side "continues from" link (same
  mechanics as §2.5).

### §3.3 Deletion posture

There is no `series_delete` event. A creator who publishes a series and
regrets it has two options:

1. Close the series immediately via `series_close`. The series record
   remains on the ledger and at `/s/{series_id}`, but no further members
   can be added. Creator-surface UI MAY render this as "closed early."
2. Live with it. Metadata is immutable; see §4 Metadata (forthcoming).

This is a deliberate posture inherited from the collection construct
(collections cannot be deleted either) and from the HIP charter's append-only
ledger posture more broadly.

### §3.4 Status and member_count consistency

The `status`, `member_count`, and `last_event_at` fields on the series
record are server-maintained. Clients MUST treat these as read-only and
MUST NOT attempt to modify them via any endpoint. The reference
implementation updates them atomically as part of the `series_add` and
`series_close` handlers.

Eventual consistency caveat: in a worker environment with KV eventual
consistency (reference: Cloudflare Workers KV has ~60s global
consistency), a series_add followed immediately by a read of
`series:{series_id}` from a different edge location MAY observe a stale
`member_count`. Clients that need strict read-after-write consistency
SHOULD read from the `series_events:{series_id}` list (which the
reference implementation writes in the same request), OR tolerate brief
staleness in the member count. This is the same posture as the collection
construct and is not specific to SERIES-SPEC-v1.

### §3.5 Tier-specific lifecycle notes

The write-authority rules in §2 are tier-symmetric: any active credential
with TI ≥ 60 may create a series, add members, and close it. This section
documents tier-specific second-order effects that arise from interactions
between those rules and the tier-specific ceilings defined in HP-SPEC-v1.2
and HP-SPEC-v1.3. None of these effects require new protocol fields; they
are consequences of existing mechanics and are captured here so client
implementations can surface them coherently.

#### §3.5.1 T3 natural ceiling on series members

A T3 credential's Trust Index ceiling (TI=60 per HP-SPEC-v1.3's provisional
clause) and the T3 provisional lifetime-attestation cap (50 per
HP-SPEC-v1.3) combine to impose a natural upper bound on the size of a
series whose creator is T3:

- T3 becomes eligible to create a series at the moment TI reaches 60 — the
  same moment the credential becomes eligible to call `register-proof`.
- `series_add` is an indexing event, not an attestation (§1.2): it
  references a pre-existing `proof:{member_hash}` record and does NOT
  consume a lifetime-attestation slot.
- However, each series member MUST resolve to an existing
  `proof:{member_hash}` record (§2.2). A T3 creator can produce at most
  50 such records across their credential's lifetime via `register-proof`.
- Therefore: a T3-creator series may have at most 50 members. Once the
  creator has used all 50 lifetime attestations, no further member proofs
  exist for them to reference, and `series_add` calls fail with 404
  `member_proof_not_found` even though the series record remains `open`
  and the credential remains active.

**This is not a frozen state.** `verifyAppAuth` does not reject writes
(the credential is not retired). The creator MAY still call
`series_close` to end the series deliberately, or leave it `open` as a
forever-empty-slot. The behavior is "open but unwritable-for-content."

Clients that render a series card SHOULD distinguish visually between
the three end-states:

- **Closed** (via `series_close`) — creator deliberately ended the series.
- **Frozen** (creator credential retired) — see §3.1, implicit.
- **At-capacity, T3** — creator has exhausted their lifetime-attestation
  cap. Render as a neutral informational badge ("Creator reached T3
  attestation cap — upgrade to continue"), not as an error state. The
  series is canonically `status: "open"` and its members remain fully
  verifiable.

#### §3.5.2 Continuation via pathway upgrade

When a T3 creator upgrades to T2 (via peer vouch) or to T1 (via Didit),
the existing HP-SPEC-v1.2 key-rotation mechanics stamp the new credential
with `recovered_from: <predecessor_credential_id>` on its trust record.
The at-capacity T3-creator case is then resolved by the standard
continuation path:

1. The creator publishes a new series under their new credential
   (which, at T2 or T1, has no 50-attestation cap).
2. Per §2.5, clients render a "continues from: /s/{predecessor_series_id}"
   link on the new series's card if and only if the new credential chains
   to the predecessor credential via `recovered_from`.
3. The predecessor series remains on the ledger, its manifest intact,
   its members verifiable. It becomes an early-chapter artifact of the
   creator's ongoing stream.

This is the intended lifecycle for T3 creators who want to keep building
a portfolio past the T3 50-attestation ceiling. No new protocol mechanism
is introduced to serve this case; it composes from §2.5 + HP-SPEC-v1.2
key-rotation.

#### §3.5.3 T2 and T1 creators

T2 and T1 credentials are not subject to the T3 lifetime-attestation
provisional cap (HP-SPEC-v1.3 §provisional ceiling applies to T3 only).
A series under a T2 or T1 creator is bounded only by the standard
credential rate limits (HP-SPEC-v1.2 §rate limits: 20/24h, 100/7d on
attestation, with series events drawing from the same budget per §2.1
and §2.2). There is no natural end-state for a T2- or T1-creator
series short of explicit `series_close` or credential retirement.

---

## §4 Metadata

### §4.1 Immutability at creation

All fields inside `manifest` (title, description, cover_member_hash,
creator) are immutable after the creation record is written. The server
MUST NOT expose any endpoint that modifies these fields. There is no
edit-in-place operation for series metadata — not for typos, not for
clarifications, not for cover-image changes.

This posture is inherited from the collection construct (collection
manifests are similarly immutable once signed) and from the HIP charter's
append-only ledger posture (DP-8 implications on protocol-level
state changes).

### §4.2 Rationale

A series is a signed declaration: "I, credential `{credential_id}`, am
starting a stream titled `{title}` described as `{description}`." The
signature binds the creator to the declaration at the stated `issued_at`
time. Modifying any of those fields after the fact would mean the creator's
stated intent at declaration time no longer matches what viewers and
downstream consumers observe, breaking the provenance chain that the
signature was supposed to establish.

If a creator wants to revise a series's framing, the correct action is to
close the existing series (via `series_close`) and publish a new one. The
new series MAY be rendered client-side with a "continues from" link per
§2.5 if the credential is the same (or chains via `recovered_from`).

### §4.3 What about typos

Typos are lived with, or the series is re-published. The spec does not
provide a mechanism to correct manifest content. Implementations SHOULD
surface this clearly in their creation UI — a confirmation step before
the signature is produced, showing the exact text that will be bound into
the manifest, gives creators a chance to catch errors before they commit.

### §4.4 `cover_member_hash` pre-declaration

The `cover_member_hash` field in §1.1 is metadata describing the creator's
intended cover image, not a binding content commitment. A creator MAY
declare a `cover_member_hash` at creation time that does not yet
correspond to a `series_add` event. Two scenarios are valid:

1. **Pre-declaration** — the cover hash is specified at creation, and
   the matching file is added via `series_add` at some later point.
   Clients render a placeholder until the matching add arrives, then
   swap in the covered thumbnail.
2. **Concurrent declaration** — the creator adds the cover file as the
   first `series_add` event immediately after creation. Functionally
   equivalent to case 1 with a very short placeholder window.

The spec does NOT require the cover file to be a member of the series
at the moment of creation. It MUST be added as a `series_add` eventually
for the cover to render; until then, the client displays the placeholder.

Implementations MAY choose to enforce a stricter posture (reject
creation with a `cover_member_hash` that is not already a
`proof:{content_hash}` record, or not yet added to the series). The
spec permits but does not require this. See §1.1 `cover_member_hash`
rule.

### §4.5 Omitted fields

- `description` is optional. Zero-length descriptions are legal (encoded
  as `""`, not as a missing field). Creators who omit the description
  have made the affirmative choice to ship without one; it cannot be
  added later.
- `cover_member_hash` is optional. A series with no cover renders as a
  tile-grid-of-members or a similar fallback at client discretion.

### §4.6 Length limits

- `title`: 1 to 200 characters, Unicode, trimmed. Leading/trailing
  whitespace MUST be stripped by the server before signature verification
  to prevent inconspicuous manifest variance. (Note: this interacts
  with JCS — the canonicalized manifest carries the trimmed value, and
  the signature is computed over that. Clients MUST trim on their side
  before signing.)
- `description`: 0 to 2000 characters, Unicode, trimmed identically.
- `cover_member_hash`: exactly 64 lowercase hex characters if present,
  else absent from the manifest.

Out-of-range values on any of these fields return 400
`invalid_manifest_field` on the creation endpoint.

---

## §5 Credit model

SERIES-SPEC-v1 is a protocol-level specification and does not impose
a credit model; credit models are implementation-surface concerns.
However, because HIP has two reference surfaces today (hipprotocol.org
as the free protocol surface, hipkit.net as the paid commercial
surface) and because the credit model for existing operations
(`register-proof` on hipprotocol is free, on hipkit is 1 credit) is
a known implementation pattern, this section documents the intended
credit model for series operations under both surfaces. Implementations
that host a series endpoint MAY adopt a different credit model
provided it is consistent with the charter's DP-7 (Zero Institutional
Cost) for the protocol surface: hipprotocol.org MUST remain free for
series operations.

### §5.1 hipprotocol.org (protocol surface)

Per DP-7, all series operations on the protocol surface are free:

| Operation | Credit cost |
|---|---|
| Series creation | 0 (free) |
| Series add | 0 (free) |
| Series close | 0 (free) |

Rate limits still apply per §2 (unified credential attest budget).

### §5.2 hipkit.net (commercial surface)

HIPKit charges credits for operations that impose compute and storage
cost. Series operations break down as follows:

| Operation | Credit cost | Rationale |
|---|---|---|
| Series creation | 1 credit | One KV write + one manifest signature verification + one rate-limit check. Cost is comparable to a single `register-proof` call. |
| Series add | 1 credit | One KV read (series record), one KV read (member proof), one KV append (series_events list), one KV append (affiliations index), one signature verification. Cost is comparable to a single attest operation. |
| Series close | 0 (free) | One signature verification + one KV write. No new attested work. Trivially bounded: at most one close per series in the lifetime of the series. |

### §5.3 Rationale for the differential

The "series-add is an indexing event, not a re-attestation" framing
(§1.2) might suggest that series_add should be cheaper than a full
`register-proof` call. In practice the compute cost is similar (a
signature verification is the dominant operation), and the storage
cost is non-zero (two KV writes). Charging 1 credit per add aligns
billing with operational cost and keeps the model simple.

Series close is free because it is terminal, bounded, and cheap. A
creator cannot abuse close-frees by closing the same series repeatedly
— it is idempotent after the first successful close.

### §5.4 Billing timing

Consistent with existing HIPKit credit semantics: credits are consumed
on successful completion of the write (not at request submission).
Failed writes (signature invalid, rate-limited, series already closed,
etc.) do NOT consume credits. This matches the existing `register-proof`
behavior and is not a new billing policy.

### §5.5 No protocol-level credit field

The series record and events do not carry any credit-related fields.
Credit accounting lives in the commercial surface's own ledgers
(reference implementation: HIPKit's `credits_consumed:{credential_id}`
bookkeeping), which are opaque to the protocol. This preserves the
clean separation between protocol (free, per DP-7) and commercial
implementations (metered, per institutional choice).

---

## §6 Discovery

### §6.1 No server-side directory

There is no protocol-level endpoint that lists all series globally.
There is no "browse all series" page, no search-by-title index, no
trending-series feed, no server-maintained catalog. A series exists
only where it is referenced — from its short URL, from the creator's
portfolio, or from wherever the creator has shared the link.

This is a deliberate posture inherited from the collection construct
and from the charter's DP-5 / DP-8 framing. The protocol does not
aggregate creator output into a platform-style discovery surface
because doing so would make the protocol a platform, and platforms
have opinions — about ranking, about surfacing, about what counts as
worth finding. SERIES-SPEC-v1 takes no such opinions.

Consumers who want to build directories, search indexes, rankings, or
aggregators MAY do so at the institutional layer, outside the protocol,
by reading public series records they have been shown. Per DP-5,
anyone may build these tools without permission. Per DP-8, no such
tool is HIP.

### §6.2 Short URL as the primary pointer

The canonical pointer to a series is its short URL: `/s/{series_id}`
served from whatever host runs the reference implementation
(`hipprotocol.org/s/{series_id}` for the primary deployment). The
short URL resolves to the series card. Creators share the short URL
through whatever channels they use to share anything — email, social
media, QR codes, in-person sharing, embedded links, etc. The protocol
does not specify or constrain how short URLs are propagated.

### §6.3 Creator portfolio

A creator's portfolio is the primary discovery surface for a creator's
own series. Portfolio views are rendered client-side by reading:

1. The creator's `creator_series:{credential_id}` index (§1.6) — for
   enumeration of series authored by this credential.
2. Each `series:{series_id}` record in the list — for current status,
   title, cover, member_count, closed_at.
3. Optionally, each `series_events:{series_id}` list — for recent
   activity timestamps.

The reference implementation surfaces this through the Portfolio tab
on `hipkit.net` (and, for the protocol surface, potentially through a
public creator page at `hipprotocol.org/p/{credential_id}` — scope
deferred to a separate Portfolio spec). The exact UI is an
implementation-surface decision; the data model supports any
reasonable rendering.

**Portfolio tabs.** The intended implementation at S111+ introduces
three tabs on the creator portfolio: Files (individual attestations),
Collections (existing closed/atomic groupings), and Series (this
spec's open/append-only groupings). Tab-level rendering semantics are
out of scope for this spec.

### §6.4 Affiliation chips at drop time

When a creator drops a file into a client surface (e.g., the Attest
flow on hipkit.net), the client MAY render an affiliation chip
indicating which series and/or collections the file already belongs
to. This is the UX motivation for the `affiliations:{content_hash}`
index (§1.5).

The read pattern is:

1. Compute `content_hash` of the dropped file.
2. `GET /affiliations/{content_hash}` — returns the full list of
   `{type, id, credential_id, added_at}` tuples (see §7 for the
   endpoint schema).
3. Render a chip per affiliation. Chips link to the corresponding
   `/c/{collection_id}` or `/s/{series_id}` short URL.
4. When the credential_id on an affiliation matches the current
   logged-in creator, the chip is rendered as "your series" / "your
   collection"; when it does not, "another creator's series /
   collection."

The affiliation chip does NOT affect the drop flow itself. It is
purely informational. A creator who sees that a file is already in
three series and two collections still drops the file normally; the
display exists to help them decide whether to add it to another
grouping.

### §6.5 Embedding and external linking

Neither the series creation record nor any series event embeds
content. Viewers of a series card retrieve member content through the
same mechanisms as they do for standalone attestations — via
`/api/proof/{member_hash}`, via the member's attested-copy hash, or
via any other retrieval mechanism the member's `proof:` record
supports. SERIES-SPEC-v1 adds no new content-retrieval surface.

External entities that want to link to a series from outside the
reference implementation SHOULD link to the short URL
`/s/{series_id}`. Deep-linking to specific series events (e.g., "this
is the link to the moment when the creator added X") is NOT
supported in v1; events are internal-ordering artifacts and do not
have their own public URLs. If per-event permalinks become
necessary in a future version, the `series_event:{event_hash}`
records are already content-addressable and could be surfaced behind
a `/se/{event_hash}` route at that time.

### §6.6 Creator attribution on the card

The series card (whether rendered on `/s/{series_id}` directly or in
a portfolio tab) MUST surface the creator credential in a
verification-compatible way:

- Display the creator's credential ID (truncated for readability;
  full hash available on hover or click).
- Display the creator's tier at series creation time (from
  `manifest.creator.tier`).
- Display the creator's public key fingerprint or a recognizable
  short form so viewers can verify the signature independently.

This matches the display posture of the collection card and of
individual proof cards. No new display rules are introduced by
SERIES-SPEC-v1.

### §6.7 Recommended read flow for external consumers

For a third-party application that wants to consume a series (e.g.,
an external viewer, an archival tool, a rendering embed):

1. `GET /api/series/{series_id}` — fetch the full series record
   including manifest and signature. Verify the signature against
   the embedded `manifest.creator.public_key`.
2. `GET /api/series/{series_id}/events` — fetch the event list
   (paginated per §7). For each event, optionally verify the event
   signature (each event is independently signed).
3. For each `series_add` event, `GET /api/proof/{member_hash}` —
   fetch the member's proof record and verify.

This flow is stateless, signature-verifiable end-to-end, and does
not require any trust in the reference implementation's KV beyond
the public-key-plus-signature model already in use for individual
proofs.

---

## §7 Wire format

SERIES-SPEC-v1 introduces three write endpoints, four read endpoints,
and one short-URL resolver. All JSON responses set
`Content-Type: application/json; charset=utf-8`. All error responses
follow the shape `{"error": "<error_code>", ...optional_fields}`. All
requests and responses use UTF-8. All timestamps are ISO-8601 with a `Z`
suffix (UTC).

**Signed payload canonicalization.** Every signed payload in this spec
is a JSON object canonicalized per RFC 8785 (JCS). The signature is
Ed25519 over `SHA-256(JCS(payload))`. Implementations MUST use the same
canonicalization and hashing behavior as the existing `register-proof`
and `register-collection-proof` handlers; mismatched canonicalization
is a known interoperability hazard and is not a new problem introduced
by this spec.

**Pagination posture.** `GET /api/series/{series_id}/events` and
`GET /api/creator/{credential_id}/series` are bounded at 500 entries
per response, newest-first. If the underlying list has more entries
than returned, the response includes `"truncated": true`. v1 does NOT
offer cursor-based continuation; clients that observe `truncated: true`
MUST tolerate the capped view. Cursor-based pagination is a candidate
for v1.1 if truncation becomes operationally common.

### §7.1 POST `/register-series`

Create a new series.

**Auth.** Authenticated via the existing `verifyAppAuth` pattern
(reference: worker.js L126). Request must carry credential-signed
application auth headers.

**Request body:**

```json
{
  "series_id": "<20-char base32-lowercase>",
  "manifest": {
    "schema_version": "hip-series-1.0",
    "issued_at": "<ISO-8601 UTC from client>",
    "title": "<string, 1–200 chars, trimmed>",
    "description": "<string, 0–2000 chars, trimmed>",
    "cover_member_hash": "<64-hex SHA-256, optional>",
    "creator": {
      "credential_id": "<64-hex>",
      "tier": 1 | 2 | 3,
      "public_key": "<base64 Ed25519 public key>"
    }
  },
  "signature": "<base64 Ed25519 over SHA-256(JCS(manifest))>"
}
```

**Validation order:**

1. Parse JSON → 400 `malformed_body` on failure.
2. Shape-check `series_id` (20-char base32-lowercase) → 400 `invalid_series_id`.
3. Pre-existence check on `series:{series_id}` → 400 `series_id_collision` if present.
4. `verifyAppAuth` on credential → 403 `credential_retired` if superseded_by is set.
5. TI ≥ 60 on credential → 403 `trust_index_below_floor`.
6. Rate-limit check (unified attest budget) → 429 `rate_limited`.
7. Manifest shape/field validation per §4.6 → 400 `invalid_manifest` or 400 `invalid_manifest_field`.
8. JCS-canonicalize manifest, SHA-256, Ed25519-verify against `manifest.creator.public_key` → 422 `invalid_signature`.
9. Write `series:{series_id}` with `status: "open"`, server-populated `created_at`, `member_count: 0`, `closed_at: null`, `last_event_at: created_at`.
10. Append to `creator_series:{credential_id}` index (non-fatal on failure).

**Success response (200):**

```json
{
  "series_id": "<20-char base32>",
  "status": "open",
  "created_at": "<ISO-8601 UTC>",
  "short_url": "https://<host>/s/<series_id>"
}
```

**Error response shape:**

```json
{ "error": "<error_code>", "detail": "<optional diagnostic string>" }
```

### §7.2 POST `/register-series-member`

Add a member to an open series.

**Auth.** Same `verifyAppAuth` pattern.

**Request body:**

```json
{
  "event": {
    "event_type": "series_add",
    "schema_version": "hip-series-event-1.0",
    "series_id": "<20-char base32>",
    "member_hash": "<64-hex SHA-256>",
    "member_type": "file",
    "added_at": "<ISO-8601 UTC from client>",
    "added_by_credential_id": "<64-hex>"
  },
  "signature": "<base64 Ed25519 over SHA-256(JCS(event))>"
}
```

Note: the signed payload is the `event` object in full. The server
computes `event_hash = SHA-256(JCS(event))` at write time.

**Validation order:**

1. Parse JSON → 400 `malformed_body`.
2. Validate `event.event_type === "series_add"` → 400 `invalid_event_type`.
3. Validate `event.member_type === "file"` → 400 `invalid_member_type` (see §1.2 forward-compat).
4. Shape-check `series_id`, `member_hash`, `added_by_credential_id` → 400 `invalid_series_id` / `invalid_member_hash` / `invalid_credential_id`.
5. Read `series:{series_id}` → 404 `series_not_found` if missing.
6. Check `status === "open"` → 400 `series_closed` if closed.
7. Check `event.added_by_credential_id === series.manifest.creator.credential_id` → 403 `not_series_creator`.
8. `verifyAppAuth` on credential → 403 `credential_retired` if superseded_by is set.
9. Read `proof:{member_hash}` → 404 `member_proof_not_found` if missing.
10. Duplicate check — scan `series_events:{series_id}` for an existing `series_add` with the same `member_hash` → 400 `member_already_in_series` if found. (Reference implementation may optimize this with a secondary index `series_members:{series_id}` — implementation detail.)
11. Rate-limit check → 429 `rate_limited`.
12. JCS-canonicalize `event`, SHA-256, Ed25519-verify against creator's public key → 422 `invalid_signature`.
13. Compute `event_hash`, write `series_event:{event_hash}`.
14. Append `{event_hash, event_type: "series_add", applied_at: server_now}` to `series_events:{series_id}`.
15. Increment `series.member_count`, update `series.last_event_at = server_now`, persist `series:{series_id}`.
16. Append `{type: "series", id: series_id, credential_id, added_at: server_now}` to `affiliations:{member_hash}` (non-fatal, dedup on tuple per §1.5).

**Success response (200):**

```json
{
  "event_hash": "<64-hex>",
  "series_id": "<20-char base32>",
  "member_hash": "<64-hex>",
  "applied_at": "<ISO-8601 UTC>",
  "member_count": <integer>
}
```

### §7.3 POST `/close-series`

Close an open series.

**Auth.** Same `verifyAppAuth` pattern.

**Request body:**

```json
{
  "event": {
    "event_type": "series_close",
    "schema_version": "hip-series-event-1.0",
    "series_id": "<20-char base32>",
    "closed_at": "<ISO-8601 UTC from client>",
    "closed_by_credential_id": "<64-hex>"
  },
  "signature": "<base64 Ed25519 over SHA-256(JCS(event))>"
}
```

**Validation order:**

1. Parse JSON → 400 `malformed_body`.
2. Validate `event.event_type === "series_close"` → 400 `invalid_event_type`.
3. Shape-check `series_id`, `closed_by_credential_id` → 400 `invalid_series_id` / `invalid_credential_id`.
4. Read `series:{series_id}` → 404 `series_not_found` if missing.
5. Check `status === "open"` → 400 `series_already_closed` if closed.
6. Check `event.closed_by_credential_id === series.manifest.creator.credential_id` → 403 `not_series_creator`.
7. `verifyAppAuth` on credential → 403 `credential_retired`.
8. JCS-canonicalize `event`, SHA-256, Ed25519-verify → 422 `invalid_signature`.
9. Compute `event_hash`, write `series_event:{event_hash}`.
10. Append `{event_hash, event_type: "series_close", applied_at: server_now}` to `series_events:{series_id}`.
11. Update `series.status = "closed"`, `series.closed_at = event.closed_at`, persist `series:{series_id}`.

**Success response (200):**

```json
{
  "event_hash": "<64-hex>",
  "series_id": "<20-char base32>",
  "status": "closed",
  "closed_at": "<ISO-8601 UTC>"
}
```

**Close events are NOT rate-limited** per §2.3 (idempotent terminal
operation, one per series).

### §7.4 GET `/s/{series_id}`

Short-URL resolver. Symmetric with `/c/{collection_id}`.

**Validation:**

1. Method is GET → else falls to bottom-of-dispatch 404.
2. Shape-check `series_id` → 400 `invalid_series_id`.
3. Read `series:{series_id}` → 404 `series_not_found`.
4. Sanity-check that the record is parseable JSON with a `status`
   field of `"open"` or `"closed"` → 404 `series_not_found` on
   malformed or unexpected state.

**Success response:** 302 redirect with `Location` header pointing
to the reference implementation's series-card page. Proposed default:

```
Location: https://<host>/series.html?id={series_id}
```

Implementations MAY choose a different landing path; the protocol
spec mandates only that the short URL resolves to a card-rendering
destination.

**HEAD method.** `GET /s/{series_id}` handlers SHOULD also accept
`HEAD` and return the same 302 Location header with no body, to
support link-checkers and crawlers. (This is a fix to the analogous
issue observed on `/c/{id}` — see S110 kickoff §0 probe diagnosis.)

### §7.5 GET `/api/series/{series_id}`

JSON read of the series creation record.

**Validation:**

1. Shape-check `series_id` → 400 `invalid_series_id`.
2. Read `series:{series_id}` → 404 `series_not_found`.

**Success response (200):** the full series record as persisted:

```json
{
  "series_id": "<20-char base32>",
  "manifest": { ... },
  "signature": "<base64>",
  "status": "open" | "closed",
  "created_at": "<ISO-8601 UTC>",
  "closed_at": null | "<ISO-8601 UTC>",
  "member_count": <integer>,
  "last_event_at": "<ISO-8601 UTC>",
  "short_url": "https://<host>/s/<series_id>"
}
```

### §7.6 GET `/api/series/{series_id}/events`

JSON read of the series event list, bounded at 500 entries, newest-first.

**Validation:**

1. Shape-check `series_id` → 400 `invalid_series_id`.
2. Read `series:{series_id}` → 404 `series_not_found`.
3. Read `series_events:{series_id}` → return empty list `[]` if missing (a series with zero events after creation — unusual but not an error).

**Success response (200):**

```json
{
  "series_id": "<20-char base32>",
  "events": [
    {
      "event_hash": "<64-hex>",
      "event_type": "series_add" | "series_close",
      "applied_at": "<ISO-8601 UTC>",
      "event": {
        "event_type": "series_add",
        "schema_version": "hip-series-event-1.0",
        "series_id": "<20-char base32>",
        "member_hash": "<64-hex>",
        "member_type": "file",
        "added_at": "<ISO-8601 UTC>",
        "added_by_credential_id": "<64-hex>",
        "signature": "<base64>"
      }
    },
    ...
  ],
  "truncated": false
}
```

The inner `event` object is the verbatim signed event as stored in
`series_event:{event_hash}`. Consumers MAY independently verify each
event's signature against the creator's public key (obtained from
`/api/series/{series_id}` → `manifest.creator.public_key`).

If the underlying `series_events:{series_id}` list has more than 500
entries, `"truncated": true` is set and the 500 most recent entries
are returned.

### §7.7 GET `/api/creator/{credential_id}/series`

JSON read of the creator's series index (§1.6), bounded at 500 entries,
newest-first.

**Validation:**

1. Shape-check `credential_id` (64-hex) → 400 `invalid_credential_id`.
2. Read trust record for credential → 404 `creator_not_found` if no trust record exists. (A well-formed credential_id that was never issued.)
3. Read `creator_series:{credential_id}` → return empty list `[]` if the creator has never authored a series.

**Success response (200):**

```json
{
  "credential_id": "<64-hex>",
  "series": [
    {
      "series_id": "<20-char base32>",
      "created_at": "<ISO-8601 UTC>",
      "status_at_write": "open",
      "series_snapshot": {
        "title": "<string>",
        "status": "open" | "closed",
        "member_count": <integer>,
        "closed_at": null | "<ISO-8601 UTC>",
        "cover_member_hash": "<64-hex, optional>"
      }
    },
    ...
  ],
  "truncated": false
}
```

The `series_snapshot` is a convenience join populated server-side by
reading each `series:{series_id}` at response time. Clients that want
the full record call `/api/series/{series_id}` per entry. Snapshots
MAY be omitted if the read budget is constrained (implementation
choice); if omitted, the field is absent rather than null, and
clients MUST fall back to individual series reads.

### §7.8 GET `/api/affiliations/{content_hash}`

JSON read of the multi-affiliation index (§1.5) for a specific content
hash.

**Validation:**

1. Shape-check `content_hash` (64-hex lowercase) → 400 `invalid_content_hash`.
2. Read `affiliations:{content_hash}` → return empty list `[]` if missing.

**Success response (200):**

```json
{
  "content_hash": "<64-hex>",
  "affiliations": [
    {
      "type": "series" | "collection",
      "id": "<20-char base32>",
      "credential_id": "<64-hex>",
      "added_at": "<ISO-8601 UTC>"
    },
    ...
  ]
}
```

The response is always 200 with an `affiliations` array, even if the
content_hash is not present as a `proof:{content_hash}` record. Per
§6.4 and the §6 design discussion, this endpoint's purpose is "list
affiliations," not "verify attestation." Clients that want to confirm
attestation call `/api/proof/{content_hash}` as a separate request.

Affiliations are returned newest-last in the underlying storage per
§1.5; this endpoint reverses to newest-first for rendering convenience.

---

## §8 Relationship to collection spec

A **collection** is a closed, atomic, signed set of members bound
together by a single creation signature at a single point in time.
Members are locked at sign time; a collection's membership cannot
grow, shrink, or change after creation. The collection's signature
covers the manifest including the full member list, so any
modification would invalidate the signature. Collections are ideal
for "here is a publication" use cases where the creator wants to
commit to a specific set of content as a unit.

A **series** is an open, append-only, creator-bound stream of
members. Members are added over time via `series_add` events, each
signed independently. The series creation signature covers only the
manifest (title, description, cover, creator) — not the membership.
Membership grows as the creator adds more events, until the series
is explicitly closed or the creator's credential is retired. Series
are ideal for "here is my ongoing thread" use cases where the
creator wants a durable heading under which to accumulate content
without committing to a final set.

**A file may belong to both a collection and one or more series
simultaneously.** Collection membership and series membership are
independent; the same `proof:{content_hash}` record may be cited by
a closed collection and by multiple open series at the same time.
The `affiliations:{content_hash}` index (§1.5) surfaces all such
co-memberships in a single read.

**Collections are not series members in v1.** Per §1.2,
`member_type` is reserved and fixed to `"file"` in v1. The spec
leaves open the possibility of a future version accepting
`member_type: "collection"`, which would allow a creator to add a
published collection as a unit to their ongoing series. This is
explicitly deferred.

**The two constructs are complementary, not competing.** A creator
may publish a collection ("Mammoth 2026") and simultaneously add
its members to an ongoing series ("Peter's 2026 Trips"). The
collection freezes the specific trip; the series aggregates the
year. Both are valid and both may render on the creator's
portfolio under separate tabs per §6.3.

---

## Document history

| Version | Date | Notes |
|---|---|---|
| v1.0-draft | 2026-04-21 | Initial draft (S110CW). All 8 sections + §3.5 tier-specific lifecycle notes + §1.6 creator→series index. |


