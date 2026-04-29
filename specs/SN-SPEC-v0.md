# HIP — Human Integrity Protocol
## SN-SPEC-v0: Steward Nodes Roadmap Specification
### v0 ROADMAP | 2026-04-29 | Pre-implementable; published to establish the path to true protocol fulfillment

---

## Status

**This document is a roadmap specification (v0).** It establishes the architectural
path from the current single-operator deployment to a federated multi-operator
Steward Node network. It is intentionally not over-specified. Concrete operational
parameters — activation thresholds, onboarding flow, software contract — lock at
**v1**, when the first willing third-party operator is in-frame.

The protocol functions correctly today without any Steward Node. This document
exists to make the path to genuine multi-operator decentralization a public,
host-facing commitment rather than implicit roadmap language.

---

## Authority and Scope

This specification derives its authority from and must remain consistent with:

- **HIP Genesis Covenant Charter v1.0** — in particular **DP-5 (Permissionless
  Proliferation)**, **DP-7 (Zero Institutional Cost)**, and **DP-8 (Protocol,
  Not Entity)**
- **HP-SPEC-v1.2** — credential mechanics; Steward Nodes do not issue
  credentials and do not change credential semantics
- **WF-SPEC-v1** — Proof Bundle wire format; Steward Nodes serve canonical
  records as written by pathway providers and the protocol layer

In any conflict between this specification and the documents above, the parent
document controls. SN-SPEC-v0 introduces no principle that contradicts them.

This specification is a companion roadmap document. It is not part of the
Genesis inscription. Its evolution does not require Charter amendment.

### What This Specification Covers

- Why Steward Nodes exist and how they complement ledger anchoring
- What a Steward Node is, in software-and-operations terms
- Activation triggers — the criteria that would cause Steward Nodes to be
  recruited and stood up
- Architecture transition path from single-operator to federated reads
- A schedule, expressed as quarterly intent
- A placeholder for the operator onboarding flow that will be defined at v1

### What This Specification Does Not Cover

- Credential mechanics or identity verification — see HP-SPEC-v1.2 and
  PATHWAY-SPEC-v1
- Ledger anchoring of individual record proofs — covered by the ledger
  anchoring strategy locked at S151CW (OpenTimestamps + Bitcoin); spec
  document forthcoming
- Pathway provider roles or T1 issuance — covered by PATHWAY-SPEC-v1
- Cryptographic primitives — see CRYPTO-SPEC-v1.1

---

## §1 Why Steward Nodes Exist

The protocol's durability claim has two distinct components.

**Proof of existence at time T** is the cryptographic guarantee that a given
record (a `proof:{content_hash}`, a `series:{id}` event, or a
`collection:{id}` manifest) existed in its observed shape at the moment it was
attested. This guarantee is provided by ledger anchoring: each record's
canonical hash is committed to a public ledger (Bitcoin via OpenTimestamps,
per the strategy locked at S151CW), and any party with the resulting proof
file plus access to a Bitcoin block explorer can verify the anchor without
trusting any HIP operator. Existing anchored proofs verify forever, even if
every HIP service disappears tomorrow.

**Ongoing record retrievability** is the operational guarantee that the
record's full body (the signed manifest, signatures, indices, related
pointers) remains fetchable on demand. Today, this is served from a single
Cloudflare KV namespace owned by a single operator. That single namespace is
sufficient for current scale and for the launch window, but it is a
single-point-of-failure for record availability. If the operator's
infrastructure goes away, anchored proofs of existence remain verifiable
against the ledger, but the full record bodies they reference would have to
be rehosted by anyone holding a copy.

**Steward Nodes provide the second guarantee at network scale.** Each
Steward Node operates an independent, synchronized copy of the canonical
record store (`DEDUP_KV` and its derived indices), and serves read queries
against its copy. Together with ledger anchoring, multi-operator Steward
Nodes turn the durability claim into a charter-honest one: anchored proofs
verify forever via Bitcoin; record retrieval federates across N independent
operators rather than depending on any single one.

Charter alignment:

- **DP-5 (Permissionless Proliferation):** any aligned organization may run
  a Steward Node. Operating a node is not gated on permission from any HIP
  authority; the node's correctness is verifiable against the ledger
  anchors.
- **DP-7 (Zero Institutional Cost):** Steward Nodes are operator-cost,
  charter-acceptable per DP-7's institutional-implementation language. The
  protocol layer remains free; institutions choosing to host nodes do so
  on their own dime, the same way pathway providers operate.
- **DP-8 (Protocol, Not Entity):** Steward Nodes are not HIP. They are
  institutional implementations of a protocol-layer contract.

---

## §2 What a Steward Node Is

A Steward Node, at v0, is defined by the read-side contract it must satisfy.
The full software/operations spec locks at v1; this section establishes the
shape.

**Operational responsibilities:**

- Operates a synchronized, read-only mirror of the canonical record store
  (`DEDUP_KV` and its derived indices: `cred_proofs:{id}`, `collection:{id}`,
  `series:{id}`, `series_event:{hash}`, `affiliations:{hash}`).
- Serves read queries against its mirror over public HTTPS endpoints
  matching the protocol layer's read API surface (`GET /api/proof/{hash}`,
  `GET /api/series/{id}`, `GET /api/collection/{id}`,
  `GET /api/affiliations/{hash}`, `GET /api/credential/{id}/attestations`,
  and the public verify endpoint).
- Synchronizes from the canonical record store via a published
  synchronization protocol (defined at v1; expected to be a periodic
  changelog-and-fetch pattern).

**Non-responsibilities:**

- A Steward Node does **not** issue credentials. Credential issuance flows
  through pathway providers (HIPVerify for T1, the protocol layer for T2/T3
  per PATHWAY-SPEC-v1).
- A Steward Node does **not** accept writes. New records are written
  through the canonical write path. Steward Nodes mirror; they do not
  originate.
- A Steward Node does **not** redefine record semantics. It serves
  bytes-identical canonical records as the protocol wrote them.

**Cost profile (rough order-of-magnitude, locked at v1):**

- **Storage:** today's `DEDUP_KV` is in single-digit MB at current
  attestation volume. At 1M lifetime attestations with average record size
  ~5 KB, total store size is ~5 GB — comfortable on commodity hosting.
- **Bandwidth:** read-heavy; bandwidth scales with verification queries.
  At T2/T3 free-tier scale plus HIPKit institutional usage, expect tens to
  hundreds of GB/month per node at launch scale.
- **Compute:** serving signed records is mostly I/O-bound; minimal compute.
  A small VPS or a Cloudflare Workers + KV deployment is sufficient.

These numbers are illustrative. The intent is to show that operating a
Steward Node is not a heavy commitment for an aligned institution, library,
research center, or technical partner.

---

## §3 Activation Triggers

Steward Node recruitment activates when **any of** the following thresholds
are met, **and** at least one willing operator is in-frame:

- **Sustained protocol traffic threshold:** ≥X attestations/week sustained
  over a rolling 4-week window, OR
- **Institutional credential threshold:** ≥Y institutional credentials
  issued (organizations relying on the protocol for material business
  process), OR
- **Third-party verification threshold:** ≥Z third-party verification
  queries/day sustained over a rolling 4-week window.

**Concrete numbers (X, Y, Z) lock at v1.** v0 deliberately does not pin
these thresholds because their right values depend on the operational
context at the time recruitment becomes warranted. Pinning numbers
prematurely would either be too low (recruiting nodes for traffic that
doesn't justify them) or too high (deferring recruitment past the point
where availability federation matters).

Triggers are not gates. The protocol does not wait for thresholds before
**accepting** a willing operator. If an institution wants to run a Steward
Node sooner, the protocol welcomes that. The thresholds describe when
recruitment moves from passive ("we'd accept a node if offered") to active
("we are seeking nodes").

---

## §4 Architecture Transition

The transition from single-operator to federated reads happens in stages.

**Stage 0 — Today (single operator).** All reads serve from the canonical
worker (`hip-tier1-worker`) backed by a single `DEDUP_KV` namespace.
Ledger anchoring (per the S151CW strategy lock) provides proof-of-existence
durability. Record retrieval is single-operator.

**Stage 1 — First Steward Node stand-up.** A first willing operator
provisions infrastructure, replicates the canonical record store via the
synchronization protocol (defined at v1), and begins serving read queries
against their mirror. The protocol's published documentation begins
referencing the Steward Node's URL alongside the canonical worker. Clients
gain optional federation: read failures against one endpoint fall back to
another.

**Stage 2 — Federation read path live.** Client surfaces (proof.html,
Portfolio, cert PDFs, third-party SDKs) implement first-responder-wins
federation across all known Steward Nodes plus the canonical worker.
Integrity check: any node returning a record whose hash mismatches the
canonical hash, or whose claim conflicts with the ledger anchor, fails
closed (the federation rejects the response and tries another node).

**Stage 3 — Recruit additional independent operators.** Three or more
independent operators (different organizations, different geographies,
different infrastructure providers) operate Steward Nodes. The single-
point-of-failure window closes meaningfully. The decentralization claim
is structurally honest.

**Stage 4 — Eventual operator portfolio.** A stable community of aligned
operators maintains the Steward Node network. Onboarding becomes routine
per the v1 onboarding flow.

**Migration path notes:**

- The synchronization protocol defined at v1 must be operator-friendly:
  pull-based (the node fetches changes from the canonical source), with a
  durable changelog the canonical operator commits to, and with
  ledger-anchored integrity checks.
- The canonical operator's role does not disappear during the transition.
  The protocol layer still has a write path; only reads federate.
- **Failure mode containment:** if a Steward Node serves a corrupt record,
  the federation must detect it via ledger-anchor mismatch or canonical-
  hash mismatch, not via trust in any node. This is the load-bearing
  property that makes Steward Nodes operate without permission from a
  central authority.

---

## §5 Schedule

The schedule below is **intent, not commitment**. Quarterly granularity
acknowledges that activation depends on real-operator availability and
real-traffic trajectory.

| Quarter | Intended outcome |
|---|---|
| 2026 Q3 | First willing Steward Node operator identified; v1 of this specification drafted (synchronization protocol locked) |
| 2026 Q4 | First Steward Node stand-up (Stage 1); replication verified end-to-end; initial federation read path drafted |
| 2027 Q1 | Federation read path live in production clients (Stage 2); two or more Steward Nodes operational |
| 2027 Q2-Q4 | Recruit additional independent operators (Stage 3); refine onboarding flow; document operator economics |
| 2028+ | Stable operator portfolio (Stage 4); routine onboarding; eventual closure of the single-point-of-failure window |

If activation triggers (§3) fire earlier than this schedule anticipates,
the schedule advances. If real-operator availability is later than the
schedule anticipates, the schedule slips. Both are acceptable. The schedule
is published so progress can be measured against it openly.

---

## §6 How to Become a Steward Node

**v0 placeholder.** The full operator onboarding flow locks at v1.

For prospective operators interested in running a Steward Node, the v0
expression of intent is:

1. Read this specification and the Charter (DP-5, DP-7, DP-8 in particular).
2. Contact the canonical operator (current contact: HIPKit support
   surface at hipkit.net).
3. Describe your organization, infrastructure intent, and operational
   commitment horizon.

A v1 onboarding flow will define:

- A formal application or registration step
- Technical preconditions (TLS posture, uptime expectations, geographic
  redundancy preferences)
- The synchronization protocol contract (canonical changelog format,
  catch-up mechanism, integrity checks)
- A directory of currently-operational Steward Nodes published at a
  canonical URL on the protocol layer
- A protocol-layer mechanism for clients to discover live Steward Nodes
- Failure-mode escalation (what happens if a Steward Node serves bad data,
  goes offline for an extended period, or otherwise diverges)

v0 deliberately does not encode any of this. The intent is to publish the
fact that the path exists, name what's TBD, and begin conversations with
candidate operators rather than pre-empt decisions that need real-operator
input.

---

## Specification Sections (Planned for v1)

1. Synchronization Protocol (canonical changelog + pull contract)
2. Operator Onboarding Flow
3. Steward Node Software Reference (recommended deployment shapes)
4. Federation Read-Path Contract (client expectations)
5. Integrity-Check Specification (ledger-anchor verification + canonical-
   hash verification)
6. Failure-Mode Escalation
7. Operator Directory Format
8. v0 → v1 Migration Notes

---

## Dependencies

| Document | Relationship |
|---|---|
| Charter v1.0 | Governing — DP-5, DP-7, DP-8 framing |
| HP-SPEC-v1.2 | Sibling — Steward Nodes mirror records produced under HP-SPEC-v1.2 semantics; do not redefine |
| WF-SPEC-v1 | Sibling — Steward Nodes serve canonical records in WF-SPEC-v1 wire format |
| PATHWAY-SPEC-v1 | Sibling — Steward Nodes do not issue credentials; pathway providers do |
| Ledger Anchoring Strategy (S151CW lock; spec doc forthcoming) | Sibling — Steward Nodes complement ledger anchoring; together provide full charter durability claim |
| INT-SPEC-v1 (future) | Sibling — Steward Node URLs surface in client integration documentation |

---

## Revision History

| Version | Date | Summary |
|---|---|---|
| v0 | 2026-04-29 | Initial roadmap publication. Establishes the path to multi-operator federation; concrete activation thresholds, synchronization protocol, and onboarding flow deferred to v1 when real-operator availability is in-frame. |

---

*This specification will be revised to v1 when at least one willing
third-party operator is in-frame and the synchronization protocol is ready
to lock. v1 is the implementation specification; v0 is the publicly-stated
roadmap commitment that the path exists.*
