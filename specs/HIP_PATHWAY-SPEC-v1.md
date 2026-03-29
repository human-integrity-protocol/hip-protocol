# HIP — Human Integrity Protocol
## PATHWAY-SPEC-v1: Issuance Pathway Governance Specification
### v1.0 STUB | 2026-03-28 | Initial Structure

---

## Status

**This document is a specification stub.** It defines the scope, structure, and
key concepts of PATHWAY-SPEC-v1. The full specification is under development.

---

## Authority and Scope

This specification is referenced by:

- **HP-SPEC-v1.2** — which defers pathway evaluation criteria, pathway states,
  Declassification governance, and contingency pathways to this document
- **HIP Genesis Covenant Charter v1.0** — which assigns the Pathway Auditor
  role responsibility for pathway evaluation and PHI monitoring oversight

### What This Specification Covers

1. **Pathway Definition and Registration** — how new issuance pathways are
   proposed, evaluated against published criteria, and registered
2. **Pathway Tiering Criteria** — the specific criteria by which proposed
   pathways are assigned to Tier 1, Tier 2, or Tier 3
3. **Pathway States** — the lifecycle states a pathway can occupy (Active,
   Under Review, Suspended, Declassified) and the transitions between them
4. **Pathway Health Index (PHI)** — the monitoring score that tracks whether
   a pathway is operating within normal parameters, including computation
   methodology and threshold definitions
5. **Declassification Process** — the governance process for downgrading or
   removing a pathway, including evidence requirements, review timelines,
   proportionality assessment, and credential impact
6. **Contingency Pathways** — fallback pathways for credentials whose primary
   pathway is suspended or declassified
7. **Pathway Operator Requirements** — technical, operational, and compliance
   requirements for entities operating issuance pathways

### What This Specification Does Not Cover

- Credential mechanics, Trust Index, key management — see HP-SPEC-v1.2
- Cryptographic primitives — see CRYPTO-SPEC-v1.1
- Behavioral signal analysis — see PFV-SPEC-v1
- Interface display rules — see INT-SPEC-v1 (future)

---

## Key Concepts (Preview)

### Issuance Pathway

An issuance pathway is a defined method by which a human identity is verified
and a HIP credential is issued. Each pathway has:

- A **tier assignment** (1, 2, or 3) reflecting its assurance level
- A **pathway operator** responsible for its operation
- A **PHI score** reflecting operational health
- A **pathway state** indicating its current status

### Current Pathways

| Pathway | Tier | Operator | Method |
|---|---|---|---|
| Government ID Verification | 1 | hipverify.org | Document scan + liveness check via Didit |
| Peer Vouch | 2 | Protocol-native | Existing credential holder vouches for new human |
| Device Biometric | 3 | Protocol-native | WebAuthn platform authenticator |

### Pathway Health Index (PHI)

PHI is a monitoring score that tracks whether a pathway is operating within
normal parameters. It is computed from:

- Fraud detection rates (flagged credentials / total issued)
- Sybil resistance metrics (duplicate detection effectiveness)
- Operational uptime and response times
- PFV anomaly rates among credentials issued through the pathway

PHI is referenced in HP-SPEC-v1.2 as a factor in credential Trust Index
computation. When a pathway's PHI falls below defined thresholds, it triggers
review by the Pathway Auditor.

### Pathway States

- **Active** — operating normally, issuing credentials
- **Active — Under Review** — operating but under Auditor scrutiny
- **Suspended** — temporarily halted; existing credentials remain valid but
  affected (Trust Index multiplier applied per HP-SPEC-v1.2)
- **Declassified** — permanently removed; credentials may be migrated to
  contingency pathways

### Declassification

Declassification is the most severe pathway action. It requires:

1. Evidence of systematic failure or compromise
2. Proportionality assessment (impact on existing credential holders)
3. Defined timeline with advance notice
4. Contingency pathway availability for affected credentials
5. Auditor consensus (not unilateral)

Declassification is irreversible. A declassified pathway may be re-proposed
as a new version under fresh evaluation.

### Tiering Criteria

Tier assignment is based on:

- **Verification strength** — how strongly the pathway confirms human identity
- **Sybil resistance** — how effectively the pathway prevents one human from
  obtaining multiple credentials
- **Durability** — how resistant the pathway is to technological obsolescence
- **Accessibility** — cost, geographic availability, device requirements
- **Independence** — degree of reliance on third-party infrastructure

Tier 1 requires the strongest verification and Sybil resistance.
Tier 3 has the lowest barrier but the weakest assurance.

---

## Specification Sections (Planned)

1. Pathway Registration Protocol
2. Tiering Criteria (Detailed)
3. Pathway State Machine
4. PHI Computation and Thresholds
5. Declassification Governance
6. Contingency Pathway Framework
7. Pathway Operator Compliance
8. Existing Pathway Profiles
9. Pathway Proposal Template

---

## Dependencies

| Document | Relationship |
|---|---|
| HP-SPEC-v1.2 | Parent — defers pathway criteria, states, and Declassification to this document |
| CRYPTO-SPEC-v1.1 | Sibling — cryptographic requirements for pathway operators |
| Charter v1.0 | Governing — Pathway Auditor role, PHI monitoring oversight |
| PFV-SPEC-v1 | Sibling — PFV anomaly rates feed into PHI computation |

---

## Revision History

| Version | Date | Summary |
|---|---|---|
| v1.0-stub | 2026-03-28 | Initial structure and scope definition |

---

*This stub will be replaced by the complete PATHWAY-SPEC-v1 specification.
Pathway evaluation criteria will be published before any new pathways beyond
the three genesis pathways are accepted.*
