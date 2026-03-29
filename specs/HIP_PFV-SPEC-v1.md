# HIP — Human Integrity Protocol
## PFV-SPEC-v1: Propagation Fingerprint Vector Specification
### v1.0 STUB | 2026-03-28 | Initial Structure

---

## Status

**This document is a specification stub.** It defines the scope, structure, and
key concepts of PFV-SPEC-v1. The full specification is under development. When
complete, it will be hash-declared and anchored before activation, as required
by Phoenix Firewall clause PF-9.

---

## Authority and Scope

This specification is referenced by:

- **HP-SPEC-v1.2** — which defers PFV signal formulas, analysis triggers,
  and Pathway Health Index scoring to this document
- **HIP Genesis Covenant Charter v1.0** — which requires PFV transparency
  (PF-9), public formula vectors, and hash-declared specifications before
  activation

### What This Specification Covers

1. **PFV Signal Definitions** — the specific behavioral signals extracted from
   attestation patterns that form the Propagation Fingerprint Vector
2. **PFV Analysis Formulas** — the mathematical formulas by which individual
   attestation behavior is analyzed for anomaly detection
3. **Signal Annotation Stages** — the T0, T1, and T2 analysis stages referenced
   in the Charter, including timing, computation, and appending rules
4. **Credential Review Triggers** — the signal patterns and thresholds that
   trigger automatic credential review (referenced in HP-SPEC-v1.2 §8)
5. **Historical Content Analysis** — period designations and methodology for
   analyzing content created before HIP existed, ensuring honest treatment
   without retroactive judgment (Charter requirement)
6. **PFV Version Management** — how PFV updates are proposed, anchored,
   activated, and how transition periods are handled

### What This Specification Does Not Cover

- Credential mechanics, Trust Index computation, tier definitions — see HP-SPEC-v1.2
- Cryptographic primitives, key management, signature schemes — see CRYPTO-SPEC-v1.1
- Issuance pathway evaluation, Declassification, PHI monitoring — see PATHWAY-SPEC-v1
- Interface display rules, Proofcard rendering — see INT-SPEC-v1 (future)

---

## Key Concepts (Preview)

### Propagation Fingerprint Vector (PFV)

A multi-dimensional behavioral signature derived from a credential's attestation
history. The PFV captures temporal patterns, classification distributions,
volume characteristics, and cross-reference signals. It is computed from public
attestation data and is fully reproducible by any observer with access to the
ledger.

### Signal Annotations

Each attestation record carries signal annotations appended at three stages:

- **T0 (Registration)** — computed at proof registration time
- **T1 (Short-term)** — computed within hours of registration
- **T2 (Long-term)** — computed after a stabilization period

Signal annotations are append-only. Once written, they are never modified.

### Anomaly Detection

PFV analysis identifies behavioral patterns inconsistent with genuine human
creative output. Anomalies may include: bulk attestation patterns, temporal
clustering inconsistent with human work, classification distributions that
diverge from established baselines, and content fingerprint patterns suggesting
automated generation.

Anomaly detection triggers credential review, not automatic invalidation.
Human review is required before any credential state change.

### PFV Transparency (PF-9 Compliance)

Per Phoenix Firewall clause PF-9:
- All PFV formulas are public
- New PFV versions must be hash-declared as specifications before activation
- No black-box scoring mechanisms are permitted
- Any Steward introducing opaque scoring ceases to operate HIP

---

## Specification Sections (Planned)

1. Signal Taxonomy
2. Vector Computation
3. Annotation Pipeline (T0 / T1 / T2)
4. Anomaly Thresholds and Review Triggers
5. Historical Content Methodology
6. PFV Version Governance
7. Reference Implementation Notes
8. Test Vectors

---

## Dependencies

| Document | Relationship |
|---|---|
| HP-SPEC-v1.2 | Parent — defers PFV formulas to this document |
| CRYPTO-SPEC-v1.1 | Sibling — cryptographic primitives used in signal computation |
| Charter v1.0 | Governing — PF-9 transparency requirement |
| PATHWAY-SPEC-v1 | Sibling — PHI scoring uses PFV signals |

---

## Revision History

| Version | Date | Summary |
|---|---|---|
| v1.0-stub | 2026-03-28 | Initial structure and scope definition |

---

*This stub will be replaced by the complete PFV-SPEC-v1 specification.
The full specification will be hash-declared and publicly anchored before
any PFV analysis is activated in production.*
