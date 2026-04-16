# HIP — Human Integrity Protocol
## HP-SPEC-v1.3: HUMAN-PROOF Credential Mechanics Specification
### v1.3 REVISION | 2026-04-14 | Tier 3 Provisional Ceiling (PFV-gated)

---

## Authority and Status

This specification derives its authority from and must remain consistent with:

- **Document 3: HUMAN-PROOF Scope Statement** — the governing principles document
  from which all credential mechanics are derived
- **Document 2: Attestation Architecture Decision** — the architectural decisions
  governing how attestations are made and recorded
- **Document 1: HIP Core Definitions** — the classification system and definition
  of human-origin content
- **HIP Genesis Covenant Charter v1.0** — the covenant document

In any conflict between this specification and the documents listed above,
the parent document controls. This specification may not introduce principles
that contradict those documents. Where this specification addresses cases not
covered by those documents, it may propose extensions, provided those extensions
are consistent with the governing principles established there.

This specification is a companion document. It is not part of the Genesis
inscription. Its evolution does not require Charter amendment and does not
trigger fork conditions. It is versioned separately and updated as the
implementation landscape evolves.

---

## Purpose

HP-SPEC-v1 specifies the mechanics by which HUMAN-PROOF credentials are issued,
weighted, monitored, and determined through criteria-based review. It translates the governing principles
established in Document 3 into the precise formulas, thresholds, process
definitions, and behavioral rules that any conforming implementation must apply.

Document 3 defined *what* a HUMAN-PROOF credential is and is not. This
specification defines *how it works* — the numbers, the processes, the
failure modes, and the implementation requirements.

---

## Scope

This specification covers:

- HUMAN-PROOF credential structure and lifecycle states
- Credential issuance mechanics at each tier, including point-of-use liveness
  requirements at issuance
- The Trust Index: its components, initial values by tier, accumulation events,
  and decay rules including PHI-linked decay
- Classification access gating: the Trust Index thresholds that govern which
  HIP classifications a credential may assert at attestation time
- Rate limiting architecture: attestation rate limits and vouching rate limits
- Point-of-use liveness at attestation time: device attestation path, fallback
  behavioral indicators, and liveness failure handling
- Credential portability mechanics: device migration, pathway upgrade, and
  key rotation
- Credential Compromise Determination: compromise types, reporting mechanisms,
  determination process, timelines, and outcomes

This specification explicitly defers:

- The criteria by which proposed issuance pathways are evaluated and tiered,
  the PHI signal definitions and scoring, the transition thresholds between
  pathway states, and the governance process for Declassification — these
  belong to PATHWAY-SPEC-v1
- The wire format of the Proof Bundle and the specific fields in which
  credential and liveness data are encoded — these belong to WF-SPEC-v1
- The PFV vector formulas by which individual attestation behavior contributes
  to PFV analysis, and the specific signals that contribute to Pathway Health
  Index scoring — these belong to PFV-SPEC-v1
- The cryptographic primitives used for credential signing and content hashing
  — these belong to CRYPTO-SPEC-v1
- The specific external device attestation APIs (Apple, Google, and successors)
  and their contingency pathways — these are documented in PATHWAY-SPEC-v1 as
  monitored external dependencies

---

## Definitions Used in This Specification

**HUMAN-PROOF Credential:** The instrument by which a living human actor binds
themselves to HIP attestations. A credential consists of a public/private
key pair and a ledger-side record that includes the issuance pathway,
issuance timestamp, Trust Index state, and any compromise or migration records.

**Trust Index (TI):** The continuously updated numerical value associated
with a credential on the ledger, representing the combined weight of the
credential's issuance assurance and accumulated behavioral history. TI is
an internal protocol instrument — a Sybil-resistance and weighting mechanism
that governs how the protocol treats attestations internally and how they are
weighted in PFV analysis. TI is not exposed to verifiers as a public score
or ranking. It is not a measure of how human someone is. Every credentialed
human is equally human. TI measures only the protocol's accumulated confidence
in the credential as an instrument — how hard it would be to fake its history,
and how consistently it has behaved. A low TI human and a high TI human
are equally entitled to attest their work honestly. The protocol records
both claims. It does not rank the humans.

**IssuanceWeight:** The component of the Trust Index derived from the
credential's issuance pathway. Established at issuance based on tier.
Subject to PHI-linked decay. Not subject to inactivity decay.

**BehavioralScore:** The component of the Trust Index accumulated from
the credential holder's on-ledger attestation behavior over time. Subject
to inactivity decay. Not subject to PHI-linked decay.

**Active Credential Floor:** The minimum Trust Index value a credential
must hold to assert any creator-attested attestation category. A single,
low threshold applies equally to all tiers and all categories — there
is no separate threshold for Complete Human Origin versus Human Origin
Assisted versus Human-Directed Collaborative. The Floor's sole purpose is to ensure a brand-new credential
has demonstrated a minimal behavioral presence before making its first
strong claim. It is not a measure of creative output, a barrier to low-output
creators, or a quality threshold. Any living human with a valid credential
and a small number of prior attestations clears it. Above the Floor,
the category a creator may assert is determined entirely by the
honest truth of how they made their work — not by how much work they have
made, how fast they make it, or what tier their credential was issued under.

**Liveness Attestation:** A cryptographic or behavioral signal, produced at
the moment of credential use, that indicates a living human was present at
the device and actively initiating the attestation event.

**Pathway Health Index (PHI):** The signal score assigned to each approved
issuance pathway, indicating whether that pathway is operating within normal
parameters. Defined in PATHWAY-SPEC-v1. Referenced in this specification
for its effects on IssuanceWeight.

**Vouching:** The act by which a Tier 1 credentialed human attests that a new
credential applicant is a living human, enabling credential issuance through
the Tier 2 pathway.

**Compromise Event:** A record appended to a credential's ledger entry when
the credential is found to have been stolen, fraudulently obtained, or used
for systematic false attestation. Permanently visible.

**Credential Lifecycle State:** The operational status of a credential at any
point in time: Active, Active — Under Review (Algorithmic), Suspended
(Under Review), Invalidated, or Withdrawn by Holder.

---

## Credential Architecture Overview

A HUMAN-PROOF credential is, at its core, a cryptographic key pair whose
private key is held exclusively by a verified living human actor, and whose
public key is registered on the HIP ledger alongside a record that specifies
how the human's identity was verified, what that verification established,
and how the credential has behaved since issuance.

The credential's standing on the ledger has two components that evolve
independently: the IssuanceWeight, which reflects the assurance provided
by the pathway used to obtain the credential, and the BehavioralScore,
which reflects the history of honest, consistent attestation accumulated
since issuance. Together they form the Trust Index, which is the measure
the protocol uses to determine what the credential may claim.

This architecture means that a credential's value is not fixed at issuance.
A Tier 3 credential that has been used consistently and honestly for two years
may carry substantially more total TI than a Tier 2 credential that has
barely been used. The pathway is the starting point. The behavior is the
record. Both are permanently visible, and both matter.

---

## HUMAN-PROOF Credential Structure

Every HUMAN-PROOF credential has an associated ledger record that contains,
at minimum:

**Credential Identifier:** A unique, ledger-assigned identifier. This is
the public-facing reference used in Proof Bundles to identify which
credential made an attestation. It does not expose the credential holder's
identity unless the holder chooses to make that association public.

**Public Key:** The credential's public key, used to verify the cryptographic
signatures on attestations made under this credential. The corresponding
private key is held exclusively by the credential holder and must never be
transmitted or stored outside the holder's secure device environment.

**Issuance Record:** The issuance pathway used to obtain the credential,
the tier assignment of that pathway at the time of issuance, the pathway
version, and the issuance timestamp. If the credential has been re-verified
through a subsequent pathway, all re-verification records are appended in
chronological order. No issuance record is ever deleted or overwritten.

**Trust Index Value:** The current TI value, maintained by the protocol and
updated as events occur. Not user-settable. Composed of IssuanceWeight
and BehavioralScore as specified below.

**Credential Lifecycle State:** The current operational state of the
credential: Active, Active — Under Review (Algorithmic), Suspended
(Under Review), Invalidated, or Withdrawn by Holder. Transitions
between states are logged with timestamps.

**Vouching Record (Tier 2 credentials only):** The credential identifier
of the vouching credential(s) and the vouching timestamp(s). This record
creates the accountability linkage described in Document 3.

**Compromise Record (if applicable):** Any compromise events appended to
this credential, including the type of compromise, the timestamp of the
record, and the determination outcome. These records are permanent and
publicly visible.

**Key Rotation Records (if applicable):** Any history of key rotation events,
each referencing the predecessor key and the rotation timestamp. The chain
of identity is maintained through rotation.

---

## Credential Lifecycle States

Every credential is in exactly one of the following states at all times:

**Active:** The credential is in normal operation. Its holder may use it
to make attestations subject to their current Trust Index standing.
Classification access gating applies. Rate limits apply.

**Active — Under Review (Algorithmic):** PFV signals have triggered
algorithmic review of the credential. The credential remains Active —
the holder may continue to make attestations. However, all attestations
made during this period carry the "Under Review — Algorithmic" notation
in the Proof Bundle, visible to verifiers. The reviewing body has 10
business days to assess the algorithmic flag and either escalate to
Suspended or clear the review. If not escalated within the deadline,
the credential returns to standard Active state.

**Suspended — Under Review:** A compromise report has been filed and
accepted for determination, or an algorithmic flag has been escalated
following human review. The credential may not be used to make new
attestations during the suspension period. Existing attestations are not
altered. The determination timeline defined in this specification applies.

**Invalidated:** Determination has confirmed a compromise. The credential
may not be used for new attestations. All prior attestations stand on
the ledger with appropriate compromise flags. Trust Index collapses to
zero and is permanently non-restorable on this credential. The holder
may apply for a new credential that begins a fresh TI history from zero.

**Withdrawn by Holder:** The credential holder has voluntarily withdrawn
their credential from active use. No new attestations may be made under
this credential. Prior attestations stand on the ledger unaltered. The
withdrawal record is permanent and publicly visible. A holder who
subsequently wishes to use HIP may apply for a new credential.

State transitions are irreversible except for: Active — Under Review
(Algorithmic) -> Active (when cleared within 10-day assessment), and
Suspended -> Active (when determination concludes with no confirmed
compromise).

---

## Credential Issuance Mechanics

### Tier 1 — High-Assurance Issuance

Tier 1 pathways require verification against an authoritative external
record of human existence: a government-issued identity document, a
recognized institutional affiliation with its own identity verification
process, or an approved equivalent proof-of-personhood system. The
specific pathways approved at Tier 1 are defined and maintained by
PATHWAY-SPEC-v1.

**Issuance process:** The credential applicant submits to the verification
process defined for the specific Tier 1 pathway they are using. Upon
successful verification, the pathway issues a credential with the
initial IssuanceWeight defined in this specification for Tier 1. The
verification acts attest that a specific, externally verifiable human
identity corresponds to this credential.

**Initial IssuanceWeight (Tier 1):** 400

**Initial Trust Index (Tier 1):** 400 (IssuanceWeight: 400 + BehavioralScore: 0)

**Point-of-use liveness at issuance:** All issuance events require a
liveness confirmation at the moment of issuance. For Tier 1 pathways
conducted through a device-capable interface, this is a device-attested
liveness signal as defined in the Point-of-Use Liveness section below.
For Tier 1 pathways conducted in-person or through institutional processes
with supervised presence, the institutional process itself satisfies the
liveness requirement, and this must be documented in the pathway's
PATHWAY-SPEC-v1 entry.

**Pseudonymity:** A Tier 1 credential does not expose the verified identity
to the ledger. The issuance record confirms that Tier 1 verification was
completed and which pathway version was used. The association between the
credential and the verified identity is held by the pathway provider, not
recorded on the public ledger, unless the credential holder explicitly
chooses to make that association public.

---

### Tier 2 — Vouched Issuance

Tier 2 pathways use peer vouching: an existing Tier 1 credentialed
human attests that a new credential applicant is a living human known
to them. This pathway operates without external infrastructure dependencies
beyond the vouching credential holder's own standing.

**Issuance process:** The credential applicant is vouched for by a Tier 1
credential holder who meets the vouching eligibility requirements defined
in this specification. The vouching credential holder executes a signed
vouching transaction. Upon receipt of a valid vouch from an eligible
Tier 1 credential, the applicant's credential is issued.

**Initial IssuanceWeight (Tier 2):** 50

**Initial Trust Index (Tier 2):** 50 (IssuanceWeight: 50 + BehavioralScore: 0)

**Vouching eligibility requirements:**
A credential holder is eligible to vouch if:
- Their credential is a Tier 1 credential in Active lifecycle state
- Their current Trust Index is at or above 200
- They have not exceeded the vouching rate limits defined in this specification
- They have no unresolved compromise flags

**Tier 1 restriction:** Only Tier 1 (Government ID) credential holders
may vouch for new Tier 2 credentials. This restriction ensures that every
vouched credential is backed by a credential holder whose own identity
was verified against an authoritative external record. Tier 2 and Tier 3
credential holders may not vouch regardless of their Trust Index.

**Single-vouch sufficiency:** One valid vouch from an eligible Tier 1
credential is sufficient to trigger issuance. Additional vouches may be
submitted and are recorded in the credential's vouching record, providing
additional context to verifiers.

**Vouch chain independence:** A credential may not vouch for a credential
that vouched for it, or that was vouched for by a credential in the
same vouch chain within four degrees of separation. This prevents closed
vouching loops from manufacturing TI networks.

**Vouching accountability:** The vouching credential holder's Trust Index
is affected by the subsequent behavior of vouched credentials, as defined
in the TI Accumulation and Decay section below. This accountability is
the structural mechanism by which the protocol makes Tier 2 meaningful
rather than trivially gameable.

**Point-of-use liveness at issuance:** Both the applicant and the vouching
credential holder must complete liveness confirmation at the moment of
the vouching transaction where device attestation is available. Where
device attestation is unavailable for either party, the fallback behavioral
liveness indicators apply.

---

### Tier 3 — Biometric-Presence Issuance

Tier 3 pathways use biometric liveness attestation via the applicant's
own device or synced passkey manager. The pathway establishes that a
live human was physically present and completed a biometric check at
the moment of credential issuance. Tier 3 claims **biometric presence**,
not biometric uniqueness — it does not attempt to prevent one human
from holding multiple Tier 3 credentials across devices or services.
Sybil resistance for Tier 3 is provided by behavioral controls (Trust
Index ceiling, lifetime attestation cap, IP rate limiting) and, when
operational, by PFV cross-credential correlation.

Tier 3 is the most accessible pathway — it requires no external
identity documents and no existing credential holder — but carries
the lowest initial assurance weight.

**Issuance process:** The credential applicant initiates issuance through
a HIP-conforming client application on a device capable of hardware-attested
liveness. The application initiates a server-side registration flow:

1. The client requests a registration challenge from the HIP worker
   (POST /tier3/challenge). The server generates a cryptographic
   challenge (32 random bytes) bound to a session ID and the
   requester's IP hash. The session has a 5-minute TTL.
2. The client invokes the WebAuthn credential creation ceremony
   using the server-issued challenge. The device's secure hardware
   (Touch ID, Face ID, Windows Hello, or equivalent) performs a
   biometric check and produces a signed attestation.
3. The client submits the WebAuthn attestation to the server
   (POST /tier3/register) along with the session ID, credential ID,
   attestation object, client data JSON, and public key.
4. The server validates the session, verifies the IP matches, confirms
   the challenge, and checks the WebAuthn ceremony type. Upon
   successful validation, the server issues a registration token.
5. The client creates the credential locally using the server-issued
   token as proof of valid registration.

**IP rate limiting:** The server enforces a maximum of 2 Tier 3
credential registrations per network address per 24-hour period. This
prevents bulk credential farming from a single location while allowing
legitimate household or shared-network scenarios.

**Initial IssuanceWeight (Tier 3):** 10

**Initial Trust Index (Tier 3):** 10 (IssuanceWeight: 10 + BehavioralScore: 0)

**Rationale for low initial weight:** Biometric-presence attestation
confirms that a live human completed a biometric check, but it does
not establish identity or uniqueness. The same human may create
multiple Tier 3 credentials on different devices, and a willing
human-accomplice may perform biometric checks on behalf of a
credential farmer. The low initial weight reflects this honest
assessment. Sybil defense at Tier 3 is structural, not issuance-gated:

- **Trust Index ceiling (60):** Tier 3 credentials cannot exceed
  TI 60 regardless of BehavioralScore, bounding the influence any
  single Tier 3 credential can carry.
- **Lifetime attestation cap (50):** Each Tier 3 credential is
  limited to 50 OriginalAttestation proof registrations, bounding
  total utility.
- **IP rate limiting (2/24h):** Bounds credential farming velocity
  from any single network address.
- **PFV correlation (future):** When PFV-SPEC-v1 is operational,
  cross-credential behavioral correlation will detect coordinated
  Tier 3 farming. Until then, the ceiling + cap provide a
  conservative upper bound on Tier 3 weight in the ecosystem.

A Tier 3 credential holder who uses the protocol consistently and
honestly can reach TI 60 through accumulated BehavioralScore. To
exceed TI 60, the holder must upgrade to Tier 1 or Tier 2.

**Point-of-use liveness at issuance:** The issuance process is itself a
device-attested liveness event. No separate liveness confirmation is
required at issuance beyond what the Tier 3 process entails.

**Device or passkey binding:** A Tier 3 credential is bound to the
device or passkey manager that performed the biometric check at
issuance. On platforms with synced passkey infrastructure (e.g.,
iCloud Keychain), the WebAuthn credential may be available across
the user's synced devices — this is expected and permitted. The
credential's attestation format (`fmt`) may be `"none"` when a
synced passkey manager handles the ceremony rather than device-bound
secure hardware. Cross-device portability via QR transfer remains
available as an alternative mechanism.

**Pseudonymity:** Tier 3 establishes device-level liveness, not identity.
The ledger record confirms that Tier 3 issuance was completed; it does not
record which device, which biometric, or which individual was involved.

---

## The Trust Index

### Definition and Purpose

The Trust Index is the ledger-maintained numerical value associated with
every active HUMAN-PROOF credential. It is the mechanism by which the
protocol operationalizes Document 3's governing principle of credentialed
claim under economic accountability.

TI is not an external score or rating. It is a protocol-internal capability
register. A creator with a higher TI has greater capability on the ledger —
access to stronger classification claims, higher weight given to their
attestations in PFV analysis, and greater vouching authority. This
capability is earned through behavior and staked on continued honest use.

TI has a defined scale of 0 to 1000. It is never negative. Values above
1000 are not achievable through any combination of legitimate accumulation
events. TI is an integer value; fractional values are rounded to the
nearest integer at each update event.

### Components

**Trust Index = IssuanceWeight + BehavioralScore**

These two components evolve under different rules and are maintained
separately on the ledger, though they are summed to produce the current
TI value. The separation matters for two reasons: it allows verifiers
to assess the composition of a credential's TI (how much is issuance
assurance vs. earned history), and it ensures that PHI-linked decay to
IssuanceWeight does not erase earned behavioral history.

**IssuanceWeight** is established at the time of credential issuance based
on the tier of the pathway used. It is subject to PHI-linked decay when
the issuance pathway degrades. It is not subject to inactivity decay.
It can be upgraded — but never downgraded except through PHI-linked decay
— when a credential holder re-verifies through a higher-tier pathway.

**BehavioralScore** is zero at the time of credential issuance for all tiers.
It accumulates through legitimate on-ledger attestation behavior over time.
It is subject to inactivity decay as defined below. It is not subject
to PHI-linked decay. BehavioralScore has no independent ceiling. The
maximum achievable TI is 1000, enforced by TI = min(1000, IssuanceWeight
+ BehavioralScore). A Tier 3 credential with IssuanceWeight of 10 may
accumulate a BehavioralScore of 990, reaching the same TI ceiling as
any Tier 1 credential.

### Initial Trust Index Values by Tier

| Tier | Initial IssuanceWeight | Initial BehavioralScore | Initial TI |
|------|----------------------|------------------------|------------|
| Tier 1 | 400 | 0 | 400 |
| Tier 2 | 50 | 0 | 50 |
| Tier 3 | 10 | 0 | 10 |

### IssuanceWeight Upgrade on Re-Verification

When a credential holder re-verifies through a pathway whose tier assigns
a higher IssuanceWeight than their current IssuanceWeight, the IssuanceWeight
is updated to the higher value. The BehavioralScore is unaffected.

When a credential holder re-verifies through a pathway whose tier assigns
an equal or lower IssuanceWeight than their current IssuanceWeight, the
IssuanceWeight is not changed. Re-verification records the new pathway
in the Issuance Record for provenance purposes even when no weight upgrade
results.

A credential holder whose pathway has entered Declassified state and
whose IssuanceWeight has consequently decayed to zero may restore their
IssuanceWeight by re-verifying through an Active pathway of any tier.
Upon re-verification, IssuanceWeight is set to the initial value for
the new pathway's tier, as if newly issued through that tier.

### Trust Index Formula

**TI = min(1000, IssuanceWeight + BehavioralScore)**

The ceiling of 1000 applies to the sum, not to either component independently.
BehavioralScore has no independent ceiling. A Tier 3 credential with
IssuanceWeight of 10 and a long, clean behavioral history may accumulate
a BehavioralScore of 990, reaching the TI ceiling of 1000 — the same
maximum standing as any Tier 1 credential.

IssuanceWeight is a head start. It determines where a credential begins
and how quickly it reaches meaningful standing. It is not a permanent
structural advantage. A credential that was issued through device biometric
and has been used honestly for years stands on equal terms with a
credential issued through government ID that has barely been used.
The ledger does not permanently discount the human who started without
institutional backing.

**Tier 3 provisional ceiling (v1.3).** Pending the operational readiness
of PFV-SPEC-v1 and the Pathway Health Index, Tier 3 credentials are
subject to a provisional TI ceiling defined in the Tier 3 Provisional
Ceiling section. The formula above describes the unconstrained
relationship between IssuanceWeight, BehavioralScore, and Trust Index;
the Tier 3 Provisional Ceiling section specifies a clamp on the
effective TI value of Tier 3 credentials that applies for all
verification and attestation-gating purposes until the removal
condition defined in that section is met.

### Trust Index Accumulation Events

The following events cause BehavioralScore to increase. All increments
apply to the credential that made the attestation unless otherwise noted.
Rate limits apply to all accumulation events — no accumulation event
can be artificially triggered outside the rate limits defined in this
specification.

**Contemporaneous attestation (device liveness verified):**
A valid attestation submitted within 24 hours of the attested content's
publication date, with a device-attested liveness signal confirmed at
the moment of signing.
BehavioralScore increment: **+5**

**Contemporaneous attestation (fallback behavioral liveness):**
A valid attestation submitted within 24 hours of the attested content's
publication date, where device attestation was unavailable and fallback
behavioral liveness indicators were used instead.
BehavioralScore increment: **+3**

**Contemporaneous attestation (liveness unverified):**
A valid attestation submitted within 24 hours of the attested content's
publication date, where neither device attestation nor adequate behavioral
indicators were present.
BehavioralScore increment: **+1**
Note: liveness-unverified attestations are automatically flagged for
PFV review per the PFV trigger model.

**Retroactive attestation — short delay (>24 hours, ≤30 days):**
A valid attestation submitted more than 24 hours after publication but
within 30 days of the attested content's publication date, regardless
of liveness verification status.
BehavioralScore increment: **+2**

**Retroactive attestation — long delay (>30 days):**
A valid attestation submitted more than 30 days after the attested
content's publication date, regardless of liveness verification status.
BehavioralScore increment: **+1**

**Vouching — sustained positive outcome:**
Awarded to the vouching credential holder when a Tier 2 credential
they vouched for reaches 90 days of Active status with no compromise
flags and at least 5 attestations on the ledger.
BehavioralScore increment to voucher: **+3**

No BehavioralScore increment is awarded to a vouching credential holder
at the time of the vouch itself. The increment is earned when the vouched
credential's subsequent behavior justifies it.

### Trust Index Decay Rules

#### Inactivity Decay

If a credential makes no new attestations within a 30-day period, its
BehavioralScore decreases by **2** at the end of that 30-day period.
This decay continues for each consecutive 30-day period of inactivity.

BehavioralScore has a floor of **0**. It cannot be reduced below zero
by inactivity decay.

IssuanceWeight is not subject to inactivity decay.

**Rationale:** TI reflects a current relationship with the protocol, not
just historical activity. Inactivity decay is modest — a credential that
has accumulated 200 BehavioralScore points and then goes completely
inactive will not fall below its original issuance standing for many
years. But it ensures that dormant credentials with high TI from distant
activity are not equivalent in weight to actively engaged credentials
with the same accumulated score.

#### Negative Behavioral Events

**Bad vouch — vouched credential confirmed Type B (fraudulently obtained):**
The vouch enabled a fraudulent credential to exist. Whether the voucher
was complicit or merely negligent cannot always be established from
outcome alone — but the outcome is the same: a fake credential entered
the protocol because a credentialed human allowed it through. The voucher's
accountability for that outcome is the structural mechanism by which
Tier 2 vouching carries meaningful weight.
BehavioralScore penalty to vouching credential: **−15**

**Bad vouch — vouched credential confirmed Type A (stolen, then misused):**
The vouch was honest. The credential was legitimately issued to a real
human whose credential was subsequently stolen by an unauthorized actor.
The voucher correctly verified a genuine human. The theft is not the
voucher's failure.
BehavioralScore penalty: **none**

**Bad vouch — vouched credential confirmed Type C (real human, systematic
false attestation):**
The person vouched for is a real human who chose to misuse their credential.
The voucher correctly verified their humanity. The voucher cannot be held
responsible for a genuine human's subsequent dishonest choices.
BehavioralScore penalty: **none**

The bad-vouch penalty applies in exactly one situation: a vouch that
enabled a fraudulent credential to exist. This is the situation the
vouching accountability model is designed to prevent. The penalty is
a downstream output of the Credential Compromise Determination process —
when a Type B outcome is confirmed and a vouching credential was involved,
the penalty applies automatically without a separate proceeding.

#### PHI-Linked IssuanceWeight Decay

The Pathway Health Index (PHI) monitors the integrity of each approved
issuance pathway. When a pathway's PHI degrades, the IssuanceWeight
conferred by that pathway degrades in proportion. This decay is applied
to the IssuanceWeight of all credentials issued through the affected
pathway, regardless of when those credentials were issued. The BehavioralScore
is unaffected.

**Watch state entry:**
When a pathway transitions from Active to Watch state, the IssuanceWeight
of all credentials issued through that pathway (or the affected pathway
version, as specified in PATHWAY-SPEC-v1) is multiplied by **0.75**.
This reduction is applied once at the moment of Watch transition. It
is not applied again for each month the pathway remains in Watch state.

Example: A Tier 1 credential with IssuanceWeight of 400 issued through
a pathway that subsequently enters Watch state has its IssuanceWeight
updated to 300 (400 × 0.75, rounded to nearest integer). If the pathway
subsequently exits Watch state and returns to Active state (through
remediation), the IssuanceWeight is restored to the full 400.

**Declassified state entry:**
When a pathway transitions from Watch to Declassified state, the
IssuanceWeight of all credentials issued through the affected pathway
version is reduced to **0**. This reduction is applied at the moment
the Declassification is confirmed through the governance process defined
in PATHWAY-SPEC-v1.

IssuanceWeight of 0 persists unless and until the credential holder
re-verifies through a currently Active pathway. Upon re-verification,
IssuanceWeight is set to the initial value for the new pathway's tier.

**Restoration:**
If a pathway in Watch state is remediated and returned to Active state,
all IssuanceWeight reductions applied at Watch entry are reversed.
Credentials that had their IssuanceWeight reduced at Watch entry have
it restored to its pre-Watch value. This restoration is automatic and
does not require any action by the credential holder.

Watch-to-Active restoration does not apply to pathways that progressed
to Declassified state before remediation. A Declassified pathway may
be re-approved as a new version under PATHWAY-SPEC-v1, but existing
credentials issued under the Declassified version do not automatically
gain the new version's IssuanceWeight.

---

## Tier 3 Provisional Ceiling

### Purpose

Tier 3 credentials (device-attested issuance) do not cryptographically
prevent a single human from acquiring multiple credentials across
devices or services. HP-SPEC-v1.2 relied on PFV-SPEC-v1 (Proof Fraud
Verification) and the Pathway Health Index (PHI) defined in
PATHWAY-SPEC-v1 to detect correlated Sybil behavior across personas
and bound the weight any single non-identity-verified human could
accumulate. PFV-SPEC-v1 has deferred formulas for the T0, T1, and T2
annotation stages, and PHI computation is not yet operational in
production. Until those defenses are live, the protocol applies a
provisional ceiling to the Trust Index attainable by a Tier 3
credential. This ceiling is a compensating control, not a permanent
feature of the protocol. It is removed automatically upon a
Guardian-signed declaration of PFV and PHI operational readiness, as
specified below.

### Protocol-Level Trust Index Ceiling

A Tier 3 credential's Trust Index MUST NOT exceed **TI = 60** (equal
to the Active Credential Floor). BehavioralScore accumulation events
that would raise a Tier 3 credential's TI above 60 are computed and
retained in the credential's behavioral history for provenance, but
the credential's effective TI is clamped at 60 for all verification,
attestation-gating, and signal-weighting purposes. Clamping is a
property of the credential's current TI value; it does not modify the
underlying BehavioralScore increment events defined in the Trust Index
Accumulation Events section.

Tier 1 and Tier 2 credentials are not subject to this ceiling. Their
Trust Index is bounded only by the formula ceiling of 1000 defined in
the Trust Index Formula section.

### Tier 3 Lifetime Attestation Count Limit

A Tier 3 credential MAY record at most **50 OriginalAttestation Proof
Bundles** over its lifetime. Corrections and Withdrawal Records do not
count toward this limit, consistent with their exclusion from
attestation rate limits in the Rate Limiting Architecture section.
Attestation attempts beyond the limit are rejected at submission; the
attestation content is not recorded on the ledger.

The lifetime attestation count limit is separate from and additional
to the rolling attestation rate limits (20 per 24-hour rolling window,
100 per 7-day rolling window). A Tier 3 credential must remain within
both the rolling limits and the lifetime limit.

### Product-Level Recognition Caps

Pathway operators and verifying institutions MAY enforce a tighter
recognition threshold for Tier 3 credentials within their own
implementations (for example, treating Tier 3 credentials with an
effective weight lower than the protocol-level TI value), consistent
with DP-5 (Permissionless Proliferation) and DP-8 (Protocol, Not
Entity) of the HIP Genesis Covenant Charter. Such institutional caps
do not alter the protocol-level TI value recorded on the ledger and
are not defined by this specification. They are documented by each
pathway operator in their own operational documentation.

### Effective Date and Application to Existing Credentials

The provisional ceiling takes effect upon the cutover date of this
revision (HP-SPEC-v1.3). On that date:

- All existing Tier 3 credentials, regardless of their prior TI or
  prior OriginalAttestation count, are assigned a fresh lifetime
  attestation budget of 50 OriginalAttestations counted from the
  cutover date forward. Prior OriginalAttestations remain valid on
  the ledger and retain their BehavioralScore contributions subject
  to the TI ceiling clamp, but do not consume budget under this
  revision's counting.
- The TI ceiling clamp applies immediately to all existing Tier 3
  credentials. Credentials that were above TI = 60 prior to cutover
  have their effective TI clamped at 60 from the cutover date forward.
  Underlying BehavioralScore values are retained; the clamp is applied
  at read time.

This treatment ensures uniform application of the provisional control
at the moment it takes effect, without retroactively invalidating
attestations made in good faith under the prior specification.

### Removal Condition

The protocol-level TI ceiling and the lifetime attestation count limit
defined in this section are removed automatically for all Tier 3
credentials upon a Guardian-signed declaration that:

1. PFV-SPEC-v1 has reached full specification, with formulas defined
   for all annotation stages (T0, T1, T2) and no deferred components
   material to Sybil detection;
2. PFV signal computation is live in production across all those
   annotation stages; and
3. PHI monitoring is active across all registered pathways per
   PATHWAY-SPEC-v1.

The declaration is a single operational event. Upon its issuance:

- The TI ceiling clamp is released for all Tier 3 credentials. A
  credential whose underlying BehavioralScore plus IssuanceWeight
  previously summed above 60 has its effective TI restored to that
  value (subject to the formula ceiling of 1000).
- The lifetime attestation count limit ceases to apply. Remaining
  budget becomes irrelevant. Future attestations are bounded only by
  the rolling rate limits.

Tier 3 credentials in `Active — Under Review` or
`Suspended — Under Review` lifecycle state at the time of the
declaration retain the ceiling and the count limit until their
Credential Compromise Determination completes and the credential
returns to `Active` state.

### Interaction with the Upgrade Pathway

A creator whose intended use of the protocol requires a Trust Index
above 60, or a greater lifetime attestation volume than the Tier 3
limit permits, MUST re-verify through a Tier 1 or Tier 2 pathway.
Re-verification is handled by the existing IssuanceWeight Upgrade on
Re-Verification mechanism: the credential's IssuanceWeight is updated
to the higher tier's initial value, the BehavioralScore is preserved,
and the Issuance Record is updated to include the new pathway.
Key Rotation Records link the upgraded credential to the prior Tier 3
issuance for continuity of attestation history.

A credential that has been upgraded to Tier 1 or Tier 2 is no longer
subject to this section. The provisional ceiling and the lifetime
attestation count limit do not apply after the upgrade takes effect.

### Rationale

The Trust Index ceiling equal to the Active Credential Floor preserves
Tier 3's function as an entry pathway into the protocol — any
credentialed human may attest any classification at TI ≥ 60 per the
Classification Access Gating section — while preventing accumulation
of BehavioralScore weight that PFV is not yet equipped to audit for
Sybil patterns. The lifetime attestation count limit bounds the
aggregate volume of unaudited attestations any single non-identity-
verified credential may contribute to the ledger. Both controls are
conservative by design and are removed in full upon operational
readiness of the detection layer they compensate for.

This section does not restrict which HIP classifications a Tier 3
creator may assert once the Active Credential Floor is met. Tier 3
creators retain equal access to Complete Human Origin, Human Origin
Assisted, and Human-Directed Collaborative classifications, consistent
with DP-4 (Legitimacy From Proof, Not Recognition) and the governing
principle of the Classification Access Gating section.

---

## Classification Access Gating

### Governing Principle

Any credentialed human being has an equal claim to human origin. The
classification a creator may assert is governed by the honest truth of
how they made their work — not by how much work they have made, how
frequently they publish, how high their Trust Index is, or what tier
their credential was issued under.

The purpose of gating is narrow and specific: to prevent a credential
with zero behavioral history from making its very first protocol action
a strong claim. A single, low Active Credential Floor accomplishes this.
Above that floor, the full range of creator-asserted classifications is
available to every credentialed human equally.

TI operates as an internal weighting mechanism above the floor — it
affects how the protocol treats attestations in PFV analysis and how
much weight a credential's history carries in aggregate signal scoring.
It does not restrict which classification an honest creator may assert.

### The Active Credential Floor

**Active Credential Floor: TI ≥ 60**

A credential with a current Trust Index at or above 60 may assert any
creator-attested attestation category, including Complete Human Origin.
No further TI threshold applies.

A Tier 3 credential begins at TI 10. It reaches the floor after
approximately 10-12 contemporaneous attestations of any content —
a blog post, a chapter draft, a letter, a short story. There is no
requirement that this content be the work the creator ultimately wishes
to strongly attest. The floor is reached through ordinary use of the
protocol. It is not a barrier to any creator who is genuinely present
on the ledger.

A Tier 2 credential begins at TI 50. It reaches the floor after
approximately 3-4 contemporaneous attestations.

A Tier 1 credential begins at TI 400. It clears the floor at issuance.

For all tiers, there is no separate threshold between categories.
Complete Human Origin, Human Origin Assisted, and Human-Directed Collaborative are equally
accessible once the floor is cleared. The creator selects the category
that honestly describes their work.

### What TI Does Not Do

TI does not make one creator's attestation more "valid" than another's.
A TI 65 Complete Human Origin claim and a TI 840 Complete Human Origin
claim are both valid attestations by credentialed humans claiming sole creative
agency over their work. The protocol accepts both. The ledger records
both. The category is the same.

What differs is the internal weight those attestations carry in PFV
signal analysis — the protocol's anomaly-detection layer. A low-TI
credential whose first attestation is a suspicious claim may attract
PFV scrutiny that a high-TI credential with a long consistent history
would not. This is the legitimate Sybil-resistance function of TI:
new credentials are watched more carefully, not locked out.

### Proofcard Display

TI is not displayed on the Proofcard. It is not shown to verifiers as
a number, a score, a rating, or any other publicly comparable value.
Displaying TI would create a visible ranking of human creators by a
metric that reflects protocol history rather than human worth. HIP does
not rank humans.

What the Proofcard displays, alongside the attestation category, is the
**verification pathway description** — a plain-language statement of
how the credential was verified:

- "Verified via Government ID" (Tier 1 — government ID pathway)
- "Verified via Institutional Sponsorship" (Tier 1 — institutional pathway)
- "Verified via Peer Vouching" (Tier 2)
- "Verified via Biometric Presence" (Tier 3)

This is transparent, factual, and non-hierarchical in presentation.
It tells the verifier what the protocol did to confirm a human held
this credential. It does not tell the verifier that one human is more
human than another. The verifier may weigh pathway types differently
in their own assessment. The protocol does not do that weighting for
them on the public display.

### The Floor is Evaluated at Attestation Time

The Active Credential Floor check occurs at the moment the creator
submits an attestation. The TI value used is the current value at that
moment, including any PHI-linked decay applied to IssuanceWeight.

**The floor is not retroactively applied.** An attestation accepted
at the time of submission remains valid regardless of subsequent TI
changes. If a credential's TI falls below 60 following PHI-linked decay,
prior attestations are unaffected. Future attestations will be held
until TI is restored above the floor.

### Floor Failure Behavior

If a creator submits an attestation while their TI is below 60, the
attestation is held — not rejected — pending TI restoration. The
creator is informed clearly that their credential is below the Active
Credential Floor and what actions will restore it: additional attestations,
pathway re-verification, or simply waiting for a suspended pathway to
be remediated. The held attestation is not recorded on the ledger and
does not affect the content hash or attestation timestamp.

Implementations MUST NOT silently downgrade a creator's chosen
classification. They MUST communicate the floor status and restoration
path clearly. A creator who cannot currently assert their chosen
classification must be able to understand why and what they can do.

---

## Rate Limiting Architecture

Rate limiting is a mandatory property of the protocol. It is the primary
architectural mechanism against industrial-scale attestation farming and
credential issuance factories.

### Attestation Rate Limits

The following rate limits apply per credential, per rolling time window.
"Unique content attestations" means attestations referencing distinct
content hashes. Corrections and Withdrawal Records do not count toward
attestation rate limits.

| Window | Maximum Unique Content Attestations |
|---|---|
| 24-hour rolling | **20** |
| 7-day rolling | **100** |

**Tier 3 lifetime attestation count (v1.3).** In addition to the
rolling rate limits above, Tier 3 credentials are subject to a
lifetime cap of 50 OriginalAttestations per the Tier 3 Provisional
Ceiling section. That cap is separate from and additional to the
rolling windows defined here. Corrections and Withdrawal Records are
excluded from both the rolling limits and the lifetime cap.

These limits are calibrated to the behavior of prolific but credible
human creators. A journalist filing multiple stories per day, a social
media creator posting at volume, or a research team attesting across
a body of work can operate comfortably within these limits. An automated
system making hundreds of attestations per day cannot.

When a credential approaches its rate limit, the protocol signals
the approaching limit to the creator in a way that is visible to them.
A limit being hit is not in itself a violation; it may simply reflect
a high-output creator. The protocol records the attestation rate
alongside the credential's behavioral data, where it is available to
PFV analysis as a signal.

A credential that consistently operates near its maximum rate limits
across multiple windows is a behavioral signal worth monitoring. The
specific interaction between attestation rate and PFV analysis is
defined in PFV-SPEC-v1.

### Vouching Rate Limits

The following rate limits apply per credential for vouching activity.
These limits are the mechanism by which the protocol prevents any
credential from becoming an issuance factory.

| Period | Maximum New Vouches Issued |
|---|---|
| 30-day rolling | **3** |

| Standing Constraint | Limit |
|---|---|
| Maximum active, unresolved vouches outstanding at any time | **10** |

A "vouch" is considered active and unresolved until the vouched credential
either achieves 90 days of clean Active status (at which point the vouch
is considered resolved with a positive outcome) or is Invalidated through
determination (at which point the vouch is resolved with a negative outcome).

**Vouching eligibility floor:** A credential must be a Tier 1 credential
with a current Trust Index of at least **200** to be eligible to issue
vouches. The Tier 1 requirement ensures that vouching authority traces
back to government-ID-verified identity. The TI floor ensures that the
vouching credential has demonstrated meaningful standing before extending
that standing to others. Tier 2 and Tier 3 credentials are ineligible
to vouch regardless of TI.

**Vouch chain limit:** The protocol tracks vouch chains (A vouches for
B, B vouches for C, etc.) to a depth of four. A credential may not
vouch for any credential within four degrees of its own vouch chain.
This prevents the construction of self-reinforcing vouching loops.

### Rate Limit Enforcement

Rate limits are enforced at the protocol layer before inscription.
An attestation or vouching transaction that would exceed a rate limit
is rejected before it reaches the ledger. The rejection is logged in
the protocol's operational records (not the public ledger) for
monitoring purposes.

Implementations MUST communicate clearly to creators and vouchers
when a rate limit has been reached and when the limit window resets.
They MUST NOT silently queue or delay transactions beyond the rate
limit window without the user's knowledge and consent.

---

## Point-of-Use Liveness at Attestation Time

### Purpose

Issuance liveness confirms that a living human obtained the credential.
Attestation liveness confirms that a living human is using the credential
at the moment it is making a claim. These are different properties and
both are required.

A credential that was legitimately issued to a human but subsequently
stolen and operated by an automated system represents an attack that
issuance-time liveness alone cannot prevent. Point-of-use liveness at
attestation time is the architectural response to this attack vector.

### Primary Path: Device Attestation

Where device attestation infrastructure is available, every attestation
event MUST be accompanied by a hardware-attested liveness signal.

**What hardware attestation establishes:** A signed, manufacturer-verifiable
attestation that a genuine, unmodified device produced a genuine biometric
confirmation at a specific moment. This does not establish identity.
It establishes that a live human was present at this device at this moment,
as confirmed by hardware that the protocol can verify cryptographically
without trusting any intermediary beyond the device manufacturer's
attestation infrastructure.

**Freshness requirement:** The liveness attestation token must be generated
within **300 seconds (5 minutes)** of the attestation bundle signing
timestamp. Tokens older than 300 seconds at the time of bundle signing
are rejected. This prevents pre-generated liveness tokens from being
used to automate attestation after the fact.

**Supported attestation mechanisms:** The specific APIs used to obtain
hardware-attested liveness signals — including Apple App Attest, Android
Play Integrity API, and their successors — are documented as monitored
external dependencies in PATHWAY-SPEC-v1. This specification does not
enumerate them here because they evolve. Any hardware attestation
mechanism that satisfies the following properties is conforming:

- The attestation is generated by dedicated hardware on the device (a
  secure enclave, hardware security module, or equivalent)
- The attestation is cryptographically verifiable against the device
  manufacturer's public attestation infrastructure
- The attestation confirms that a genuine biometric check was performed
  (not merely that the device was present)
- The attestation includes a timestamp and a nonce derived from or
  associated with the current attestation event, preventing replay

**Liveness attestation in the Proof Bundle:** The liveness attestation
token (or a cryptographic commitment to it) is included in the Proof
Bundle as a liveness field. The specific wire format of this field
is defined in WF-SPEC-v1.

### Fallback Path: Behavioral Liveness Indicators

Where device attestation infrastructure is genuinely unavailable —
either because the creator's device does not support hardware-attested
biometrics, or because the attesting interface is not device-native —
the liveness requirement is satisfied through behavioral indicators.

Behavioral liveness is a weaker signal than device attestation.
It does not produce a cryptographic proof. It produces a probabilistic
assessment. The TI accumulation differential (contemporaneous device
attestation: +5 vs. contemporaneous behavioral: +3) reflects this
difference.

**Behavioral liveness indicators:**

*Interaction timing variance:* The attestation workflow requires multiple
active inputs (field completion, review, confirmation). The timing
between inputs is recorded. Automated systems exhibit either
inhuman regularity (fixed-interval clicks) or inhuman speed (faster
than any human could reasonably read and respond). The implementation
measures the distribution of inter-action delays and produces a
variance score. Very low variance or implausibly rapid completion
reduces the behavioral liveness score.

*Session continuity markers:* The device session parameters available
to the attesting interface — not personally identifying; device
category, approximate session duration, interaction patterns — are
compared against prior sessions from this credential. Marked
inconsistency with prior human-pattern sessions reduces the behavioral
liveness score.

*Multi-step active engagement:* The attestation workflow is designed
to require active engagement at multiple points that cannot be trivially
automated. The classification selection, in particular, requires a
distinct choice from a set of options rather than a single-click
confirmation. Attestation workflows MUST be designed consistent with
this requirement. An interface that can be completed by a single
programmatic action is non-conforming.

**Behavioral Liveness Score (BLS):** The combination of behavioral
indicators produces a BLS on a scale of 0-100. A BLS above **70** is
considered sufficient to satisfy the fallback liveness requirement.
A BLS between 40 and 70 triggers automatic PFV review. A BLS below 40
results in the attestation being flagged as liveness-unverified, with
the corresponding reduced TI increment and automatic PFV review.

**BLS is included in the Proof Bundle.** Verifiers can see whether
a given attestation was backed by device liveness, fallback behavioral
liveness, or neither. This is part of the honest representation
requirement established in Document 3.

### Liveness Failure Handling

An attestation submitted without any liveness signal — neither device
attestation nor behavioral indicators — is not rejected. It is accepted
with the liveness-unverified designation, the reduced TI increment (+1),
and automatic PFV review.

The rationale for not rejecting liveness-unverified attestations
entirely is that genuine creators in constrained environments — older
devices, non-standard interfaces, legacy publishing workflows — may
have legitimate reasons for being unable to provide liveness signals.
Blanket rejection would exclude these creators from HIP, violating
DP-2 (No New Behaviors Required) and the universal accessibility
commitment. The reduced TI increment and heightened scrutiny are
the protocol's calibrated response, not exclusion.

---

## Credential Portability

### Principle

Credential portability is a requirement, not a feature. Document 3
is explicit: "A creator who leaves an institution, changes devices, or
migrates to a new pathway retains their attestation history." This section
defines the mechanics.

A credential's identity is its public key identifier on the ledger.
The accumulated Trust Index and the attestation history are ledger-side
records permanently associated with that identifier. Portability means
those records travel with the credential regardless of device, platform,
or pathway changes.

### Device Migration

When a credential holder acquires a new primary device and needs to
migrate their credential's key material:

**Process:**
1. The holder initiates a key rotation on the existing device
2. A new key pair is generated on the new device's secure enclave
3. The existing device's private key signs a Key Rotation Record:
   a signed statement containing the new public key, the rotation
   timestamp, and the existing credential identifier
4. The Key Rotation Record is submitted to the protocol and inscribed
   on the ledger, permanently associating the new public key with
   the credential's history
5. The old private key is retired and should be deleted from the
   existing device's secure storage

Following a valid key rotation, attestations made with the new key
carry the full TI history of the credential. The Key Rotation Record
is permanently visible in the credential's ledger entry.

**If the existing device is unavailable (lost or stolen):**
The holder may initiate a forced key rotation through the credential
compromise reporting process. If the compromise report concerns
unauthorized use of the old key by a third party following device
loss, the compromise type is "stolen credential" and the determination
process applies. If the holder is simply reporting device loss with
no evidence of unauthorized use, an expedited rotation process applies
without the full compromise determination timeline.

### Pathway Upgrade

A credential holder may re-verify through a higher-tier pathway to
upgrade their IssuanceWeight.

**Process:**
1. The holder completes the verification process for the target pathway
2. Upon successful verification, a new Issuance Record is appended to
   the credential's ledger entry
3. IssuanceWeight is updated to the higher of: the current IssuanceWeight
   or the initial IssuanceWeight for the new pathway's tier
4. BehavioralScore is unchanged
5. The credential identifier and key material are unchanged unless the
   holder also requests a key rotation in the same transaction

The updated IssuanceWeight takes effect immediately following the
pathway upgrade inscription.

### Institutional Credential Migration

When a credential was issued through an institutional Tier 1 pathway
(an employer or institution that sponsored credential issuance) and
the holder leaves that institution, the credential remains valid and
the IssuanceWeight is not automatically reduced. The institutional
relationship is part of the issuance record; the credential's standing
is earned independent of the institution remaining a HIP participant.

If the institution's pathway is subsequently Declassified through
the PHI process, the IssuanceWeight decay rules apply in the same
way they apply to any pathway in Declassified state.

A holder who leaves an institution may re-verify through any other
Active pathway to establish a new, independent issuance record
alongside their institutional record.

---

## Credential Compromise Determination

### Overview

Document 2 establishes that "HIP does not operate a credential court."
The protocol records compromise events; it does not resolve them through a governance body
with discretionary authority. This section
defines the structured, criteria-based process by which compromise
events are evaluated and recorded — consistent with that principle.

Credential Compromise Determination is a criteria-based review, not a
discretionary judgment. A designated reviewing body applies the criteria
defined in this specification to the evidence presented. The outcomes
are defined here; the reviewing body chooses among them based on
evidence, not on judgment calls the spec does not authorize. The word
"Adjudication" is deliberately not used: HIP is not a court, the
reviewing body is not a judge, and no outcome is within their discretion
to invent.

### Compromise Types

**Type A — Stolen Credential:**
The credential was legitimately issued to a living human through a
valid pathway, but the private key was subsequently accessed by an
unauthorized actor who used it to make attestations.

Defining characteristic: The credential holder can establish a boundary
between their legitimate use and the unauthorized use, typically through
device records, attestation pattern analysis, or other evidence.

Treatment: Pre-theft attestations retain their integrity assessment;
post-theft attestations are flagged as Post-Compromise. TI collapses.
Credential is Invalidated. The holder is eligible for a new credential.

**Type B — Fraudulently Obtained Credential:**
The credential was obtained by gaming or bypassing the issuance pathway
— for example, by using an AI system to pass a liveness check at
issuance, or by using a false identity to obtain Tier 1 issuance.

Defining characteristic: The issuance event itself was fraudulent.
There is no authentic human-held period to protect.

Treatment: All attestations made under the credential are flagged as
Credential-Suspect — Fraudulent Issuance. TI collapses. Credential is
Invalidated. New credential eligibility is determined by the Credential Compromise Determination
outcome and any applicable waiting period.

**Type C — Systematic False Attestation:**
The credential was legitimately issued and the private key is held
by a living human, but that human has deliberately and systematically
misclassified content — asserting Complete Human Origin or Human Origin
Assisted for content that does not meet the definition.

Defining characteristic: The credential is authentic. The misconduct
is in its use. This type may co-occur with Type A (stolen key used
for false attestation) but is distinct when the credential holder
themselves is responsible.

Treatment: Credential is Suspended pending Credential Compromise Determination. Upon confirmation,
attestations flagged as Systematic False Attestation — see disposition
detail below. TI collapses. Credential Invalidated. New credential
eligibility determined by determination outcome.

### Reporting Mechanisms

**Self-Report:**
A credential holder may report their own credential as compromised —
typically when their device is lost or stolen and they are concerned
about unauthorized use. Self-reports are treated with elevated priority
given the holder's direct interest in resolution.

Process: the holder submits a signed self-report statement using
any device where they can authenticate their identity (through a
recovery mechanism defined in their credential's issuance record).
The protocol immediately transitions the credential to Suspended —
Self-Reported state. The holder is prompted to initiate a device migration
to a new key.

**Third-Party Report (Identified):**
Any party may submit a compromise report alleging that a specific
credential has been used in a way inconsistent with authentic human
origin. Identified third-party reports must include:
- The credential identifier
- The nature of the alleged compromise (one of the three types above)
- Supporting evidence (attestation records, external analysis, or other)
- Contact information for the reporting party (not published; used
  only for determination follow-up)

A third-party report that does not include supporting evidence and a
specific allegation type is not accepted for determination.

**Third-Party Report (Anonymous):**
The protocol accepts anonymous third-party reports, subject to an
elevated evidentiary threshold. Anonymous reports exist to protect
whistleblowers — particularly those reporting compromise by powerful
actors where identification could create retaliation risk.

Anonymous reports must include:
- The credential identifier
- The nature of the alleged compromise (one of the three types above)
- **Substantive, independently verifiable evidence** sufficient for the
  reviewing body to assess the report without any interaction with the
  reporting party. This is a higher evidentiary bar than for identified
  reports, where the reviewing body can request additional information
  from the reporter.

The protocol holds no identifying information for anonymous reporters.
There is nothing to subpoena, nothing to disclose, and no metadata
retained that could identify the source. The submission mechanism MUST
be designed to prevent identification of anonymous reporters through
technical means (IP logging, browser fingerprinting, etc.).

Anonymous reports that do not include independently verifiable evidence
are not accepted for determination. The elevated evidence threshold
is the mechanism by which the protocol prevents anonymous reporting
from becoming a harassment tool while preserving its value as a
whistleblower protection.

Reports are reviewed within **5 business days** by the determination
body. If the report is accepted for full determination, the credential
is transitioned to Suspended — Under Review. If the report is rejected
as insufficient, the credential is not suspended and the reporting
party is notified.

**Algorithmic Flag:**
PFV-SPEC-v1 defines the signal patterns that trigger automatic credential-
level review. When these signals are detected, the credential enters a
heightened monitoring state — it does NOT automatically transition to
Suspended. The credential remains Active with an "Under Review —
Algorithmic" notation visible to verifiers. The creator can continue to
attest while under review. An automated report is entered into the
determination queue for expedited human review.

Algorithmic flags trigger monitoring and expedited review, not suspension.
The rationale is threefold: (1) for professional creators, suspension of
attestation capability for up to 60 days on algorithmic signal alone —
with no human review, no adversarial proceeding, and no pre-suspension
challenge — could have material professional consequences; (2) algorithmic
signals are probabilistic and may reflect legitimate anomalous behavior
rather than compromise; (3) due process principles require that adverse
action with real-world impact be reviewed by a human before taking effect.

Transition from "Under Review — Algorithmic" to Suspended requires:
- A human-reviewed report by the reviewing body confirming that the
  algorithmic signals, combined with any additional evidence gathered
  during the review period, meet the criteria for one of the three
  compromise types defined in this specification
- A **Suspension Impact Statement** documenting: the credential's
  attestation volume and frequency, the professional context derivable
  from ledger data (e.g., institutional pathway, publication frequency),
  and a proportionality analysis explaining why suspension is warranted
  given the evidence and the impact on the credential holder

The reviewing body MUST complete its initial assessment of an algorithmic
flag within **10 business days**. If the assessment concludes that
suspension is not warranted, the "Under Review — Algorithmic" notation
is removed and the credential returns to standard Active status. The
review and its outcome are permanently recorded.

If the assessment concludes that suspension is warranted, the credential
transitions to Suspended — Under Review and the standard determination
timeline (30-day determination, one 30-day extension, 60-day hard cap)
begins from that point. The Suspension Impact Statement is included in
the permanent record.

Attestations made by the credential during the "Under Review —
Algorithmic" period carry the review notation in the Proof Bundle.
Verifiers can see that the credential was under algorithmic review at
the time of attestation. If the credential is subsequently cleared,
the review notation remains as historical context but the attestations
are not flagged as suspect.

### Reviewing Body

The composition and governance of the reviewing body is defined in
the HIP Governance provisions of the Charter. For the purposes of this
specification, the reviewing body is a defined panel that:
- Applies the criteria defined in this specification
- Does not exercise discretionary authority beyond those criteria
- Is subject to the Phoenix Firewall provisions of the Charter
- Cannot be composed of a majority of members with direct economic
  interest in any outcome

The reviewing body evaluates evidence against the compromise type
definitions. It issues a determination. It does not have authority
to impose outcomes not defined in this specification. It is not a
court. Its conclusions are findings of fact against defined criteria,
not judgments.

### Determination Timeline

| Stage | Deadline |
|---|---|
| Initial review of third-party report (accept/reject for determination) | 5 business days from report submission |
| Initial assessment of algorithmic flag (suspend/clear) | 10 business days from flag generation |
| Full determination | 30 calendar days from Suspended state entry |
| Extension (once, with published justification) | Additional 30 calendar days |
| Maximum total time in Suspended state before determination | 60 calendar days |

If no determination is issued within the maximum timeline, the credential
is automatically restored to Active state and all suspension flags are
removed. This is not a finding of no compromise — it is an acknowledgment
that the protocol cannot indefinitely suspend a credential without
resolving the question. The report and the timeline failure are both
permanently recorded.

Note: The algorithmic review timeline (10 business days) runs independently.
A credential under algorithmic review that is not escalated to Suspended
within 10 business days is returned to standard Active status. The
Suspended-state timeline (30+30 day determination period) does not begin
until the credential actually enters Suspended state — either through
algorithmic escalation or through an accepted third-party/self-report.

### Determination Outcomes

**Confirmed Type A (Stolen):**
- Compromise timestamp established (the point at which unauthorized
  access is found to have begun)
- Attestations prior to compromise timestamp: status unchanged
- Attestations following compromise timestamp: flagged Post-Compromise —
  Integrity Suspect
- TI collapses to zero
- Credential Invalidated
- Holder eligible for new credential immediately; new TI begins at
  zero from initial issuance of the new credential
- Key rotation is completed as part of the Invalidation process

**Confirmed Type B (Fraudulent Issuance):**
- All attestations under the credential: flagged Credential-Suspect —
  Fraudulent Issuance
- TI collapses to zero
- Credential Invalidated
- New credential eligibility: the determination body may impose a
  waiting period before new credential application. The maximum
  waiting period is 12 months. The waiting period, if any, is
  published in the compromise record.
- If a Tier 2 vouch was involved in the fraudulent issuance, the
  vouching credential's bad-vouch penalty applies.

**Confirmed Type C (Systematic False Attestation):**
- All attestations under the credential during the period of confirmed
  misconduct: flagged Systematic False Attestation — Classification
  Suspect
- Attestations outside the confirmed misconduct period: status unchanged
- TI collapses to zero
- Credential Invalidated
- New credential eligibility: same as Type B (reviewing body may
  impose a waiting period, maximum 12 months)

**Not Confirmed:**
- All suspension flags removed from the credential
- Credential restored to Active state
- TI restored to its value immediately before suspension, with any
  accumulation events that would have occurred during the suspension
  period applied retroactively (i.e., the suspension does not create
  a TI gap for a credential subsequently cleared)
- The report, the investigation, and the outcome of "not confirmed"
  are permanently recorded and visible on the credential
- This outcome is not confidential. A credential that was investigated
  and cleared is transparently labeled as such. A clean outcome is
  not a stigma; concealing that an investigation occurred would
  create a worse dynamic.

---

## Trust Score (v1.1)

### Purpose and Relationship to Trust Index

The Trust Score is a public-facing, user-visible metric that provides
credential holders with a human-readable summary of their credential's
standing. It is distinct from the Trust Index.

**Trust Index (TI)** is the protocol-internal instrument defined in
earlier sections of this specification. It operates on a scale of 0-1000,
is composed of IssuanceWeight and BehavioralScore, and governs
classification access gating, PFV weighting, and vouching eligibility.
TI is not displayed on the Proofcard or exposed to verifiers as a
public number.

**Trust Score** is a derived, simplified metric on a scale of 0-100 that
is displayed to the credential holder and included in verification
results. It provides a practical, legible signal of credential maturity
without exposing the internal TI mechanics. Trust Score is informational
— it does not gate any protocol capability. All gating decisions are
made by TI.

### Trust Score Formula

Trust Score is computed from five components, each reflecting a
different dimension of credential standing:

**Trust Score = min(100, tier_base + age_bonus + volume_bonus + consistency_bonus + liveness_bonus)**

**Tier Base Points:**

| Tier | Tier Base |
|------|-----------|
| Tier 1 (Government ID) | 40 |
| Tier 2 (Peer Vouch) | 25 |
| Tier 3 (Biometric Presence) | 10 |

**Age Bonus:** Linear accumulation up to a maximum of **+20** points
over the credential's first year of existence. Computed as:
`min(credential_age_days / 365 × 20, 20)`. A credential that has
existed for 6 months receives +10. A credential older than 1 year
receives the full +20.

**Volume Bonus:** Linear accumulation up to a maximum of **+15** points
at 50 attestations. Computed as: `min(attestation_count / 50 × 15, 15)`.
A credential with 25 attestations receives +7.5. A credential with 50
or more attestations receives the full +15.

**Consistency Bonus:** Linear accumulation up to a maximum of **+10**
points over 12 active months. An "active month" is any calendar month
in which the credential made at least one attestation. Computed as:
`min(active_months / 12 × 10, 10)`. A credential active in 6 distinct
months receives +5. A credential active in 12 or more months receives
the full +10.

**Liveness Bonus:** Up to **+15** points based on the proportion of
attestations that include device-verified liveness. Computed as:
`liveness_verified_count / attestation_count × 15`. A credential
where 100% of attestations are liveness-verified receives the full +15.
A credential with no liveness-verified attestations receives 0. If the
credential has zero attestations, the liveness bonus is 0.

### Trust Score Ranges

The Trust Score is displayed with color-coded feedback to the
credential holder:

| Score Range | Color | Interpretation |
|-------------|-------|----------------|
| 75–100 | Green | High maturity credential |
| 50–74 | Orange | Established credential |
| 25–49 | Yellow | Developing credential |
| 0–24 | Red | New or low-activity credential |

These ranges are display guidance, not protocol gating. No protocol
capability is locked behind a Trust Score threshold. A credential
holder with a Trust Score of 5 and a Trust Score of 95 have the same
protocol capabilities if their TI values both clear the Active
Credential Floor.

### Trust Score in Verification Results

When a credential is looked up through the verification tool, the
Trust Score is included in the verification response alongside the
tier, attestation count, credential age, and score breakdown. This
gives verifiers a quick-read signal of credential maturity without
exposing raw TI internals.

### Trust Score Computation Timing

Trust Score is recomputed on every trust-relevant event: credential
initialization, attestation registration, and trust record lookup.
It is not cached between events. The score returned is always current
as of the moment of computation.

---

## QR Credential Transfer (v1.1)

### Purpose

A credential holder may need to use their credential on a different
device — for example, when a Tier 1 credential is issued on a phone
via hipverify.org but the holder primarily attests from a desktop
browser, or when migrating to a new device. QR Credential Transfer
provides a secure, ephemeral mechanism for moving credential material
between devices without exposing private keys in transit.

This mechanism supplements the Key Rotation process defined in the
Credential Portability section. Key Rotation is the formal,
ledger-recorded mechanism for changing a credential's key pair. QR
Transfer is a practical convenience for moving an existing credential's
key material to a second device while the same key pair remains active.

### Transfer Flow

1. **Initiation (receiving device):** The receiving device generates
   a random transfer code (minimum 8 characters, maximum 64) and
   displays it as a QR code.

2. **Scanning (sending device):** The sending device scans the QR code
   to obtain the transfer code.

3. **Encryption (sending device):** The sending device encrypts the
   full credential blob (including private key material) using a key
   derived from the transfer code. The encrypted payload is submitted
   to the transfer relay endpoint (POST /transfer/:code).

4. **Storage (relay):** The relay stores the encrypted payload in
   ephemeral key-value storage with a **5-minute TTL**. The payload
   is keyed by the transfer code. Each transfer code may be used
   exactly once — a code that has already been written to cannot be
   overwritten.

5. **Retrieval (receiving device):** The receiving device polls the
   relay endpoint (GET /transfer/:code). When the payload is available,
   it is returned and immediately deleted from the relay. The receiving
   device decrypts the credential blob using the transfer code and
   stores it locally.

### Security Properties

**Ephemeral storage:** The encrypted payload exists on the relay for a
maximum of 5 minutes. After TTL expiration or first retrieval, it is
permanently deleted.

**Single-use codes:** A transfer code that has already been used for a
push operation cannot be reused. This prevents replay attacks.

**Payload size limit:** Encrypted payloads are limited to 16,384 bytes.
This is sufficient for credential material but prevents the transfer
mechanism from being used as a general-purpose data relay.

**End-to-end encryption:** The relay never has access to the unencrypted
credential material. The transfer code, which serves as the decryption
key, is exchanged between devices via QR code and never transmitted
to the relay.

### Limitations

QR Transfer moves credential material — it does not perform a Key
Rotation. After transfer, both devices hold the same key pair. If the
credential holder subsequently loses access to one device, they should
perform a formal Key Rotation through the process defined in the
Credential Portability section.

QR Transfer currently operates in one direction: from the device
holding the credential to the device requesting it. Reverse-direction
transfer (desktop to phone) is a deferred feature.

---

## File Uniqueness and Byte-Level Attestation (v1.1)

### Principle

An attestation in HIP is a claim about a specific file — a specific
sequence of bytes. The content hash in the Proof Bundle is computed
from the exact byte content of the attested file. Two files that are
semantically identical but differ by even a single byte produce
different hashes and are treated as different attestations.

### What This Means for Creators

A creator attests a file, not a work. If a creator publishes the same
photograph in three formats (JPEG, PNG, TIFF), each format produces a
different byte sequence and therefore a different content hash. Each
format requires its own attestation if the creator wishes to cover all
three. Attesting the JPEG does not cover the PNG.

If a creator makes any modification to a file after attestation — even
metadata changes, re-encoding, or lossless compression — the modified
file has a different hash and is not covered by the original attestation.

### Rationale

Byte-level attestation is the only model that produces unambiguous,
cryptographically verifiable claims. Any attempt to define "sameness"
at a semantic level (same image, different encoding) would require
subjective similarity judgments that undermine the protocol's
deterministic verification model. A verifier can always answer the
question "is this exact file attested?" with certainty. The question
"is something like this file attested?" requires interpretation, and
HIP does not interpret.

### EXIF and Metadata

When a creator attests a file through the HIP tool, the tool writes
HIP metadata into the file's EXIF data (for supported formats: JPEG).
This metadata includes the HIP protocol marker, credential ID prefix,
tier, timestamp, and Proof Card filename. The content hash is computed
from the file as modified by the EXIF write — meaning the attested
file includes its own HIP metadata. Any subsequent EXIF modification
would change the hash.

Support for additional metadata-bearing formats (PNG, TIFF) is a
planned extension.

---

## Credential Tier Migration (v1.1)

### Background

HP-SPEC-v1 defined Tier 2 as Device Biometric and Tier 3 as Peer Vouch.
HP-SPEC-v1.1 swaps these assignments: Tier 2 is now Peer Vouch and
Tier 3 is now Biometric Presence (formerly "Device Biometric"; renamed
in HP-SPEC-v1.2 to reflect that the pathway claims biometric presence,
not per-device uniqueness). This section specifies how existing
credentials issued under the v1 tier definitions are migrated.

### Migration Rule

Any credential issued under the v1 tier definitions is automatically
migrated on first use after the v1.1 update:

- A credential with tier=2 and pathway="device-biometric-webauthn-v1"
  is migrated to tier=3.
- A credential with tier=3 and pathway="peer-vouch-bound-token-v1"
  is migrated to tier=2.

The migration is applied once. A migration flag ("_tierMigrated": "s29")
is set to prevent re-application. The credential's pathway identifier
is unchanged — only the tier number is updated.

### Effect on Trust Index

Tier migration does not alter the credential's Trust Index. A credential
that was issued as Tier 2 (Device Biometric) at IssuanceWeight 150 under
v1 retains its current IssuanceWeight after migration to Tier 3. The
new initial IssuanceWeight values (Tier 2: 50, Tier 3: 10) apply only
to credentials issued after the v1.1 update.

### Effect on Trust Score

The Trust Score tier_base component is recalculated using the credential's
migrated tier number. A credential migrated from Tier 2 to Tier 3 will
see its tier_base change from 25 to 10 on the next Trust Score
computation. This reflects the credential's actual verification pathway
rather than its legacy tier number.

---

## Implementation Requirements

Any HIP-conforming implementation of HUMAN-PROOF credentials MUST:

- Implement the Trust Index formula exactly as specified, with
  IssuanceWeight and BehavioralScore maintained as separate values
- Apply the initial TI values by tier as specified; implementations
  MAY NOT assign different initial weights without specifying a
  version deviation that is transparent to verifiers
- Apply the Active Credential Floor (TI ≥ 60) at attestation time;
  implementations MAY NOT permit attestations from credentials below
  the floor, and MAY NOT silently downgrade a creator's chosen
  classification — the floor failure behavior defined in this
  specification applies
- NOT display TI as a public score, ranking, or number to verifiers;
  the Proofcard displays the verification pathway description only
- Implement the rate limits as specified; implementations MAY impose
  stricter rate limits in specific deployment contexts but MAY NOT
  relax the minimums defined here
- Implement the point-of-use liveness requirement and include the
  liveness designation in the Proof Bundle
- Communicate TI standing, classification access status, and liveness
  availability clearly to creators at the moment of attestation
- Implement the credential portability mechanics without loss of
  TI history or issuance records
- Participate in the compromise determination process when required,
  including honoring Suspended state and applying the outcomes
  as specified
- (v1.1) Implement the Trust Score formula as specified and display it
  to credential holders; Trust Score MUST NOT be used for protocol
  gating decisions — all gating uses TI
- (v1.1) Enforce Tier 1 vouching restriction: implementations MUST NOT
  permit Tier 2 or Tier 3 credentials to vouch regardless of TI
- (v1.1) Implement server-side Tier 3 registration through the
  challenge/response flow; implementations MUST NOT issue Tier 3
  credentials through client-only flows
- (v1.1) Apply automatic tier migration for pre-v1.1 credentials
  as specified in the Credential Tier Migration section
- (v1.1) Compute content hashes from exact byte content of attested
  files; implementations MUST NOT apply normalization, transcoding,
  or semantic equivalence before hashing

Implementations MAY:

- Build user-facing interfaces that present TI information in
  simplified form, provided the underlying values remain accessible
- Integrate additional liveness signals beyond those specified here,
  provided they do not replace the device attestation path where
  device attestation is available
- Cache TI values locally for performance, provided the cache is
  invalidated and refreshed on any attestation event

Implementations MUST NOT:

- Represent TI as a publicly visible "score" in a way that invites
  social comparison rather than protocol-capability understanding
- Expose private key material in the Proof Bundle or any other
  ledger-facing record
- Accept or process attestations from credentials in Suspended or
  Invalidated state
- Represent a liveness-unverified attestation as liveness-verified

---

## Post-Quantum Posture

HIP's cryptographic design acknowledges the long-term implications of
quantum computing and distinguishes between components with different
risk profiles.

### Unaffected Components

Content hashes (SHA-256) and the Genesis inscription are not meaningfully
threatened by known quantum algorithms. Grover's algorithm reduces SHA-256's
effective security from 256 to 128 bits — a reduction that does not approach
practical attack thresholds under any near-term projection. NIST and the
broader cryptographic community consider 128-bit post-Grover security
adequate for the foreseeable future. Bitcoin itself depends on SHA-256; if
this boundary falls, the consequences extend far beyond HIP.

The Genesis OP_RETURN inscription is permanent on-chain data. Its integrity
does not depend on asymmetric cryptography and cannot be retroactively
altered regardless of future cryptographic developments. The inscription
will read what it reads, permanently, regardless of what quantum computing
achieves. IPFS and Arweave content addresses are likewise hash-based and
carry the same posture as content hashes.

### At-Risk Components

Ed25519, used for Guardian Key signatures and credential issuance, is an
elliptic curve scheme. Shor's algorithm, executed on a cryptographically
relevant quantum computer (CRQC), could derive a private key from a
published public key. The Guardian Public Key is intentionally public — this
is required for open verification — but it also constitutes the input
Shor's algorithm would require to compromise the signing key.

Current consensus among cryptographic bodies places CRQCs capable of
attacking 256-bit elliptic curves at a minimum of one to two decades away,
with substantial uncertainty in both directions. This is not a reason to
ignore the threat; it is a reason to build with migration in mind.

Ed25519-signed credentials carry the same long-term exposure. A CRQC
capable of deriving the Guardian private key could forge credential
issuance. Individual credential key pairs face the same attack surface.

### Migration Path

HIP's credential architecture anticipates this transition. When
post-quantum signature standards become practical to deploy — NIST
finalized ML-DSA (CRYSTALS-Dilithium) as its primary post-quantum
signature standard in 2024 — HIP will execute the following:

1. Generate a new Guardian Key using an approved post-quantum algorithm
2. Publish a signed transition announcement anchored to Bitcoin
3. Open a re-attestation window during which existing credentials are
   reissued under the new key
4. Deprecate Ed25519-signed credentials on a published timeline with
   sufficient advance notice for credential holders to migrate

The recovery and upgrade infrastructure introduced in HP-SPEC-v1.1
(credential recovery, tier upgrade flows) provides the existing
re-attestation pathway. No architectural change to the credential
lifecycle model is required — only a Guardian Key rotation and a
managed migration period.

This transition, when it occurs, will itself be anchored to Bitcoin
and recorded permanently, preserving the chain of protocol authority
through the key rotation.

### Design Principle

HIP does not claim to be quantum-resistant today. It claims to be
quantum-aware: the threat is scoped, the unaffected components are
identified, and the migration path exists within the existing architecture.
Cryptographic agility — the ability to rotate primitives without
rebuilding the protocol — is a first-class design goal. Implementations
MUST support key rotation mechanics as specified in this document.
Implementations MUST NOT hardcode Ed25519 as a permanent, non-rotatable
primitive.

### Risk Summary

| Component | Quantum Algorithm | Assessment | Action |
|---|---|---|---|
| SHA-256 content hashes | Grover (halves bit security) | 128-bit residual — not a practical threat | None required |
| Genesis OP_RETURN inscription | None applicable | Permanent on-chain data, no asymmetric dependency | None required |
| IPFS / Arweave CIDs | Grover (hash-based) | Same as SHA-256 content hashes | None required |
| Ed25519 Guardian Key | Shor's (breaks EC crypto) | Long-term threat; public key is exposed by design | Plan rotation to ML-DSA when practical |
| Ed25519 credential key pairs | Shor's (breaks EC crypto) | Long-term threat; same attack surface | Re-attestation migration via existing upgrade flow |

---

## Consistency with Parent Documents

This specification was drafted against and is consistent with:

- Document 3: HUMAN-PROOF Scope Statement, which established that
  HUMAN-PROOF is a credentialed claim under economic accountability,
  not a biometric proof; that TI is the common currency normalizing
  across pathways; that liveness applies at both issuance and point
  of use; that PHI decay affects IssuanceWeight but not BehavioralScore;
  and that credential portability preserves attestation history.

- Document 2: Attestation Architecture Decision, which established
  the Proof Bundle structure, the on-chain/off-chain split, the
  classification selection as an active creator choice, the TI
  consultation at attestation time, and the credential compromise
  architecture including Trust Index collapse on confirmed compromise
  and permanent survival of all records.

- Document 1: HIP Core Definitions, which established the six-category
  system and the three creator-attested categories that TI
  gating governs.

- Section 12: Deployment Philosophy, principles DP-2 (No New
  Behaviors Required — the liveness fallback path and the rejection of
  blanket exclusion for liveness-unverified attestations) and DP-5
  (Permissionless Proliferation — conforming implementations may
  be built by any actor subject to the requirements above).

Where this specification addresses cases not explicitly resolved by
the parent documents, it has done so in a manner consistent with the
governing principles those documents establish. The parent documents
control in any conflict.

---

## Open Items — All Resolved

All items flagged for review have been confirmed. The following records
the decisions and their rationale for the permanent record.

**Resolved — Classification access model:**
The binary threshold model has been replaced with a single Active Credential
Floor of TI >= 60 applying equally to all creator-attested categories.
Above the floor, all categories are accessible to all credentialed
humans regardless of output volume, tier, or TI level. TI operates as an
internal weighting mechanism only. Proofcard shows pathway description,
not TI. Confirmed design.

**Resolved — TI visibility:**
TI is an internal protocol instrument, not displayed on the Proofcard
or any public-facing display. Pathway description shown instead.
Confirmed design.

**Resolved — TI scale (0-1000):**
Confirmed. Provides required granularity. Masked from public view entirely.
No human is more human than any other human.

**Resolved — Initial tier weights (400 / 50 / 10):**
Tier 1 at 400: durable, externally cross-referenced verification.
Tier 2 at 50: peer vouching carries meaningful social accountability
through the Tier 1 vouching restriction — every vouched credential
traces back to a government-ID-verified human. Tier 3 at 10: device
biometric is maximally accessible but the human-accomplice attack
vector means initial assurance is low. PHI monitoring handles future
pathway degradation automatically. Ratio approximately 40:5:1.
Revised in v1.1 from the pre-Genesis ratio of 8:3:1. Confirmed design.

**Resolved — BehavioralScore cap removed:**
No independent ceiling on BehavioralScore. TI = min(1000, IssuanceWeight
+ BehavioralScore). Any credentialed human can reach TI 1000 through
sustained honest behavior regardless of starting tier. IssuanceWeight
is a head start, not a permanent structural advantage. Confirmed design.

**Resolved — Bad-vouch penalty model:**
Type B (fraudulently obtained): -15 BehavioralScore to voucher.
Type A (stolen, misused): no penalty to voucher.
Type C (real human, false attestation): no penalty to voucher.
Penalty is automatic downstream output of Type B determination.
Confirmed design.

**Resolved — "Adjudication" renamed:**
Renamed to "Credential Compromise Determination" throughout. Reviewing
body applies defined criteria; does not exercise discretionary judgment.
Confirmed design.

**Resolved — CDI-2: Algorithmic flag treatment:**
Algorithmic flags now trigger heightened monitoring and expedited human
review, not automatic suspension. Credential remains Active with "Under
Review — Algorithmic" notation. Suspension requires human-reviewed report
with specific evidence and a Suspension Impact Statement documenting
proportionality. 10-business-day initial assessment deadline. Protects
professional creators from algorithmically-triggered suspension while
maintaining the protocol's ability to act on genuine compromise. Confirmed
design.

**Resolved — CDI-3: Anonymous reporting:**
Anonymous third-party reports now accepted with elevated evidentiary
threshold: independently verifiable evidence required. Protocol holds no
identifying information for anonymous reporters — nothing to subpoena.
Protects whistleblowers against retaliation while preventing anonymous
harassment through the elevated evidence bar. Identified reports retain
lower evidence threshold. Confirmed design.

---

*HP-SPEC-v1.3: HUMAN-PROOF Credential Mechanics Specification — Tier 3 Provisional Ceiling (PFV-gated).*
*v1.3 adds: Tier 3 Provisional Ceiling section — protocol-level TI ceiling of 60 and lifetime*
*attestation count cap of 50 OriginalAttestations for Tier 3 credentials, removable upon Guardian-signed*
*declaration of PFV-SPEC-v1 + PHI operational readiness. Cross-reference notes added to the Trust Index*
*Formula and Attestation Rate Limits sections. Effective date application is uniform across all existing*
*Tier 3 credentials (fresh 50-count budget from cutover; TI clamp applied at read time with underlying*
*BehavioralScore preserved). Compensating control for the deferred operational status of PFV-SPEC-v1 and*
*PHI. Drafted and locked in Session S86CW; committed in Session S87CW.*
*v1.2 adds: Post-Quantum Posture section — risk assessment by component, Ed25519 migration path,*
*ML-DSA transition plan, cryptographic agility as first-class design requirement.*
*v1.1 incorporates: tier reassignment (Tier 2 = Peer Vouch,
Tier 3 = Biometric Presence, formerly "Device Biometric"), revised initial weights (400/50/10), Tier 1 vouching
restriction, server-side Tier 3 registration, Trust Score specification, QR credential
transfer, byte-level file uniqueness clarification, and credential tier migration.*
*Derived from Document 3 (HUMAN-PROOF Scope Statement), Document 2 (Attestation
Architecture Decision), and Document 1 (HIP Core Definitions).*
