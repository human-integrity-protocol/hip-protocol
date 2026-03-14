# HIP — Human Integrity Protocol
## WF-SPEC-v1: Proof Bundle Wire Format Specification
### WORKING DRAFT | 2026-03-03 | Pre-inscription | CSR corrections applied

---

## Authority and Status

This specification derives its authority from and must remain
consistent with:

- **Document 2: Attestation Architecture Decision** — the governing
  architectural decisions establishing the Proof Bundle / Proof
  Anchor split, the on-chain / off-chain model, and the W3C
  Verifiable Credentials alignment
- **Document 1: HIP Core Definitions** — the six-category system and
  definition of human-origin content
- **Document 3: HUMAN-PROOF Scope Statement** — the credential model
  and tiered pathway architecture
- **HP-SPEC-v1: HUMAN-PROOF Credential Mechanics Specification** —
  credential structure, Trust Index mechanics, liveness
  requirements, and Credential Compromise Determination process
- **PATHWAY-SPEC-v1: Issuance Pathway Governance Specification** —
  pathway versioning model, pathway version identifier structure,
  and PHI state definitions
- **PFV-SPEC-v1: Propagation Fingerprint & Verification Signal Specification** —
  signal annotation format, classification display reframe, and
  staged analysis model
- **Section 12: Deployment Philosophy** — particularly DP-1 (Day-One
  Utility), DP-5 (Permissionless Proliferation), DP-7 (Zero
  Institutional Cost), and DP-8 (Protocol, Not Entity)
- **HIP Genesis Covenant Charter v1.0** — the covenant document

In any conflict between this specification and the documents listed
above, the parent document controls. This specification may not
introduce principles that contradict those documents. Where this
specification addresses cases not covered by those documents, it may
propose extensions, provided those extensions are consistent with the
governing principles established there.

This specification is a companion document. It is not part of the
Genesis inscription. Its evolution does not require Charter amendment
and does not trigger fork conditions. It is versioned separately.

---

## Purpose

WF-SPEC-v1 specifies the wire format — the precise data structure,
field definitions, encoding, and serialization — of the two core
data objects in HIP's attestation architecture: the Proof Bundle
(off-chain, complete) and the Proof Anchor (on-chain, minimal). It
also specifies the Bundle-to-Anchor hash construction that links
them, the Proof Anchor Link format that enables Bundle retrieval,
the schema versioning model that allows the format to evolve, and
the Proof Bundle hosting architecture that ensures Bundles remain
available.

Document 2 established *what* the Proof Bundle and Proof Anchor
contain and *why* the on-chain / off-chain split exists. This
specification defines *how* that content is structured, encoded,
and transmitted — the byte-level reality that any conforming
implementation must produce and consume.

The wire format is the protocol's interoperability contract. Two
implementations that produce the same wire format for the same
attestation event are interoperable. An implementation that deviates
from this format produces data that other implementations cannot
verify. The format must therefore be precise, unambiguous, and
versioned so that it can evolve without breaking backward
compatibility.

---

## Scope

This specification covers:

- **Proof Bundle structure and field definitions:** Every field in
  the Proof Bundle — its name, its data type, its encoding, whether
  it is required or optional, and what it represents
- **Proof Anchor structure and field definitions:** The minimal
  on-chain record and its field definitions
- **Bundle-to-Anchor hash construction:** The deterministic process
  by which a Proof Bundle produces the hash recorded in the Proof
  Anchor
- **Proof Anchor Link format:** The URI structure that connects a
  Proof Anchor to its corresponding Bundle
- **Pathway version identifier format:** The wire-level encoding of
  pathway version identifiers referenced in PATHWAY-SPEC-v1
- **Schema versioning model:** How the wire format evolves across
  specification versions while maintaining backward compatibility
- **Proof Bundle hosting architecture:** The distributed hosting
  model, Steward Node hosting obligations, redundancy requirements,
  and retrieval protocol
- **Proof Bundle size constraints:** Design constraints that keep
  Bundles in the kilobyte range

This specification explicitly defers:

- The specific cryptographic hash function used for Bundle-to-Anchor
  hash construction and content hashing — these belong to
  CRYPTO-SPEC-v1. This specification defines *where* hashes appear
  and *what* they cover. CRYPTO-SPEC-v1 defines *which algorithm*
  produces them.
- The specific digital signature scheme used for credential signing
  — this belongs to CRYPTO-SPEC-v1
- The ledger-specific encoding of Proof Anchors — individual ledger
  implementations may have their own encoding requirements. This
  specification defines the canonical anchor content. Ledger-
  specific encoding is an implementation concern.
- The verification endpoint API by which Bundles are retrieved and
  attestation status is queried — this belongs to INT-SPEC-v1
- The signal annotation data format — the signal annotation fields
  in the Proof Bundle reference PFV-SPEC-v1's canonical annotation
  format

---

## Design Principles

### W3C Verifiable Credentials Alignment

Document 2 establishes that the Proof Bundle is modeled on the W3C
Verifiable Credentials specification. This alignment is structural,
not cosmetic — it means the Proof Bundle uses the W3C VC data model
as its foundation, extending it with HIP-specific fields rather than
inventing a novel schema.

The specific alignment properties:

- The Proof Bundle is a JSON-LD document conforming to the W3C
  Verifiable Credentials Data Model
- The credential subject is the content being attested (identified
  by content hash), not the human holding the credential
- The issuer is the HUMAN-PROOF credential (identified by
  credential identifier)
- HIP-specific fields are defined in a HIP JSON-LD context
  namespace
- Standard VC fields (type, issuanceDate, proof) retain their
  W3C-defined semantics

This alignment provides two practical benefits. First, existing VC
tooling — libraries, validators, wallets — can process HIP Proof
Bundles with minimal adaptation. Second, the W3C VC model has
undergone extensive review for structural completeness and
cryptographic soundness — building on it reduces the risk of
structural omissions in HIP's format.

### Minimal Anchor, Complete Bundle

The on-chain / off-chain split is the governing architectural
constraint. The Proof Anchor must be small enough that ledger
inscription cost does not become a participation barrier (DP-7).
The Proof Bundle must be complete enough that any party with the
Bundle and the Anchor can independently verify the attestation
without trusting any intermediary (DP-4).

This means the Anchor contains only: the Bundle hash (verification
linkage), the credential identifier (who attested), the
classification claim (what was claimed), the content hash (what was
attested to), and the timestamp (when). Everything else — liveness
data, device attestation, editorial statement, pathway reference,
signal annotations — lives in the Bundle.

### Content Referenced, Not Stored

The Proof Bundle references content by cryptographic hash. It does
not contain the content itself. This is a privacy and scalability
commitment:

- A video attestation produces a Proof Bundle measured in kilobytes,
  not gigabytes
- The protocol never stores content — it stores a mathematical
  fingerprint of content that can be compared against the content
  when verification is needed
- Content can be deleted, moved, or modified by the creator without
  affecting the attestation record — the record attests to what the
  content was at the moment of attestation, not where it is now

---

## Proof Bundle Structure

### Encoding

The Proof Bundle is encoded as a JSON-LD document serialized to
canonical JSON (RFC 8785 — JSON Canonicalization Scheme). Canonical
serialization ensures that any implementation producing the same
logical content produces byte-identical output, which is required
for deterministic hash computation.

Character encoding: UTF-8. No BOM.

### Top-Level Structure

```
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://hip.protocol/contexts/v1"
  ],
  "type": ["VerifiableCredential", "HIPAttestationBundle"],
  "version": "<schema_version>",
  "id": "<bundle_identifier>",
  "issuer": { ... },
  "issuanceDate": "<timestamp>",
  "credentialSubject": { ... },
  "attestation": { ... },
  "liveness": { ... },
  "pathway": { ... },
  "signalAnnotations": [ ... ],
  "bundleMetadata": { ... },
  "proof": { ... }
}
```

### Field Definitions — Required Fields

**@context** (required, array of URI strings)
The JSON-LD context declarations. The first element MUST be the W3C
VC context URI. The second element MUST be the HIP context URI for
the schema version indicated in the `version` field. Additional
context URIs MAY be included for extension namespaces.

**type** (required, array of strings)
MUST include "VerifiableCredential" (W3C VC requirement) and
"HIPAttestationBundle" (HIP type identifier). Additional type
strings MAY be included for extension types.

**version** (required, string)
The WF-SPEC schema version under which this Bundle was constructed.
Format: "WF-v<major>.<minor>" (e.g., "WF-v1.0"). The schema version
determines which fields are expected, which are required, and how
the Bundle-to-Anchor hash is constructed. See Schema Versioning
Model below.

**id** (required, string, URI)
A globally unique identifier for this Bundle. Format:
"urn:hip:bundle:<bundle_hash>" where <bundle_hash> is the
hexadecimal-encoded hash of the canonical Bundle content (excluding
the `id` field itself and the `proof` field — see Bundle-to-Anchor
Hash Construction). The id is deterministic — any implementation
can compute it from the Bundle content.

**issuer** (required, object)
The HUMAN-PROOF credential that produced this attestation.

```
"issuer": {
  "id": "<credential_identifier>",
  "type": "HIPCredential",
  "pathwayVersion": "<pathway_version_identifier>",
  "issuanceTier": <1|2|3>
}
```

- `id`: The credential's public identifier (public key fingerprint
  or derived identifier). Format defined in CRYPTO-SPEC-v1. MUST
  NOT contain any information that identifies the human holder.
- `type`: Always "HIPCredential".
- `pathwayVersion`: The pathway version identifier under which this
  credential was issued, in the format defined in this specification
  (see Pathway Version Identifier Format below).
- `issuanceTier`: The tier of the issuance pathway (1, 2, or 3).

**issuanceDate** (required, string, ISO 8601 datetime)
The timestamp of the attestation event. UTC. Format:
"YYYY-MM-DDThh:mm:ssZ". This is the protocol-assigned timestamp,
not a self-reported time from the creator. The timestamp is assigned
by the Steward Node that processes the attestation.

**credentialSubject** (required, object)
The content being attested.

```
"credentialSubject": {
  "id": "urn:hip:content:<content_hash>",
  "contentHash": "<content_hash>",
  "hashAlgorithm": "<algorithm_identifier>",
  "classification": "<classification_claim>",
  "contentType": "<media_type>"
}
```

- `id`: The content identifier, derived from its hash. Format:
  "urn:hip:content:<hexadecimal_content_hash>".
- `contentHash`: The hexadecimal-encoded cryptographic hash of the
  content at the moment of attestation. The content itself is not
  stored. Algorithm specified in CRYPTO-SPEC-v1.
- `hashAlgorithm`: Identifier for the hash algorithm used. Value
  defined in CRYPTO-SPEC-v1.
- `classification`: The creator's attestation category. One of:
  "CompleteHumanOrigin", "HumanOriginAssisted", or "HumanDirectedCollaborative". These are
  the three creator-attested categories. Unattested content
  does not produce Proof Bundles.
- `contentType`: MIME type of the attested content (e.g.,
  "text/plain", "image/jpeg", "video/mp4", "text/html"). Used for
  context in signal analysis — not for content storage or
  processing.

**attestation** (required, object)
The attestation event details.

```
"attestation": {
  "type": "OriginalAttestation" | "CorrectionAttestation"
         | "WithdrawalAttestation",
  "editorialStatement": "<creator_statement>",
  "priorVersion": "<bundle_id_of_prior>" | null,
  "attestationChain": [ ... ] | null
}
```

- `type`: The attestation event type.
  - "OriginalAttestation": First attestation of this content.
  - "CorrectionAttestation": Correction of previously attested
    content. `priorVersion` MUST reference the original Bundle.
  - "WithdrawalAttestation": Withdrawal of a prior attestation.
    `priorVersion` MUST reference the withdrawn Bundle.
- `editorialStatement`: The creator's optional free-text statement
  about the content and the attestation. May be empty string. MUST
  NOT exceed 2000 UTF-8 characters. The protocol records but does
  not evaluate this statement.
- `priorVersion`: For corrections and withdrawals, the `id` of the
  Bundle being corrected or withdrawn. Null for original
  attestations.
- `attestationChain`: For multi-author content using the Attestation
  Chain model (Document 2, Decision 9), an array of attestation
  references from other credential holders who have independently
  attested to this content hash. Null for single-author attestations.
  Each element:

```
{
  "credentialId": "<credential_identifier>",
  "bundleId": "<bundle_identifier>",
  "role": "<attestation_role>"
}
```

  - `role`: Free-text description of the contributor's role (e.g.,
    "author", "editor", "institutional-attestor"). The protocol does
    not define a closed list of roles — the attestation chain records
    what each contributor claimed about their involvement.

**liveness** (required, object)
The liveness verification status at the moment of attestation.

```
"liveness": {
  "method": "DeviceAttestation" | "BehavioralFallback"
           | "LivenessUnverified",
  "deviceAttestation": { ... } | null,
  "behavioralScore": <number> | null,
  "timestamp": "<ISO_8601_datetime>"
}
```

- `method`: The liveness verification method used at attestation
  time.
  - "DeviceAttestation": Hardware-backed liveness confirmation via
    device attestation API. `deviceAttestation` object MUST be
    populated.
  - "BehavioralFallback": Behavioral Liveness Score used as
    fallback. `behavioralScore` MUST be populated.
  - "LivenessUnverified": Neither device attestation nor behavioral
    fallback produced a sufficient liveness signal. This status is
    recorded honestly — the attestation proceeds but the liveness
    gap is visible.
- `deviceAttestation`: When method is "DeviceAttestation", contains
  the device attestation evidence. Structure is specific to the
  device attestation API used and is documented in the pathway's
  External Dependency Register. At minimum:

```
{
  "platform": "<platform_identifier>",
  "attestationToken": "<base64_encoded_token>",
  "tokenVerification": "Verified" | "VerificationFailed"
                      | "VerificationUnavailable"
}
```

  - `platform`: Identifier for the device attestation platform
    (e.g., "apple-app-attest", "android-play-integrity").
  - `attestationToken`: The base64-encoded attestation token from
    the platform. Enables independent verification against the
    platform's public verification infrastructure.
  - `tokenVerification`: The result of the node's own verification
    of the token at attestation time.

- `behavioralScore`: When method is "BehavioralFallback", the BLS
  score computed per PFV-SPEC-v1 Section: Behavioral Liveness Score.
  Integer 0-100.
- `timestamp`: The timestamp of the liveness verification event.
  UTC, ISO 8601. May differ slightly from the attestation timestamp
  if liveness verification is a separate step in the attestation
  flow.

**pathway** (required, object)
The issuance pathway reference for the attesting credential.

```
"pathway": {
  "versionId": "<pathway_version_identifier>",
  "class": "<pathway_class>",
  "tier": <1|2|3>,
  "pathwayState": "Active" | "Watch" | "Declassified"
             | "Retired" | "Archived",
  "pathwayStateTimestamp": "<ISO_8601_datetime>"
}
```

- `versionId`: The pathway version identifier in the format defined
  in this specification (see below). Matches the `pathwayVersion`
  field in `issuer`.
- `class`: The pathway class name (e.g., "DeviceBiometric",
  "GovernmentID", "PeerVouch").
- `tier`: The pathway's tier assignment.
- `pathwayState`: The pathway's lifecycle state at the moment of
  attestation. Active, Watch, and Declassified are PHI-driven
  states per PATHWAY-SPEC-v1. Retired is the post-grace-period
  state for deprecated pathways. Archived is the terminal state
  for long-Declassified pathways. This is a snapshot — the
  pathway's state may subsequently change. The attestation records
  the state as it was, per the temporal integrity principle.
- `pathwayStateTimestamp`: The timestamp of the most recent
  pathway state transition at the moment of attestation.

**proof** (required, object)
The cryptographic proof binding the Bundle to the attesting
credential.

```
"proof": {
  "type": "<signature_type>",
  "created": "<ISO_8601_datetime>",
  "verificationMethod": "<credential_identifier>",
  "proofPurpose": "assertionMethod",
  "proofValue": "<base64_encoded_signature>"
}
```

- `type`: The signature algorithm identifier. Defined in
  CRYPTO-SPEC-v1.
- `created`: Timestamp of signature creation.
- `verificationMethod`: The credential identifier whose public key
  can verify this signature. MUST match `issuer.id`.
- `proofPurpose`: Always "assertionMethod" for attestation Bundles.
- `proofValue`: The base64-encoded digital signature over the
  canonical Bundle content (excluding the `proof` object itself).
  Algorithm and format defined in CRYPTO-SPEC-v1.

### Field Definitions — Optional Fields

**signalAnnotations** (optional, array of objects)
Signal annotations added by PFV analysis at T₀, T₁, or T₂ stages.
The signalAnnotations array is empty when the Bundle is initially
created and its Bundle-to-Anchor hash computed. The T₀ annotation
entry, computed from ledger data available at inscription time (MRS,
TI-W, and CSP per PFV-SPEC-v1 Stage 1), is the first append
operation after Proof Anchor inscription. Because signalAnnotations
is excluded from the Bundle-to-Anchor hash construction, this append
does not affect the on-chain Anchor verification. Subsequent T₁
(72-hour) and T₂ (30-day) entries follow per PFV-SPEC-v1's staged
analysis timelines.

```
"signalAnnotations": [
  {
    "stage": "T0" | "T1" | "T2",
    "timestamp": "<ISO_8601_datetime>",
    "annotations": [
      {
        "signal": "<signal_identifier>",
        "value": <number>,
        "threshold": <number>,
        "thresholdExceeded": <boolean>,
        "note": "<canonical_annotation_text>"
      }
    ],
    "compositeScore": <number>,
    "periodDesignation": "Period1" | "Period2" | "Period3"
  }
]
```

- `stage`: The PFV analysis stage (T₀ at inscription, T₁ at 72
  hours, T₂ at 30 days for provisional Mismatches).
- `annotations`: Array of individual signal results. Each signal
  includes its identifier, computed value, the applicable threshold,
  whether the threshold was exceeded, and the canonical annotation
  note text per PFV-SPEC-v1's classification display reframe.
- `compositeScore`: The PFV composite score at this analysis stage.
- `periodDesignation`: The three-period framework designation per
  PFV-SPEC-v1.

Signal annotation entries are appended per the append model. Prior
stage entries are never modified when later stage entries are added.

For Attestation-Signal Mismatch annotations, the `signalAnnotations`
object MUST support the following additional fields:

- `credentialContext`: object containing credential age, behavioral
  consistency assessment, anomaly status
- `amplificationPattern`: string enum ("third-party", "indeterminate",
  "first-party-pattern") — included at T₁ and T₂ stages when
  determinable
- `attestationPropagationOffset`: duration between attestation
  timestamp and propagation anomaly onset (positive = attestation
  preceded anomaly; negative = anomaly preceded attestation)

These fields are OPTIONAL at T₀ (when data may be insufficient) and
REQUIRED at T₁ and T₂ for ASM-annotated content.

The `threshold` and `thresholdExceeded` fields within individual
signal annotation entries record informational diagnostic context,
not independent annotation trigger thresholds. Signal annotations
are triggered by the composite PFV score exceeding the composite
anomaly threshold defined in PFV-SPEC-v1 (PFV_composite ≥ 2.5
standard, ≥ 3.0 when VHR is null). The per-signal threshold
values correspond to the interpretive range boundaries documented
in PFV-SPEC-v1 for each vector (e.g., VHR > 3.5 for "strong
synthetic propagation signal") and indicate whether the individual
vector's value crossed that diagnostic boundary. These per-signal
values provide diagnostic context for verifiers inspecting the
computation detail; they do not independently determine whether a
signal annotation is applied.

**bundleMetadata** (optional, object)
Operational metadata about the Bundle itself.

```
"bundleMetadata": {
  "processingNode": "<node_identifier>",
  "bundleSize": <integer_bytes>,
  "schemaExtensions": [ "<extension_context_uri>", ... ]
}
```

- `processingNode`: Identifier of the Steward Node that processed
  the attestation and created the Bundle. For audit and
  accountability purposes.
- `bundleSize`: The size of the canonical Bundle in bytes.
- `schemaExtensions`: Any extension context URIs beyond the base
  HIP context, if present.

---

## Proof Anchor Structure

The Proof Anchor is the minimal on-chain record. It contains only
what is necessary for: (a) linking to the off-chain Bundle, (b)
basic query functionality without Bundle retrieval, and (c)
verification that a specific Bundle has not been altered.

### Canonical Anchor Content

```
{
  "type": "HIPProofAnchor",
  "version": "<schema_version>",
  "contentHash": "<content_hash>",
  "credentialId": "<credential_identifier>",
  "classification": "<classification_claim>",
  "timestamp": "<ISO_8601_datetime>",
  "bundleHash": "<bundle_hash>",
  "anchorLink": "<proof_anchor_link_uri>"
}
```

**type**: Always "HIPProofAnchor".

**version**: The WF-SPEC schema version. MUST match the Bundle's
version field.

**contentHash**: The content hash from `credentialSubject.contentHash`.
Duplicated here for on-chain query capability — a verifier can look
up attestations by content hash without retrieving Bundles.

**credentialId**: The credential identifier from `issuer.id`.
Duplicated for on-chain query capability.

**classification**: The classification claim from
`credentialSubject.classification`. Duplicated for on-chain query
capability.

**timestamp**: The attestation timestamp from `issuanceDate`.
Duplicated for on-chain ordering and query capability.

**bundleHash**: The cryptographic hash of the canonical Proof Bundle
(see Bundle-to-Anchor Hash Construction below). This is the
verification linkage — anyone with the Bundle can hash it and compare
to this value to confirm the Bundle has not been altered.

**anchorLink**: The Proof Anchor Link URI that resolves to the
off-chain Bundle. See Proof Anchor Link Format below.

### Anchor Size Budget

The Proof Anchor is designed to fit within approximately **256 bytes**
of application-layer payload (excluding ledger-specific encoding
overhead). This budget constrains the field sizes:

- contentHash: 32 bytes (256-bit hash, hexadecimal = 64 chars)
- credentialId: 32 bytes (256-bit identifier)
- classification: ≤30 chars
- timestamp: 20 chars (ISO 8601)
- bundleHash: 32 bytes (256-bit hash)
- anchorLink: ≤64 chars (compact URI)
- type, version, field names: ~50 chars overhead

Total: approximately 240-250 bytes of structured content. Specific
ledger implementations may require additional encoding overhead;
the application-layer content must remain within this budget to
ensure inscription cost does not become a participation barrier
per DP-7.

---

## Bundle-to-Anchor Hash Construction

The Bundle-to-Anchor hash is the cryptographic link between the
off-chain Bundle and the on-chain Anchor. It must be deterministic
— any implementation that has the same Bundle must produce the same
hash.

### Construction Process

**Step 1 — Canonical Serialization:**
The Proof Bundle is serialized to canonical JSON per RFC 8785 (JSON
Canonicalization Scheme), with the following exclusions:
- The `proof` object is excluded (it is computed over the Bundle
  content, and the Bundle hash must be computable before the proof
  is generated)
- The `id` field is excluded (it is derived from the hash, creating
  a circular dependency if included)
- The `signalAnnotations` array is excluded (annotations are added
  after initial Bundle creation and must not change the Bundle hash
  that was recorded on-chain at inscription)

The resulting byte string is the **canonical Bundle content**.

**Step 2 — Hash Computation:**
The canonical Bundle content is hashed using the algorithm specified
in CRYPTO-SPEC-v1. The output is the **Bundle hash** — a fixed-
length byte string that uniquely identifies this Bundle content.

**Step 3 — Encoding:**
The Bundle hash is encoded as a lowercase hexadecimal string for
inclusion in the Proof Anchor's `bundleHash` field and in the
Bundle's own `id` field (as "urn:hip:bundle:<hex_bundle_hash>").

### Determinism Requirement

Any conforming implementation that processes the same attestation
event must produce the same canonical Bundle content and therefore
the same Bundle hash. This requires:
- Identical field ordering (enforced by RFC 8785)
- Identical value encoding (enforced by RFC 8785)
- Identical character encoding (UTF-8, no BOM)
- Identical inclusion/exclusion of optional fields (empty optional
  fields are omitted, not included as null)

Implementations MUST validate that their serialization produces
byte-identical output to the reference implementation's
serialization for the same logical content.

### Signal Annotation Exclusion Rationale

Signal annotations are excluded from the Bundle hash because they
are added after the initial attestation event — at T₁ (72 hours)
and T₂ (30 days). If annotations changed the Bundle hash, the
on-chain Anchor would no longer verify the Bundle after any signal
analysis update. The Bundle hash verifies the attestation event
itself. Signal annotations are verified through their own integrity
mechanism — each annotation entry carries its own timestamp and the
processing node's signature.

---

## Proof Anchor Link Format

The Proof Anchor Link is a URI that resolves to the off-chain Proof
Bundle. It must be compact (to fit within the Anchor size budget),
stable (to remain valid as the hosting infrastructure evolves), and
resolvable through the distributed Steward Node network.

### URI Format

```
hip://<bundle_hash_prefix>/<bundle_hash>
```

- **Scheme**: `hip` — a protocol-specific URI scheme. Resolvers map
  this scheme to the appropriate Steward Node endpoint.
- **bundle_hash_prefix**: The first 8 characters of the Bundle hash.
  Used for distributed routing — nodes can determine whether they
  host a Bundle based on hash prefix without retrieving the full
  record.
- **bundle_hash**: The full hexadecimal Bundle hash.

Example: `hip://a3f8c921/a3f8c92104bf7e2d...` (truncated for
illustration; full hash in production)

### Resolution Process

A resolver (any software that needs to retrieve a Bundle from a
Proof Anchor Link) follows this process:

1. Parse the `hip://` URI to extract the Bundle hash
2. Query any known Steward Node's Bundle retrieval endpoint with
   the Bundle hash
3. The node returns the Bundle if it hosts a copy, or returns a
   redirect to a node that does (see Proof Bundle Hosting
   Architecture below)
4. The resolver verifies the retrieved Bundle by hashing it and
   comparing the result to the `bundleHash` in the Proof Anchor

Step 4 is the critical integrity check. A resolver MUST NOT accept
a Bundle whose hash does not match the on-chain Anchor. A mismatch
indicates either corruption or tampering — the Bundle is invalid
regardless of its content.

### Fallback Resolution

If the `hip://` scheme is not resolvable (resolver does not support
the scheme, no known nodes are available), implementations MAY
provide HTTP-based fallback resolution through well-known URLs:

```
https://<node_domain>/.well-known/hip/bundles/<bundle_hash>
```

The HTTP fallback provides the same Bundle content. The same hash
verification applies. The `hip://` scheme is preferred because it
is implementation-independent; the HTTP fallback is provided for
practical interoperability during early adoption when `hip://`
resolver support may not be universal.

---

## Pathway Version Identifier Format

PATHWAY-SPEC-v1 defines pathway versioning conceptually. This
section specifies the wire-level format of pathway version
identifiers as they appear in Proof Bundles and on the ledger.

### Format

```
<PathwayClass>-<VersionNumber>-<ApprovalDate>
```

- **PathwayClass**: A short alphanumeric identifier for the pathway
  class. Assigned by the OC at pathway class registration.
  Lowercase, no spaces, hyphens only within the class name
  component. Maximum 32 characters. Examples: "device-biometric",
  "gov-id", "peer-vouch", "institutional-sponsor".
- **VersionNumber**: Semantic version in the format "vN.M" where N
  is the major version and M is the minor version. Major version
  increments indicate material changes to the verification mechanism.
  Minor version increments indicate operational or documentation
  changes that do not affect assurance properties.
- **ApprovalDate**: The date of OC approval in "YYYYMMDD" format.

Example: `device-biometric-v1.0-20260915`

**Parsing rule:** The three components are delimited by hyphens.
The VersionNumber component is identified by the prefix "v"
followed by a digit (matching the pattern `v[0-9]+\.[0-9]+`).
The ApprovalDate component is the final eight-digit numeric
segment (matching the pattern `[0-9]{8}`). All hyphen-delimited
segments preceding the VersionNumber constitute the PathwayClass.
Example parse: `device-biometric-v1.0-20260915` → PathwayClass:
`device-biometric`, VersionNumber: `v1.0`, ApprovalDate:
`20260915`.

### Uniqueness

The combination of PathwayClass + VersionNumber + ApprovalDate is
globally unique. No two approved pathway versions may share the same
identifier. The OC is responsible for ensuring uniqueness at the time
of approval.

### Identifier Permanence

Once assigned, a pathway version identifier is permanent. It is never
reassigned, recycled, or modified. A Declassified pathway version
retains its identifier in Archived state. The identifier appears in
every credential's issuance record and every Proof Bundle — changing
it would break referential integrity across the ledger.

---

## Schema Versioning Model

### Purpose

The wire format will evolve. New fields may be needed as the protocol
matures. Optional fields may become required. New attestation event
types may be defined. The schema versioning model ensures that this
evolution does not break backward compatibility — older Bundles
remain verifiable under newer implementations, and older
implementations can process the required fields of newer Bundles
even if they do not recognize all optional extensions.

### Version Numbering

Schema versions follow the format "WF-v<major>.<minor>":

- **Major version** increments when a change would cause an
  implementation that only understands the prior major version to
  produce incorrect verification results. Examples: changing a
  required field's semantics, removing a required field, changing
  the Bundle-to-Anchor hash construction.
- **Minor version** increments when a change adds new optional
  fields or capabilities without affecting the processing of
  existing fields. An implementation that does not understand a
  minor version increment can still correctly verify Bundles at
  that version — it simply ignores fields it does not recognize.

### Backward Compatibility Rules

**Rule 1 — Required fields are permanent.** A field that is required
in version WF-v1.0 remains required in all subsequent versions
within major version 1. Required fields may be added in minor
version increments (implementations that predate the field ignore
it), but existing required fields may not be removed or have their
semantics changed without a major version increment.

**Rule 2 — Hash construction is frozen within major versions.** The
Bundle-to-Anchor hash construction — which fields are included, the
serialization order, the exclusion list — is fixed for the lifetime
of a major version. Any change to hash construction requires a major
version increment because it would cause existing Anchors to fail
verification against existing Bundles.

**Rule 3 — Unknown fields are preserved, not rejected.** A
conforming implementation that encounters a field it does not
recognize (from a newer minor version or an extension namespace)
MUST preserve the field in any Bundle it retransmits or stores.
It MUST NOT reject a Bundle solely because it contains unrecognized
fields. It MAY ignore unrecognized fields in its own processing.

**Rule 4 — Major version transitions require dual support.** When
a major version increment occurs, implementations MUST support both
the prior and current major versions for a transition period of at
least **365 calendar days**. During this period, implementations
MUST be able to verify Bundles at either major version. After the
transition period, support for the prior major version is optional.

---

## Proof Bundle Hosting Architecture

### The Problem

The Proof Bundle is the complete attestation record. It lives
off-chain. It must be retrievable by any verifier who encounters a
Proof Anchor. If the Bundle is not available, the Anchor is an
unverifiable pointer — the attestation exists on-chain but its
evidence cannot be examined.

Document 2 specifies that Bundles are "independently hostable." CDI-6
identifies the practical problem: who hosts at Genesis? Creator
self-hosting is unrealistic. A dedicated hosting service is a paid
dependency that violates DP-7. The hosting architecture must be
distributed, redundant, zero-cost to the protocol, and resilient to
individual node failure.

### Hosting as a Steward Node Function

Proof Bundle hosting is a core function of Steward Nodes. Every
Steward Node that participates in the HIP network MUST host Proof
Bundles and serve them in response to retrieval requests. This is
not an optional add-on — it is part of what it means to be a
Steward Node.

This works because Steward Nodes are operated by institutions that
benefit from the protocol's operation (DP-7, DP-8). The storage
cost of hosting Bundles is part of the node's operational investment
— the same investment that covers ledger operation, verification
endpoint hosting, and signal data processing. Institutions operate
Steward Nodes because doing so serves their institutional interest.
Bundle hosting is included in that function.

### Redundancy Requirements

**Minimum replication:** Every Proof Bundle MUST be hosted by a
minimum of **three (3)** Steward Nodes. The processing node (the
node that created the Bundle upon receiving the attestation) is one
of the three. The remaining copies are distributed to other nodes
through the Bundle replication protocol.

**Replication protocol:** When a Steward Node creates a new Proof
Bundle, it distributes the Bundle to peer nodes. The distribution
mechanism is implementation-specific (gossip protocol, direct push,
pull synchronization), but the result must satisfy the three-node
minimum within **24 hours** of Bundle creation.

**Ongoing replication monitoring:** Nodes periodically verify that
the Bundles they are responsible for remain available at the
required replication count. If a node determines that a Bundle's
replication count has dropped below three (due to a peer node going
offline, a node leaving the network, or data loss), it initiates
re-replication to restore the minimum count.

**No single-point-of-failure:** The three-node minimum ensures that
the failure of any single node does not make any Bundle unavailable.
At network scales beyond Genesis (many nodes), replication counts
will naturally exceed three as nodes synchronize their holdings.

### Storage Cost Model

Bundles are metadata documents, not content repositories. The design
constraints in this specification (content referenced by hash, not
stored; editorial statement capped at 2000 characters; structured
data in JSON-LD) produce Bundle sizes in the **1–5 kilobyte range**
for typical attestations.

At this size, the storage cost per Bundle is negligible:

- 1 million Bundles at 5 KB each = 5 GB of storage per node
- 10 million Bundles = 50 GB per node
- 100 million Bundles = 500 GB per node

Even at extreme scale, Bundle storage is within the capacity of
commodity hardware. Storage cost does not become a participation
barrier for Steward Nodes at any realistic adoption level.

Signal annotations added at T₁ and T₂ increase Bundle size by an
estimated 200–500 bytes per analysis stage. The cost impact is
similarly negligible.

### Bundle Retrieval Protocol

When a resolver requests a Bundle (via `hip://` URI or HTTP
fallback):

**If the queried node hosts the Bundle:** Return the Bundle directly.

**If the queried node does not host the Bundle:** The node queries
its peer network to locate a node that does, and either:
- Returns an HTTP redirect to a node that hosts the Bundle, or
- Proxies the retrieval and returns the Bundle to the resolver

The choice between redirect and proxy is implementation-specific.
Redirect is more efficient (avoids double transfer). Proxy is
simpler for the resolver (single request-response). Implementations
MAY support both and choose based on context.

**If no node in the network hosts the Bundle:** Return a "Bundle
Not Available" response. This should be a rare condition given the
replication requirements, but the protocol must handle it gracefully.
The Proof Anchor remains valid on-chain — the attestation happened.
The Bundle's unavailability means the full evidence record cannot
currently be examined, not that the attestation is invalid.

### Bundle Immutability and Append Operations

The core Bundle content (everything hashed in the Bundle-to-Anchor
construction) is immutable. Once created and anchored, it cannot be
modified.

Signal annotations are the one append operation. When PFV analysis
produces annotations at T₁ or T₂, the annotation data is appended
to the Bundle's `signalAnnotations` array. This append does not
change the Bundle hash (annotations are excluded from hash
construction). The annotation entry is signed by the processing
node to provide its own integrity chain.

Hosting nodes that receive annotation updates MUST apply them to
their stored copies. An annotation update is not a Bundle
modification — it is additional data attached to an immutable base.

### Creator-Initiated Hosting

While Steward Node hosting is the protocol's primary infrastructure,
the protocol does not prohibit additional hosting:

- Creators MAY host their own Bundles at any URL of their choosing.
  A creator's self-hosted Bundle is verifiable by the same
  hash-comparison mechanism — the Proof Anchor provides the ground
  truth.
- Institutions MAY host Bundles for content attested through their
  workflows.
- Third-party services MAY offer Bundle hosting as a value-added
  service built on HIP.

None of these additional hosting options are required by the
protocol. They are permitted by DP-5 (Permissionless Proliferation).
The Steward Node network is the guaranteed baseline availability.

---

## Proof Bundle Size Constraints

### Design Goal

Proof Bundles should remain in the **1–10 kilobyte range** for
typical attestations. This constraint is a design goal, not a hard
enforcement limit — the protocol does not reject Bundles that exceed
it. But it governs design decisions throughout this specification:

- Content is referenced by hash, not stored
- Editorial statements are capped at 2000 characters
- Device attestation tokens are the primary size variable (typically
  200–1000 bytes depending on platform)
- Signal annotations are compact structured data
- No binary attachments, images, or media content in the Bundle

### Size Budget (Typical Single-Author Attestation)

| Component | Estimated Size |
|---|---|
| JSON-LD structure and context | ~200 bytes |
| issuer object | ~150 bytes |
| credentialSubject object | ~200 bytes |
| attestation object (minimal editorial statement) | ~300 bytes |
| liveness object (device attestation) | ~500 bytes |
| pathway object | ~150 bytes |
| proof object | ~300 bytes |
| **Subtotal (at creation)** | **~1,800 bytes** |
| Signal annotations (T₀) | ~300 bytes |
| Signal annotations (T₁) | ~300 bytes |
| Signal annotations (T₂, if applicable) | ~300 bytes |
| **Subtotal (fully annotated)** | **~2,700 bytes** |

Attestation Chain entries for multi-author content add approximately
100 bytes per additional attestor. A 10-author institutional
attestation would add ~1,000 bytes, bringing the total to ~3,700
bytes — still well within the design goal.

---

## Implementation Requirements

Any HIP-conforming implementation MUST:

- Produce Proof Bundles conforming to the structure and field
  definitions in this specification
- Serialize Bundles to canonical JSON per RFC 8785
- Compute Bundle-to-Anchor hashes using the construction defined
  in this specification with the algorithm specified in CRYPTO-SPEC-v1
- Include all required fields in every Proof Bundle
- Encode pathway version identifiers in the format defined in this
  specification
- Verify retrieved Bundles against their Proof Anchor by hash
  comparison before accepting them as valid
- Preserve unknown fields when retransmitting or storing Bundles
  (forward compatibility)
- Maintain Proof Bundle hosting with minimum three-node replication
  if operating as a Steward Node

Implementations MUST NOT:

- Store content in the Proof Bundle (content is referenced by hash
  only)
- Modify the core Bundle content after Proof Anchor inscription
- Include human-identifying information in any Bundle field
  (credential identifiers only)
- Reject Bundles solely because they contain unrecognized fields
  from a newer minor version or extension namespace
- Present a Bundle as valid without verifying its hash against the
  corresponding Proof Anchor
- Remove or modify signal annotation entries (append model — entries
  are additive and permanent)

Implementations MAY:

- Add extension fields in a registered extension namespace
- Support additional serialization formats for transport, provided
  canonical JSON remains the normative format for hash computation
- Host Bundles at replication counts exceeding the three-node minimum
- Implement caching, CDN distribution, or other performance
  optimizations for Bundle retrieval, provided the served content
  is identical to the canonical Bundle

---

## Consistency with Parent Documents

This specification was drafted against and is consistent with:

- **Document 2: Attestation Architecture Decision**, which
  established the Proof Bundle / Proof Anchor split, the W3C VC
  alignment, the content hash model, and the independent
  verifiability requirement. The Bundle structure defined here
  implements Document 2's architectural decisions.

- **Document 1: HIP Core Definitions**, which defined the six-category
  system. The `classification` field in this specification uses the
  three creator-attested category identifiers from Document 1.

- **Document 3: HUMAN-PROOF Scope Statement**, which defined the
  credential model. The `issuer` object in this specification
  references credentials as defined in Document 3 and HP-SPEC-v1.

- **HP-SPEC-v1**, which defined liveness requirements and credential
  structure. The `liveness` object in this specification encodes the
  liveness verification result per HP-SPEC-v1's requirements.

- **PATHWAY-SPEC-v1**, which defined pathway versioning. The pathway
  version identifier format in this specification is the wire-level
  encoding of PATHWAY-SPEC-v1's versioning model.

- **PFV-SPEC-v1**, which defined the staged analysis model and
  classification display reframe. The `signalAnnotations` structure
  in this specification encodes PFV-SPEC-v1's analysis outputs per
  the display reframe framework.

- **Section 12: Deployment Philosophy**, particularly DP-1 (the
  Bundle format supports single-actor utility), DP-5 (the format
  is public and any actor may build tools to produce or consume it),
  DP-7 (the Anchor size budget prevents inscription cost from
  becoming a participation barrier; hosting is a distributed node
  function), and DP-8 (hosting is distributed across independent
  nodes, not centralized in an entity).

Where this specification addresses cases not explicitly resolved by
the parent documents, it has done so in a manner consistent with the
governing principles those documents establish. Specifically:

- The Bundle-to-Anchor hash construction (excluding proof, id, and
  signalAnnotations) is this specification's resolution of the
  practical challenge of deterministic hashing in a document that
  contains fields computed from its own hash and fields added
  after inscription
- The schema versioning model is new to this specification,
  addressing format evolution not explicitly covered in Document 2
- The Proof Bundle hosting architecture resolves CDI-6 by
  establishing Bundle hosting as a Steward Node function with
  defined replication requirements, consistent with DP-7 and DP-8
- The Proof Anchor Link format (hip:// URI scheme) is this
  specification's resolution of the link mechanism Document 2
  describes conceptually

The parent documents control in any conflict.

---

## Open Items

**Resolved — CDI-6: Proof Bundle hosting architecture:**
Bundle hosting is a core Steward Node function with three-node
minimum replication. Storage cost is negligible at any realistic
scale due to the kilobyte-range Bundle size constraint (content
referenced by hash, not stored). The hosting model is consistent
with DP-7 (zero cost to the protocol — nodes host as part of their
operational investment) and DP-8 (distributed across independent
nodes, not centralized). Rationale: the off-chain Bundle must be
reliably available for the on-chain Anchor to be useful. Steward
Nodes already operate ledger and verification infrastructure;
Bundle hosting is a natural extension of that function at negligible
marginal cost.

**Resolved — CRYPTO-SPEC-v1 dependencies:**
This specification references CRYPTO-SPEC-v1 for: the content hash
algorithm (SHA-256), the Bundle-to-Anchor hash algorithm (SHA-256),
the credential identifier derivation (SHA-256 of Ed25519 public key),
and the digital signature scheme (Ed25519). All algorithm selections
are resolved in CRYPTO-SPEC-v1. No structural change to this
specification was required — CRYPTO-SPEC-v1 fills in algorithm
identifiers; WF-SPEC-v1 defines where they are used.

**Deferred — Ledger-specific Anchor encoding:**
The canonical Proof Anchor content is defined. The encoding of that
content into a specific ledger's transaction format is implementation-
specific and not defined here. Implementations targeting specific
ledgers will need encoding guidance, which may be provided in a
ledger-specific implementation guide or as an appendix to this
specification.

---

*WF-SPEC-v1: Proof Bundle Wire Format Specification — WORKING DRAFT.
CDI-6 (Proof Bundle hosting) resolved. CRYPTO-SPEC-v1 dependencies
pending. Derived from Document 2 (Attestation Architecture), Document
1 (Core Definitions), Document 3 (HUMAN-PROOF Scope Statement),
HP-SPEC-v1, PATHWAY-SPEC-v1, PFV-SPEC-v1, and Section 12 (Deployment
Philosophy).*
