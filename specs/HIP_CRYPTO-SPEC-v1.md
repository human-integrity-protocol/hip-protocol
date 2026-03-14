# HIP — Human Integrity Protocol
## CRYPTO-SPEC-v1: Cryptographic Primitives Specification
### WORKING DRAFT | 2026-03-01 | Pre-inscription

---

## Authority and Status

This specification derives its authority from and must remain
consistent with:

- **Document 2: Attestation Architecture Decision** — the governing
  architectural decisions establishing the cryptographic verification
  model, the content hash model, and the independent verifiability
  requirement
- **WF-SPEC-v1: Proof Bundle Wire Format Specification** — which
  defines the fields where cryptographic outputs appear and defers
  algorithm selection to this specification
- **INT-SPEC-v1: Integration Specification** — which defines the
  VEPA sourceToken mechanism and defers the HMAC algorithm to this
  specification
- **HP-SPEC-v1: HUMAN-PROOF Credential Mechanics Specification** —
  which defines the credential model and the public/private key
  relationship underlying credential signatures
- **Section 12: Deployment Philosophy** — particularly DP-1 (Day-
  One Utility), DP-5 (Permissionless Proliferation), and DP-7
  (Zero Institutional Cost)
- **HIP Genesis Covenant Charter v1.0** — the covenant
  document

In any conflict between this specification and the documents listed
above, the parent document controls.

This specification is a companion document. It is not part of the
Genesis inscription. Cryptographic algorithm selection may evolve
as the threat landscape changes. Algorithm transitions are governed
by the versioning model defined here and by WF-SPEC-v1's schema
versioning rules.

---

## Purpose

CRYPTO-SPEC-v1 specifies the cryptographic algorithms used
throughout the HIP protocol. WF-SPEC-v1 defines where hashes,
signatures, and identifiers appear. INT-SPEC-v1 defines where
HMACs are used for privacy. HP-SPEC-v1 defines the credential key
model. This specification defines which algorithms produce them.

Cryptographic selection is a design decision with long-term
consequences. The algorithms chosen here will be embedded in every
Proof Bundle, every Proof Anchor, every credential identifier, and
every verification operation for the lifetime of the protocol's
first major version. They must be secure against known attacks,
widely implemented in standard libraries, and efficient enough that
cryptographic overhead does not become a participation barrier
(DP-7).

This specification covers five cryptographic functions:

1. **Content hashing** — the algorithm that produces the content
   hash in `credentialSubject.contentHash`
2. **Bundle-to-Anchor hashing** — the algorithm that produces the
   `bundleHash` linking the Proof Anchor to the Proof Bundle
3. **Credential identifier derivation** — the algorithm that
   derives the public credential identifier from the credential
   key pair
4. **Digital signature scheme** — the algorithm used for credential
   signatures in the `proof` object
5. **HMAC for privacy mechanisms** — the algorithm used for VEPA
   sourceTokens and contributor identity isolation

---

## Design Principles

### Conservative Selection

HIP selects algorithms that are widely deployed, extensively
analyzed, and supported by standard cryptographic libraries in
every major programming language and platform. Novel or cutting-
edge algorithms — however promising — introduce implementation
risk and reduce the pool of implementations that can conform to
the protocol. Where multiple algorithms provide equivalent
security, the more widely deployed algorithm is preferred.

### Agility Through Versioning

Cryptographic algorithms have finite lifetimes. CRYPTO-SPEC-v1
defines the algorithms for WF-SPEC major version 1. When
algorithms need replacement (due to cryptanalytic advances,
performance improvements, or regulatory requirements), a new
CRYPTO-SPEC version is issued alongside a WF-SPEC major version
increment. The WF-SPEC-v1 schema versioning model's dual-support
transition period (365 days minimum) ensures that algorithm
transitions do not break existing attestation verification.

Algorithm identifiers are always explicit in the wire format.
WF-SPEC-v1 includes `hashAlgorithm` in `credentialSubject` and
`type` in `proof`. A verifier always knows which algorithm was
used and can select the appropriate verification path.

### No Custom Cryptography

HIP does not define novel cryptographic constructions. Every
algorithm specified here is a published standard implemented in
widely available libraries. Implementations MUST use standard
library implementations, not custom implementations, of the
specified algorithms.

---

## Content Hash Algorithm

### Purpose

The content hash uniquely identifies the content being attested.
It appears in `credentialSubject.contentHash` (WF-SPEC-v1),
`credentialSubject.id` (as part of the URN), and in the Proof
Anchor's `contentHash` field. It is the cryptographic fingerprint
by which the protocol references content without storing it.

### Algorithm Selection

**Algorithm:** SHA-256 (SHA-2 family, 256-bit output)

**Standard:** FIPS 180-4 / RFC 6234

**Algorithm identifier for wire format:** `"sha-256"`

This value is used in the `hashAlgorithm` field of
`credentialSubject` in the Proof Bundle (WF-SPEC-v1).

### Rationale

SHA-256 is the most widely deployed cryptographic hash function.
It is implemented in every major programming language's standard
library, every major operating system's cryptographic API, and
every major hardware security module. It provides 128-bit
collision resistance and 256-bit preimage resistance, both well
above any foreseeable attack capability for the purpose of content
identification.

SHA-3 (Keccak) was considered. SHA-3 provides equivalent security
and is a distinct algorithmic family (providing defense-in-depth
against a SHA-2 family break). However, SHA-3 is less widely
deployed in existing tooling, particularly in embedded and mobile
environments where HIP attestation occurs. The practical benefit
of SHA-256's universal availability outweighs the theoretical
benefit of algorithmic diversity at this time.

If SHA-2 family weaknesses are discovered, CRYPTO-SPEC-v2 will
specify SHA-3-256 as the replacement, with a WF-SPEC major
version increment and the standard transition period.

### Computation

Content hashing applies to the raw content bytes. For text
content, the input is the UTF-8 encoded byte sequence. For binary
content (images, video, audio), the input is the raw byte
sequence of the file.

```
content_hash = SHA-256(content_bytes)
```

Output: 32 bytes (256 bits), encoded as 64 lowercase hexadecimal
characters in the wire format.

### Content Normalization

The content hash is computed over the exact bytes of the content
at the moment of attestation. The protocol does not normalize
content before hashing. If two byte-level-different representations
of the "same" content (e.g., same image at different compression
levels) are attested, they produce different content hashes and
are treated as different content.

This is intentional. Normalization introduces complexity,
ambiguity, and potential for manipulation. The creator attests
to a specific bit-identical artifact. The verifier can confirm
that the artifact they hold matches the attested artifact by
computing the same hash. If the artifact has been modified
(recompressed, reformatted, cropped), the hash will not match,
and the verifier knows the artifact differs from what was attested.

---

## Bundle-to-Anchor Hash Algorithm

### Purpose

The Bundle-to-Anchor hash links the off-chain Proof Bundle to the
on-chain Proof Anchor. It is the verification mechanism by which
any party can confirm that a retrieved Bundle matches the Anchor.
It appears in the Proof Anchor's `bundleHash` field and in the
Proof Bundle's `id` field (as part of the URN).

### Algorithm Selection

**Algorithm:** SHA-256 (SHA-2 family, 256-bit output)

**Standard:** FIPS 180-4 / RFC 6234

The same algorithm as content hashing. Using the same algorithm
for both content hashing and Bundle hashing simplifies
implementation — conforming implementations need only one hash
algorithm.

### Computation

The Bundle-to-Anchor hash is computed per WF-SPEC-v1's
construction process:

1. Serialize the Proof Bundle to canonical JSON (RFC 8785),
   excluding the `proof` object, the `id` field, and the
   `signalAnnotations` array
2. Compute SHA-256 over the resulting byte string
3. Encode as 64 lowercase hexadecimal characters

```
canonical_content = RFC8785_serialize(bundle, exclude=[proof, id, signalAnnotations])
bundle_hash = SHA-256(canonical_content)
hex_bundle_hash = lowercase_hex(bundle_hash)
```

The Bundle's `id` is then: `"urn:hip:bundle:<hex_bundle_hash>"`

The Proof Anchor's `bundleHash` is: `"<hex_bundle_hash>"`

---

## Credential Identifier Derivation

### Purpose

The credential identifier is the public reference for a HUMAN-
PROOF credential. It appears in `issuer.id` (WF-SPEC-v1), in
`proof.verificationMethod`, in the Proof Anchor's `credentialId`,
and in all credential-referencing fields across the protocol.

The credential identifier MUST be deterministically derivable from
the credential's public key, so that any party with the public key
can compute the identifier without a directory lookup.

The credential identifier MUST NOT contain any information that
identifies the human holder (WF-SPEC-v1, HP-SPEC-v1).

### Algorithm Selection

**Derivation method:** SHA-256 hash of the credential's public
key, encoded in the wire format specified below.

**Process:**

1. Serialize the credential's public key to its canonical byte
   representation (algorithm-specific — see Digital Signature
   Scheme below for the public key format)
2. Compute SHA-256 over the public key bytes
3. Encode as 64 lowercase hexadecimal characters

```
credential_id = lowercase_hex(SHA-256(public_key_bytes))
```

The credential identifier in the wire format is the 64-character
hexadecimal string. In URN contexts it appears as part of URN
schemes defined by the consuming specification.

### Rationale

A hash of the public key provides a fixed-length, deterministic
identifier that is:

- **Pseudonymous:** No identity information. The identifier is
  derived solely from the cryptographic key material.
- **Verifiable:** Anyone with the credential's public key can
  confirm the identifier by recomputing the hash.
- **Collision-resistant:** SHA-256 provides 128-bit collision
  resistance. The probability of two distinct credentials
  producing the same identifier is negligibly small.
- **Compact:** 32 bytes (64 hex characters), consistent with the
  Proof Anchor's size budget.

### Key Rotation

When a credential undergoes key rotation (HP-SPEC-v1, Credential
Portability), the credential identifier changes because it is
derived from the new public key. The protocol records the rotation
event linking the old and new identifiers, preserving attestation
history continuity. The mechanism for recording key rotation
linkage is defined in HP-SPEC-v1.

---

## Digital Signature Scheme

### Purpose

The digital signature proves that the holder of a specific
credential's private key authorized a specific attestation. It
appears in the `proof` object of the Proof Bundle (WF-SPEC-v1).
The signature scheme is also used for credential authentication
tokens in the attestation submission API (INT-SPEC-v1).

### Algorithm Selection

**Algorithm:** Ed25519 (EdDSA over Curve25519)

**Standard:** RFC 8032

**Algorithm identifier for wire format:** `"Ed25519Signature2020"`

This value is used in the `proof.type` field of the Proof Bundle
(WF-SPEC-v1), aligning with the W3C Verifiable Credentials
cryptographic suite naming convention.

### Rationale

Ed25519 is selected for the following properties:

**Security:** 128-bit security level. Equivalent to RSA-3072 or
ECDSA-P256 in security, with a stronger resistance model against
implementation-level side-channel attacks due to its deterministic
signature generation (no random nonce that, if biased, leaks the
private key).

**Performance:** Ed25519 signature generation and verification are
among the fastest of any widely deployed scheme. Verification is
approximately 3x faster than ECDSA-P256. This matters for Steward
Nodes that verify signatures at scale.

**Key and signature compactness:** Public keys are 32 bytes.
Signatures are 64 bytes. Both fit comfortably within the Proof
Anchor and Proof Bundle size budgets.

**Determinism:** Ed25519 signatures are deterministic — the same
message signed with the same key always produces the same
signature. This eliminates an entire class of implementation
vulnerabilities related to nonce generation.

**Implementation availability:** Ed25519 is implemented in
libsodium (available on every platform), OpenSSL 1.1+, Go's
standard library, Python's cryptography package, JavaScript's
noble-ed25519, Rust's ed25519-dalek, and every major HSM. It is
one of the most widely available modern signature schemes.

**W3C VC compatibility:** The Ed25519Signature2020 cryptographic
suite is a defined W3C Verifiable Credentials proof type, ensuring
interoperability with existing VC tooling.

### ECDSA-P256 Consideration

ECDSA over P-256 (secp256r1) was considered. P-256 has broader
hardware support (particularly in older HSMs and secure enclaves)
and is mandated in some government PKI frameworks. However, ECDSA
requires a random nonce per signature, and nonce bias has been the
source of real-world key compromise. Ed25519's deterministic
signatures eliminate this risk entirely.

If regulatory requirements in specific jurisdictions mandate P-256,
conforming implementations in those jurisdictions MAY additionally
support ECDSA-P256 as a second signature scheme, provided Ed25519
remains the primary scheme and the implementation correctly handles
both verification paths. This dual-support option would be
formalized in a future minor version of this specification if
demand materializes.

### Signature Computation

The signature is computed over the canonical Bundle content as
defined by WF-SPEC-v1 — the same byte string used for Bundle-to-
Anchor hash computation (canonical JSON excluding `proof`, `id`,
and `signalAnnotations`).

```
signature = Ed25519_Sign(private_key, canonical_content)
proof_value = base64_encode(signature)
```

The `proof` object in the Proof Bundle:

```json
{
  "type": "Ed25519Signature2020",
  "created": "<ISO_8601_datetime>",
  "verificationMethod": "<credential_identifier>",
  "proofPurpose": "assertionMethod",
  "proofValue": "<base64_encoded_64_byte_signature>"
}
```

### Verification

A verifier confirms the signature by:

1. Retrieving the credential's public key (from the protocol's
   credential registry, identified by `verificationMethod`)
2. Computing the canonical Bundle content (same exclusions as
   hash computation)
3. Verifying the Ed25519 signature over the canonical content
   using the public key

```
is_valid = Ed25519_Verify(public_key, canonical_content, base64_decode(proof_value))
```

### Public Key Serialization

The credential's public key is serialized as the raw 32-byte
Ed25519 public key. In contexts where a text representation is
needed (e.g., credential registry entries), the key is encoded
as 64 lowercase hexadecimal characters or as base64.

The credential identifier is derived from this serialized public
key per the Credential Identifier Derivation section above.

### Authentication Token for Attestation Submission

INT-SPEC-v1's attestation submission API uses a credential-signed
authentication token. The token format:

```
token_payload = credential_id || ":" || ISO_8601_timestamp || ":" || random_nonce
auth_token = base64(token_payload || "." || Ed25519_Sign(private_key, token_payload))
```

Where `random_nonce` is 16 bytes of cryptographically secure
random data encoded as hexadecimal. The timestamp MUST be within
300 seconds (5 minutes) of the receiving node's current time.
The nonce prevents replay attacks within the timestamp window.

---

## HMAC Algorithm for Privacy Mechanisms

### Purpose

INT-SPEC-v1 defines the sourceToken mechanism for VEPA (anonymized
query source counting) and contributor identity isolation. Both
mechanisms use keyed HMAC with per-computation-window key rotation.

### Algorithm Selection

**Algorithm:** HMAC-SHA-256

**Standard:** RFC 2104 / FIPS 198-1

### Computation

For VEPA sourceTokens:

```
source_token = HMAC-SHA-256(window_key, source_identifier)
```

Where:
- `window_key` is a 32-byte cryptographically random key generated
  at the start of each PFV computation cycle and held only by the
  Query Service (Subsystem A)
- `source_identifier` is the IP address or API key of the querying
  entity

For contributor identity isolation:

```
contributor_index = HMAC-SHA-256(cycle_key, contributor_token)
```

Where:
- `cycle_key` is a 32-byte cryptographically random key generated
  at the start of each aggregation cycle
- `contributor_token` is the contributor's registered token

Output: The full 32-byte HMAC output, encoded as 64 lowercase
hexadecimal characters. Truncation is not applied — the full
output preserves distinct-source counting accuracy.

### Key Generation and Rotation

Keys for both mechanisms MUST be generated using a
cryptographically secure random number generator (CSPRNG). Keys
MUST NOT be derived from predictable inputs (timestamps, node
identifiers, or sequential counters).

Key rotation occurs at the start of each computation window:
- VEPA sourceToken keys: every 7 days (standard PFV cycle) or
  every 3 days (Watch-accelerated cycle)
- Contributor identity keys: every aggregation cycle (aligned
  with the PFV computation cycle)

Previous-window keys MUST be securely deleted after rotation.
They serve no purpose after the window closes, and their
retention would enable cross-window linkability that the
architecture is designed to prevent.

### Rationale

HMAC-SHA-256 is the standard keyed hash construction. It inherits
SHA-256's universal availability. It provides the three properties
the privacy mechanisms require:

1. **Determinism within a key:** Same input + same key = same
   output. Required for within-window distinct counting.
2. **Pseudorandomness:** Without the key, the output is
   indistinguishable from random. Subsystem B cannot infer
   source identity from the token.
3. **Key-dependent:** Different key = different output for the
   same input. Key rotation ensures cross-window unlinkability.

---

## Algorithm Summary

| Function | Algorithm | Identifier | Output Size | Standard |
|---|---|---|---|---|
| Content hash | SHA-256 | `"sha-256"` | 32 bytes (64 hex) | FIPS 180-4 |
| Bundle-to-Anchor hash | SHA-256 | (same) | 32 bytes (64 hex) | FIPS 180-4 |
| Credential ID derivation | SHA-256(pubkey) | — | 32 bytes (64 hex) | FIPS 180-4 |
| Digital signature | Ed25519 | `"Ed25519Signature2020"` | 64 bytes | RFC 8032 |
| Public key | Ed25519 | — | 32 bytes | RFC 8032 |
| HMAC (privacy) | HMAC-SHA-256 | — | 32 bytes (64 hex) | RFC 2104 |

### Size Impact on Proof Anchor

The Proof Anchor's 256-byte application-layer budget (WF-SPEC-v1):

- contentHash: 64 hex chars (32 bytes of hash)
- credentialId: 64 hex chars (32 bytes of hash)
- bundleHash: 64 hex chars (32 bytes of hash)
- classification: ≤30 chars
- timestamp: 20 chars
- anchorLink: ≤64 chars
- type, version, field names: ~50 chars

Total: ~240-250 bytes. Consistent with WF-SPEC-v1's budget.

### Size Impact on Proof Bundle

The `proof` object with Ed25519:

- type: 23 chars (`"Ed25519Signature2020"`)
- created: 20 chars
- verificationMethod: 64 chars (credential identifier)
- proofPurpose: 15 chars (`"assertionMethod"`)
- proofValue: ~88 chars (64 bytes base64-encoded)

Total proof object: ~300 bytes including JSON structure.
Consistent with WF-SPEC-v1's size budget estimate of ~300 bytes
for the proof object.

---

## Algorithm Transition Model

### When to Transition

Algorithm transitions are triggered by:

1. **Cryptanalytic advance:** A published attack reduces the
   effective security of a specified algorithm below 100 bits.
   This is a conservative threshold — industry standard is to
   transition before practical attacks exist.
2. **Performance obsolescence:** A successor algorithm provides
   equivalent or better security with significantly better
   performance on current hardware.
3. **Regulatory mandate:** A jurisdiction with significant HIP
   adoption mandates a specific algorithm that the current
   specification does not support.
4. **Ecosystem convergence:** The W3C VC ecosystem converges on
   a successor cryptographic suite that provides interoperability
   benefits.

### How to Transition

1. A new CRYPTO-SPEC version is drafted specifying the
   replacement algorithm(s).
2. A WF-SPEC major version increment is issued (because the hash
   construction and proof type change — Rule 2 of WF-SPEC-v1's
   backward compatibility rules).
3. The WF-SPEC dual-support transition period (365 days minimum)
   begins. During this period, implementations support both the
   old and new algorithms.
4. New attestations use the new algorithm. Existing attestations
   remain verifiable under the old algorithm indefinitely — the
   algorithm identifier in each Bundle and Anchor tells the
   verifier which algorithm to use.

### Post-Quantum Consideration

Current post-quantum signature schemes (CRYSTALS-Dilithium,
SPHINCS+, FALCON) produce significantly larger signatures and/or
public keys than Ed25519. Dilithium-2 signatures are 2,420 bytes;
SPHINCS+-128s signatures are 7,856 bytes. These would substantially
exceed the Proof Bundle size budget and the Proof Anchor size
budget.

CRYPTO-SPEC-v1 does not specify post-quantum algorithms. The
current threat model does not require them — a quantum computer
capable of breaking Ed25519 does not currently exist, and the
most credible estimates place such capability at least a decade
away.

When post-quantum transition becomes necessary, the algorithm
transition model accommodates it. The Bundle size budget may need
to increase (a WF-SPEC design goal revision, not a structural
change). Hybrid schemes (classical + post-quantum) may be
appropriate during the transition to provide immediate post-quantum
resistance without losing classical verifiability.

This is a future concern, not a present one. The transition model
exists so that the protocol can adapt when the time comes.

---

## Implementation Requirements

Conforming implementations MUST:

- Use the algorithms specified in this specification for all
  cryptographic operations within the protocol
- Use standard library implementations, not custom
  implementations, of the specified algorithms
- Validate all cryptographic outputs (hash comparisons, signature
  verifications) before accepting data as valid
- Generate cryptographic keys using a CSPRNG
- Securely delete HMAC rotation keys after their window expires
- Include the correct algorithm identifiers in all wire format
  fields (`hashAlgorithm`, `proof.type`)

Conforming implementations MUST NOT:

- Use algorithms not specified in the current CRYPTO-SPEC version
  without a specification extension formally registered in the
  WF-SPEC extension namespace
- Use truncated hash outputs where this specification specifies
  full-length outputs
- Implement custom cryptographic constructions in place of the
  specified standard algorithms
- Retain HMAC rotation keys beyond their specified lifecycle

---

## Consistency with Parent Documents

This specification was drafted against and is consistent with:

- **WF-SPEC-v1**, which defined the fields where cryptographic
  outputs appear and deferred algorithm selection to this
  specification. SHA-256 outputs fit the defined field sizes. The
  Ed25519 proof object fits the ~300 byte budget estimate. The
  32-byte hash outputs fit the Proof Anchor 256-byte budget.

- **INT-SPEC-v1**, which defined the VEPA sourceToken mechanism
  and deferred the HMAC algorithm. HMAC-SHA-256 with per-window
  key rotation provides the required properties: within-window
  determinism, cross-window unlinkability, irreversibility.

- **HP-SPEC-v1**, which defined the credential key model. Ed25519
  key pairs provide the public/private key relationship. The
  credential identifier derivation (SHA-256 of public key) provides
  a pseudonymous, verifiable, compact identifier consistent with
  HP-SPEC-v1's requirement that credential identifiers not
  contain identity information.

- **Section 12: Deployment Philosophy**, particularly DP-1
  (SHA-256 and Ed25519 are available on every platform from
  day one), DP-5 (all algorithms are open standards implementable
  by anyone without license or permission), and DP-7 (no
  algorithm requires commercial library or hardware).

---

## Open Items

None. All cryptographic functions referenced by WF-SPEC-v1 and
INT-SPEC-v1 are resolved.

**Future considerations (not blocking):**
- Post-quantum transition planning (not imminent; model exists)
- ECDSA-P256 dual-support for regulatory environments (demand-
  driven; not currently required)
- Ledger-specific encoding of cryptographic outputs (implementation
  concern, not protocol-level)

---

*CRYPTO-SPEC-v1: Cryptographic Primitives Specification — WORKING
DRAFT. All algorithm placeholders in WF-SPEC-v1 and INT-SPEC-v1
resolved. SHA-256 for all hashing. Ed25519 for digital signatures.
HMAC-SHA-256 for privacy mechanisms. Conservative selection,
universal availability, agility through versioning.*
