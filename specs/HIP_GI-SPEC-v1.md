# HIP — Human Integrity Protocol
## GI-SPEC-v1: Genesis Inscription Procedure Specification
### COMPLETE | Inscribed 2026-03-13 | Genesis TX: d025505337a2e9c5a19adfcf312843432b256fe856a7e6dff5caa4842faf1a72

---

## Authority and Status

This specification derives its authority from and must remain
consistent with:

- **HIP Genesis Covenant Charter v1.0** — particularly Section 13
  (Genesis Inscription & Covenant Seal), Section 14 (Storage &
  Format Legacy Note), and Section 14-A (ASCII Canonical Form
  Specification)
- **CRYPTO-SPEC-v1: Cryptographic Primitives Specification** —
  which specifies SHA-256 as the hash algorithm and Ed25519 as
  the digital signature scheme
- **WF-SPEC-v1: Proof Bundle Wire Format Specification** — which
  establishes the canonical JSON serialization model (RFC 8785)
  and the schema versioning precedent
- **Section 12: Deployment Philosophy** — particularly DP-4
  (Legitimacy From Proof, Not Recognition) and DP-8 (Protocol,
  Not Entity)

In any conflict between this specification and the documents listed
above, the parent document controls. This specification may not
introduce principles that contradict those documents. Where this
specification addresses cases not covered by those documents, it may
propose extensions, provided those extensions are consistent with the
governing principles established there.

This specification is a companion document. It is not part of the
Genesis inscription itself. It specifies the procedure by which
the Genesis inscription is performed. Once the Genesis inscription
is complete, this specification becomes a historical record of
procedure — the inscription's validity is determined by the on-
ledger artifacts, not by this document.

---

## Purpose

GI-SPEC-v1 specifies the procedure by which the HIP Genesis
Covenant Charter is committed to permanent public record through
a single irreversible act of inscription. Charter Section 13
establishes *what* is inscribed and *why*. This specification
defines *how* — the exact steps, data formats, hash derivation
procedures, content-addressed store requirements, and OP_RETURN
encoding that produce the Genesis artifacts.

The Genesis inscription is the protocol's birth event. Every
subsequent HIP attestation, every Proof Bundle, every Proof Anchor,
and every governance action traces its lineage to the Genesis hash.
The procedure must therefore be precise, reproducible, and
independently verifiable by any party with no special tools or
permissions.

---

## Scope

This specification covers:

- **Genesis Inscription Payload format:** The canonical structure,
  field ordering, and encoding of the document committed to the
  content-addressed store
- **ASCII canonical form production:** The procedure for producing
  the Charter's canonical ASCII text from which the Charter hash
  is derived
- **Hash derivation procedure:** The step-by-step process for
  computing all hashes in the Genesis inscription
- **Content-addressed store selection:** The criteria for selecting
  a permanent content-addressed store and the publication procedure
- **OP_RETURN encoding:** The format and encoding of the Bitcoin
  OP_RETURN transaction that anchors the Genesis hash on-ledger
- **Verification procedure:** How any party independently verifies
  the Genesis inscription after the fact

This specification explicitly defers:

- The specific Bitcoin transaction construction and fee estimation
  — these are standard Bitcoin operations documented in Bitcoin's
  own specification and tooling
- The specific content-addressed store implementation details (IPFS
  pinning services, Arweave bundling) — these are operational
  decisions made at inscription time
- The ceremony or social coordination surrounding the inscription
  event — this specification covers the technical procedure only

---

## Definitions Used in This Specification

**Genesis Inscription Payload.** The canonically structured document
published to a content-addressed store, whose hash is inscribed on
the Bitcoin ledger. The Payload is the complete, self-contained
record from which the on-chain Genesis hash is derived.

**Charter Canonical Form.** The ASCII text of the Genesis Covenant
Charter produced according to the normalization rules in Charter
Section 14-A. This is the normative genesis artifact.

**Phoenix Firewall Clause Block.** The text of PF-1 through PF-11
as they appear in Charter Section 7, extracted as a contiguous
block for independent hashing.

**Genesis Covenant Line.** The exact text: "Here we begin the
ledger of human signal integrity." As specified in Charter
Section 13.1.

**Genesis Seal Statement.** The accompanying statement specified
in Charter Section 13.2.

**Guardian Key.** The Ed25519 key pair held by the first Origin
Guardian. The public key is published as part of the Genesis
Inscription Payload. The private key is held exclusively by a
living human per Charter Section 13.0.

---

## Step 1 — Produce the Charter Canonical Form

### Input

The Genesis Covenant Charter manuscript in its final pre-
inscription state (v1.0 candidate).

### Procedure

1. **Encoding normalization.** Convert the manuscript to UTF-8
   encoding. No byte order mark (BOM). Line endings normalized to
   LF (U+000A) only — no CR (U+000D) characters permitted.

2. **Character set validation.** Verify that every character in the
   document falls within the US-ASCII printable repertoire (U+0020
   SPACE through U+007E TILDE) plus LF (U+000A). Any character
   outside this range MUST be replaced with an ASCII equivalent or
   removed. Em dashes become double hyphens (--). Curly quotes
   become straight quotes. Accented characters are transliterated.

3. **Unicode normalization.** Apply NFC (Canonical Decomposition
   followed by Canonical Composition) per Unicode Standard Annex
   #15. For a document already restricted to US-ASCII, NFC is a
   no-op — this step exists to guarantee the property regardless
   of processing path.

4. **Trailing whitespace removal.** Remove any trailing whitespace
   (U+0020) from each line. Trailing whitespace does not affect
   human readability but can create hash divergence between
   implementations.

5. **Final newline.** The canonical form MUST end with exactly one
   LF character. No trailing blank lines beyond the final newline.

6. **Validation.** The resulting byte sequence is the Charter
   Canonical Form. Verify: every byte is in the range 0x0A or
   0x20–0x7E. No exceptions.

### Output

A byte sequence: the Charter Canonical Form. This is the
authoritative Charter text for all on-ledger commitments.

---

## Step 2 — Extract the Phoenix Firewall Clause Block

### Input

The Charter Canonical Form produced in Step 1.

### Procedure

1. **Extract PF-1 through PF-11.** From the Charter Canonical
   Form, extract the complete text of the Phoenix Firewall clauses.
   The extraction begins at the first character of the line
   containing "PF-1" and ends at the last character of the final
   sentence of PF-11 (including the period), before the subsequent
   paragraph beginning "Any actor, node, or institution." The extract ends at the last sentence of PF-11, including the terminal period and a single trailing LF. It does not include any subsequent paragraph or whitespace beyond the LF.

2. **Boundary precision.** The extract includes:
   - All eleven clause texts (PF-1 through PF-11), each beginning
     with its bold marker as rendered in the canonical form
   - The blank lines separating clauses
   - No content before PF-1 or after PF-11

3. **Encoding.** The extracted block retains the same encoding
   properties as the Charter Canonical Form (UTF-8, US-ASCII
   repertoire, LF line endings). The block ends with exactly one
   LF.

### Output

A byte sequence: the Phoenix Firewall Clause Block.

---

## Step 3 — Compute Component Hashes

### Input

- Charter Canonical Form (from Step 1)
- Phoenix Firewall Clause Block (from Step 2)

### Procedure

Compute SHA-256 (FIPS 180-4, per CRYPTO-SPEC-v1) over each input:

```
charter_hash = SHA-256(charter_canonical_form_bytes)
firewall_hash = SHA-256(firewall_clause_block_bytes)
```

### Output

Two 32-byte hash values, each encoded as 64 lowercase hexadecimal
characters:

- `charter_hash` — the Charter hash
- `firewall_hash` — the Phoenix Firewall hash

### Verification Property

Any party with the Charter Canonical Form can independently
compute `charter_hash` and verify it matches the on-chain record.
Any party with the Clause Block can independently compute
`firewall_hash`. Both computations require only SHA-256 — no
special tools, no permissions, no trust.

---

## Step 4 — Produce the Guardian Key Signature

### Input

- The Genesis Covenant Line: "Here we begin the ledger of human
  signal integrity."
- The Guardian's Ed25519 private key

### Procedure

1. **Encode the signing input.** The signing input is the UTF-8
   byte sequence of the exact Genesis Covenant Line, including
   the period, without any trailing newline or surrounding
   quotation marks:

   ```
   signing_input = UTF-8("Here we begin the ledger of human signal integrity.")
   ```

2. **Sign.** Compute the Ed25519 signature (RFC 8032, per
   CRYPTO-SPEC-v1) over the signing input using the Guardian's
   private key:

   ```
   guardian_signature = Ed25519_Sign(guardian_private_key, signing_input)
   ```

3. **Encode.** The signature is encoded as base64 (standard
   alphabet, with padding).

### Output

- `guardian_public_key` — the Guardian's Ed25519 public key,
  encoded as 64 lowercase hexadecimal characters (32 bytes)
- `guardian_signature` — the Ed25519 signature, base64-encoded
  (88 characters)

### Verification Property

Any party with the Guardian public key can verify the signature
against the Genesis Covenant Line. This confirms that a specific
key holder acknowledged Covenant defense responsibility at the
moment of inscription.

---

## Step 5 — Construct the Genesis Inscription Payload

### Input

- `charter_hash` (from Step 3)
- `firewall_hash` (from Step 3)
- Genesis Covenant Line (Charter Section 13.1)
- Genesis Seal Statement (Charter Section 13.2)
- `guardian_public_key` (from Step 4)
- `guardian_signature` (from Step 4)

### Payload Structure

The Genesis Inscription Payload is a JSON document serialized to
canonical JSON per RFC 8785 (the same canonicalization scheme used
in WF-SPEC-v1 for Proof Bundles):

```
{
  "type": "HIPGenesisInscription",
  "version": "GI-v1.0",
  "charterHash": "<charter_hash>",
  "charterHashAlgorithm": "sha-256",
  "firewallHash": "<firewall_hash>",
  "firewallHashAlgorithm": "sha-256",
  "genesisCovenantLine": "Here we begin the ledger of human signal integrity.",
  "genesisSealStatement": "HIP — Genesis Covenant Lineage / Ledger-Anchored Origin Attestation. This inscription binds the Human Integrity Protocol to the Covenant, the Phoenix Firewall clauses (PF-1 through PF-11), and the responsibility of public witness. No actor MAY claim HIP lineage without referencing this Genesis Hash.",
  "guardianKey": {
    "algorithm": "Ed25519",
    "publicKey": "<guardian_public_key>"
  },
  "guardianSignature": {
    "algorithm": "Ed25519",
    "signedContent": "genesisCovenantLine",
    "signatureValue": "<guardian_signature>"
  },
  "timestamp": "<ISO_8601_datetime_UTC>"
}
```

### Field Definitions

**type** (required, string)
Always "HIPGenesisInscription". Identifies this document as a
Genesis Inscription Payload.

**version** (required, string)
The GI-SPEC version under which this Payload was constructed.
Format: "GI-v1.0".

**charterHash** (required, string)
The SHA-256 hash of the Charter Canonical Form, encoded as 64
lowercase hexadecimal characters.

**charterHashAlgorithm** (required, string)
The hash algorithm identifier. Value: "sha-256" per CRYPTO-SPEC-v1.

**firewallHash** (required, string)
The SHA-256 hash of the Phoenix Firewall Clause Block, encoded as
64 lowercase hexadecimal characters.

**firewallHashAlgorithm** (required, string)
The hash algorithm identifier. Value: "sha-256" per CRYPTO-SPEC-v1.

**genesisCovenantLine** (required, string)
The Genesis Covenant Line, exactly as written in Charter Section
13.1: "Here we begin the ledger of human signal integrity."

**genesisSealStatement** (required, string)
The Genesis Seal Statement, exactly as written in Charter Section
13.2.

**guardianKey** (required, object)
The Guardian's public key.
- `algorithm`: The key algorithm. Value: "Ed25519" per CRYPTO-SPEC-v1.
- `publicKey`: The public key, encoded as 64 lowercase hexadecimal
  characters.

**guardianSignature** (required, object)
The Guardian's Ed25519 signature acknowledging Covenant defense
responsibility.
- `algorithm`: The signature algorithm. Value: "Ed25519".
- `signedContent`: Identifies the signed content. Value:
  "genesisCovenantLine" (indicating the signature is over the
  Genesis Covenant Line text).
- `signatureValue`: The base64-encoded Ed25519 signature.

**timestamp** (required, string, ISO 8601 datetime)
The timestamp of the Payload construction. UTC. Format:
"YYYY-MM-DDThh:mm:ssZ".

### Serialization

The Payload MUST be serialized to canonical JSON per RFC 8785
before hashing or publication. This ensures that any party who
retrieves the Payload from the content-addressed store can
recompute its hash deterministically.

### Output

A canonical JSON byte sequence: the Genesis Inscription Payload.

---

## Step 6 — Compute the Genesis Hash

### Input

The canonical JSON byte sequence of the Genesis Inscription
Payload (from Step 5).

### Procedure

```
genesis_hash = SHA-256(payload_canonical_json_bytes)
```

### Output

The Genesis Hash: a 32-byte value encoded as 64 lowercase
hexadecimal characters. This is the single value inscribed on the
Bitcoin ledger.

### Verification Property

Any party with the Genesis Inscription Payload can independently
compute the Genesis Hash. Any party with the Genesis Hash (from
the Bitcoin ledger) and the Payload (from the content-addressed
store) can verify they match.

---

## Step 7 — Publish to Content-Addressed Store

### Input

- The Genesis Inscription Payload (canonical JSON, from Step 5)
- The Charter Canonical Form (from Step 1)

### Content-Addressed Store Selection Criteria

The content-addressed store MUST satisfy:

1. **Permanence.** Content published to the store MUST remain
   retrievable for the indefinite future. The store's persistence
   model must not depend on continued payment, subscription, or
   organizational continuity by the publisher.

2. **Content addressing.** The store MUST use content-addressing
   (the retrieval identifier is derived from the content's hash)
   so that any party can verify that retrieved content matches
   the expected hash.

3. **Public accessibility.** Content MUST be retrievable by any
   party without authentication, account creation, or payment.

4. **Redundancy.** The store SHOULD provide built-in replication
   or incentive-based persistence mechanisms that reduce
   single-point-of-failure risk.

### Recommended Stores

The following content-addressed stores satisfy the selection
criteria at the time of this specification:

- **IPFS (InterPlanetary File System)** with persistent pinning.
  IPFS content is addressed by CID (Content Identifier). Pinning
  through multiple independent pinning services provides
  redundancy. IPFS is the recommended primary store for its
  maturity, tooling availability, and decentralized retrieval.

- **Arweave.** Arweave provides permanent storage with a one-time
  payment model. Content is addressed by transaction ID. Arweave
  provides strong permanence guarantees through its endowment
  model.

Both stores MAY be used simultaneously for redundancy. The Genesis
Inscription Payload SHOULD be published to at least two independent
content-addressed stores.

### Publication Procedure

1. Publish the Genesis Inscription Payload (canonical JSON) to the
   selected content-addressed store(s).
2. Record the content address(es) (IPFS CID, Arweave transaction
   ID, or equivalent) for each publication.
3. Publish the Charter Canonical Form to the same store(s) as a
   companion document. This allows any party to retrieve the full
   Charter text and verify the Charter hash independently.
4. Verify retrieval: confirm that the published content is
   retrievable and that its content hash matches the expected
   value.

### Output

One or more content addresses (IPFS CID, Arweave TX ID) pointing
to the Genesis Inscription Payload and the Charter Canonical Form.

---

## Step 8 — Inscribe on Bitcoin via OP_RETURN

### Input

- The Genesis Hash (from Step 6)
- The content address(es) of the published Payload (from Step 7)

### OP_RETURN Format

The Bitcoin OP_RETURN transaction carries a data payload with the
following structure:

```
HIP|GEN|<genesis_hash>|<content_address>
```

**Field definitions:**

- `HIP` — Protocol identifier (3 bytes). Identifies this as a
  HIP inscription.
- `GEN` — Inscription type (3 bytes). Identifies this as a Genesis
  inscription.
- `|` — Field delimiter (1 byte each, 0x7C).
- `<genesis_hash>` — The Genesis Hash, 64 lowercase hexadecimal
  characters (64 bytes).
- `<content_address>` — The primary content address for the
  published Payload. For IPFS, this is the CID. For Arweave, this
  is the transaction ID. If the content address exceeds the
  remaining space in the OP_RETURN budget, it MAY be truncated to
  a prefix sufficient for resolution, with the full address
  available in the Payload itself.

**Total size:** Approximately 75-80 bytes for the fixed fields
plus the content address. Bitcoin OP_RETURN supports up to 80
bytes of data. If the total exceeds 80 bytes, the content address
is truncated to fit. The full content address is always available
in the published Payload document.

### OP_RETURN Size Constraint Resolution

If the content address causes the OP_RETURN payload to exceed 80
bytes:

**Option A — Compact encoding.** Use the genesis_hash alone
without the content address:

```
HIP|GEN|<genesis_hash>
```

This produces a 72-byte payload (3+1+3+1+64 = 72 bytes). The content address is published in a companion
document (the Payload itself on the content-addressed store) and
in publicly announced retrieval instructions.

**Option B — Secondary output.** Use a second OP_RETURN output
(where the Bitcoin implementation supports it) to carry the content
address.

Option A is RECOMMENDED for simplicity and universal compatibility.
The Genesis Hash alone is sufficient for verification — anyone with
the Payload can compute the hash and confirm it matches the on-
chain value. The content address is a retrieval convenience, not a
verification requirement.

### Transaction Construction

The Bitcoin transaction containing the Genesis inscription:

1. MUST include an OP_RETURN output with the encoded payload.
2. SHOULD use a standard transaction type and fee rate sufficient
   for reliable confirmation.
3. SHOULD NOT include any additional data in the OP_RETURN output
   beyond the specified format.

The transaction ID (txid) of the confirmed Bitcoin transaction
becomes the **Genesis Transaction Identifier** — the permanent
on-ledger reference point for the protocol's birth.

### Output

A confirmed Bitcoin transaction containing the Genesis Hash in
an OP_RETURN output. The transaction ID is the Genesis Transaction
Identifier.

---

## Step 9 — Verify and Announce

### Verification Procedure

After the Bitcoin transaction is confirmed:

1. **On-chain verification.** Retrieve the OP_RETURN data from
   the confirmed transaction. Extract the Genesis Hash. Confirm
   it matches the Genesis Hash computed in Step 6.

2. **Payload retrieval.** Retrieve the Genesis Inscription Payload
   from the content-addressed store using the published content
   address.

3. **Payload hash verification.** Compute SHA-256 over the
   retrieved Payload bytes. Confirm it matches the Genesis Hash
   from the on-chain OP_RETURN.

4. **Charter hash verification.** Extract the `charterHash` from
   the Payload. Retrieve the Charter Canonical Form from the
   content-addressed store. Compute SHA-256 over the Charter bytes.
   Confirm it matches the `charterHash` in the Payload.

5. **Firewall hash verification.** Extract the `firewallHash` from
   the Payload. Extract the Firewall Clause Block from the Charter
   Canonical Form per Step 2's extraction procedure. Compute
   SHA-256. Confirm it matches the `firewallHash` in the Payload.

6. **Guardian signature verification.** Extract the
   `guardianSignature` from the Payload. Verify the Ed25519
   signature against the `guardianKey.publicKey` and the
   `genesisCovenantLine` text. Confirm the signature is valid.

If all six verification steps pass, the Genesis inscription is
confirmed as valid. If any step fails, the inscription is invalid
and MUST be investigated before the protocol proceeds.

### Announcement

The following information is published through publicly accessible
channels:

- The Genesis Transaction Identifier (Bitcoin txid)
- The content address(es) of the Genesis Inscription Payload
- The content address(es) of the Charter Canonical Form
- The Guardian's public key (for signature verification)
- Instructions for independent verification using the procedure
  above

The announcement is informational. The on-chain inscription and
the content-addressed store artifacts are self-verifying. The
announcement reduces the effort required to locate these artifacts
but does not add to their validity.

---

## Post-Genesis Hash Lineage

After the Genesis inscription, all valid HIP lineage MUST descend
from the Genesis Hash. Specifically:

- Every Proof Anchor is part of HIP lineage only if the
  implementation that produced it conforms to a specification
  whose hash traces to the Genesis Hash lineage.
- The Guardian Reserve Queue's Covenant Recitation Hash
  (Charter Section 6.5) references the Genesis Covenant Line
  exactly as inscribed.
- Guardian succession candidates are tested against the exact
  Genesis Covenant Line from the inscription.
- PFV version hashes, specification updates, and Charter
  amendments (if any) reference the Genesis Hash as the root of
  the hash lineage chain.

The Genesis Hash is the root of trust. It does not derive authority
from any institution, endorsement, or recognition. Its authority
comes from its mathematical verifiability and its permanent
presence on an immutable public ledger (DP-4).

---

## Implementation Requirements

Any actor performing the Genesis inscription MUST:

- Follow the steps in this specification in order
- Use SHA-256 (FIPS 180-4) for all hash computations per
  CRYPTO-SPEC-v1
- Use Ed25519 (RFC 8032) for the Guardian signature per
  CRYPTO-SPEC-v1
- Serialize the Payload to canonical JSON per RFC 8785
- Produce the Charter Canonical Form per the normalization rules
  in Charter Section 14-A and this specification's Step 1
- Publish the Payload to at least one content-addressed store
  satisfying the selection criteria
- Verify all computed values before inscription

Any actor verifying the Genesis inscription MUST:

- Retrieve the OP_RETURN data from the Genesis transaction
- Retrieve the Payload from the content-addressed store
- Independently compute and compare all hashes
- Independently verify the Guardian signature
- Accept the inscription as valid only if all verification steps
  pass

---

## Consistency with Parent Documents

This specification was drafted against and is consistent with:

- **Charter Section 13**, which established the Genesis Inscription
  Payload contents (Charter hash, Firewall hash, Genesis Covenant
  Line, Guardian Key signature), the Bitcoin OP_RETURN anchoring
  mechanism, and the content-addressed permanent store model. This
  specification provides the byte-level procedure for producing
  these artifacts.

- **Charter Section 14 and 14-A**, which established the ASCII
  canonical form requirements (UTF-8, US-ASCII repertoire, LF line
  endings, NFC normalization, SHA-256 hash). This specification's
  Step 1 operationalizes these requirements into a reproducible
  procedure.

- **CRYPTO-SPEC-v1**, which specified SHA-256 for hashing and
  Ed25519 for digital signatures. All hash computations and the
  Guardian signature in this specification use these algorithms.

- **WF-SPEC-v1**, which established RFC 8785 canonical JSON as
  the normative serialization format. The Genesis Inscription
  Payload uses the same canonicalization, maintaining consistency
  across the protocol's data formats.

- **Section 12: Deployment Philosophy**, particularly DP-4
  (the Genesis inscription derives legitimacy from mathematical
  proof, not institutional endorsement) and DP-8 (the inscription
  is performed by an individual acting under their own authority,
  not on behalf of an entity called "HIP").

Where this specification addresses cases not explicitly resolved by
the parent documents, it has done so in a manner consistent with the
governing principles those documents establish. Specifically:

- The OP_RETURN encoding format (HIP|GEN|<hash> structure) is
  this specification's resolution of the practical encoding
  question that Charter Section 13.3 leaves to this companion spec
- The content-addressed store selection criteria formalize the
  properties implied by Charter Section 13.3's reference to a
  "content-addressed permanent store"
- The 9-step procedure decomposes Charter Section 13.3's
  conceptual description into the reproducible technical steps
  required for implementation

The parent documents control in any conflict.

---

## Open Items

None. All elements referenced by Charter Section 13 are resolved
in this specification.

**Future considerations (not blocking):**

- Ledger-specific encoding guidance for non-Bitcoin anchoring
  substrates (permitted under PF-AG, referenced in Charter
  Section 9.5)
- Content-addressed store redundancy monitoring procedures
- Tooling for automated Genesis verification

---

*GI-SPEC-v1: Genesis Inscription Procedure Specification — COMPLETE.
Inscription date: 2026-03-13. Genesis Transaction ID:
d025505337a2e9c5a19adfcf312843432b256fe856a7e6dff5caa4842faf1a72.
Specifies the complete procedure for producing the Genesis
Inscription Payload, computing all hashes, publishing to content-
addressed store, and inscribing on Bitcoin via OP_RETURN. Derived
from Charter Sections 13, 14, and 14-A, CRYPTO-SPEC-v1 (SHA-256,
Ed25519), and WF-SPEC-v1 (RFC 8785 canonical JSON).*
