# HIP — Human Integrity Protocol

**A cryptographic attestation system that lets human creators prove — verifiably, permanently, and without any institution's permission — that their work is human-made.**

---

## Genesis Inscription

The HIP Genesis Covenant Charter was permanently inscribed on the Bitcoin blockchain on **March 13, 2026**.

| Field | Value |
|---|---|
| **Transaction** | [`d025505337a2e9c5a19adfcf312843432b256fe856a7e6dff5caa4842faf1a72`](https://mempool.space/tx/d025505337a2e9c5a19adfcf312843432b256fe856a7e6dff5caa4842faf1a72) |
| **Block** | 940,558 |
| **OP_RETURN** | `HIP\|GEN\|401aa25f00b700fe07c11931b07675c62b3ac680b22f024f2f214e91c07c1872` |
| **Genesis Hash** | `401aa25f00b700fe07c11931b07675c62b3ac680b22f024f2f214e91c07c1872` |
| **Charter Hash** | `d3aafa629236e34c642f59dfbaa1606d7adcf930d43ba33503f654a085f99493` |
| **Firewall Hash** | `a0b28876b91848938dc1b9fd0838e671b27b899ddcc8f8a521b70ec63b2dad3c` |
| **Guardian Key** | `5645059140f824e96af935a09218c0374079e62f117078965a346423109b5026` (Ed25519) |

Every subsequent HIP attestation traces its lineage to this root.

---

## What Is HIP?

HIP lets human creators cryptographically attest to the origin of their work. It does not store your content — only a mathematical fingerprint. It does not expose your identity — only a pseudonymous credential. It does not require any platform's cooperation — any tool can produce and verify HIP attestations using open standards.

Three attestation categories, each equally valid:

- **CHO** — Complete Human Origin: no AI generation tools involved
- **HOA** — Human Origin Assisted: AI tools helped at the margins
- **HDC** — Human-Directed Collaborative: human-directed, AI co-created

The protocol records truth about creative process, not a hierarchy of value.

---

## Repository Structure

```
hip-protocol/
├── README.md                  ← You are here
├── LICENSE-CODE               ← MIT License (code and tools)
├── LICENSE-DOCS               ← CC-BY-4.0 (charter, specs, docs)
├── charter/
│   └── HIP_Charter_v1_0_canonical.txt   ← Sealed Charter (inscription candidate)
├── specs/
│   ├── HIP_WF-SPEC-v1.md     ← Proof Bundle Wire Format
│   ├── HIP_HP-SPEC-v1.md     ← HUMAN-PROOF Credential Mechanics
│   ├── HIP_CRYPTO-SPEC-v1.md ← Cryptographic Primitives
│   └── HIP_GI-SPEC-v1.md     ← Genesis Inscription (Complete)
├── genesis/
│   ├── genesis_inscription_payload.json  ← The canonical Genesis payload
│   └── HIP_Genesis_Announcement.md       ← Formal announcement
├── tools/
│   └── verify_genesis.py     ← 5-step Genesis verification script
└── site/
    └── hip_landing_v4.jsx    ← Landing page source
```

**Note:** Four companion specs (PFV-SPEC-v1, PATHWAY-SPEC-v1, INT-SPEC-v1, SLA-SPEC-v1) are finalized and will be added to this repository as they are prepared for publication.

---

## Verify the Genesis Inscription

You don't have to trust this repository. Everything is independently verifiable using public tools.

### Quick Verification (Python)

```bash
python3 tools/verify_genesis.py
```

This script performs the 5-step verification automatically. It requires only the Python standard library and the `requests` package for fetching the payload from IPFS.

### Manual Verification

1. **Check the blockchain:** Look up the [Genesis Transaction](https://mempool.space/tx/d025505337a2e9c5a19adfcf312843432b256fe856a7e6dff5caa4842faf1a72) on any block explorer. Confirm the OP_RETURN contains the Genesis Hash.

2. **Retrieve and hash the payload:** Download from [IPFS](https://gateway.pinata.cloud/ipfs/bafkreicadkrf6afxad7apqizggyhm5ogfm5mnafsf4be6lzbj2i4a7ayoi) or [Arweave](https://arweave.net/nTCa0kDBClUjUyregW-SYnf_vYlq5FwNqLMS5U-ahNI). Compute SHA-256. Must match the Genesis Hash.

3. **Verify the Charter hash:** Extract `charterHash` from the payload. Download the Charter from [IPFS](https://gateway.pinata.cloud/ipfs/bafkreigtvl5gferw4nggil2z365kcydnplopsmguhortka7wksqil6musm) or [Arweave](https://arweave.net/rG0zqLOaTmeDfYUw_uN4tqcw6xPj186Yc0HfubgkP1Y). Compute SHA-256. Must match.

4. **Verify the Firewall hash:** Extract Phoenix Firewall clauses PF-1 through PF-11 from the Charter. Compute SHA-256. Must match `firewallHash` in the payload.

5. **Verify the Guardian signature:** Using the Guardian public key, verify the Ed25519 signature over: "Here we begin the ledger of human signal integrity."

All five pass = Genesis confirmed valid.

---

## Content Addresses

| Artifact | IPFS | Arweave |
|---|---|---|
| Genesis Payload | [`bafkreicadkrf6afxad7apqizggyhm5ogfm5mnafsf4be6lzbj2i4a7ayoi`](https://gateway.pinata.cloud/ipfs/bafkreicadkrf6afxad7apqizggyhm5ogfm5mnafsf4be6lzbj2i4a7ayoi) | [`nTCa0kDBClUjUyregW-SYnf_vYlq5FwNqLMS5U-ahNI`](https://arweave.net/nTCa0kDBClUjUyregW-SYnf_vYlq5FwNqLMS5U-ahNI) |
| Charter | [`bafkreigtvl5gferw4nggil2z365kcydnplopsmguhortka7wksqil6musm`](https://gateway.pinata.cloud/ipfs/bafkreigtvl5gferw4nggil2z365kcydnplopsmguhortka7wksqil6musm) | [`rG0zqLOaTmeDfYUw_uN4tqcw6xPj186Yc0HfubgkP1Y`](https://arweave.net/rG0zqLOaTmeDfYUw_uN4tqcw6xPj186Yc0HfubgkP1Y) |

---

## Specifications

| Spec | Description | Status |
|---|---|---|
| **WF-SPEC-v1** | Proof Bundle Wire Format — field definitions, Proof Anchor structure, Bundle-to-Anchor hash, hosting architecture | Finalized |
| **HP-SPEC-v1** | HUMAN-PROOF Credential Mechanics — issuance tiers, Trust Index, liveness, compromise determination | Finalized |
| **CRYPTO-SPEC-v1** | Cryptographic Primitives — SHA-256, Ed25519, HMAC-SHA-256, algorithm transition model | Finalized |
| **GI-SPEC-v1** | Genesis Inscription — payload format, OP_RETURN encoding, verification procedure | Complete (inscribed) |
| **PFV-SPEC-v1** | Propagation Fingerprint & Verification Signals | Finalized (publication pending) |
| **PATHWAY-SPEC-v1** | Issuance Pathway Governance | Finalized (publication pending) |
| **INT-SPEC-v1** | Integration & Verification Endpoints | Finalized (publication pending) |
| **SLA-SPEC-v1** | Steward Ledger Activity | Finalized (publication pending) |

---

## Building on HIP

HIP is a protocol, not a product. Deployment Principle 5: *Permissionless Proliferation*. Anyone can build tools that produce or consume HIP attestation artifacts. No license, API key, or partnership required.

Possible implementations include: platform integrations, browser extensions, creator tools, institutional workflows, verification scripts, and Steward Nodes. See the [landing page](site/) or the specifications for full details.

---

## Cryptographic Standards

| Function | Algorithm | Standard |
|---|---|---|
| Content hash | SHA-256 | FIPS 180-4 |
| Bundle-to-Anchor hash | SHA-256 | FIPS 180-4 |
| Credential ID | SHA-256(public key) | FIPS 180-4 |
| Digital signature | Ed25519 | RFC 8032 |
| Serialization | RFC 8785 (Canonical JSON) | RFC 8785 |
| Privacy (HMAC) | HMAC-SHA-256 | RFC 2104 |

---

## License

- **Charter and Specifications:** [Creative Commons Attribution 4.0 International (CC-BY-4.0)](LICENSE-DOCS)
- **Code and Tools:** [MIT License](LICENSE-CODE)

---

*"Here we begin the ledger of human signal integrity."*
— Genesis Covenant Line, signed by the Guardian Key, inscribed on Bitcoin block 940,558
