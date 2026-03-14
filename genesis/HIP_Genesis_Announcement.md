# HIP — Human Integrity Protocol
## Genesis Inscription Announcement

**Date:** 2026-03-13

---

The HIP Genesis Covenant Charter has been permanently inscribed on the Bitcoin blockchain.

This inscription is the protocol's birth event. Every subsequent HIP attestation, Proof Bundle, Proof Anchor, and governance action traces its lineage to the Genesis Hash recorded below. The inscription derives its authority from mathematical verifiability and its permanent presence on an immutable public ledger — not from any institution, endorsement, or recognition (DP-4).

---

## Genesis Transaction

**Genesis Transaction ID (Bitcoin txid):**
```
d025505337a2e9c5a19adfcf312843432b256fe856a7e6dff5caa4842faf1a72
```

**Block Explorer:**
https://mempool.space/tx/d025505337a2e9c5a19adfcf312843432b256fe856a7e6dff5caa4842faf1a72

**OP_RETURN Data (decoded):**
```
HIP|GEN|401aa25f00b700fe07c11931b07675c62b3ac680b22f024f2f214e91c07c1872
```

**Confirmation Block Height:** 940,558
**Confirmation Timestamp:** 2026-03-13 13:37:57 (local / PDT)
**Confirmations:** 8+ (as of 2026-03-13 ~15:08 PDT)
**Miner:** Foundry USA
**Confirmed After:** ~10 minutes

---

## Content Addresses

### IPFS

**Genesis Inscription Payload:**
```
CID: bafkreicadkrf6afxad7apqizggyhm5ogfm5mnafsf4be6lzbj2i4a7ayoi
```
Gateway: https://gateway.pinata.cloud/ipfs/bafkreicadkrf6afxad7apqizggyhm5ogfm5mnafsf4be6lzbj2i4a7ayoi

**Charter Canonical Form:**
```
CID: bafkreigtvl5gferw4nggil2z365kcydnplopsmguhortka7wksqil6musm
```
Gateway: https://gateway.pinata.cloud/ipfs/bafkreigtvl5gferw4nggil2z365kcydnplopsmguhortka7wksqil6musm

### Arweave

**Genesis Inscription Payload:**
```
TX ID: nTCa0kDBClUjUyregW-SYnf_vYlq5FwNqLMS5U-ahNI
```
Gateway: https://arweave.net/nTCa0kDBClUjUyregW-SYnf_vYlq5FwNqLMS5U-ahNI

**Charter Canonical Form:**
```
TX ID: rG0zqLOaTmeDfYUw_uN4tqcw6xPj186Yc0HfubgkP1Y
```
Gateway: https://arweave.net/rG0zqLOaTmeDfYUw_uN4tqcw6xPj186Yc0HfubgkP1Y

---

## Guardian Public Key

```
Algorithm: Ed25519 (RFC 8032)
Public Key (hex): 5645059140f824e96af935a09218c0374079e62f117078965a346423109b5026
```

---

## Cryptographic Values

| Component | Hash (SHA-256) |
|---|---|
| Genesis Hash | 401aa25f00b700fe07c11931b07675c62b3ac680b22f024f2f214e91c07c1872 |
| Charter Hash | d3aafa629236e34c642f59dfbaa1606d7adcf930d43ba33503f654a085f99493 |
| Firewall Hash | a0b28876b91848938dc1b9fd0838e671b27b899ddcc8f8a521b70ec63b2dad3c |

---

## Independent Verification Instructions

Any party can verify the Genesis inscription using only public tools and the information above. No special permissions, accounts, or software are required.

### Step 1 — Verify the on-chain data

Look up the Genesis Transaction ID on any Bitcoin block explorer (e.g., mempool.space, blockstream.info). Locate the OP_RETURN output. Confirm it contains the hex-encoded string `HIP|GEN|401aa25f00b700fe07c11931b07675c62b3ac680b22f024f2f214e91c07c1872`. Extract the 64-character hex value after `HIP|GEN|` — this is the Genesis Hash.

### Step 2 — Retrieve and verify the Payload

Download the Genesis Inscription Payload from IPFS using the CID above, or from Arweave using the TX ID above. Compute the SHA-256 hash of the downloaded file. Confirm it matches the Genesis Hash from Step 1: `401aa25f00b700fe07c11931b07675c62b3ac680b22f024f2f214e91c07c1872`.

### Step 3 — Verify the Charter hash

Open the downloaded Payload (it is a JSON file). Extract the `charterHash` field. Download the Charter Canonical Form from IPFS or Arweave using the CIDs/TX IDs above. Compute the SHA-256 hash of the Charter file. Confirm it matches the `charterHash` value: `d3aafa629236e34c642f59dfbaa1606d7adcf930d43ba33503f654a085f99493`.

### Step 4 — Verify the Firewall hash

From the Charter Canonical Form, extract the Phoenix Firewall clauses PF-1 through PF-11 (Section 7). The extraction begins at the first character of PF-1 and ends at the final period of PF-11, followed by a single trailing newline. Compute the SHA-256 hash. Confirm it matches the `firewallHash` value in the Payload: `a0b28876b91848938dc1b9fd0838e671b27b899ddcc8f8a521b70ec63b2dad3c`.

### Step 5 — Verify the Guardian signature

From the Payload, extract the `guardianKey.publicKey` (Ed25519 public key) and the `guardianSignature.signatureValue` (base64-encoded). The signed content is the `genesisCovenantLine` field: "Here we begin the ledger of human signal integrity." Verify the Ed25519 signature using any standard Ed25519 implementation (e.g., OpenSSL, libsodium, Python's cryptography library).

### Verification result

If all five steps pass, the Genesis inscription is confirmed as valid. The protocol's entire hash lineage descends from this root.

---

*This announcement is informational. The on-chain inscription and the content-addressed store artifacts are self-verifying. This document reduces the effort required to locate these artifacts but does not add to their validity.*
