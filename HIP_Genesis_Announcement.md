# HIP Genesis Announcement

**The Human Integrity Protocol is live.**

On March 17, 2026, the HIP Genesis Covenant was inscribed into Bitcoin block 940,558. The inscription is a one-way commitment: a SHA-256 hash of the complete Genesis Payload, anchored in an OP_RETURN output that no entity can modify, revoke, or erase. The protocol now exists independently of anyone who made it.

This post explains what HIP is, why it was built, and how to use it today.

---

## The problem

AI-generated text, images, and audio are now indistinguishable from human-made content. Every platform, newsroom, and creator faces the same question: *how do you know a human made this?*

Current solutions require trusting a company to stay honest, stay online, and not change the rules. They create walled gardens. They expire. They depend on institutions that may not exist in ten years.

## What HIP does

HIP is an open protocol that lets human creators cryptographically prove their work is human-made.

You get a credential proving you're a real person. You sign your work with it. Anyone can verify the signature — forever — using only the public protocol and the Bitcoin blockchain. No company required.

**No uploads.** Your files never leave your device. HIP fingerprints them locally using SHA-256. The protocol only needs the hash — never the content.

**Permanent.** Attestations are anchored on Bitcoin. They don't expire, can't be revoked by a third party, and are verifiable by anyone, forever.

**Open.** The protocol has no treasury, no token, and collects no fees. The Charter explicitly forbids institutional capture.

## How it works

1. **Get a credential.** Prove you're a real person through government ID verification (Tier 1, $1 one-time), a peer vouch from an existing credential holder (Tier 2, no cost), or device biometric (Tier 3, instant, no cost). Your credential is a cryptographic key pair generated in your browser. The private key never leaves your device.

2. **Attest your work.** Drop a file into the attestation tool. HIP computes its SHA-256 fingerprint locally, you choose a classification (Complete Human Origin, Human Origin Assisted, or Human-Directed Collaborative), and sign it with your credential. This produces a Proof Bundle and a Proof Card.

3. **Anyone verifies.** The Proof Card contains everything needed to verify: the content fingerprint, your credential ID, the classification, a timestamp, and your cryptographic signature. Verification requires nothing but math — no account, no API key, no trust in any institution.

## What HIP is not

HIP is not a platform, a company, or a token. It doesn't do content moderation, fact-checking, or truth arbitration. The word "Integrity" in HIP refers to integrity of origin — the ability to distinguish a living human voice from a manufactured synthetic presence. Not moral correctness.

## The Genesis inscription

The Genesis Covenant was inscribed at Bitcoin block 940,558 on March 17, 2026.

**Genesis Transaction:**
`d025505337a2e9c5a19adfcf312843432b256fe856a7e6dff5caa4842faf1a72`

**OP_RETURN:**
`HIP|GEN|401aa25f00b700fe07c11931b07675c62b3ac680b22f024f2f214e91c07c1872`

The hash in the OP_RETURN is the SHA-256 of the Genesis Inscription Payload — a JSON document containing the Charter hash, the Guardian public key, and the protocol's founding parameters. The full payload is pinned on IPFS and stored on Arweave. Anyone can download it, recompute the hashes, and verify the entire chain of integrity independently — no trust required, just math.

**IPFS Payload CID:** `bafkreicadkrf6afxad7apqizggyhm5ogfm5mnafsf4be6lzbj2i4a7ayoi`
**Arweave Payload TX:** `nTCa0kDBClUjUyregW-SYnf_vYlq5FwNqLMS5U-ahNI`

## Try it now

Everything is live and works in your browser today:

- **Protocol site:** [hipprotocol.org](https://hipprotocol.org) — get a credential, attest files, verify attestations
- **Tier 1 verification:** [hipverify.org](https://hipverify.org) — government ID verification ($1 one-time)
- **Specification:** [HP-SPEC v1.1](https://github.com/human-integrity-protocol/hip-protocol/blob/main/specs/HP-SPEC-v1.1.md) — full technical specification
- **Charter:** [Genesis Covenant Charter v1.0](https://github.com/human-integrity-protocol/hip-protocol) — the governing document
- **Source:** [github.com/human-integrity-protocol](https://github.com/human-integrity-protocol/hip-protocol) — everything is public

## What comes next

HIP is a protocol, not a product launch. The specification is public, the Charter is immutable, and the tools are live. Anyone can build on HIP — plugins, integrations, new workflows — without permission from anyone.

The protocol was designed to outlast its creators. The Bitcoin inscription ensures it will.

---

*"Here we begin the ledger of human signal integrity."*

Genesis: Block 940,558 · March 17, 2026

[hipprotocol.org](https://hipprotocol.org) · [GitHub](https://github.com/human-integrity-protocol/hip-protocol) · [hipverify.org](https://hipverify.org)
