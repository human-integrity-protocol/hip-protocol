#!/usr/bin/env python3
"""
HIP Genesis Inscription Verification Script
============================================
Performs the 5-step independent verification of the HIP Genesis Inscription.

Requirements:
  - Python 3.8+
  - requests (pip install requests)
  - PyNaCl for Ed25519 verification (pip install pynacl)

If requests or pynacl are not available, the script falls back to local file
verification for steps that require downloads, and skips signature verification.

Usage:
  python3 verify_genesis.py
  python3 verify_genesis.py --local genesis_inscription_payload.json charter.txt
"""

import hashlib
import json
import sys
import os
import base64
from pathlib import Path

# ============================================================
# KNOWN VALUES (from the on-chain OP_RETURN)
# ============================================================
GENESIS_HASH = "401aa25f00b700fe07c11931b07675c62b3ac680b22f024f2f214e91c07c1872"
CHARTER_HASH = "d3aafa629236e34c642f59dfbaa1606d7adcf930d43ba33503f654a085f99493"
FIREWALL_HASH = "a0b28876b91848938dc1b9fd0838e671b27b899ddcc8f8a521b70ec63b2dad3c"
GUARDIAN_KEY = "5645059140f824e96af935a09218c0374079e62f117078965a346423109b5026"
GENESIS_COVENANT_LINE = "Here we begin the ledger of human signal integrity."
OP_RETURN_STRING = "HIP|GEN|" + GENESIS_HASH

IPFS_PAYLOAD_URL = "https://gateway.pinata.cloud/ipfs/bafkreicadkrf6afxad7apqizggyhm5ogfm5mnafsf4be6lzbj2i4a7ayoi"
IPFS_CHARTER_URL = "https://gateway.pinata.cloud/ipfs/bafkreigtvl5gferw4nggil2z365kcydnplopsmguhortka7wksqil6musm"
ARWEAVE_PAYLOAD_URL = "https://arweave.net/nTCa0kDBClUjUyregW-SYnf_vYlq5FwNqLMS5U-ahNI"
ARWEAVE_CHARTER_URL = "https://arweave.net/rG0zqLOaTmeDfYUw_uN4tqcw6xPj186Yc0HfubgkP1Y"

TX_ID = "d025505337a2e9c5a19adfcf312843432b256fe856a7e6dff5caa4842faf1a72"
MEMPOOL_URL = f"https://mempool.space/tx/{TX_ID}"
BLOCKSTREAM_URL = f"https://blockstream.info/tx/{TX_ID}"


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash and return as lowercase hex string."""
    return hashlib.sha256(data).hexdigest()


def fetch_url(url: str) -> bytes:
    """Fetch content from a URL. Returns bytes."""
    try:
        import requests
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.content
    except ImportError:
        print(f"  [!] 'requests' not installed. Install with: pip install requests")
        print(f"      Or use --local mode with downloaded files.")
        return None
    except Exception as e:
        print(f"  [!] Failed to fetch {url}: {e}")
        return None


def print_result(step: str, passed: bool, detail: str = ""):
    """Print a verification result."""
    status = "✓ PASS" if passed else "✗ FAIL"
    color_start = "\033[92m" if passed else "\033[91m"
    color_end = "\033[0m"
    print(f"  {color_start}{status}{color_end}  {step}")
    if detail:
        print(f"         {detail}")


def verify_genesis(payload_path: str = None, charter_path: str = None):
    """Run the 5-step Genesis verification."""

    print()
    print("=" * 64)
    print("  HIP GENESIS INSCRIPTION VERIFICATION")
    print("=" * 64)
    print()
    print(f"  Genesis TX: {TX_ID}")
    print(f"  Explorer:   {MEMPOOL_URL}")
    print()

    results = []

    # ── STEP 1: On-chain verification ──
    print("─" * 64)
    print("  Step 1: On-chain OP_RETURN verification")
    print("─" * 64)
    print()
    print(f"  Expected OP_RETURN: {OP_RETURN_STRING}")
    print()
    print(f"  Verify manually at:")
    print(f"    {MEMPOOL_URL}")
    print(f"    {BLOCKSTREAM_URL}")
    print()
    print("  The OP_RETURN should contain the hex encoding of:")
    print(f"    {OP_RETURN_STRING}")
    print()
    # We can't programmatically verify the blockchain without a full node or API
    # The user must confirm this step visually
    print("  [Manual step — verify the OP_RETURN in a block explorer]")
    print()

    # ── STEP 2: Payload hash verification ──
    print("─" * 64)
    print("  Step 2: Payload retrieval and hash verification")
    print("─" * 64)
    print()

    payload_data = None
    if payload_path and os.path.exists(payload_path):
        print(f"  Loading payload from local file: {payload_path}")
        with open(payload_path, "rb") as f:
            payload_data = f.read()
    else:
        print(f"  Fetching payload from IPFS...")
        payload_data = fetch_url(IPFS_PAYLOAD_URL)
        if payload_data is None:
            print(f"  Trying Arweave...")
            payload_data = fetch_url(ARWEAVE_PAYLOAD_URL)

    if payload_data is None:
        print_result("Payload hash verification", False, "Could not retrieve payload")
        results.append(False)
    else:
        payload_hash = sha256_hex(payload_data)
        passed = payload_hash == GENESIS_HASH
        print_result(
            "Payload hash verification",
            passed,
            f"Computed: {payload_hash}" if not passed else f"Hash: {payload_hash[:24]}... ✓"
        )
        results.append(passed)
    print()

    # ── STEP 3: Charter hash verification ──
    print("─" * 64)
    print("  Step 3: Charter hash verification")
    print("─" * 64)
    print()

    # Extract charterHash from payload
    expected_charter_hash = None
    if payload_data:
        try:
            payload_json = json.loads(payload_data)
            expected_charter_hash = payload_json.get("charterHash")
            print(f"  charterHash from payload: {expected_charter_hash}")
        except json.JSONDecodeError:
            print("  [!] Could not parse payload JSON")

    charter_data = None
    if charter_path and os.path.exists(charter_path):
        print(f"  Loading charter from local file: {charter_path}")
        with open(charter_path, "rb") as f:
            charter_data = f.read()
    else:
        print(f"  Fetching charter from IPFS...")
        charter_data = fetch_url(IPFS_CHARTER_URL)
        if charter_data is None:
            print(f"  Trying Arweave...")
            charter_data = fetch_url(ARWEAVE_CHARTER_URL)

    if charter_data is None or expected_charter_hash is None:
        print_result("Charter hash verification", False, "Could not retrieve charter or extract expected hash")
        results.append(False)
    else:
        charter_hash = sha256_hex(charter_data)
        passed = charter_hash == expected_charter_hash
        print_result(
            "Charter hash verification",
            passed,
            f"Computed: {charter_hash}" if not passed else f"Hash: {charter_hash[:24]}... ✓"
        )
        results.append(passed)
    print()

    # ── STEP 4: Firewall hash verification ──
    print("─" * 64)
    print("  Step 4: Firewall hash verification")
    print("─" * 64)
    print()

    expected_firewall_hash = None
    if payload_data:
        try:
            payload_json = json.loads(payload_data)
            expected_firewall_hash = payload_json.get("firewallHash")
            print(f"  firewallHash from payload: {expected_firewall_hash}")
        except json.JSONDecodeError:
            pass

    if charter_data is None or expected_firewall_hash is None:
        print_result("Firewall hash verification", False, "Missing charter data or expected hash")
        results.append(False)
    else:
        # Extract PF-1 through PF-11 from the charter
        charter_text = charter_data.decode("utf-8")

        # Find the Phoenix Firewall clause block
        pf1_marker = "PF-1."
        pf11_end_marker = "it violates HIP."

        pf1_idx = charter_text.find(pf1_marker)
        pf11_idx = charter_text.find(pf11_end_marker)

        if pf1_idx == -1 or pf11_idx == -1:
            print_result("Firewall hash verification", False, "Could not locate PF-1 through PF-11 in charter")
            results.append(False)
        else:
            firewall_block = charter_text[pf1_idx:pf11_idx + len(pf11_end_marker)] + "\n"
            firewall_hash = sha256_hex(firewall_block.encode("utf-8"))
            passed = firewall_hash == expected_firewall_hash
            print_result(
                "Firewall hash verification",
                passed,
                f"Computed: {firewall_hash}" if not passed else f"Hash: {firewall_hash[:24]}... ✓"
            )
            if not passed:
                print(f"         Block size: {len(firewall_block.encode('utf-8'))} bytes")
            results.append(passed)
    print()

    # ── STEP 5: Guardian signature verification ──
    print("─" * 64)
    print("  Step 5: Guardian signature verification")
    print("─" * 64)
    print()

    signature_b64 = None
    if payload_data:
        try:
            payload_json = json.loads(payload_data)
            sig_obj = payload_json.get("guardianSignature", {})
            signature_b64 = sig_obj.get("signatureValue")
            signed_content_field = sig_obj.get("signedContent")
            print(f"  Signed content field: {signed_content_field}")
            print(f"  Signed content value: \"{GENESIS_COVENANT_LINE}\"")
            print(f"  Guardian public key:  {GUARDIAN_KEY}")
        except json.JSONDecodeError:
            pass

    if signature_b64 is None:
        print_result("Guardian signature verification", False, "Could not extract signature from payload")
        results.append(False)
    else:
        try:
            from nacl.signing import VerifyKey
            pub_bytes = bytes.fromhex(GUARDIAN_KEY)
            sig_bytes = base64.b64decode(signature_b64)
            message = GENESIS_COVENANT_LINE.encode("utf-8")
            verify_key = VerifyKey(pub_bytes)
            verify_key.verify(message, sig_bytes)
            print_result("Guardian signature verification", True, "Ed25519 signature valid ✓")
            results.append(True)
        except ImportError:
            print("  [!] 'pynacl' not installed. Install with: pip install pynacl")
            print("  [!] Skipping signature verification.")
            print_result("Guardian signature verification (skipped)", None, "Install pynacl to verify")
            results.append(None)
        except Exception as e:
            print_result("Guardian signature verification", False, f"Verification failed: {e}")
            results.append(False)
    print()

    # ── SUMMARY ──
    print("=" * 64)
    passed_count = sum(1 for r in results if r is True)
    failed_count = sum(1 for r in results if r is False)
    skipped_count = sum(1 for r in results if r is None)

    if failed_count == 0 and skipped_count == 0:
        print(f"  GENESIS VERIFICATION: ALL {passed_count} STEPS PASSED")
    elif failed_count == 0:
        print(f"  GENESIS VERIFICATION: {passed_count} PASSED, {skipped_count} SKIPPED")
    else:
        print(f"  GENESIS VERIFICATION: {failed_count} FAILED, {passed_count} PASSED, {skipped_count} SKIPPED")

    print()
    print("  Step 1 (on-chain OP_RETURN) requires manual verification")
    print(f"  at: {MEMPOOL_URL}")
    print("=" * 64)
    print()

    return failed_count == 0


if __name__ == "__main__":
    payload_path = None
    charter_path = None

    if "--local" in sys.argv:
        idx = sys.argv.index("--local")
        if idx + 2 < len(sys.argv):
            payload_path = sys.argv[idx + 1]
            charter_path = sys.argv[idx + 2]
        else:
            print("Usage: verify_genesis.py --local <payload.json> <charter.txt>")
            sys.exit(1)

    # Also check for files in common locations
    if payload_path is None:
        for p in ["genesis_inscription_payload.json", "../genesis/genesis_inscription_payload.json", "genesis/genesis_inscription_payload.json"]:
            if os.path.exists(p):
                payload_path = p
                break

    if charter_path is None:
        for p in ["HIP_Charter_v1_0_canonical.txt", "../charter/HIP_Charter_v1_0_canonical.txt", "charter/HIP_Charter_v1_0_canonical.txt"]:
            if os.path.exists(p):
                charter_path = p
                break

    success = verify_genesis(payload_path, charter_path)
    sys.exit(0 if success else 1)
