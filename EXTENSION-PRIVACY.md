# HIP Browser Extension — Privacy Policy

**Last updated: March 31, 2026**

## What the extension does

The HIP Browser Extension detects images on web pages you visit and checks whether they have been attested through the Human Integrity Protocol (HIP). When an attested image is found, a small badge is displayed on the image.

## What data is collected

**None.** The extension does not collect, store, or transmit any personal data.

Specifically:

- **No browsing history** is recorded or transmitted
- **No personal information** (name, email, location) is collected
- **No text, passwords, or form data** is read
- **No cookies or tracking** of any kind
- **No analytics or telemetry** is sent anywhere

## What data is processed

The extension processes images solely to verify their attestation status:

1. Images on the page are fetched and a SHA-256 hash (fingerprint) is computed locally
2. The hash is sent to the public HIP proof registry at `hip-tier1-worker.hipprotocol.workers.dev` to check if a matching attestation exists
3. Only the hash is sent — never the image content itself

This is the same as looking up a number in a public directory. The registry receives a hash and returns whether an attestation exists for it. No information about the user, the page they're on, or their browsing behavior is included in the request.

## Data storage

The extension stores one preference locally in your browser (whether badge scanning is on or off). This is stored using Chrome's `storage.local` API and never leaves your device.

## Third parties

The extension communicates only with the HIP proof registry (`hip-tier1-worker.hipprotocol.workers.dev`), which is operated as part of the open HIP protocol. No data is shared with any other third party.

## Open source

The extension source code is publicly available at [github.com/human-integrity-protocol](https://github.com/human-integrity-protocol/hip-protocol).

## Contact

For questions about this privacy policy: [github.com/human-integrity-protocol/hip-protocol/issues](https://github.com/human-integrity-protocol/hip-protocol/issues)
