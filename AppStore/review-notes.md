# App Review notes — SE Pass

## What the app is
SE Pass is a client for "pass" (the standard Unix password manager,
https://www.passwordstore.org/). A pass store is a directory of OpenPGP-encrypted
files kept in a git repository. SE Pass clones that repo, then decrypts entries
on-device using a P-256 key generated in and confined to the Secure Enclave.

There is no account and no sign-in. The app only connects to the git repository
the user configures. It collects no data and contains no analytics or tracking.

## Seeing it work
You can exercise cloning and browsing against a public demo repository:

1. **Sync** tab → URL `https://github.com/modiotlabs/sepass-demo-store.git`,
   Auth "None / public" → **Clone**.
2. **Passwords** tab → browse the synced tree.

Decryption is hardware-bound by design: an entry can only be decrypted by the
Secure Enclave key it was encrypted to, so end-to-end decryption requires
generating a key on the device and re-encrypting a store to it (the normal pass
workflow, below). If it would help review, we're happy to provide a screen
recording of the full decrypt flow, or a tailored test store — contact below.

## How the full flow works
1. **Key** tab → Generate Key in Secure Enclave → Share the public key (.asc).
2. On a computer with pass: `gpg --import`, add the key with `pass init`,
   re-encrypt, and push.
3. **Sync** tab → enter the repo URL (HTTPS or SSH) → Clone.
4. **Passwords** tab → tap an entry → Face ID → decrypt.

For real entries, decryption is gated by Face ID/Touch ID (the Enclave key
requires biometric authentication). The demo path is not biometric-gated because
its sample key is a bundled software key, not the Enclave key.

## Notes
- Network access is solely to the user-provided git remote (e.g. GitHub or a
  self-hosted server). No other endpoints are contacted.
- The app is read + sync only; it does not create or edit passwords on device.
- Open source: https://github.com/modiotlabs/sepass

## Demo contact
apps@modiot.com
