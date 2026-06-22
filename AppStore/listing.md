# App Store listing — SE Pass

## App name (30 char max)
SE Pass

## Subtitle (30 char max)
Secure Enclave client for pass

## Promotional text (170 char max)
Decrypt your pass passwords on iPhone and iPad with a key that never leaves the Secure Enclave. Clone your encrypted store over HTTPS or SSH. No account. No cloud. Your data stays yours.

## Description
SE Pass is an iPhone and iPad client for the standard Unix password manager, pass
(also known as "GNU pass" or "password-store"). It does three things, well:

• Generate a keypair inside the Secure Enclave. The private key is created in
  the Enclave and can never leave the device — unlike a synced or backed-up key.
  SE Pass exports the matching OpenPGP public key for you to add as a recipient.

• Sync your encrypted password store with git — clone and refresh over HTTPS
  (public or token) or SSH (using an Enclave-backed deploy key). SSH host keys
  are pinned on first connect (trust-on-first-use) and verified on every clone.

• Browse the password tree and decrypt any entry on demand. Decryption runs
  inside the Secure Enclave and is gated by Face ID / Touch ID. The clipboard
  clears itself automatically, like `pass -c`.

SE Pass is built for people who already run pass on the desktop. You add the
app's exported public key to your store's recipients (`pass init`), re-encrypt,
and push. Your iPhone or iPad becomes a read-only, hardware-backed window into
your existing store.

What SE Pass does NOT do: it has no account, sends nothing to us, uses no
analytics or tracking, and talks only to the git remote you configure. Adding or
editing passwords on the device is intentionally out of scope in this version —
SE Pass is a focused, auditable reader.

Free and open source (GPLv3): https://github.com/modiotlabs/sepass

Requires a pass-compatible git repository that you host. Learn about pass at
https://www.passwordstore.org/

## Keywords (100 char max, comma-separated)
pass,password-store,gpg,openpgp,secure enclave,git,ssh,encryption,self-hosted,passwords

## Support URL
https://github.com/modiotlabs/sepass

## Marketing URL (optional)
https://github.com/modiotlabs/sepass

## Primary category
Utilities

## Secondary category (optional)
Productivity

## Age rating
4+ (no objectionable content)
