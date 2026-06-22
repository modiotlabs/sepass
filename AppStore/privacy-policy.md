# SE Pass — Privacy Policy

_Last updated: 2026-06-13_

SE Pass is designed so that your data stays on your device and under your
control. We — Modiot Labs — do not operate any server for SE Pass, and the app
does not send your information to us or to any third party.

## What SE Pass stores, and where
- **Encryption keys.** SE Pass generates P-256 keys inside your device's Secure
  Enclave. The private keys never leave the Secure Enclave and are never
  transmitted anywhere. Related non-secret metadata and any git credentials you
  enter are stored in the iOS Keychain on your device.
- **Your password store.** When you clone a git repository, its (already
  OpenPGP-encrypted) contents are stored locally in the app's sandbox, protected
  by iOS data protection. Decrypted text exists only transiently in memory while
  you view an entry and is never written to disk.
- **Settings.** The repository URL, chosen authentication method, and pinned SSH
  host keys are stored locally on your device.

## What SE Pass collects
Nothing. SE Pass contains no analytics, no advertising, no trackers, and no
third-party SDKs. We receive no information about you or your usage.

## Network connections
SE Pass connects only to the git repository you configure (over HTTPS or SSH),
in order to clone or refresh your store. It contacts no other servers.

## Clipboard
When you copy a password, it is placed on the local clipboard with a 45-second
auto-expiry and marked local-only so it is not shared via Universal Clipboard.

## Data deletion
You can remove everything at any time from the About tab: "Erase Passwords"
deletes the cloned store; "Erase All Data" removes the Enclave keys, store,
pinned hosts, and settings. Deleting the app also removes all of its data.

## Children
SE Pass is not directed at children and collects no personal information.

## Changes
If this policy changes, the updated version will be posted at
https://github.com/modiotlabs/sepass.

## Contact
apps@modiot.com
