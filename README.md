# FINUFF — License Revocation List

Public by design. This repo exists solely so the app can fetch `revoked.json`
unauthenticated at runtime via `raw.githubusercontent.com` (same pattern as
the `mutualfundslogo` asset repo).

## What's in it

`revoked.json` — a flat array of entries, one per expired identity (single
state, no revoked/paused distinction):

```json
[{"h": "<sha256 hex of the identity claim>", "at": 1751500000000}]
```

`h` is the SHA-256 of the licence holder's identity claim after trimming and
upper-casing it. For licences issued today (v2, `PKWP2.…` keys) the claim is
the **login email / account ID**; for legacy licences it was the **PAN**.

`at` is a cutoff timestamp, not a permanent ban: the app blocks any license
for that identity with an `issued` time **at or before** `at`, but a license
issued **after** `at` is honored normally. This is what makes "generate the
customer a new license" the actual way back in — a fresh license naturally
has a later `issued` timestamp than any past expiry, so it isn't blocked,
with no separate restore step needed.

Only SHA-256 hashes are stored, never raw PANs, emails or any other
identifying customer data. That said, an unsalted SHA-256 is not strong
protection on its own. **Privacy properties of this public list:**

- The hashes give obscurity, not confidentiality. Someone who already holds a
  candidate email (or account ID) can hash it and check whether it is listed;
  the list does not reveal identities to someone who has no candidate.
- Each entry's `at` timestamp is public, so a match also shows approximately
  when that licence was expired or re-issued.
- A salted or server-side check would improve this, but it needs an app change
  and a migration that keeps existing licences working. It is a planned privacy
  improvement; the format is deliberately unchanged until then.

For legacy PANs the same applies: Indian
PANs follow a fixed, low-entropy
structure (5 letters + 4 digits + 1 check letter, with the 4th letter fixed
by holder type and the 5th by surname initial), so for a guessed surname
initial and the common "individual" holder type, the unknown space collapses
to a brute-forceable few hundred million combinations — and the hash is also
checkable against any previously-leaked PAN database. Treat this list as
"obscured, not cryptographically irreversible": it doesn't hand out a PAN
directly, but a motivated party can often determine which real customers are
on it.

`revoked.sig` — a detached ECDSA P-256/SHA-256 signature (base64) over the
exact bytes of `revoked.json`, signed with a keypair dedicated to this list
alone (never the same key that signs license keys themselves). The app
verifies this signature before trusting anything in `revoked.json`; a
mismatch is treated the same as an unreachable list rather than as a fatal
error (see "How the app uses it" below) — this protects against a
compromised repo or leaked push credential silently un-revoking a blocked
license, or injecting bogus entries to lock out real customers, without
turning a signing-pipeline outage into an app-wide denial of service.

## How it's updated

Use the License Generator tool's "Expire a license immediately" menu option
(`PKWealthPulse-LicenseGenerator` repo) — it computes the hash, updates
`revoked.json`, re-signs it with `revocation-signing-key.local.json` into
`revoked.sig`, and pushes both files here automatically. There's no
"restore" tool since none is needed: issuing a new license (option 1 in that
same tool) is the restore. The signing key is a separate, gitignored file in
that repo — never committed, same treatment as the license-signing key.

## How the app uses it

The app checks this file **before** granting dashboard access (every kind of
sign-in), not just afterward — fetches `revoked.json` and `revoked.sig`
together, verifies the signature against the public key embedded in the app,
and only then hashes the identity being signed in (email/account ID, or PAN
for a legacy licence) and checks it against the list for a match. If there's
a matching entry, it compares the license's own `issued` time against that
entry's `at` cutoff (see above). It re-checks periodically while a session is
already open, as a safety net for access that gets expired mid-session.

Behaviour when the list can't be used: a correctly-signed list is cached
(in memory for about 30 minutes, and on disk), and a rollback guard refuses
any signed list whose newest timestamp is older than the newest one already
seen. If the fetch fails (offline) the app uses the last verified cached list.
With no usable verified list (for example a first run that is offline, or a
list whose signature does not verify) the app does not block sign-in; it only
blocks on a correctly-signed revocation match.

This is a deliberate availability-over-enforcement trade-off: a network or
hosting problem never locks paying customers out, at the cost that a revocation
cannot be enforced on a device that has no verified list. A maximum-staleness
(freshness) policy for the cached list has not been defined yet; until one is
approved and implemented, this behaviour is unchanged.

## Verifying the published list

`node verify-revocations.js` is a read-only check (it never signs or writes): it fetches the live `revoked.json` and `revoked.sig`
from the URLs the app uses and confirms the signature verifies over the exact bytes with the app's public key and that the list has the
expected shape. `--local` checks the files in this folder, `--check-app <path to src-tauri/src/license.rs>` also confirms the key
matches the one compiled into the app, and `--selftest` proves the checker itself rejects tampered or malformed input. Run it after
every update to the list. Backup and recovery of the signing keys is described in the LicenseGenerator repo (`BACKUP-AND-RECOVERY.md`).
