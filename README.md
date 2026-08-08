# PK WealthPulse — License Revocation List

Public by design. This repo exists solely so the app can fetch `revoked.json`
unauthenticated at runtime via `raw.githubusercontent.com` (same pattern as
the `mutualfundslogo` asset repo).

## What's in it

`revoked.json` — a flat array of entries, one per expired PAN (single
state, no revoked/paused distinction):

```json
[{"h": "<sha256 hex of the customer's PAN>", "at": 1751500000000}]
```

`at` is a cutoff timestamp, not a permanent ban: the app blocks any license
for that PAN with an `issued` time **at or before** `at`, but a license
issued **after** `at` is honored normally. This is what makes "generate the
customer a new license" the actual way back in — a fresh license naturally
has a later `issued` timestamp than any past expiry, so it isn't blocked,
with no separate restore step needed.

Only SHA-256 hashes of PANs are stored, never raw PANs or any other
identifying customer data. That said, an unsalted SHA-256 of a PAN is not
strong protection on its own: Indian PANs follow a fixed, low-entropy
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

The app checks this file **before** granting dashboard access (both PAN+Name
and credential login), not just afterward — fetches `revoked.json` and
`revoked.sig` together, verifies the signature against the public key
embedded in the app, and only then hashes the PAN being signed in and
checks it against the list for a match. If there's a matching entry, it
compares the license's own `issued` time against that entry's `at` cutoff
(see above). It also re-checks periodically while a session is already
open, as a safety net for access that gets expired mid-session. If the
fetch fails (offline) or the signature doesn't verify, the check is
skipped — it never blocks login on a failed network request or a
verification miss, it only ever blocks on a genuine, correctly-signed
revocation match.
