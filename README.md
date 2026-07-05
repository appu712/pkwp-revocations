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
identifying customer data. A hash isn't practically reversible back to the
original PAN, so publishing this list publicly doesn't expose customers —
the app hashes the currently logged-in user's PAN locally and checks it
against this list for a match.

## How it's updated

Use the License Generator tool's "Expire a license immediately" menu option
(`PKWealthPulse-LicenseGenerator` repo) — it computes the hash, updates this
file, and pushes here automatically. There's no "restore" tool since none is
needed: issuing a new license (option 1 in that same tool) is the restore.

## How the app uses it

The app checks this file **before** granting dashboard access (both PAN+Name
and credential login), not just afterward — hashes the PAN being signed in,
and if there's a matching entry, compares the license's own `issued` time
against that entry's `at` cutoff (see above). It also re-checks periodically
while a session is already open, as a safety net for access that gets
expired mid-session. If the fetch fails (offline), the check is skipped —
it never blocks login on a failed network request.
