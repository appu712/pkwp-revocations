# PK WealthPulse — License Revocation List

Public by design. This repo exists solely so the app can fetch `revoked.json`
unauthenticated at runtime via `raw.githubusercontent.com` (same pattern as
the `mutualfundslogo` asset repo).

## What's in it

`revoked.json` — a flat array of entries:

```json
[{"h": "<sha256 hex of the customer's PAN>", "reason": "revoked", "at": 1751500000000}]
```

Only SHA-256 hashes of PANs are stored, never raw PANs or any other
identifying customer data. A hash isn't practically reversible back to the
original PAN, so publishing this list publicly doesn't expose customers —
the app hashes the currently logged-in user's PAN locally and checks it
against this list for a match.

## How it's updated

Never edit this file by hand. Use the License Generator tool's "Revoke or
pause a license" / "Restore a revoked/paused license" menu options
(`PKWealthPulse-LicenseGenerator` repo) — it computes the hash, updates this
file, and pushes here automatically.

## How the app uses it

After a successful login (license signature already verified), the app
does a background fetch of this file, hashes the current PAN, and checks
for a match. If found, it shows an "Activation Suspended" screen and clears
the locally cached license. If the fetch fails (offline), the check is
skipped for that session — it never blocks login on a failed network
request.
