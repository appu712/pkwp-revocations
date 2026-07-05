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

Only SHA-256 hashes of PANs are stored, never raw PANs or any other
identifying customer data. A hash isn't practically reversible back to the
original PAN, so publishing this list publicly doesn't expose customers —
the app hashes the currently logged-in user's PAN locally and checks it
against this list for a match.

## How it's updated

Never edit this file by hand unless you're manually reversing an expiry (see
below). Use the License Generator tool's "Expire a license immediately" menu
option (`PKWealthPulse-LicenseGenerator` repo) — it computes the hash,
updates this file, and pushes here automatically.

This is deliberately one-way — there is no "restore" tool. Expiring a PAN
blocks every license ever issued to it (the list is keyed by PAN hash, not
by any one license key), including a brand new one, until the hash is
removed from this file. If access needs to come back, edit this file by
hand, remove the entry, and push.

## How the app uses it

The app checks this file **before** granting dashboard access (both PAN+Name
and credential login), not just afterward — hashes the PAN being signed in
and checks for a match. If found, access is blocked and the user is sent to
the license field to enter a new key or contact support. It also re-checks
in the background after login, as a safety net for a session that was
already open when a PAN got expired. If the fetch fails (offline), the check
is skipped — it never blocks login on a failed network request.
