#!/usr/bin/env node
// Read-only check of the published revocation list: does revoked.sig verify over the exact bytes of revoked.json with the public key the
// FINUFF app embeds, and does revoked.json have the shape the app expects? It never signs anything, never writes anywhere and prints counts
// only (no hashes). It is separate from the licence-generator, which is the only thing that signs.
//
//   node verify-revocations.js                  fetch the live files from raw.githubusercontent.com (the URLs the app uses) and verify
//   node verify-revocations.js --local          verify revoked.json / revoked.sig sitting next to this script
//   node verify-revocations.js --check-app <path\to\src-tauri\src\license.rs>
//                                               also confirm the public key below equals the one compiled into the app
//   node verify-revocations.js --selftest       prove the checker itself works (throwaway key; valid passes, tampered / malformed fail)
//
// Exit code 0 = everything verified, 1 = a problem was found, 2 = usage or network error.
'use strict';
const { webcrypto } = require('crypto');
const fs = require('fs');
const path = require('path');
const subtle = webcrypto.subtle;

const LIST_URL = 'https://raw.githubusercontent.com/appu712/pkwp-revocations/main/revoked.json';
const SIG_URL = 'https://raw.githubusercontent.com/appu712/pkwp-revocations/main/revoked.sig';
const MAX_BYTES = 512 * 1024; // the app's cap on the downloaded list
// Public key of the revocation-signing keypair. Must equal REVOCATION_PUB_X / REVOCATION_PUB_Y in the app's src-tauri/src/license.rs
// and PKWP_REVOCATION_PUBKEY_JWK in web/index.html (--check-app confirms the first).
const PUBLIC_JWK = { kty: 'EC', crv: 'P-256', x: 'DLFt2qoO-e2zZPp-yMZToWkuvEgGcvP8g6UcXqSv6js', y: 'OYJwCD9xaSna-PF_Vkx7tmEredlXRIM6e7uBGIchleo' };

// An entry is { h: 64 lowercase hex chars (sha256 of the identity), at: cutoff epoch ms }.
function listProblem(parsed) {
  if (!Array.isArray(parsed)) return 'not a JSON array';
  for (let i = 0; i < parsed.length; i++) {
    const e = parsed[i];
    if (!e || typeof e !== 'object' || Array.isArray(e)) return `entry ${i} is not an object`;
    if (typeof e.h !== 'string' || !/^[0-9a-f]{64}$/.test(e.h)) return `entry ${i} has no valid 64-character lowercase hex hash`;
    if (typeof e.at !== 'number' || !isFinite(e.at) || e.at <= 0) return `entry ${i} has no valid timestamp`;
  }
  return '';
}

// body: Buffer of revoked.json, sigText: contents of revoked.sig (base64 of a P1363 ECDSA P-256 signature), jwk: public key.
// Returns { ok, problems: [string], count, maxAt, duplicates }.
async function verifyList(body, sigText, jwk) {
  const problems = [];
  let count = null, maxAt = null, duplicates = 0;
  if (body.length > MAX_BYTES) problems.push(`list is ${body.length} bytes, over the app's ${MAX_BYTES}-byte cap`);
  let parsed = null;
  try { parsed = JSON.parse(body.toString('utf8')); } catch (e) { problems.push('revoked.json is not valid JSON: ' + e.message); }
  if (parsed !== null) {
    const p = listProblem(parsed);
    if (p) problems.push('schema: ' + p);
    else {
      count = parsed.length;
      maxAt = parsed.reduce((m, e) => Math.max(m, e.at), 0);
      duplicates = count - new Set(parsed.map((e) => e.h)).size;
      if (maxAt > Date.now() + 24 * 3600 * 1000) problems.push('schema: a cutoff timestamp is more than a day in the future');
    }
  }
  let sig = null;
  const text = String(sigText).trim();
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text)) problems.push('signature is not base64');
  else { sig = Buffer.from(text, 'base64'); if (sig.length !== 64) problems.push(`signature is ${sig.length} bytes, expected 64 (P1363 ECDSA P-256)`); }
  if (sig && sig.length === 64) {
    try {
      const key = await subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, body);
      if (!ok) problems.push('signature does NOT verify over the exact bytes of revoked.json');
    } catch (e) { problems.push('signature check failed to run: ' + e.message); }
  }
  return { ok: problems.length === 0, problems, count, maxAt, duplicates };
}

// Reads the public key the app was compiled with out of license.rs (constants REVOCATION_PUB_X / REVOCATION_PUB_Y) and compares it to PUBLIC_JWK.
function appKeyMatches(rsPath) {
  const src = fs.readFileSync(rsPath, 'utf8');
  const x = /REVOCATION_PUB_X\s*:\s*&str\s*=\s*"([^"]+)"/.exec(src), y = /REVOCATION_PUB_Y\s*:\s*&str\s*=\s*"([^"]+)"/.exec(src);
  if (!x || !y) return { ok: false, why: 'REVOCATION_PUB_X / REVOCATION_PUB_Y not found in ' + rsPath };
  return { ok: x[1] === PUBLIC_JWK.x && y[1] === PUBLIC_JWK.y, why: x[1] === PUBLIC_JWK.x && y[1] === PUBLIC_JWK.y ? '' : 'the key in the app differs from the key in this script' };
}

async function fetchBuf(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(15000), headers: { 'Cache-Control': 'no-cache' } });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

async function selftest() {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await subtle.exportKey('jwk', pair.publicKey);
  const sign = async (buf) => Buffer.from(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, buf)).toString('base64') + '\n';
  const body = Buffer.from(JSON.stringify([{ h: 'a'.repeat(64), at: 1760000000000 }], null, 2) + '\n');
  const cases = [];
  const run = async (name, wantOk, b, s, k) => { const r = await verifyList(b, s, k || jwk); cases.push([name, r.ok === wantOk, r.problems.join('; ')]); };
  await run('valid list + valid signature passes', true, body, await sign(body));
  await run('empty list + valid signature passes', true, Buffer.from('[]\n'), await sign(Buffer.from('[]\n')));
  const flipped = Buffer.from(body); flipped[flipped.length - 3] ^= 1;
  await run('a single changed byte in the list fails', false, flipped, await sign(body));
  const sig = Buffer.from((await sign(body)).trim(), 'base64'); sig[10] ^= 1;
  await run('a changed signature fails', false, body, sig.toString('base64'));
  const other = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  await run('a signature from a different key fails', false, body, await sign(body), await subtle.exportKey('jwk', other.publicKey));
  for (const [n, v] of [['short hash', [{ h: 'abc', at: 1 }]], ['uppercase hash', [{ h: 'A'.repeat(64), at: 1 }]], ['bad timestamp', [{ h: 'a'.repeat(64), at: 'x' }]], ['not an array', { h: 1 }], ['non-object entry', [5]]]) {
    const b = Buffer.from(JSON.stringify(v)); await run('malformed schema (' + n + ') fails even with a valid signature', false, b, await sign(b));
  }
  const junk = Buffer.from('not json'); await run('invalid JSON fails even with a valid signature', false, junk, await sign(junk));
  await run('signature of the wrong length fails', false, body, Buffer.from('short').toString('base64'));
  await run('a signature that is not base64 fails', false, body, '!!!not-base64!!!');
  await run('oversized list fails', false, Buffer.alloc(MAX_BYTES + 1, 0x20), await sign(body));
  const future = Buffer.from(JSON.stringify([{ h: 'a'.repeat(64), at: Date.now() + 5 * 86400000 }])); await run('a cutoff far in the future fails', false, future, await sign(future));
  return cases;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--selftest')) {
    const cases = await selftest(); let bad = 0;
    for (const [name, pass, why] of cases) { console.log((pass ? 'PASS  ' : 'FAIL  ') + name + (pass ? '' : '  -- ' + why)); if (!pass) bad++; }
    console.log(`\n${cases.length - bad} passed, ${bad} failed`);
    process.exit(bad ? 1 : 0);
  }
  let body, sigText, origin;
  try {
    if (args.includes('--local')) {
      body = fs.readFileSync(path.join(__dirname, 'revoked.json')); sigText = fs.readFileSync(path.join(__dirname, 'revoked.sig'), 'utf8'); origin = 'local files next to this script';
    } else { body = await fetchBuf(LIST_URL); sigText = (await fetchBuf(SIG_URL)).toString('utf8'); origin = 'live raw.githubusercontent.com'; }
  } catch (e) { console.error('Could not read the list: ' + e.message); process.exit(2); }
  const r = await verifyList(body, sigText, PUBLIC_JWK);
  console.log(`Source: ${origin}`);
  console.log(`Entries: ${r.count === null ? 'n/a' : r.count}${r.duplicates ? ` (${r.duplicates} duplicate hash(es))` : ''} | newest cutoff: ${r.maxAt ? new Date(r.maxAt).toISOString() : 'n/a'} | list ${body.length} bytes`);
  let bad = r.ok ? 0 : 1;
  const ai = args.indexOf('--check-app');
  if (ai >= 0) {
    const m = appKeyMatches(args[ai + 1] || '');
    console.log('App public key == this script\'s key: ' + (m.ok ? 'yes' : 'NO -- ' + m.why)); if (!m.ok) bad = 1;
  }
  if (r.ok) console.log('RESULT: signature verifies and the schema is valid.');
  else { r.problems.forEach((p) => console.log('PROBLEM: ' + p)); console.log('RESULT: NOT OK'); }
  process.exit(bad ? 1 : 0);
}

module.exports = { listProblem, verifyList, appKeyMatches, PUBLIC_JWK, MAX_BYTES };
if (require.main === module) main().catch((e) => { console.error('Error: ' + e.message); process.exit(2); });
