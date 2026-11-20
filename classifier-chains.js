/* Crypto Transaction Classifier — address detection, non-EVM chains and bridge/NFT/DeFi explorers.
   Loaded before the main script in evm-tx-classifier.html. Every fetcher returns "buckets" in the same
   shape the EVM code uses ({hash, ts, from, to, toName, method, ok, fee, legs[], flags[]}) so the shared
   classify() logic and the Excel export work the same for every chain. */

/* ---------- encoding helpers ---------- */
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const XRP58 = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';
function b58decode(s, alpha = B58) {
  let n = 0n; for (const c of s) { const i = alpha.indexOf(c); if (i < 0) return null; n = n * 58n + BigInt(i); }
  const bytes = []; while (n > 0n) { bytes.unshift(Number(n & 255n)); n >>= 8n; }
  for (const c of s) { if (c === alpha[0]) bytes.unshift(0); else break; }
  return new Uint8Array(bytes);
}
function b58encode(bytes, alpha = B58) {
  let n = 0n; for (const b of bytes) n = n * 256n + BigInt(b);
  let s = ''; while (n > 0n) { s = alpha[Number(n % 58n)] + s; n /= 58n; }
  for (const b of bytes) { if (b === 0) s = alpha[0] + s; else break; }
  return s;
}
const hasSubtle = () => !!(globalThis.crypto && crypto.subtle);
async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)); }
async function b58check(s, alpha = B58) {
  const d = b58decode(s, alpha); if (!d || d.length < 5) return null;
  const body = d.slice(0, -4); if (!hasSubtle()) return body;
  const h = await sha256(await sha256(body)); const cs = d.slice(-4);
  return h.slice(0, 4).every((x, i) => x === cs[i]) ? body : null;
}
async function b58checkEncode(body, alpha = B58) {
  const h = await sha256(await sha256(body)); const out = new Uint8Array(body.length + 4);
  out.set(body); out.set(h.slice(0, 4), body.length); return b58encode(out, alpha);
}
/* ---------- Substrate (Polkadot-family) SS58 addresses: one key, a different prefix per chain ---------- */
function blake2b(input, outlen = 64) { // RFC 7693, BigInt version (only used on short inputs)
  const M = (1n << 64n) - 1n, IV = [0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n, 0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n];
  const S = [[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],[11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],[7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],[9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],[2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],[12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],[13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],[6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],[10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0]];
  const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & M;
  const h = IV.slice(); h[0] ^= 0x01010000n ^ BigInt(outlen);
  const blocks = Math.max(1, Math.ceil(input.length / 128)); let t = 0n;
  for (let b = 0; b < blocks; b++) {
    const chunk = new Uint8Array(128); chunk.set(input.slice(b * 128, b * 128 + 128));
    const last = b === blocks - 1; t += BigInt(last ? input.length - b * 128 : 128);
    const m = []; for (let i = 0; i < 16; i++) { let w = 0n; for (let k = 7; k >= 0; k--) w = (w << 8n) | BigInt(chunk[i * 8 + k]); m.push(w); }
    const v = [...h, ...IV]; v[12] ^= t & M; v[13] ^= t >> 64n; if (last) v[14] ^= M;
    const G = (a, b2, c, d, x, y) => { v[a] = (v[a] + v[b2] + x) & M; v[d] = rotr(v[d] ^ v[a], 32n); v[c] = (v[c] + v[d]) & M; v[b2] = rotr(v[b2] ^ v[c], 24n);
      v[a] = (v[a] + v[b2] + y) & M; v[d] = rotr(v[d] ^ v[a], 16n); v[c] = (v[c] + v[d]) & M; v[b2] = rotr(v[b2] ^ v[c], 63n); };
    for (let r = 0; r < 12; r++) { const s2 = S[r % 10];
      G(0, 4, 8, 12, m[s2[0]], m[s2[1]]); G(1, 5, 9, 13, m[s2[2]], m[s2[3]]); G(2, 6, 10, 14, m[s2[4]], m[s2[5]]); G(3, 7, 11, 15, m[s2[6]], m[s2[7]]);
      G(0, 5, 10, 15, m[s2[8]], m[s2[9]]); G(1, 6, 11, 12, m[s2[10]], m[s2[11]]); G(2, 7, 8, 13, m[s2[12]], m[s2[13]]); G(3, 4, 9, 14, m[s2[14]], m[s2[15]]); }
    for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
  }
  const out = new Uint8Array(outlen); for (let i = 0; i < outlen; i++) out[i] = Number((h[i >> 3] >> BigInt(8 * (i & 7))) & 255n); return out;
}
const SS58PRE = new TextEncoder().encode('SS58PRE');
function ss58Decode(s) {
  if (!/^[1-9A-HJ-NP-Za-km-z]{45,50}$/.test(s)) return null;
  const d = b58decode(s); if (!d || (d.length !== 35 && d.length !== 36)) return null;
  const pl = d[0] < 64 ? 1 : 2; if (d[0] >= 128 || d.length - pl - 2 !== 32) return null;
  const prefix = pl === 1 ? d[0] : (((d[0] & 0x3f) << 2) | (d[1] >> 6)) | ((d[1] & 0x3f) << 8);
  const body = d.slice(0, d.length - 2), cs = blake2b(new Uint8Array([...SS58PRE, ...body]));
  if (cs[0] !== d[d.length - 2] || cs[1] !== d[d.length - 1]) return null;
  return {prefix, pub: d.slice(pl, pl + 32)};
}
function ss58Encode(prefix, pub) {
  const p = prefix < 64 ? [prefix] : [((prefix & 0xfc) >> 2) | 0x40, (prefix >> 8) | ((prefix & 0x03) << 6)];
  const body = new Uint8Array([...p, ...pub]), cs = blake2b(new Uint8Array([...SS58PRE, ...body]));
  return b58encode(new Uint8Array([...body, cs[0], cs[1]]));
}
const SS58_NAMES = {0: 'Polkadot', 2: 'Kusama', 42: 'generic Substrate / Bittensor'};
// Nomination-pool accounts are derived from "modlpy/nopls" + type (0 = bonded stake, 1 = reward) + pool id.
// Staking reward pots ("modlpy/stkng" + era) pay Asset Hub staking rewards since the 2025 migration.
function poolAccount(addr) {
  const d = ss58Decode(addr || ''); if (!d) return null;
  const tag = new TextDecoder().decode(d.pub.slice(0, 12));
  if (tag === 'modlpy/stkng') return {type: 'staking'};
  if (tag !== 'modlpy/nopls') return null;
  return {type: d.pub[12] === 1 ? 'reward' : 'bonded', id: d.pub[13] | (d.pub[14] << 8) | (d.pub[15] << 16) | (d.pub[16] << 24)};
}
const BECH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function bechPolymod(v) {
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; let c = 1;
  for (const x of v) { const b = c >>> 25; c = ((c & 0x1ffffff) << 5) ^ x; for (let i = 0; i < 5; i++) if ((b >>> i) & 1) c ^= G[i]; }
  return c >>> 0;
}
const hrpExp = h => [...[...h].map(c => c.charCodeAt(0) >> 5), 0, ...[...h].map(c => c.charCodeAt(0) & 31)];
function bech32Decode(s) {
  if (s !== s.toLowerCase() && s !== s.toUpperCase()) return null;
  s = s.toLowerCase(); const p = s.lastIndexOf('1'); if (p < 1 || p + 7 > s.length) return null;
  const hrp = s.slice(0, p), data = [];
  for (const c of s.slice(p + 1)) { const i = BECH.indexOf(c); if (i < 0) return null; data.push(i); }
  const pm = bechPolymod([...hrpExp(hrp), ...data]); if (pm !== 1 && pm !== 0x2bc830a3) return null;
  return {hrp, words: data.slice(0, -6)};
}
function bech32Encode(hrp, words) {
  const pm = bechPolymod([...hrpExp(hrp), ...words, 0, 0, 0, 0, 0, 0]) ^ 1; const cs = [];
  for (let i = 0; i < 6; i++) cs.push((pm >> (5 * (5 - i))) & 31);
  return hrp + '1' + [...words, ...cs].map(i => BECH[i]).join('');
}
const hexToBytes = h => new Uint8Array((h.match(/../g) || []).map(x => parseInt(x, 16)));
const hexAscii = h => { try { return new TextDecoder().decode(hexToBytes(h)).replace(/\0/g, '').trim(); } catch { return ''; } };
const postJSON = (url, body, headers = {}) => getJSON(url, {method: 'POST', headers: {'Content-Type': 'application/json', ...headers}, body: JSON.stringify(body)});
const proxied = url => { if (!HELPER) throw new Error('needs the local helper — run "python3 start-classifier.py" and use the page it opens'); return '/proxy/' + url.replace(/^https:\/\//, ''); };
const notFound = e => /HTTP 404|HTTP 400/.test(e.message || '');

/* ---------- Cosmos chains (one key → same address on every coin-type-118 chain) ---------- */
const COSMOS = [
  {id: 'atom',  dir: 'cosmoshub', hrp: 'cosmos',   name: 'Cosmos Hub', code: 'ATOM',  denom: 'uatom',  dec: 6,  ms: 'cosmos',    ct: 118},
  {id: 'osmo',  dir: 'osmosis',   hrp: 'osmo',     name: 'Osmosis',    code: 'OSMO',  denom: 'uosmo',  dec: 6,  ms: 'osmosis',   ct: 118},
  {id: 'tia',   dir: 'celestia',  hrp: 'celestia', name: 'Celestia',   code: 'TIA',   denom: 'utia',   dec: 6,  ms: 'celestia',  ct: 118},
  {id: 'inj',   dir: 'injective', hrp: 'inj',      name: 'Injective',  code: 'INJ',   denom: 'inj',    dec: 18, ms: 'injective', ct: 60, evm: true},  {id: 'dydx',  dir: 'dydx',      hrp: 'dydx',     name: 'dYdX Chain', code: 'DYDX',  denom: 'adydx',  dec: 18, ms: 'dydx',      ct: 118},
  {id: 'akt',   dir: 'akash',     hrp: 'akash',    name: 'Akash',      code: 'AKT',   denom: 'uakt',   dec: 6,  ms: 'akash',     ct: 118},
  {id: 'strd',  dir: 'stride',    hrp: 'stride',   name: 'Stride',     code: 'STRD',  denom: 'ustrd',  dec: 6,  ms: 'stride',    ct: 118},
  {id: 'ntrn',  dir: 'neutron',   hrp: 'neutron',  name: 'Neutron',    code: 'NTRN',  denom: 'untrn',  dec: 6,  ms: 'neutron',   ct: 118},
  {id: 'juno',  dir: 'juno',      hrp: 'juno',     name: 'Juno',       code: 'JUNO',  denom: 'ujuno',  dec: 6,  ms: 'juno',      ct: 118},
  {id: 'stars', dir: 'stargaze',  hrp: 'stars',    name: 'Stargaze',   code: 'STARS', denom: 'ustars', dec: 6,  ms: 'stargaze',  ct: 118},
  {id: 'sei',   dir: 'sei',       hrp: 'sei',      name: 'Sei',        code: 'SEI',   denom: 'usei',   dec: 6,  ms: 'sei',       ct: 118},
  {id: 'noble', dir: 'noble',     hrp: 'noble',    name: 'Noble',      code: 'NOBLE', denom: 'uusdc',  dec: 6,  ms: 'noble',     ct: 118, sym: 'USDC'},
];
const COSMOS_HRP = Object.fromEntries(COSMOS.map(c => [c.hrp, c]));

/* ---------- Address detection ---------- */
async function detectAddress(s) {
  s = s.trim();
  if (/^0x[0-9a-fA-F]{40}$/.test(s)) return {family: 'evm', addr: s.toLowerCase(), label: 'EVM'};
  if (/^xdc[0-9a-fA-F]{40}$/i.test(s)) return {family: 'evm', addr: '0x' + s.slice(3).toLowerCase(), label: 'EVM (XDC address)'};
  if (/^0x[0-9a-fA-F]{64}$/.test(s)) return {family: 'iota', addr: s.toLowerCase(), label: 'IOTA'};
  if (/^G[A-Z2-7]{55}$/.test(s)) return {family: 'xlm', addr: s, label: 'Stellar'};
  if (/^0\.0\.\d+(-[a-z]{5})?$/i.test(s)) return {family: 'hbar', addr: s.split('-')[0], label: 'Hedera'};
  if (/^[A-Z2-7]{58}$/.test(s)) return {family: 'algo', addr: s, label: 'Algorand'};
  if (/^f(0\d+|1[a-z2-7]{39}|2[a-z2-7]{39}|3[a-z2-7]{84}|410f[a-z2-7]{39,})$/.test(s)) return {family: 'fil', addr: s, label: 'Filecoin'};
  if (/^(01[0-9a-fA-F]{64}|02[0-9a-fA-F]{66})$/.test(s)) return {family: 'cspr', addr: s.toLowerCase(), label: 'Casper'};
  // Substrate SS58 (Polkadot 1…, Kusama C…/H…, generic/Bittensor 5…, parachains …): the same key works on every chain
  if (/^[1-9A-HJ-NP-Za-km-z]{45,50}$/.test(s)) { const d = ss58Decode(s); if (d) return {family: 'substrate', addr: s, pub: d.pub, prefix: d.prefix, label: `Substrate (${SS58_NAMES[d.prefix] || 'prefix ' + d.prefix})`}; }
  if (/^@?[a-z1-5.]{1,12}$/.test(s) && !/\.$/.test(s)) return {family: 'xpr', addr: s.replace(/^@/, ''), label: 'XPR Network account'};
  if (/^[xyz]pub[1-9A-HJ-NP-Za-km-z]{100,112}$/.test(s)) return {family: 'btc', addr: s, xpub: true, label: 'Bitcoin ' + s.slice(0, 4)};
  if (/^(addr1|stake1)[0-9a-z]{40,}$/.test(s)) return {family: 'ada', addr: s, label: 'Cardano'};
  if (/^(EQ|UQ|Ef|Uf|kQ|0Q)[A-Za-z0-9_-]{46}$/.test(s) || /^-?[01]:[0-9a-fA-F]{64}$/.test(s)) return {family: 'ton', addr: s, label: 'TON'};
  const bech = bech32Decode(s);
  if (bech) {
    if (bech.hrp === 'thor') return {family: 'thor', addr: s.toLowerCase(), label: 'THORChain'};
    if (bech.hrp === 'bc') return {family: 'btc', addr: s.toLowerCase(), label: 'Bitcoin'};
    if (bech.hrp === 'ltc') return {family: 'ltc', addr: s.toLowerCase(), label: 'Litecoin'};
    if (COSMOS_HRP[bech.hrp]) return {family: 'cosmos', addr: s.toLowerCase(), hrp: bech.hrp, words: bech.words, label: 'Cosmos (' + bech.hrp + ')'};
  }
  if (/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(s) && await b58check(s, XRP58)) return {family: 'xrp', addr: s, label: 'XRP Ledger'};
  if (/^[1-9A-HJ-NP-Za-km-z]{25,35}$/.test(s)) {
    const body = await b58check(s);
    if (body && body.length === 21) {
      const v = body[0];
      if (v === 0x00 || v === 0x05) return {family: 'btc', addr: s, label: 'Bitcoin'};
      if (v === 0x30 || v === 0x32) return {family: 'ltc', addr: s, label: 'Litecoin'};
      if (v === 0x1e || v === 0x16) return {family: 'doge', addr: s, label: 'Dogecoin'};
      if (v === 0x41) return {family: 'trx', addr: s, label: 'Tron'};
    }
  }
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s)) { const d = b58decode(s); if (d && d.length === 32) return {family: 'sol', addr: s, label: 'Solana'}; }
  return {family: null, addr: s, label: 'Unknown format'};
}
// The address to use on a given chain (Cosmos addresses are re-encoded for each coin-type-118 chain).
// 8-bit bytes -> 5-bit bech32 words
function toWords(bytes) { let acc = 0, bits = 0; const out = []; for (const b of bytes) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; out.push((acc >> bits) & 31); } } if (bits) out.push((acc << (5 - bits)) & 31); return out; }
function chainAddr(chain, det) {
  if (chain.family === 'substrate') { if (det.family === 'substrate' && !chain.evmAccounts) return chain.ss58 == null ? det.addr : ss58Encode(chain.ss58, det.pub); if (det.family === 'evm' && chain.evmAccounts) return det.addr; return null; }
  if (chain.family === 'hbar' && det.family === 'evm') return det.addr; // Hedera accounts also have a 0x… EVM address
  // Kava and Injective accounts share their bytes with the 0x… address of the same key
  if (chain.family === 'cosmos' && chain.evm && det.family === 'evm') return bech32Encode(chain.hrp, toWords(hexToBytes(det.addr.slice(2))));
  if (!det.family || chain.family !== det.family) return null;
  if (det.family !== 'cosmos') return det.addr;
  if (det.hrp === chain.hrp) return det.addr;
  const src = COSMOS_HRP[det.hrp];
  return src.ct === 118 && chain.ct === 118 ? bech32Encode(chain.hrp, det.words) : null;
}

/* ---------- UTXO chains (Bitcoin, Litecoin, Dogecoin) ---------- */
// txs: [{hash, ts, fee, ins:[{addr, value}], outs:[{addr, value}]}] with values in coins.
function utxoBuckets(chain, txs, own, me) {
  const map = new Map(), EPS = 1e-10;
  for (const t of txs) {
    if (!t.ts) continue;
    const b = bucket(map, t.hash); b.ts = t.ts; b.ok = true; b.initKnown = true; b.method = 'transfer';
    const ownIn = t.ins.filter(i => own.has(i.addr)).reduce((s, i) => s + i.value, 0);
    const ownOut = t.outs.filter(o => own.has(o.addr)).reduce((s, o) => s + o.value, 0);
    const totIn = t.ins.reduce((s, i) => s + i.value, 0);
    const extOut = t.outs.find(o => o.addr && !own.has(o.addr)), extIn = t.ins.find(i => i.addr && !own.has(i.addr));
    if (ownIn > EPS) {
      b.from = me; b.fee = totIn > 0 ? t.fee * Math.min(1, ownIn / totIn) : t.fee;
      const sent = ownIn - ownOut - b.fee;
      if (sent > EPS) { b.to = extOut?.addr || ''; b.legs.push(natLeg(chain, 'out', +sent.toFixed(8), b.to)); }
      else if (sent < -EPS) b.legs.push(natLeg(chain, 'in', +(-sent).toFixed(8), extIn?.addr || ''));
      else { b.to = me; b.toName = 'your own addresses (consolidation/change)'; }
    } else if (ownOut > EPS) {
      b.from = extIn?.addr || ''; b.to = me;
      b.legs.push(natLeg(chain, 'in', +ownOut.toFixed(8), b.from));
    }
  }
  return [...map.values()];
}
async function fetchEsplora(chain, base, addr, opt) {
  const raw = []; let last = null, cutoff = null;
  for (let p = 0; p < opt.maxPages * 2; p++) {
    const j = await getJSON(`${base}/address/${addr}/txs${last ? '/chain/' + last : ''}`);
    const conf = (j || []).filter(t => t.status?.confirmed); raw.push(...conf);
    if (conf.length < 25) break;
    last = conf[conf.length - 1].txid;
    const ts = conf[conf.length - 1].status.block_time * 1000;
    if (opt.from && ts < +opt.from) break;
    if (p === opt.maxPages * 2 - 1) cutoff = new Date(ts);
    await sleep(250);
  }
  const txs = raw.map(t => ({hash: t.txid, ts: new Date(t.status.block_time * 1000), fee: (t.fee || 0) / 1e8,
    ins: t.vin.map(v => ({addr: v.prevout?.scriptpubkey_address || '', value: (v.prevout?.value || 0) / 1e8})),
    outs: t.vout.map(v => ({addr: v.scriptpubkey_address || '', value: (v.value || 0) / 1e8}))}));
  return trimToCutoff(utxoBuckets(chain, txs, new Set([addr, ...(opt.ownBySameFamily || [])]), addr), cutoff);
}
async function scanEsplora(base, addr) {
  const j = await getJSON(`${base}/address/${addr}`);
  const n = (j.chain_stats?.tx_count || 0) + (j.mempool_stats?.tx_count || 0);
  return {active: n > 0, count: n};
}
/* ---------- Bitcoin xpub/ypub/zpub worked out in the browser (no helper, no key) ----------
   The extended public key is turned into the wallet's receive (…/0/i) and change (…/1/i) addresses with
   standard BIP32 maths; each address is then read from mempool.space. Stops after 20 unused addresses in a row. */
const SECP = {p: 2n ** 256n - 2n ** 32n - 977n, n: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n,
  G: [0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n]};
const modp = a => { const r = a % SECP.p; return r < 0n ? r + SECP.p : r; };
const powp = (b, e) => { let r = 1n; b = modp(b); while (e > 0n) { if (e & 1n) r = r * b % SECP.p; b = b * b % SECP.p; e >>= 1n; } return r; };
const invp = a => powp(a, SECP.p - 2n);
function ecAdd(P, Q) {
  if (!P) return Q; if (!Q) return P;
  if (P[0] === Q[0]) { if (modp(P[1] + Q[1]) === 0n) return null; const l = modp(3n * P[0] * P[0] * invp(2n * P[1])); const x = modp(l * l - 2n * P[0]); return [x, modp(l * (P[0] - x) - P[1])]; }
  const l = modp((Q[1] - P[1]) * invp(Q[0] - P[0])); const x = modp(l * l - P[0] - Q[0]); return [x, modp(l * (P[0] - x) - P[1])];
}
function ecMul(k, P) { let R = null, A = P; while (k > 0n) { if (k & 1n) R = ecAdd(R, A); A = ecAdd(A, A); k >>= 1n; } return R; }
const bytesToBig = b => b.reduce((n, x) => (n << 8n) | BigInt(x), 0n);
const bigTo32 = n => { const o = new Uint8Array(32); for (let i = 31; i >= 0; i--) { o[i] = Number(n & 255n); n >>= 8n; } return o; };
function ecDecompress(c) { const x = bytesToBig(c.slice(1)); let y = powp(x * x * x + 7n, (SECP.p + 1n) / 4n); if ((y & 1n) !== BigInt(c[0] & 1)) y = SECP.p - y; return [x, y]; }
const ecCompress = P => { const o = new Uint8Array(33); o[0] = P[1] & 1n ? 3 : 2; o.set(bigTo32(P[0]), 1); return o; };
async function hmac512(key, data) { const k = await crypto.subtle.importKey('raw', key, {name: 'HMAC', hash: 'SHA-512'}, false, ['sign']); return new Uint8Array(await crypto.subtle.sign('HMAC', k, data)); }
async function ckdPub(node, i) { // non-hardened child of {key (33 bytes), chain (32 bytes)}
  const d = new Uint8Array(37); d.set(node.key); d[33] = i >>> 24; d[34] = (i >>> 16) & 255; d[35] = (i >>> 8) & 255; d[36] = i & 255;
  const I = await hmac512(node.chain, d); const il = bytesToBig(I.slice(0, 32));
  return {key: ecCompress(ecAdd(ecMul(il, SECP.G), ecDecompress(node.key))), chain: I.slice(32)};
}
function ripemd160(msg) {
  const rl = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
  const rr = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
  const sl = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
  const sr = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
  const KL = [0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e], KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0];
  const f = (j, x, y, z) => j < 16 ? x ^ y ^ z : j < 32 ? (x & y) | (~x & z) : j < 48 ? (x | ~y) ^ z : j < 64 ? (x & z) | (y & ~z) : x ^ (y | ~z);
  const rol = (x, n) => (x << n) | (x >>> (32 - n));
  const len = msg.length, padLen = ((len + 8) >> 6 << 6) + 64, m = new Uint8Array(padLen); m.set(msg); m[len] = 0x80;
  const bits = len * 8; m[padLen - 8] = bits & 255; m[padLen - 7] = (bits >>> 8) & 255; m[padLen - 6] = (bits >>> 16) & 255; m[padLen - 5] = (bits >>> 24) & 255;
  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  for (let o = 0; o < padLen; o += 64) {
    const X = []; for (let i = 0; i < 16; i++) X.push(m[o + i * 4] | (m[o + i * 4 + 1] << 8) | (m[o + i * 4 + 2] << 16) | (m[o + i * 4 + 3] << 24));
    let al = h0, bl = h1, cl = h2, dl = h3, el = h4, ar = h0, br = h1, cr = h2, dr = h3, er = h4;
    for (let j = 0; j < 80; j++) {
      let t = (rol((al + f(j, bl, cl, dl) + X[rl[j]] + KL[j >> 4]) | 0, sl[j]) + el) | 0; al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = t;
      t = (rol((ar + f(79 - j, br, cr, dr) + X[rr[j]] + KR[j >> 4]) | 0, sr[j]) + er) | 0; ar = er; er = dr; dr = rol(cr, 10); cr = br; br = t;
    }
    const t = (h1 + cl + dr) | 0; h1 = (h2 + dl + er) | 0; h2 = (h3 + el + ar) | 0; h3 = (h4 + al + br) | 0; h4 = (h0 + bl + cr) | 0; h0 = t;
  }
  const out = new Uint8Array(20); [h0, h1, h2, h3, h4].forEach((h, i) => { for (let k = 0; k < 4; k++) out[i * 4 + k] = (h >>> (8 * k)) & 255; }); return out;
}
const hash160 = async b => ripemd160(await sha256(b));
async function xpubAddress(pubkey, kind) {
  const h = await hash160(pubkey);
  if (kind === 'zpub') return bech32Encode('bc', [0, ...toWords(h)]);
  if (kind === 'ypub') { const rs = new Uint8Array(22); rs[0] = 0; rs[1] = 20; rs.set(h, 2); const body = new Uint8Array(21); body[0] = 5; body.set(await hash160(rs), 1); return b58checkEncode(body); }
  const body = new Uint8Array(21); body[0] = 0; body.set(h, 1); return b58checkEncode(body);
}
async function xpubNode(x) {
  const d = await b58check(x); if (!d || d.length !== 78) throw new Error('not a valid xpub/ypub/zpub');
  return {key: d.slice(45, 78), chain: d.slice(13, 45), kind: x.slice(0, 4)};
}
// Two free Esplora servers with identical APIs; requests alternate between them and back off when one is busy.
const ESPLORA = ['https://mempool.space/api', 'https://blockstream.info/api']; let esploraTurn = 0; const esploraRest = {};
// Each request waits at most 15 s; a server that fails or is busy rests for 2 minutes while the other one is used.
async function esploraGet(path) {
  let err;
  for (let k = 0; k < 10; k++) {
    if (typeof STOP !== 'undefined' && STOP) throw new Error('Stopped');
    const ready = ESPLORA.filter(b => !(esploraRest[b] > Date.now()));
    if (!ready.length) { await sleep(5000); continue; }
    const base = ready[esploraTurn++ % ready.length];
    const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), 15000);
    try {
      const r = await fetch(base + path, {signal: ctl.signal});
      if (r.status === 429 || r.status >= 500) throw new Error('HTTP ' + r.status);
      if (!r.ok) { const e = new Error('HTTP ' + r.status); e.final = true; throw e; }
      return await r.json();
    } catch (e) { err = e; if (e.final) throw e; esploraRest[base] = Date.now() + 120000; }
    finally { clearTimeout(timer); }
  }
  throw err || new Error('Bitcoin servers busy — try again in a few minutes');
}
// Walk receive (0) and change (1) addresses until 20 in a row are unused. Returns [{addr, n}] with tx counts.
const XPUB_CACHE = new Map(); // xpub -> address list from the scan, reused by the fetch (saves ~40+ requests)
async function xpubAddresses(x, log2) {
  if (XPUB_CACHE.has(x)) return XPUB_CACHE.get(x);
  const root = await xpubNode(x), found = [], GAP = 20;
  // A plain "xpub" can hold legacy, native-SegWit or nested-SegWit addresses: peek at the first 5 receive addresses of each.
  let kinds = [root.kind];
  if (root.kind === 'xpub') {
    const r0 = await ckdPub(root, 0); kinds = [];
    for (const k of ['xpub', 'zpub', 'ypub']) {
      for (let i = 0; i < 5; i++) { const ad = await xpubAddress((await ckdPub(r0, i)).key, k); const j = await esploraGet(`/address/${ad}`);
        if ((j.chain_stats?.tx_count || 0) + (j.mempool_stats?.tx_count || 0)) { kinds.push(k); break; } await sleep(150); }
    }
    if (!kinds.length) kinds = ['xpub'];
    if (log2) log2(`   xpub address types with history: ${kinds.map(k => ({xpub: 'legacy (1…)', zpub: 'native SegWit (bc1q…)', ypub: 'nested SegWit (3…)'})[k]).join(', ')}`);
  }
  for (const kind of kinds) for (const branch of [0, 1]) {
    const bn = await ckdPub(root, branch); let gap = 0;
    // 4 addresses at a time, spread over the two Bitcoin servers
    for (let i = 0; gap < GAP && i < 2000; i += 4) {
      const addrs = await Promise.all([0, 1, 2, 3].map(async k => xpubAddress((await ckdPub(bn, i + k)).key, kind)));
      const res = await Promise.all(addrs.map(ad => esploraGet(`/address/${ad}`)));
      for (let k = 0; k < 4 && gap < GAP; k++) {
        const n = (res[k].chain_stats?.tx_count || 0) + (res[k].mempool_stats?.tx_count || 0);
        found.push({addr: addrs[k], n, path: `${branch}/${i + k}`}); gap = n ? 0 : gap + 1;
      }
      if (log2 && (i + 4) % 20 === 0) log2(`   xpub: checked ${i + 4} ${branch ? 'change' : 'receive'} addresses… (${found.filter(f => f.n).length} used so far)`);
      await sleep(300);
    }
  }
  XPUB_CACHE.set(x, found);
  return found;
}
async function fetchXpubLocal(chain, x, opt) {
  const all = await xpubAddresses(x, typeof log === 'function' ? log : null);
  const used = all.filter(a => a.n > 0), own = new Set(all.map(a => a.addr));
  log(`   xpub: ${used.length} used address(es) of ${all.length} checked.`);
  const seen = new Map(); let cutoff = null, done = 0;
  for (const a of used) {
    if (++done % 10 === 0) log(`   xpub: downloaded history of ${done} of ${used.length} addresses…`);
    let last = null;
    for (let p = 0; p < opt.maxPages * 2; p++) {
      const j = await esploraGet(`/address/${a.addr}/txs${last ? '/chain/' + last : ''}`);
      const conf = (j || []).filter(t => t.status?.confirmed); conf.forEach(t => seen.set(t.txid, t));
      if (conf.length < 25) break;
      last = conf[conf.length - 1].txid;
      const ts = conf[conf.length - 1].status.block_time * 1000;
      if (opt.from && ts < +opt.from) break;
      if (p === opt.maxPages * 2 - 1 && (!cutoff || ts > +cutoff)) cutoff = new Date(ts);
      await sleep(200);
    }
    await sleep(150);
  }
  const txs = [...seen.values()].map(t => ({hash: t.txid, ts: new Date(t.status.block_time * 1000), fee: (t.fee || 0) / 1e8,
    ins: t.vin.map(v => ({addr: v.prevout?.scriptpubkey_address || '', value: (v.prevout?.value || 0) / 1e8})),
    outs: t.vout.map(v => ({addr: v.scriptpubkey_address || '', value: (v.value || 0) / 1e8}))}));
  return trimToCutoff(utxoBuckets(chain, txs, own, x), cutoff);
}
const BLOCKBOOK = 'https://btc1.trezor.io/api/v2';
// An "xpub" may belong to any address type: wallets such as Ledger, Exodus or Electrum export SegWit accounts as xpub too.
// Blockbook takes output descriptors, so every type is checked and the ones with history are used.
const XPUB_FORMS = new Map();
async function xpubForms(x) {
  if (XPUB_FORMS.has(x)) return XPUB_FORMS.get(x);
  const forms = /^xpub/.test(x) ? [x, `wpkh(${x})`, `sh(wpkh(${x}))`, `tr(${x})`] : [x];
  const found = [];
  for (const f of forms) { try { const j = await getJSON(proxied(`${BLOCKBOOK}/xpub/${encodeURIComponent(f)}?details=basic`)); if (+j.txs > 0) found.push({form: f, txs: +j.txs}); } catch (e) {} }
  XPUB_FORMS.set(x, found); return found;
}
const XPUB_TYPE = f => /^tr\(/.test(f) ? 'Taproot (bc1p…)' : /^sh\(wpkh/.test(f) ? 'nested SegWit (3…)' : /^wpkh/.test(f) ? 'native SegWit (bc1q…)' : 'legacy (1…)';
async function fetchXpub(chain, x, opt) {
  const forms = (await xpubForms(x)).map(f => f.form);
  if (forms.length > 1 || (forms[0] && forms[0] !== x)) log(`   xpub address types with history: ${forms.map(XPUB_TYPE).join(', ')}`);
  const all = []; for (const f of forms.length ? forms : [x]) all.push(...await fetchXpubForm(chain, f, opt, x));
  const seen = new Map(); all.forEach(b => { if (!seen.has(b.hash)) seen.set(b.hash, b); });
  return [...seen.values()];
}
async function fetchXpubForm(chain, x, opt, me = x) {
  const own = new Set(), raw = []; let cutoff = null, pages = 1;
  for (let p = 1; p <= Math.min(pages, opt.maxPages); p++) {
    const j = await getJSON(proxied(`${BLOCKBOOK}/xpub/${encodeURIComponent(x)}?details=txs&tokens=used&page=${p}&pageSize=100`));
    (j.tokens || []).forEach(t => own.add(t.name)); pages = j.totalPages || 1;
    raw.push(...(j.transactions || []));
    const last = raw[raw.length - 1];
    if (opt.from && last && last.blockTime * 1000 < +opt.from) break;
    if (p === opt.maxPages && pages > p && last) cutoff = new Date(last.blockTime * 1000);
    await sleep(300);
  }
  const mark = io => { const a = io.addresses?.[0] || ''; if (io.isOwn) own.add(a); return {addr: a, value: (+io.value || 0) / 1e8}; };
  const txs = raw.filter(t => t.blockTime).map(t => ({hash: t.txid, ts: new Date(t.blockTime * 1000), fee: (+t.fees || 0) / 1e8, ins: t.vin.map(mark), outs: t.vout.map(mark)}));
  return trimToCutoff(utxoBuckets(chain, txs, own, me), cutoff);
}
async function fetchDoge(chain, addr, opt) {
  const raw = []; let before = null, cutoff = null;
  for (let p = 0; p < opt.maxPages; p++) {
    const j = await getJSON(`https://api.blockcypher.com/v1/doge/main/addrs/${addr}/full?limit=50${before ? '&before=' + before : ''}`);
    const txs = (j.txs || []).filter(t => t.block_height > 0); raw.push(...txs);
    if (!j.hasMore || !txs.length) break;
    before = txs[txs.length - 1].block_height;
    if (opt.from && new Date(txs[txs.length - 1].confirmed) < opt.from) break;
    if (p === opt.maxPages - 1) cutoff = new Date(txs[txs.length - 1].confirmed);
    await sleep(500);
  }
  const txs = raw.map(t => ({hash: t.hash, ts: new Date(t.confirmed), fee: (t.fees || 0) / 1e8,
    ins: (t.inputs || []).map(i => ({addr: i.addresses?.[0] || '', value: (i.output_value || 0) / 1e8})),
    outs: (t.outputs || []).map(o => ({addr: o.addresses?.[0] || '', value: (o.value || 0) / 1e8}))}));
  return trimToCutoff(utxoBuckets(chain, txs, new Set([addr]), addr), cutoff);
}

/* ---------- Solana (Helius) ---------- */
const SOL_TYPE = {SWAP: 'swap', BUY: 'swap', SELL: 'swap', ADD_LIQUIDITY: 'addLiquidity', WITHDRAW_LIQUIDITY: 'removeLiquidity', REMOVE_LIQUIDITY: 'removeLiquidity',
  STAKE_SOL: 'stake', UNSTAKE_SOL: 'unstake', STAKE_TOKEN: 'stake', UNSTAKE_TOKEN: 'unstake', CLAIM_REWARDS: 'claimRewards', HARVEST: 'harvest',
  NFT_MINT: 'mint', COMPRESSED_NFT_MINT: 'mint', TOKEN_MINT: 'mint', NFT_SALE: 'nftSale', BURN: 'burn', BURN_NFT: 'burn', TRANSFER: 'transfer'};
const NFT_IFACE = /NFT|MplCore|Custom|Identity/i;
const heliusRpc = (key, method, params) => postJSON(`https://mainnet.helius-rpc.com/?api-key=${encodeURIComponent(key)}`, {jsonrpc: '2.0', id: 1, method, params});
async function fetchSolana(chain, addr, opt) {
  const key = opt.heliusKey; if (!key) throw new Error('paste a free Helius API key (helius.dev) to use Solana');
  const all = []; let before = '', cutoff = null;
  for (let p = 0; p < opt.maxPages; p++) {
    const j = await getJSON(`https://api.helius.xyz/v0/addresses/${addr}/transactions?api-key=${encodeURIComponent(key)}&limit=100${before ? '&before=' + before : ''}`);
    if (!Array.isArray(j) || !j.length) break;
    all.push(...j); before = j[j.length - 1].signature;
    const ts = j[j.length - 1].timestamp * 1000;
    if (opt.from && ts < +opt.from) break;
    if (p === opt.maxPages - 1) cutoff = new Date(ts);
    await sleep(150);
  }
  // token metadata (symbol, decimals, NFT or not, has a market price)
  const mints = new Set();
  all.forEach(t => { (t.tokenTransfers || []).forEach(x => mints.add(x.mint)); (t.accountData || []).forEach(a => (a.tokenBalanceChanges || []).forEach(c => mints.add(c.mint))); });
  const meta = {}; const ids = [...mints];
  for (let i = 0; i < ids.length; i += 1000) {
    try { const r = await heliusRpc(key, 'getAssetBatch', {ids: ids.slice(i, i + 1000)}); (r.result || []).forEach(a => { if (a) meta[a.id] = a; }); }
    catch (e) { log(`   ⚠ Solana token names unavailable (${e.message.slice(0, 60)})`, 'w'); }
  }
  const map = new Map();
  for (const t of all) {
    const b = bucket(map, t.signature);
    b.ts = new Date(t.timestamp * 1000); b.ok = !t.transactionError; b.from = t.feePayer; b.initKnown = true;
    b.method = SOL_TYPE[t.type] || (t.type && t.type !== 'UNKNOWN' ? t.type.toLowerCase().replace(/_/g, ' ') : '');
    b.toName = t.source && !/^(SYSTEM_PROGRAM|UNKNOWN|SOLANA_PROGRAM_LIBRARY)$/.test(t.source) ? t.source.replace(/_/g, ' ') : '';
    b.fee = t.feePayer === addr ? (t.fee || 0) / 1e9 : 0; b.desc = t.description || '';
    if (!b.ok) continue;
    const me = (t.accountData || []).find(a => a.account === addr);
    const nat = (me?.nativeBalanceChange || 0) + (t.feePayer === addr ? (t.fee || 0) : 0);
    const natCp = (t.nativeTransfers || []).find(n => n.fromUserAccount === addr || n.toUserAccount === addr);
    if (Math.abs(nat) > 0) b.legs.push(natLeg(chain, nat > 0 ? 'in' : 'out', Math.abs(nat) / 1e9, natCp ? (natCp.fromUserAccount === addr ? natCp.toUserAccount : natCp.fromUserAccount) : ''));
    const per = {};
    (t.accountData || []).forEach(a => (a.tokenBalanceChanges || []).forEach(c => {
      if (c.userAccount !== addr) return;
      per[c.mint] = (per[c.mint] || 0) + units(c.rawTokenAmount?.tokenAmount || '0', c.rawTokenAmount?.decimals ?? 0);
    }));
    for (const [mint, amt] of Object.entries(per)) {
      if (!amt) continue;
      const m = meta[mint] || {}, md = m.content?.metadata || {}, tt = (t.tokenTransfers || []).find(x => x.mint === mint);
      const nft = NFT_IFACE.test(m.interface || '') || /NonFungible/i.test(tt?.tokenStandard || '');
      const dir = amt > 0 ? 'in' : 'out';
      b.legs.push({dir, amount: nft ? 1 : Math.abs(amt), sym: (nft ? md.name || md.symbol : m.token_info?.symbol || md.symbol) || short(mint), name: md.name || '', token: mint,
        kind: nft ? 'NFT' : 'SPL', id: nft ? short(mint) : null, cp: tt ? (dir === 'out' ? tt.toUserAccount : tt.fromUserAccount) : '',
        priced: m.id ? !!m.token_info?.price_info : undefined, spam: false});
    }
    (t.events?.compressed || []).forEach(c => {
      if (c.newLeafOwner === addr && c.oldLeafOwner !== addr) b.legs.push({dir: 'in', amount: 1, sym: 'cNFT', name: '', token: c.assetId, kind: 'NFT', id: short(c.assetId), cp: c.oldLeafOwner || '', fromZero: !c.oldLeafOwner});
      if (c.oldLeafOwner === addr && c.newLeafOwner !== addr) b.legs.push({dir: 'out', amount: 1, sym: 'cNFT', name: '', token: c.assetId, kind: 'NFT', id: short(c.assetId), cp: c.newLeafOwner || ''});
    });
  }
  return trimToCutoff([...map.values()], cutoff);
}

/* ---------- Tron (TronGrid) ---------- */
const TRX_KNOWN = {TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t: 'USDT', TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8: 'USDC', TPYmHEhy5n8TCEfYGqW2rPxsghSfzghPDn: 'USDD',
  TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR: 'WTRX', TAFjULxiVgT4qWk6UZwjqwZXTSaGaqnVp4: 'BTT', TCFLL5dx5ZJdKnWuesXxi1VPwjLVmWZZy9: 'JST', TSSMHYeV2uE9qYH95DqyoCuNCzEL1NvU3S: 'SUN',
  TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7: 'WIN', TUpMhErZL2fhh4sVNULAbNKLokS4GjC1F4: 'TUSD', THb4CqiFdwNHsWsQCs4JhzwjMWys4aqCbF: 'ETH', TN3W4H6rK2ce4vX9YnFQHwKENnHjoxb3m9: 'BTC'};
const TRX_SYMS = new Set(Object.values(TRX_KNOWN));
const tronAddr = async h => !h ? '' : h.startsWith('T') ? h : (hasSubtle() ? b58checkEncode(hexToBytes(h)) : h);
const TRX_NOVALUE = {FreezeBalanceV2Contract: ['Staking (Stake 2.0 freeze)', 'Froze TRX for staking (still yours; no balance change recorded)'], FreezeBalanceContract: ['Staking (freeze)', 'Froze TRX for staking (still yours)'],
  UnfreezeBalanceV2Contract: ['Staking (Unstake)', 'Started unfreezing staked TRX (no balance change recorded)'], UnfreezeBalanceContract: ['Staking (Unstake)', 'Unfroze TRX'],
  WithdrawExpireUnfreezeContract: ['Staking (Withdraw unlocked)', 'Withdrew unfrozen TRX back to available balance'], VoteWitnessContract: ['Staking (Vote)', 'Voted for Super Representatives'],
  DelegateResourceContract: ['Resource Delegation', 'Delegated energy/bandwidth'], UnDelegateResourceContract: ['Resource Delegation', 'Reclaimed delegated energy/bandwidth'],
  AccountCreateContract: ['Account Activation', 'Activated a new Tron account'], AccountPermissionUpdateContract: ['Account Settings', 'Changed account permissions — check this was you']};
async function fetchTron(chain, addr, opt) {
  const map = new Map(); const G = 'https://api.trongrid.io/v1/accounts/' + addr; let cutoff = null;
  const page = async (path) => {
    const out = []; let fp = '';
    for (let p = 0; p < opt.maxPages; p++) {
      const j = await getJSON(`${G}${path}?limit=200${fp ? '&fingerprint=' + encodeURIComponent(fp) : ''}${opt.from ? '&min_timestamp=' + (+opt.from) : ''}`);
      out.push(...(j.data || [])); fp = j.meta?.fingerprint; if (!fp) break;
      if (p === opt.maxPages - 1 && out.length) { const d = new Date(out[out.length - 1].block_timestamp); if (!cutoff || d > cutoff) cutoff = d; }
      await sleep(300);
    }
    return out;
  };
  for (const t of await page('/transactions')) {
    const c = t.raw_data?.contract?.[0] || {}, v = c.parameter?.value || {};
    const b = bucket(map, t.txID); b.ts = new Date(t.block_timestamp); b.initKnown = true;
    b.ok = (t.ret?.[0]?.contractRet || 'SUCCESS') === 'SUCCESS'; b.from = await tronAddr(v.owner_address);
    const feeSun = (t.ret?.[0]?.fee || 0) || ((t.energy_fee || 0) + (t.net_fee || 0)); b.fee = b.from === addr ? feeSun / 1e6 : 0;
    if (c.type === 'TransferContract') {
      b.to = await tronAddr(v.to_address); b.method = 'transfer';
      if (b.ok && v.amount) b.legs.push(natLeg(chain, b.from === addr ? 'out' : 'in', v.amount / 1e6, b.from === addr ? b.to : b.from));
    } else if (c.type === 'TransferAssetContract') {
      b.to = await tronAddr(v.to_address); b.method = 'transfer';
      if (b.ok) b.legs.push({dir: b.from === addr ? 'out' : 'in', amount: +v.amount, sym: 'TRC10-' + (hexAscii(v.asset_name || '') || v.asset_name), name: '', token: 'trc10:' + v.asset_name, kind: 'TRC10', cp: b.from === addr ? b.to : b.from, priced: false});
    } else if (c.type === 'TriggerSmartContract') {
      b.to = await tronAddr(v.contract_address); b.method = 'contract call';
      if (b.ok && v.call_value && b.from === addr) b.legs.push(natLeg(chain, 'out', v.call_value / 1e6, b.to));
    } else if (c.type === 'WithdrawBalanceContract') {
      b.method = 'claimRewards'; b.toName = 'TRON voting rewards';
      try { const info = await postJSON('https://api.trongrid.io/wallet/gettransactioninfobyid', {value: t.txID}); if (info.withdraw_amount) b.legs.push(natLeg(chain, 'in', info.withdraw_amount / 1e6, '')); } catch {}
    } else if (TRX_NOVALUE[c.type]) {
      const [cat, cmt] = TRX_NOVALUE[c.type]; const amt = v.frozen_balance || v.unfreeze_balance || v.balance;
      b.noValue = {cat, comment: `${cmt}${amt ? ` (${fmtNum(amt / 1e6)} TRX)` : ''}. Gas/resource fee only.`};
    } else b.method = (c.type || '').replace(/Contract$/, '');
  }
  for (const t of await page('/transactions/trc20')) {
    if (t.type && t.type !== 'Transfer') continue;
    const b = bucket(map, t.transaction_id); if (!b.ts) b.ts = new Date(t.block_timestamp);
    if (t.from === t.to) continue;
    const dir = t.from === addr ? 'out' : t.to === addr ? 'in' : null; if (!dir) continue;
    const ti = t.token_info || {}, known = TRX_KNOWN[ti.address], sym = ti.symbol || short(ti.address);
    b.legs.push({dir, amount: units(t.value, ti.decimals), sym, name: ti.name || '', token: ti.address, kind: 'TRC-20', cp: dir === 'out' ? t.to : t.from,
      priced: !!known, spam: !known && TRX_SYMS.has(String(sym).toUpperCase()), fromZero: false});
    if (!known && TRX_SYMS.has(String(sym).toUpperCase())) b.flags.push(`fake "${sym}" token (not the real ${sym} contract) — classic Tron address-poisoning scam`);
  }
  // A contract call on the token contract itself is just a token transfer.
  for (const b of map.values()) if (b.method === 'contract call' && b.legs.length && b.legs.every(l => l.kind === 'TRC-20' && l.token === b.to)) b.method = 'transfer';
  return trimToCutoff([...map.values()].filter(b => b.ts), cutoff);
}

/* ---------- Cosmos (public REST via cosmos.directory) ---------- */
const COS_DENOM = {};
function denomFromBase(base) {
  if (/^gamm\/pool\/\d+$/.test(base)) return {sym: 'GAMM-' + base.split('/').pop(), dec: 18};
  if (base.startsWith('factory/')) return {sym: base.split('/').pop().replace(/^u/, '').toUpperCase(), dec: 6};
  if (/^u[a-z]{2,}$/.test(base)) return {sym: base.slice(1).toUpperCase(), dec: 6};
  if (/^a[a-z]{2,}$/.test(base)) return {sym: base.slice(1).toUpperCase(), dec: 18};
  if (base === 'inj') return {sym: 'INJ', dec: 18};
  return {sym: base.toUpperCase().slice(0, 20), dec: 0};
}
async function cosmosDenom(c, d) {
  if (d === c.denom) return {sym: c.sym || c.code, dec: c.dec};
  const k = c.dir + '|' + d; if (COS_DENOM[k]) return COS_DENOM[k];
  let base = d;
  if (d.startsWith('ibc/')) {
    const h = d.slice(4);
    try { const j = await getJSON(`https://rest.cosmos.directory/${c.dir}/ibc/apps/transfer/v1/denom_traces/${h}`); base = j.denom_trace?.base_denom || base; }
    catch { try { const j = await getJSON(`https://rest.cosmos.directory/${c.dir}/ibc/apps/transfer/v1/denoms/${h}`); base = j.denom?.base || base; } catch {} }
    if (base === d) return (COS_DENOM[k] = {sym: 'IBC-' + h.slice(0, 6), dec: 6});
  }
  return (COS_DENOM[k] = denomFromBase(base));
}
const parseCoins = s => String(s || '').split(',').map(x => x.trim().match(/^(\d+)(.+)$/)).filter(Boolean).map(m => ({amt: m[1], denom: m[2]}));
const COS_NOVALUE = {MsgDelegate: 'Staking (Delegate)', MsgUndelegate: 'Staking (Undelegate)', MsgBeginRedelegate: 'Staking (Redelegate)', MsgCancelUnbondingDelegation: 'Staking (Cancel unbonding)',
  MsgVote: 'Governance Vote', MsgVoteWeighted: 'Governance Vote', MsgGrant: 'Authz Grant', MsgRevoke: 'Authz Revoke', MsgSetWithdrawAddress: 'Account Settings'};
function cosmosHint(types, msgs) {
  const t = types.join(' ');
  if (/Swap/.test(t)) return 'swap';
  if (/JoinPool|JoinSwap|CreatePosition|AddToPosition|ProvideLiquidity|CreateBalancerPool|MsgLock$/.test(t)) return 'addLiquidity';
  if (/ExitPool|ExitSwap|WithdrawPosition|WithdrawLiquidity/.test(t)) return 'removeLiquidity';
  if (/MsgTransfer|MsgRecvPacket|MsgAcknowledgement/.test(t)) return 'bridge';
  if (/WithdrawDelegatorReward|WithdrawValidatorCommission|ClaimRewards/.test(t)) return 'claimRewards';
  if (/MsgLiquidStake/.test(t)) return 'stake';
  if (/MsgRedeemStake/.test(t)) return 'unstake';
  if (/MsgExecuteContract/.test(t)) {
    const k = Object.keys(msgs.find(m => m.msg)?.msg || {})[0] || '';
    if (/swap/.test(k)) return 'swap'; if (/provide_liquidity|deposit/.test(k)) return 'addLiquidity';
    if (/withdraw_liquidity|withdraw/.test(k)) return 'removeLiquidity'; if (/claim/.test(k)) return 'claimRewards';
    if (/unbond|unstake/.test(k)) return 'unstake'; if (/bond|stake/.test(k)) return 'stake';
    return k.replace(/_/g, ' ');
  }
  return /MsgSend|MsgMultiSend/.test(t) ? 'transfer' : '';
}
async function fetchCosmos(chain, addr, opt) {
  const base = `https://rest.cosmos.directory/${chain.dir}/cosmos/tx/v1beta1/txs`, seen = new Map();
  let legacy = false, cutoff = null;
  for (const q of [`message.sender='${addr}'`, `transfer.recipient='${addr}'`]) {
    for (let page = 1; page <= opt.maxPages; page++) {
      const url = legacy ? `${base}?events=${encodeURIComponent(q)}&pagination.limit=50&pagination.offset=${(page - 1) * 50}&order_by=ORDER_BY_DESC`
                         : `${base}?query=${encodeURIComponent(q)}&page=${page}&limit=50&order_by=ORDER_BY_DESC`;
      let j;
      try { j = await getJSON(url); }
      catch (e) { if (!legacy && page === 1 && /HTTP 4|HTTP 5|Too many/.test(e.message)) { legacy = true; page--; continue; } throw e; }
      const list = j.tx_responses || []; list.forEach(r => seen.set(r.txhash, r));
      if (list.length < 50) break;
      const ts = new Date(list[list.length - 1].timestamp);
      if (opt.from && ts < opt.from) break;
      if (page === opt.maxPages && (!cutoff || ts > cutoff)) cutoff = ts;
      await sleep(250);
    }
  }
  const map = new Map();
  for (const r of seen.values()) {
    const b = bucket(map, r.txhash); b.ts = new Date(r.timestamp); b.ok = r.code === 0; b.initKnown = true;
    let msgs = r.tx?.body?.messages || [];
    msgs = msgs.flatMap(m => m.msgs ? m.msgs : [m]); // authz MsgExec
    const types = msgs.map(m => (m['@type'] || '').split('.').pop());
    const init = msgs.some(m => [m.sender, m.from_address, m.delegator_address, m.signer, m.creator, m.owner, m.voter, m.granter, m.depositor].includes(addr));
    b.from = init ? addr : (msgs[0]?.signer || msgs[0]?.sender || msgs[0]?.from_address || '');
    b.to = msgs[0]?.to_address || msgs[0]?.receiver || msgs[0]?.contract || msgs[0]?.validator_address || '';
    b.method = cosmosHint(types, msgs); b.typesText = types.join(', ');
    if (b.method === 'bridge') b.toName = 'IBC transfer' + (msgs[0]?.receiver ? ` to ${short(msgs[0].receiver)}` : '');
    let feeCoin = null;
    if (init) {
      const f = r.tx?.auth_info?.fee?.amount?.[0];
      if (f) { const di = await cosmosDenom(chain, f.denom); feeCoin = {denom: f.denom, amt: BigInt(f.amount)}; b.fee = units(f.amount, di.dec); b.feeCur = di.sym; }
    }
    if (!b.ok) continue;
    // value movements from "transfer" events (decode base64 attributes on old chains)
    const evs = (r.events?.length ? r.events : (r.logs || []).flatMap(l => l.events || []));
    const KEYS = new Set(['recipient', 'sender', 'amount', 'delegator', 'validator']);
    const attrs = e => (e.attributes || []).map(a => {
      if (KEYS.has(a.key)) return a;
      try { const k = atob(a.key || ''); if (KEYS.has(k)) return {key: k, value: a.value ? atob(a.value) : ''}; } catch {}
      return a;
    });
    const delta = {}, cps = {}, rewards = {};
    for (const e of evs) {
      const at = attrs(e);
      if (e.type === 'transfer') {
        let cur = {};
        for (const a of at) {
          if (['recipient', 'sender', 'amount'].includes(a.key)) cur[a.key] = a.value;
          if (cur.recipient && cur.sender && cur.amount !== undefined) {
            for (const c of parseCoins(cur.amount)) {
              if (cur.recipient === addr && cur.sender !== addr) { delta[c.denom] = (delta[c.denom] || 0n) + BigInt(c.amt); cps[c.denom] = cps[c.denom] || cur.sender; }
              if (cur.sender === addr && cur.recipient !== addr) { delta[c.denom] = (delta[c.denom] || 0n) - BigInt(c.amt); cps[c.denom] = cps[c.denom] || cur.recipient; }
            }
            cur = {};
          }
        }
      }
      if (e.type === 'withdraw_rewards') {
        const g = Object.fromEntries(at.map(a => [a.key, a.value]));
        if (!g.delegator || g.delegator === addr) parseCoins(g.amount).forEach(c => { rewards[c.denom] = (rewards[c.denom] || 0n) + BigInt(c.amt); });
      }
    }
    if (feeCoin && delta[feeCoin.denom] !== undefined) delta[feeCoin.denom] += feeCoin.amt; // fee is reported separately
    b.preRows = [];
    for (const [d, amt] of Object.entries(rewards)) {
      if (amt <= 0n) continue;
      if (delta[d] !== undefined) delta[d] -= amt;
      const di = await cosmosDenom(chain, d), leg = {dir: 'in', amount: units(amt.toString(), di.dec), sym: di.sym, token: d, kind: 'native', cp: ''};
      b.preRows.push({type: 'Staking', cat: 'Staking Rewards', buy: leg, sell: null, lp: '', comment: `Staking rewards received: ${legStr(leg)} (claimed or auto-withdrawn when changing delegation). Msgs: ${b.typesText}.`});
    }
    for (const [d, amt] of Object.entries(delta)) {
      if (amt === 0n) continue;
      const di = await cosmosDenom(chain, d);
      b.legs.push({dir: amt > 0n ? 'in' : 'out', amount: units((amt < 0n ? -amt : amt).toString(), di.dec), sym: di.sym, name: '', token: d, kind: d === chain.denom ? 'native' : 'IBC/token', cp: cps[d] || '', priced: undefined});
    }
    const nv = types.find(t => COS_NOVALUE[t]);
    if (nv && !b.legs.length) {
      const m = msgs.find(x => (x['@type'] || '').endsWith(nv)) || {}; let what = '';
      if (m.amount?.amount) { const di = await cosmosDenom(chain, m.amount.denom); what = ` ${fmtNum(units(m.amount.amount, di.dec))} ${di.sym}`; }
      b.noValue = {cat: COS_NOVALUE[nv], comment: `${nv.replace(/^Msg/, '').replace(/([a-z])([A-Z])/g, '$1 $2')}${what}${m.validator_dst_address || m.validator_address ? ' with validator ' + short(m.validator_dst_address || m.validator_address) : ''}. Bonded tokens stay yours; no balance change recorded. Fee only.`};
    }
    if (types.includes('MsgUndelegate')) b.desc = 'Unbonded tokens return automatically after the unbonding period (no separate transaction).';
  }
  return trimToCutoff([...map.values()], cutoff);
}

/* ---------- TON (tonapi.io) ---------- */
async function fetchTon(chain, addr, opt) {
  const acc = await getJSON(`https://tonapi.io/v2/accounts/${encodeURIComponent(addr)}`); const raw = acc.address;
  const me = x => x && x.address === raw;
  const map = new Map(); let before = '', cutoff = null; const evs = [];
  for (let p = 0; p < opt.maxPages; p++) {
    const j = await getJSON(`https://tonapi.io/v2/accounts/${encodeURIComponent(addr)}/events?limit=100${before ? '&before_lt=' + before : ''}`);
    const list = j.events || []; evs.push(...list);
    if (!list.length || !j.next_from) break; before = j.next_from;
    const ts = list[list.length - 1].timestamp * 1000;
    if (opt.from && ts < +opt.from) break;
    if (p === opt.maxPages - 1) cutoff = new Date(ts);
    await sleep(1100); // free tonapi allows about 1 request per second
  }
  const jet = (j, amt) => ({amount: units(amt, j?.decimals ?? 9), sym: j?.symbol || short(j?.address || ''), name: j?.name || '', token: j?.address || '?', kind: 'Jetton', priced: j?.verification === 'whitelist' ? true : j?.verification === 'none' ? false : undefined, spam: j?.verification === 'blacklist'});
  for (const e of evs) {
    if (e.in_progress) continue;
    const b = bucket(map, e.event_id); b.ts = new Date(e.timestamp * 1000); b.ok = (e.actions || []).every(a => a.status === 'ok'); b.initKnown = true;
    // Initiated by this wallet if it is the sender/user/buyer/staker/executor of any action (receivers also pay tiny fees on TON).
    const init = (e.actions || []).some(a => { const x = a[a.type] || {}; return [x.sender, x.user_wallet, x.buyer, x.staker, x.executor, x.owner].some(me); });
    b.fee = init && e.extra < 0 ? -e.extra / 1e9 : 0; b.from = init ? addr : ''; b.desc = (e.actions || []).map(a => a.simple_preview?.description).filter(Boolean).join('; ');
    if (e.is_scam) b.flags.push('tonapi flagged this event as scam');
    for (const a of e.actions || []) {
      const x = a[a.type] || {};
      if (a.type === 'TonTransfer') {
        if (me(x.sender) && !me(x.recipient)) { b.legs.push(natLeg(chain, 'out', x.amount / 1e9, x.recipient?.address)); b.to = x.recipient?.address || ''; b.toName = x.recipient?.name || ''; b.method = 'transfer'; }
        if (me(x.recipient) && !me(x.sender)) { b.legs.push(natLeg(chain, 'in', x.amount / 1e9, x.sender?.address)); if (!b.from) b.from = x.sender?.address || ''; b.method = b.method || 'transfer'; }
        if (x.sender?.is_scam && me(x.recipient)) b.flags.push('sender flagged as scam by tonapi');
        if (me(x.recipient) && !me(x.sender) && x.amount < 1e7 && x.comment) b.possibleSpam = `tiny ${fmtNum(x.amount / 1e9)} TON transfer carrying a text message ("${String(x.comment).slice(0, 40)}") — typical TON ad/spam`;
      } else if (a.type === 'JettonTransfer') {
        const l = jet(x.jetton, x.amount);
        if (me(x.sender) && !me(x.recipient)) b.legs.push({...l, dir: 'out', cp: x.recipient?.address || ''});
        if (me(x.recipient) && !me(x.sender)) b.legs.push({...l, dir: 'in', cp: x.sender?.address || ''});
        b.method = b.method || 'transfer';
      } else if (a.type === 'JettonSwap') {
        if (me(x.user_wallet)) {
          if (x.ton_in) b.legs.push(natLeg(chain, 'out', x.ton_in / 1e9, x.router?.address)); else if (x.jetton_master_in) b.legs.push({...jet(x.jetton_master_in, x.amount_in), dir: 'out', cp: x.router?.address || ''});
          if (x.ton_out) b.legs.push(natLeg(chain, 'in', x.ton_out / 1e9, x.router?.address)); else if (x.jetton_master_out) b.legs.push({...jet(x.jetton_master_out, x.amount_out), dir: 'in', cp: x.router?.address || ''});
        }
        b.method = 'swap'; b.toName = x.dex || 'DEX';
      } else if (a.type === 'NftItemTransfer') {
        const l = {amount: 1, sym: 'TON NFT', name: '', token: x.nft, kind: 'NFT', id: short(x.nft || '')};
        if (me(x.sender) && !me(x.recipient)) b.legs.push({...l, dir: 'out', cp: x.recipient?.address || ''});
        if (me(x.recipient) && !me(x.sender)) b.legs.push({...l, dir: 'in', cp: x.sender?.address || '', fromZero: !x.sender});
      } else if (a.type === 'NftPurchase') {
        const nft = {amount: 1, sym: x.nft?.collection?.name || x.nft?.metadata?.name || 'TON NFT', name: x.nft?.metadata?.name || '', token: x.nft?.address, kind: 'NFT', id: short(x.nft?.address || '')};
        const price = x.amount?.token_name === 'TON' || !x.amount?.token_name ? natLeg(chain, 'out', x.amount?.value / 1e9, x.seller?.address) : {amount: +x.amount?.value || 0, sym: x.amount?.token_name, token: x.amount?.token_name, kind: 'Jetton', cp: ''};
        if (me(x.buyer)) { b.legs.push({...nft, dir: 'in', cp: x.seller?.address || ''}, {...price, dir: 'out'}); }
        if (me(x.seller)) { b.legs.push({...nft, dir: 'out', cp: x.buyer?.address || ''}, {...price, dir: 'in'}); }
        b.toName = x.auction_type || 'NFT marketplace';
      } else if (a.type === 'DepositStake' && me(x.staker)) { b.legs.push(natLeg(chain, 'out', x.amount / 1e9, x.pool?.address)); b.method = 'stake'; b.toName = (x.pool?.name || 'staking pool') + ' staking';
      } else if (a.type === 'WithdrawStake' && me(x.staker)) { b.legs.push(natLeg(chain, 'in', x.amount / 1e9, x.pool?.address)); b.method = 'unstake'; b.toName = (x.pool?.name || 'staking pool') + ' staking';
      } else if (a.type === 'WithdrawStakeRequest' && me(x.staker)) { b.noValue = {cat: 'Staking (Unstake request)', comment: `Requested withdrawal from ${x.pool?.name || 'staking pool'}. Fee only.`};
      } else if (a.type === 'JettonMint' && me(x.recipient)) { b.legs.push({...jet(x.jetton, x.amount), dir: 'in', cp: '', fromZero: true});
      } else if (a.type === 'JettonBurn' && me(x.sender)) { b.legs.push({...jet(x.jetton, x.amount), dir: 'out', cp: '', toZero: true});
      } else if (a.type === 'SmartContractExec' && me(x.executor) && x.ton_attached > 0) { b.legs.push(natLeg(chain, 'out', x.ton_attached / 1e9, x.contract?.address)); b.to = x.contract?.address || ''; b.method = x.operation || 'contract call';
      }
    }
  }
  return trimToCutoff([...map.values()], cutoff);
}

/* ---------- XRP Ledger ---------- */
const XRPL = 'https://xrplcluster.com/';
const xrpRpc = async (method, params) => (await postJSON(XRPL, {method, params: [params]})).result || {};
const xrpCur = c => c.length === 3 ? c : c.startsWith('03') ? 'AMM-LP' : (hexAscii(c) || c.slice(0, 8));
const XRP_TYPE = {Payment: 'transfer', OfferCreate: 'swap', AMMDeposit: 'addLiquidity', AMMCreate: 'addLiquidity', AMMWithdraw: 'removeLiquidity', TrustSet: 'approve (trust line)',
  NFTokenMint: 'mint', NFTokenAcceptOffer: 'nft trade', NFTokenBurn: 'burn', EscrowCreate: 'escrow create', EscrowFinish: 'escrow finish', CheckCash: 'check cash'};
async function fetchXrp(chain, addr, opt) {
  const map = new Map(); let marker, cutoff = null; const all = [];
  for (let p = 0; p < opt.maxPages; p++) {
    const r = await xrpRpc('account_tx', {account: addr, limit: 200, ledger_index_min: -1, ledger_index_max: -1, forward: false, ...(marker ? {marker} : {})});
    if (r.error) throw new Error('XRPL: ' + r.error);
    all.push(...(r.transactions || [])); marker = r.marker; if (!marker) break;
    const t = all[all.length - 1], tx = t.tx_json || t.tx || {};
    const ts = t.close_time_iso ? new Date(t.close_time_iso) : new Date((tx.date + 946684800) * 1000);
    if (opt.from && ts < opt.from) break;
    if (p === opt.maxPages - 1) cutoff = ts;
    await sleep(300);
  }
  for (const t of all) {
    const tx = t.tx_json || t.tx || {}, meta = t.meta || t.metaData || {}, hash = t.hash || tx.hash;
    if (!hash || typeof meta !== 'object') continue;
    const b = bucket(map, hash);
    b.ts = t.close_time_iso ? new Date(t.close_time_iso) : new Date((tx.date + 946684800) * 1000);
    b.ok = meta.TransactionResult === 'tesSUCCESS'; b.from = tx.Account; b.to = tx.Destination || ''; b.initKnown = true;
    b.method = XRP_TYPE[tx.TransactionType] || tx.TransactionType || ''; b.fee = tx.Account === addr ? (+tx.Fee || 0) / 1e6 : 0;
    if (!b.ok) continue;
    let xrpDelta = 0; const tok = {};
    for (const node of meta.AffectedNodes || []) {
      const kind = Object.keys(node)[0], n = node[kind], F = n.FinalFields || n.NewFields || {}, P = n.PreviousFields || {};
      if (n.LedgerEntryType === 'AccountRoot' && F.Account === addr) {
        const prev = P.Balance !== undefined ? +P.Balance : kind === 'CreatedNode' ? 0 : +F.Balance;
        xrpDelta += ((+F.Balance || 0) - prev) / 1e6;
      } else if (n.LedgerEntryType === 'RippleState') {
        const low = F.LowLimit?.issuer, high = F.HighLimit?.issuer; if (low !== addr && high !== addr) continue;
        const fv = +(F.Balance?.value || 0), pv = P.Balance ? +P.Balance.value : kind === 'CreatedNode' ? 0 : fv;
        let d = fv - pv; if (addr === high) d = -d; if (!d) continue;
        const cur = F.Balance?.currency || '?', issuer = addr === low ? high : low, k = cur + '.' + issuer;
        tok[k] = tok[k] || {amt: 0, cur, issuer}; tok[k].amt += d;
      }
    }
    if (tx.Account === addr) xrpDelta += (+tx.Fee || 0) / 1e6;
    if (Math.abs(xrpDelta) > 1e-9) b.legs.push(natLeg(chain, xrpDelta > 0 ? 'in' : 'out', +Math.abs(xrpDelta).toFixed(6), tx.Account === addr ? b.to : tx.Account));
    for (const [k, v] of Object.entries(tok)) b.legs.push({dir: v.amt > 0 ? 'in' : 'out', amount: Math.abs(v.amt), sym: xrpCur(v.cur), name: '', token: k, kind: 'IOU', cp: v.issuer, priced: undefined});
    if (tx.Account !== addr && b.legs.length === 1 && b.legs[0].kind === 'native' && b.legs[0].dir === 'in' && b.legs[0].amount < 0.001) b.possibleSpam = 'tiny XRP "dust" payment (usually carries an ad/scam memo)';
    if (!b.legs.length && tx.Account === addr) {
      const nv = {OfferCreate: ['DEX Order (not filled)', 'Placed a DEX order that did not fill in this transaction'], OfferCancel: ['DEX Order Cancelled', 'Cancelled a DEX order'],
        TrustSet: ['Trust Line', 'Set or changed a trust line (lets this account hold a token)'], AccountSet: ['Account Settings', 'Changed account settings'],
        SetRegularKey: ['Account Settings', 'Changed the regular key — check this was you'], SignerListSet: ['Account Settings', 'Changed multi-sign signers — check this was you']}[tx.TransactionType]
        || ['Ledger Operation', `${tx.TransactionType} with no balance change`];
      b.noValue = {cat: nv[0], comment: nv[1] + '. Fee only.'};
    }
  }
  const names = await xrpNames();
  for (const b of map.values()) {
    b.legs.forEach(l => { if (names[l.cp]) l.cpName = names[l.cp]; });
    const n = names[b.to] || names[b.from]; if (n && !b.toName) b.toName = n;
    b.desc = 'Bithomp: https://bithomp.com/explorer/' + b.hash;
  }
  return trimToCutoff([...map.values()], cutoff);
}

/* ---------- Cardano (Koios, through the helper) ---------- */
const KOIOS = 'https://api.koios.rest/api/v1';
const koios = (path, body) => postJSON(proxied(KOIOS + path), body);
async function adaStake(addr) {
  if (addr.startsWith('stake1')) return {stake: addr, exists: true};
  const info = await koios('/address_info', {_addresses: [addr]});
  return {stake: info?.[0]?.stake_address || null, exists: !!info?.length};
}
async function fetchCardano(chain, addr, opt) {
  const {stake} = await adaStake(addr); let list = [];
  for (let off = 0; off < 100000; off += 1000) {
    const page = stake ? await koios(`/account_txs?offset=${off}&limit=1000`, {_stake_address: stake}) : await koios(`/address_txs?offset=${off}&limit=1000`, {_addresses: [addr]});
    list.push(...page); if (page.length < 1000) break;
  }
  list.sort((x, y) => y.block_time - x.block_time);
  if (opt.from) list = list.filter(t => t.block_time * 1000 >= +opt.from);
  let cutoff = null; const cap = opt.maxPages * 50;
  if (list.length > cap) { cutoff = new Date(list[cap - 1].block_time * 1000); list = list.slice(0, cap); }
  const own = io => (stake && io.stake_addr === stake) || io.payment_addr?.bech32 === addr;
  const map = new Map();
  for (let i = 0; i < list.length; i += 25) {
    const infos = await koios('/tx_info', {_tx_hashes: list.slice(i, i + 25).map(t => t.tx_hash), _inputs: true, _metadata: false, _assets: true, _withdrawals: true, _certs: true, _scripts: false, _bytecode: false});
    for (const t of infos) {
      const b = bucket(map, t.tx_hash); b.ts = new Date((t.tx_timestamp || t.block_time) * 1000); b.ok = true; b.initKnown = true;
      const ins = t.inputs || [], outs = t.outputs || [];
      const ownIn = ins.filter(own), ownOut = outs.filter(own);
      const sum = arr => arr.reduce((s, x) => s + BigInt(x.value || 0), 0n);
      const init = ownIn.length > 0, fee = BigInt(t.fee || 0);
      const wd = (t.withdrawals || []).filter(w => w.stake_addr === stake).reduce((s, w) => s + BigInt(w.amount || 0), 0n);
      b.from = init ? addr : (ins.find(x => !own(x))?.payment_addr?.bech32 || ''); b.fee = init ? units(fee.toString(), 6) : 0;
      const cpOut = outs.find(x => !own(x))?.payment_addr?.bech32 || '', cpIn = ins.find(x => !own(x))?.payment_addr?.bech32 || '';
      const ada = sum(ownOut) - sum(ownIn) + (init ? fee : 0n) - wd;
      if (ada !== 0n) b.legs.push(natLeg(chain, ada > 0n ? 'in' : 'out', units((ada < 0n ? -ada : ada).toString(), 6), ada > 0n ? cpIn : cpOut));
      const assets = {};
      const addA = (x, sign) => (x.asset_list || []).forEach(a => { const k = a.policy_id + a.asset_name; assets[k] = assets[k] || {q: 0n, a}; assets[k].q += sign * BigInt(a.quantity || 0); });
      ownOut.forEach(x => addA(x, 1n)); ownIn.forEach(x => addA(x, -1n));
      for (const {q, a} of Object.values(assets)) {
        if (q === 0n) continue;
        const nm = hexAscii(a.asset_name || '') || (a.fingerprint || '').slice(0, 12), nft = q === 1n || q === -1n ? !a.decimals && /\d|#|NFT/i.test(nm) : false;
        b.legs.push({dir: q > 0n ? 'in' : 'out', amount: nft ? 1 : units((q < 0n ? -q : q).toString(), a.decimals || 0), sym: nm || 'ASSET', name: nm, token: a.policy_id + a.asset_name, kind: nft ? 'NFT' : 'CNT', id: nft ? (a.fingerprint || '').slice(0, 14) : null, cp: q > 0n ? cpIn : cpOut, priced: undefined});
      }
      b.preRows = [];
      if (wd > 0n) { const leg = natLeg(chain, 'in', units(wd.toString(), 6), ''); b.preRows.push({type: 'Staking', cat: 'Staking Rewards', buy: leg, sell: null, lp: '', comment: `Withdrew ${legStr(leg)} of staking rewards from your stake account.`}); }
      const certs = (t.certificates || []).map(c => c.type);
      if (certs.length) { b.method = certs.some(c => /deleg/.test(c)) ? 'stake' : certs.join(', '); b.toName = 'Cardano staking';
        if (!b.legs.length) b.noValue = {cat: 'Staking (Delegate)', comment: `Stake certificate(s): ${certs.join(', ')}. Fee only.`};
        if (certs.includes('stake_registration')) b.desc = 'Includes the refundable 2 ADA staking deposit.'; }
      else b.method = b.legs.some(l => l.kind !== 'native') && b.legs.some(l => l.kind === 'native') && init ? 'swap' : 'transfer';
    }
    await sleep(300);
  }
  return trimToCutoff([...map.values()], cutoff);
}

/* ---------- Stellar (Horizon + StellarExpert directory) ---------- */
const HORIZON = 'https://horizon.stellar.org';
const xlmAsset = (type, code, issuer) => type === 'native' || !type ? {sym: 'XLM', token: 'native', kind: 'native'} : {sym: code, token: code + ':' + issuer, kind: 'Stellar asset'};
const xlmAssetStr = s => s === 'native' ? xlmAsset('native') : xlmAsset('credit', s.split(':')[0], s.split(':')[1]);
async function sxDirectory(addrs) {
  const out = {}; const list = [...new Set(addrs.filter(a => /^G[A-Z2-7]{55}$/.test(a)))];
  for (let i = 0; i < list.length; i += 50) {
    try {
      const q = list.slice(i, i + 50).map(a => 'address[]=' + a).join('&');
      const j = await getJSON(`https://api.stellar.expert/explorer/directory?${q}&limit=50`);
      (j._embedded?.records || []).forEach(r => { out[r.address] = r; });
    } catch {}
  }
  return out;
}
async function fetchStellar(chain, addr, opt) {
  let cutoff = null;
  const pages = async (path) => {
    const out = []; let url = `${HORIZON}/accounts/${addr}/${path}${path.includes('?') ? '&' : '?'}order=desc&limit=200`;
    for (let p = 0; p < opt.maxPages && url; p++) {
      const j = await getJSON(url); const recs = j._embedded?.records || []; out.push(...recs);
      if (recs.length < 200) break;
      const ts = new Date(recs[recs.length - 1].created_at);
      if (opt.from && ts < opt.from) break;
      if (p === opt.maxPages - 1 && (!cutoff || ts > cutoff)) cutoff = ts;
      url = j._links?.next?.href; await sleep(200);
    }
    return out;
  };
  const ops = new Map((await pages('operations?join=transactions&include_failed=true')).map(o => [o.id, o]));
  const effects = await pages('effects');
  const opOf = e => BigInt(e.id.split('-')[0]).toString();
  for (const id of [...new Set(effects.map(opOf))].filter(id => !ops.has(id)).slice(0, 100)) {
    try { ops.set(id, await getJSON(`${HORIZON}/operations/${id}?join=transactions`)); } catch {}
  }
  const map = new Map(), byOp = {};
  effects.forEach(e => { if (e.account === addr) (byOp[opOf(e)] = byOp[opOf(e)] || []).push(e); });
  const TYPE = {payment: 'transfer', create_account: 'transfer', path_payment_strict_send: 'path payment', path_payment_strict_receive: 'path payment', manage_sell_offer: 'swap', manage_buy_offer: 'swap',
    create_passive_sell_offer: 'swap', liquidity_pool_deposit: 'addLiquidity', liquidity_pool_withdraw: 'removeLiquidity', claim_claimable_balance: 'accept pending payment', account_merge: 'account merge'};
  const NOVAL = {change_trust: ['Trust Line', 'Added or removed a trust line (lets this account hold a token)'], set_options: ['Account Settings', 'Changed account settings — check this was you'],
    manage_data: ['Account Data', 'Stored data on the account'], bump_sequence: ['Account Settings', 'Bumped sequence number'], manage_sell_offer: ['DEX Order (not filled)', 'Placed/changed a DEX offer that did not fill'],
    manage_buy_offer: ['DEX Order (not filled)', 'Placed/changed a DEX offer that did not fill'], create_passive_sell_offer: ['DEX Order (not filled)', 'Placed a passive DEX offer'], begin_sponsoring_future_reserves: ['Account Settings', 'Reserve sponsorship']};
  for (const op of ops.values()) {
    const tx = op.transaction || {}, h = op.transaction_hash; const b = bucket(map, h);
    b.ts = new Date(op.created_at); b.ok = op.transaction_successful !== false; b.initKnown = true;
    const payer = tx.fee_account || tx.source_account;
    if (payer === addr) { b.from = addr; b.fee = (+tx.fee_charged || 0) / 1e7; } else if (!b.from) b.from = op.source_account;
    b.types = [...new Set([...(b.types || []), op.type])]; b.typesText = b.types.join(', ');
    b.method = b.method && b.method !== 'transfer' ? b.method : (TYPE[op.type] || op.type.replace(/_/g, ' '));
    if (/path payment/.test(b.method) && (op.to || op.account) === addr && op.from === addr) b.method = 'swap';
    if (!b.to) b.to = op.to || op.account || op.into || op.liquidity_pool_id || '';
    if (tx.memo && !b.desc) b.desc = 'memo: ' + String(tx.memo).slice(0, 40);
    if (NOVAL[op.type] && op.source_account === addr) b.noValue = {cat: NOVAL[op.type][0], comment: NOVAL[op.type][1] + '. Fee only.'};
    if (!b.ok) continue;
    const ef = byOp[op.id] || [], hasCD = ef.some(e => /^account_(credited|debited)$/.test(e.type));
    for (const e of ef) {
      const cp = op.from === addr ? (op.to || op.account || '') : (op.from || op.funder || op.source_account || '');
      if (e.type === 'account_credited' || e.type === 'account_debited') { const a = xlmAsset(e.asset_type, e.asset_code, e.asset_issuer); b.legs.push({...a, dir: e.type === 'account_credited' ? 'in' : 'out', amount: +e.amount, name: '', cp}); }
      else if (e.type === 'account_created') b.legs.push({...xlmAsset('native'), dir: 'in', amount: +e.starting_balance, name: '', cp: op.funder || op.source_account});
      else if (e.type === 'trade' && !hasCD) {
        const sold = xlmAsset(e.sold_asset_type, e.sold_asset_code, e.sold_asset_issuer), bought = xlmAsset(e.bought_asset_type, e.bought_asset_code, e.bought_asset_issuer);
        b.legs.push({...sold, dir: 'out', amount: +e.sold_amount, name: '', cp: e.seller || ''}, {...bought, dir: 'in', amount: +e.bought_amount, name: '', cp: e.seller || ''}); b.method = 'swap'; b.noValue = null;
      } else if (e.type === 'liquidity_pool_deposited' || e.type === 'liquidity_pool_withdrew') {
        const dep = e.type === 'liquidity_pool_deposited', pool = e.liquidity_pool?.id || '';
        (dep ? e.reserves_deposited : e.reserves_received || []).forEach(r => b.legs.push({...xlmAssetStr(r.asset), dir: dep ? 'out' : 'in', amount: +r.amount, name: '', cp: pool}));
        b.legs.push({sym: 'XLM-LP', name: 'Stellar LP ' + pool.slice(0, 8), token: 'lp:' + pool, kind: 'LP', dir: dep ? 'in' : 'out', amount: +(dep ? e.shares_received : e.shares_redeemed), cp: pool});
        b.to = pool;
      }
    }
  }
  // Name known accounts and flag malicious ones (StellarExpert directory)
  const dir = await sxDirectory([...map.values()].flatMap(b => [b.from, b.to, ...b.legs.map(l => l.cp)]));
  for (const b of map.values()) {
    for (const l of b.legs) { const d = dir[l.cp]; if (d) { l.cpName = d.name; if ((d.tags || []).some(t => /malicious|unsafe|scam|phishing/.test(t))) { l.spam = true; b.flags.push(`StellarExpert tags ${d.name || short(l.cp)} as ${d.tags.join('/')}`); } } }
    const d = dir[b.to !== addr ? b.to : ''] || dir[b.from !== addr ? b.from : '']; if (d && !b.toName) b.toName = d.name + (d.tags?.length ? ` (${d.tags.join(', ')})` : '');
  }
  return trimToCutoff([...map.values()].filter(b => b.ts), cutoff);
}

/* ---------- Hedera (Mirror Node) ---------- */
const HEDERA = 'https://mainnet-public.mirrornode.hedera.com';
const HBAR_SYSTEM = a => { const n = +String(a).split('.')[2]; return n <= 1000; }; // nodes, fee & staking-reward accounts
const HTOK = {};
async function hederaToken(id) {
  if (!HTOK[id]) HTOK[id] = getJSON(`${HEDERA}/api/v1/tokens/${id}`).then(t => ({sym: t.symbol || id, name: t.name || '', dec: +t.decimals || 0, nft: t.type === 'NON_FUNGIBLE_UNIQUE'})).catch(() => ({sym: id, name: '', dec: 0, nft: false}));
  return HTOK[id];
}
const HBAR_NOVAL = {TOKENASSOCIATE: ['Token Association', 'Associated a token with the account'], TOKENDISSOCIATE: ['Token Association', 'Removed a token association'],
  CRYPTOUPDATEACCOUNT: ['Account Update', 'Updated the account (e.g. chose a staking node)'], CONSENSUSSUBMITMESSAGE: ['HCS Message', 'Submitted a consensus message'],
  CRYPTOAPPROVEALLOWANCE: ['Approval', 'Approved a spender allowance'], CRYPTODELETEALLOWANCE: ['Approval', 'Removed an allowance']};
// The public mirror node only searches ~60 days per request and returns an empty page plus a "next" link
// for older periods, so we bound the search by the account's creation date and walk back through empty pages.
async function hederaStart(addr, opt) {
  let created = 0;
  try { created = Math.floor(+(await getJSON(`${HEDERA}/api/v1/accounts/${addr}?transactions=false`)).created_timestamp || 0); } catch {}
  const from = opt?.from ? Math.floor(+opt.from / 1000) : 0;
  return Math.max(created, from);
}
async function fetchHedera(chain, addr, opt) {
  const start = await hederaStart(addr, opt);
  const all = []; let url = `${HEDERA}/api/v1/transactions?account.id=${addr}&limit=100&order=desc${start ? '&timestamp=gte:' + start : ''}`, cutoff = null;
  let pages = 0, hops = 0;
  while (url && pages < opt.maxPages * 2 && hops < 200) {
    const j = await getJSON(url); const list = j.transactions || []; hops++;
    url = j.links?.next ? HEDERA + j.links.next : '';
    if (!list.length) { await sleep(80); continue; } // empty 60-day window: keep going back
    all.push(...list); pages++;
    const ts = new Date(+list[list.length - 1].consensus_timestamp * 1000);
    if (pages === opt.maxPages * 2 && url) cutoff = ts;
    await sleep(150);
  }
  const map = new Map();
  for (const t of all) {
    const b = bucket(map, t.transaction_id); b.ts = new Date(+t.consensus_timestamp * 1000); b.ok = t.result === 'SUCCESS'; b.initKnown = true;
    b.url = `https://hashscan.io/mainnet/transaction/${t.consensus_timestamp}`;
    const payer = String(t.transaction_id).split('-')[0]; b.from = payer; b.fee = payer === addr ? (t.charged_tx_fee || 0) / 1e8 : 0;
    b.method = t.name === 'CRYPTOTRANSFER' ? 'transfer' : t.name === 'CONTRACTCALL' ? 'contract call' : (t.name || '').toLowerCase();
    if (HBAR_NOVAL[t.name]) b.noValue = {cat: HBAR_NOVAL[t.name][0], comment: HBAR_NOVAL[t.name][1] + '. Fee only.'};
    if (t.memo_base64) { try { const m = atob(t.memo_base64).trim(); if (m) b.desc = 'memo: ' + m.slice(0, 40); } catch {} }
    if (!b.ok) continue;
    const reward = (t.staking_reward_transfers || []).filter(r => r.account === addr).reduce((s, r) => s + r.amount, 0);
    const mine = (t.transfers || []).filter(x => x.account === addr).reduce((s, x) => s + x.amount, 0);
    const net = mine + (payer === addr ? (t.charged_tx_fee || 0) : 0) - reward;
    const other = (t.transfers || []).filter(x => x.account !== addr && !HBAR_SYSTEM(x.account)).sort((x, y) => Math.abs(y.amount) - Math.abs(x.amount))[0]?.account || '';
    b.to = payer === addr ? other : addr;
    if (net) b.legs.push(natLeg(chain, net > 0 ? 'in' : 'out', Math.abs(net) / 1e8, other));
    const per = {}; (t.token_transfers || []).filter(x => x.account === addr).forEach(x => { per[x.token_id] = (per[x.token_id] || 0) + x.amount; });
    for (const [id, amt] of Object.entries(per)) {
      if (!amt) continue; const tk = await hederaToken(id);
      const cp = (t.token_transfers || []).find(x => x.token_id === id && x.account !== addr)?.account || '';
      b.legs.push({dir: amt > 0 ? 'in' : 'out', amount: Math.abs(amt) / 10 ** tk.dec, sym: tk.sym, name: tk.name, token: id, kind: 'HTS', cp, priced: undefined});
    }
    for (const n of t.nft_transfers || []) {
      const tk = await hederaToken(n.token_id), l = {amount: 1, sym: tk.sym, name: tk.name, token: n.token_id + '/' + n.serial_number, kind: 'NFT', id: n.serial_number};
      if (n.receiver_account_id === addr && n.sender_account_id !== addr) b.legs.push({...l, dir: 'in', cp: n.sender_account_id || '', fromZero: !n.sender_account_id});
      if (n.sender_account_id === addr && n.receiver_account_id !== addr) b.legs.push({...l, dir: 'out', cp: n.receiver_account_id || ''});
    }
    b.preRows = [];
    if (reward > 0) { const leg = natLeg(chain, 'in', reward / 1e8, '0.0.800'); b.preRows.push({type: 'Staking', cat: 'Staking Rewards', buy: leg, sell: null, lp: '', comment: `Hedera staking reward paid out with this transaction: ${legStr(leg)}.`}); }
  }
  return trimToCutoff([...map.values()], cutoff);
}

/* ---------- Algorand (Nodely indexer) ---------- */
const ALGO_IDX = 'https://mainnet-idx.4160.nodely.dev/v2';
const ASA = {};
async function algoAsset(id) {
  if (!ASA[id]) ASA[id] = getJSON(`${ALGO_IDX}/assets/${id}?include-all=true`).then(j => { const p = j.asset?.params || {}; return {sym: p['unit-name'] || p.name || 'ASA-' + id, name: p.name || '', dec: p.decimals || 0, nft: p.total === 1 && !p.decimals}; }).catch(() => ({sym: 'ASA-' + id, name: '', dec: 0, nft: false}));
  return ASA[id];
}
async function fetchAlgorand(chain, addr, opt) {
  const all = []; let next = '', cutoff = null;
  for (let p = 0; p < opt.maxPages; p++) {
    const j = await getJSON(`${ALGO_IDX}/accounts/${addr}/transactions?limit=500${next ? '&next=' + encodeURIComponent(next) : ''}`);
    const list = j.transactions || []; all.push(...list); next = j['next-token'];
    if (!list.length || !next) break;
    const ts = new Date(list[list.length - 1]['round-time'] * 1000);
    if (opt.from && ts < opt.from) break;
    if (p === opt.maxPages - 1) cutoff = ts;
    await sleep(150);
  }
  const map = new Map();
  for (const t of all) {
    const key = t.group ? 'g:' + t.group + ':' + t['confirmed-round'] : t.id;
    const b = bucket(map, key); if (!b.hashes) { b.hashes = []; b.hash = t.id; }
    b.hashes.push(t.id); b.ts = new Date(t['round-time'] * 1000); b.ok = true; b.initKnown = true; b.url = 'https://allo.info/tx/' + b.hash;
    if (t.sender === addr) { b.from = addr; b.fee += (t.fee || 0) / 1e6; } else if (!b.from) b.from = t.sender;
    const types = new Set(b.types || []); types.add(t['tx-type']); b.types = [...types];
    const walk = async (x, top) => {
      const pay = x['payment-transaction'], ax = x['asset-transfer-transaction'];
      if (pay) {
        const amt = pay.amount || 0, close = pay['close-amount'] || 0;
        if (x.sender === addr && pay.receiver !== addr && amt) b.legs.push(natLeg(chain, 'out', amt / 1e6, pay.receiver));
        if (pay.receiver === addr && x.sender !== addr && amt) b.legs.push(natLeg(chain, 'in', amt / 1e6, x.sender));
        if (pay['close-remainder-to'] === addr && x.sender !== addr && close) b.legs.push(natLeg(chain, 'in', close / 1e6, x.sender));
        if (x.sender === addr && pay['close-remainder-to'] && pay['close-remainder-to'] !== addr && close) b.legs.push(natLeg(chain, 'out', close / 1e6, pay['close-remainder-to']));
        if (top && pay.receiver === addr && x.sender !== addr && amt < 1e4 && x.note) b.possibleSpam = 'tiny ALGO payment carrying a note (typical Algorand ad/spam)';
      }
      if (ax) {
        const from = ax.sender || x.sender, a = await algoAsset(ax['asset-id']), amt = ax.amount || 0;
        const leg = (dir, n, cp) => b.legs.push({dir, amount: a.nft ? 1 : n / 10 ** a.dec, sym: a.sym, name: a.name, token: 'asa:' + ax['asset-id'], kind: a.nft ? 'NFT' : 'ASA', id: a.nft ? ax['asset-id'] : null, cp, priced: undefined});
        if (top && !amt && ax.receiver === addr && x.sender === addr) b.optin = true;
        if (from === addr && ax.receiver !== addr && amt) leg('out', amt, ax.receiver);
        if (ax.receiver === addr && from !== addr && amt) leg('in', amt, from);
        if (ax['close-to'] === addr && from !== addr && ax['close-amount']) leg('in', ax['close-amount'], from);
        if (from === addr && ax['close-to'] && ax['close-to'] !== addr && ax['close-amount']) leg('out', ax['close-amount'], ax['close-to']);
      }
      for (const inner of x['inner-txns'] || []) await walk(inner, false);
    };
    await walk(t, true);
    const rw = (t.sender === addr ? t['sender-rewards'] : 0) + (t['payment-transaction']?.receiver === addr ? t['receiver-rewards'] : 0) || 0;
    if (rw > 0) { b.preRows = b.preRows || []; const leg = natLeg(chain, 'in', rw / 1e6, ''); b.preRows.push({type: 'Staking', cat: 'Staking Rewards', buy: leg, sell: null, lp: '', comment: `Algorand participation rewards credited with this transaction: ${legStr(leg)}.`}); }
    if (t['tx-type'] === 'appl') { b.method = b.method || 'app call'; b.to = b.to || 'app ' + (t['application-transaction']?.['application-id'] || ''); }
    else if (!b.method) b.method = 'transfer';
    if (t['tx-type'] === 'keyreg' && t.sender === addr) b.noValue = {cat: 'Staking (Consensus participation)', comment: 'Registered/deregistered participation keys for consensus (staking). Fee only.'};
    if (t['tx-type'] === 'acfg' && t.sender === addr) b.noValue = {cat: 'Asset Config', comment: 'Created or changed an Algorand asset. Fee only.'};
  }
  for (const b of map.values()) { if (b.optin && !b.legs.length && !b.noValue) b.noValue = {cat: 'Asset Opt-in', comment: 'Opted in to an Algorand asset (lets this account hold it). Fee only.'}; b.typesText = (b.types || []).join(', '); }
  return trimToCutoff([...map.values()], cutoff);
}

/* ---------- Filecoin (Filfox) ---------- */
async function fetchFilecoin(chain, addr, opt) {
  const all = []; let cutoff = null;
  for (let p = 0; p < opt.maxPages; p++) {
    const j = await getJSON(`https://filfox.info/api/v1/address/${addr}/transfers?pageSize=100&page=${p}`);
    const list = j.transfers || []; all.push(...list);
    if (list.length < 100) break;
    const ts = new Date(list[list.length - 1].timestamp * 1000);
    if (opt.from && ts < opt.from) break;
    if (p === opt.maxPages - 1) cutoff = ts;
    await sleep(250);
  }
  const map = new Map();
  for (const t of all) {
    const b = bucket(map, t.message || `h${t.height}-${t.type}`); b.ts = new Date(t.timestamp * 1000); b.ok = true; b.initKnown = true;
    const v = units(String(t.value).replace('-', ''), 18) * (String(t.value).startsWith('-') ? -1 : 1);
    if (/fee/.test(t.type)) { b.fee += -v; b.from = addr; continue; }
    if (t.type === 'reward' || t.type === 'miner-reward') { b.method = 'claimRewards'; b.toName = 'Filecoin block reward'; }
    else b.method = b.method || 'transfer';
    const cp = v < 0 ? t.to : t.from; if (v < 0) { b.from = addr; b.to = t.to; } else if (!b.from) b.from = t.from;
    if (v) b.legs.push({...natLeg(chain, v > 0 ? 'in' : 'out', Math.abs(v), cp), cpName: (v < 0 ? t.toTag : t.fromTag)?.name});
  }
  for (const b of map.values()) if (b.from === addr && !b.legs.length) b.noValue = {cat: 'Contract Interaction', comment: 'Message with no FIL transfer for this address (e.g. miner/actor operation). Fee only.'};
  return trimToCutoff([...map.values()], cutoff);
}

/* ---------- IOTA (Move-based mainnet) ---------- */
const IOTA_RPC = 'https://api.mainnet.iota.cafe';
const iotaRpc = async (method, params) => { const j = await postJSON(IOTA_RPC, {jsonrpc: '2.0', id: 1, method, params}); if (j.error) throw new Error('IOTA: ' + j.error.message); return j.result; };
const ICOIN = {};
async function iotaCoin(type) {
  if (/::iota::IOTA$/.test(type)) return {sym: 'IOTA', dec: 9};
  if (!ICOIN[type]) ICOIN[type] = iotaRpc('iotax_getCoinMetadata', [type]).then(m => ({sym: m?.symbol || type.split('::').pop(), dec: m?.decimals ?? 9})).catch(() => ({sym: type.split('::').pop(), dec: 9}));
  return ICOIN[type];
}
async function fetchIota(chain, addr, opt) {
  const seen = new Map(); let cutoff = null;
  for (const f of [{FromAddress: addr}, {ToAddress: addr}]) {
    let cursor = null;
    for (let p = 0; p < opt.maxPages; p++) {
      const r = await iotaRpc('iotax_queryTransactionBlocks', [{filter: f, options: {showBalanceChanges: true, showEffects: true, showInput: true}}, cursor, 50, true]);
      (r.data || []).forEach(t => seen.set(t.digest, t));
      if (!r.hasNextPage || !(r.data || []).length) break;
      cursor = r.nextCursor; const ts = new Date(+r.data[r.data.length - 1].timestampMs);
      if (opt.from && ts < opt.from) break;
      if (p === opt.maxPages - 1 && (!cutoff || ts > cutoff)) cutoff = ts;
      await sleep(150);
    }
  }
  const map = new Map();
  for (const t of seen.values()) {
    const b = bucket(map, t.digest); b.ts = new Date(+t.timestampMs); b.initKnown = true;
    b.ok = (t.effects?.status?.status || 'success') === 'success';
    const sender = t.transaction?.data?.sender || ''; b.from = sender;
    const g = t.effects?.gasUsed || {}; const gas = (+g.computationCost || 0) + (+g.storageCost || 0) - (+g.storageRebate || 0);
    if (sender === addr) b.fee = Math.max(0, gas) / 1e9;
    const calls = (t.transaction?.data?.transaction?.transactions || []).map(x => x.MoveCall).filter(Boolean);
    const fn = calls.map(c => `${c.module}::${c.function}`).join(', ');
    b.method = /request_add_stake/.test(fn) ? 'stake' : /request_withdraw_stake/.test(fn) ? 'unstake' : /swap/i.test(fn) ? 'swap' : /add_liquidity|deposit/i.test(fn) ? 'addLiquidity' : /remove_liquidity|withdraw/i.test(fn) ? 'removeLiquidity' : /claim|harvest/i.test(fn) ? 'claimRewards' : fn ? fn : 'transfer';
    if (/stake/.test(b.method)) b.toName = 'IOTA staking';
    if (!b.ok) continue;
    const others = (t.balanceChanges || []).filter(c => c.owner?.AddressOwner && c.owner.AddressOwner !== addr);
    for (const c of t.balanceChanges || []) {
      if (c.owner?.AddressOwner !== addr) continue;
      let amt = BigInt(c.amount); const coin = await iotaCoin(c.coinType);
      if (/::iota::IOTA$/.test(c.coinType) && sender === addr) amt += BigInt(Math.max(0, gas)); // gas is reported in the fee column
      if (amt === 0n) continue;
      const cp = others.find(o => o.coinType === c.coinType && (BigInt(o.amount) > 0n) === (amt < 0n))?.owner?.AddressOwner || (amt > 0n && sender !== addr ? sender : '');
      b.legs.push({dir: amt > 0n ? 'in' : 'out', amount: units((amt < 0n ? -amt : amt).toString(), coin.dec), sym: coin.sym, name: '', token: c.coinType, kind: /::iota::IOTA$/.test(c.coinType) ? 'native' : 'Coin', cp, cpName: /^0x0+$/.test(cp) ? 'IOTA system' : undefined, priced: undefined});
      if (sender === addr && cp) b.to = cp;
    }
    if (!b.legs.length && sender === addr && /stake/.test(b.method)) b.noValue = {cat: b.method === 'stake' ? 'Staking (Stake)' : 'Staking (Unstake)', comment: 'Staking operation with no IOTA balance change for this address. Fee only.'};
    if (b.method === 'unstake' && b.legs.some(l => l.dir === 'in')) b.desc = 'The amount returned includes staking rewards earned; compare with the original stake to split principal and rewards.';
  }
  return trimToCutoff([...map.values()], cutoff);
}

/* ---------- Casper (CSPR.cloud, through the helper) ---------- */
const CSPR = 'https://api.cspr.cloud';
const csprGet = (path, key) => getJSON(proxied(CSPR + path), {headers: {Authorization: key}});
async function fetchCasper(chain, pk, opt) {
  const key = opt.csprKey; if (!key) throw new Error('paste a free CSPR.cloud access token to use Casper');
  // CSPR.cloud returns public keys, entry-point names and exchange labels only when asked for them ("includes").
  const pages = async (path, limit, what) => {
    const out = []; let cut = null;
    for (let p = 1; p <= limit; p++) {
      const j = await csprGet(`${path}${path.includes('?') ? '&' : '?'}page=${p}&page_size=250`, key); const list = j.data || []; out.push(...list);
      if (p >= (j.page_count || 1) || !list.length) break;
      const ts = new Date(list[list.length - 1].timestamp);
      if (opt.from && ts < opt.from) break;
      if (p === limit) cut = ts;
      if (what === 'rewards' && p % 10 === 0) log(`   Casper rewards: page ${p} of ${Math.min(j.page_count || p, limit)} (back to ${fmtDate(ts, $('utc').checked)})…`);
      await sleep(250);
    }
    if (cut && what) log(`   ⚠ Casper ${what}: page limit reached, only ${what} from ${fmtDate(cut, $('utc').checked)} onward were fetched. Raise "Max pages" or set a From date.`, 'w');
    return {out, cut};
  };
  // The account's main purse and account hash identify its own transfers even when a public key is missing.
  let purse = '', acctHash = '';
  try { const a = (await csprGet(`/accounts/${pk}`, key)).data || {}; purse = String(a.main_purse_uref || a.main_purse || '').replace(/-\d{3}$/, ''); acctHash = String(a.account_hash || '').replace(/^account-hash-/, '').toLowerCase(); } catch (e) { if (!notFound(e)) throw e; }
  const mine = (pubKey, pur, hash) => (pubKey && pubKey.toLowerCase() === pk) || (purse && pur && String(pur).replace(/-\d{3}$/, '') === purse) || (acctHash && hash && String(hash).toLowerCase() === acctHash);
  const map = new Map();
  const deploys = await pages(`/accounts/${pk}/deploys?includes=contract_entrypoint,contract_package`, opt.maxPages, 'deploys');
  for (const d of deploys.out) {
    const b = bucket(map, d.deploy_hash); b.ts = new Date(d.timestamp); b.from = pk; b.initKnown = true;
    b.ok = !d.error_message && d.status !== 'expired'; b.fee = units(d.cost || '0', 9);
    const ep = d.contract_entrypoint?.name || d.entry_point?.name || d.entry_point_name || '';
    b.method = ep || (d.execution_type_id === 6 ? 'transfer' : 'contract call');
    if (d.contract_package?.name) b.toName = d.contract_package.name;
    const argAmt = d.args?.amount?.parsed != null ? units(String(d.args.amount.parsed), 9) : null;
    const amtTxt = argAmt ? `${argAmt} CSPR ` : 'CSPR ';
    const vld = d.args?.validator?.parsed || '';
    if (/^delegate$/.test(ep)) b.noValue = {cat: 'Staking (Delegate)', comment: `Delegated ${amtTxt}to a validator${vld ? ' ' + String(vld).slice(0, 10) + '…' : ''} (still yours; locked in stake, no transfer). Fee only.`};
    if (/^undelegate$/.test(ep)) b.noValue = {cat: 'Staking (Undelegate)', comment: `Started undelegating ${amtTxt}— it returns to the main balance after the unbonding period (about 14 hours) without a separate transaction. Fee only.`};
    if (/^redelegate$/.test(ep)) b.noValue = {cat: 'Staking (Redelegate)', comment: `Moved ${amtTxt}of delegated stake to another validator. Fee only.`};
  }
  const transfers = await pages(`/accounts/${pk}/transfers?includes=initiator_public_key,to_public_key,from_purse_public_key,to_purse_public_key,from_purse_centralized_account_info,to_purse_centralized_account_info`, opt.maxPages, 'transfers');
  for (const t of transfers.out) {
    const b = bucket(map, t.deploy_hash); if (!b.ts) b.ts = new Date(t.timestamp);
    const fromMine = mine(t.from_purse_public_key, t.from_purse, null) || (!t.from_purse_public_key && !purse && t.initiator_public_key?.toLowerCase() === pk);
    const toMine = mine(t.to_purse_public_key || t.to_public_key, t.to_purse, t.to_account_hash);
    if (!b.from) b.from = t.initiator_public_key || t.initiator_account_hash || '';
    const amt = units(t.amount || '0', 9);
    // Delegating moves CSPR into a stake purse that is still yours, and CSPR.cloud never records the way back
    // when it unbonds — so keep delegate/redelegate fee-only and count rewards separately (balances then add up).
    if (b.noValue && /delegate$/.test(b.method)) continue;
    if (fromMine && !toMine) { b.to = t.to_purse_public_key || t.to_public_key || t.to_account_hash || t.to_purse || ''; b.legs.push({...natLeg(chain, 'out', amt, b.to), cpName: t.to_purse_centralized_account_info?.name || t.to_centralized_account_info?.name}); }
    else if (toMine && !fromMine) b.legs.push({...natLeg(chain, 'in', amt, t.from_purse_public_key || t.initiator_public_key || t.from_purse || ''), cpName: t.from_purse_centralized_account_info?.name});
    if (b.method === 'contract call' || !b.method) b.method = 'transfer';
  }
  // Delegation rewards arrive every era (~2h) for each validator. Each payment is its own row with its exact
  // time, because the time a reward is received sets its cost basis.
  const rewards = await pages(`/accounts/${pk}/delegation-rewards`, Math.max(opt.maxPages * 5, 200), 'rewards');
  let nRew = 0;
  for (const r of rewards.out) {
    const ts = new Date(r.timestamp); if (opt.from && ts < opt.from) continue; if (opt.to && ts > opt.to) continue;
    const v = r.validator_public_key || '';
    const b = bucket(map, `reward-${r.era_id}-${v}`); b.ts = ts; b.url = `https://cspr.live/account/${pk}`; b.reward = true;
    const leg = natLeg(chain, 'in', units(String(r.amount || '0'), 9), v);
    b.preRows = [{type: 'Staking', cat: 'Staking Rewards', buy: leg, sell: null, lp: '', comment: `Delegation reward for era ${r.era_id} from validator ${v.slice(0, 10)}…${v.slice(-4)} (auto-compounded into your stake).`}];
    nRew++;
  }
  log(`   Casper: ${deploys.out.length} deploys, ${transfers.out.length} transfers, ${rewards.out.length} reward payments → ${nRew} reward rows.`);
  const cutoff = [deploys.cut, transfers.cut].filter(Boolean).sort((a, b) => b - a)[0] || null;
  const all = [...map.values()].filter(b => b.ts);
  return trimToCutoff(all.filter(b => !b.reward), cutoff).concat(all.filter(b => b.reward));
}

/* ---------- THORChain (Midgard public API — free, no key, browser-friendly) ---------- */
const MIDGARD = 'https://gateway.liquify.com/chain/thorchain_midgard/v2';
// Midgard asset names: CHAIN.SYMBOL (native L1), CHAIN-SYMBOL (secured), CHAIN~SYMBOL (trade), CHAIN/SYMBOL (synth); tokens add -CONTRACT.
const thorSym = a => { const m = String(a || '').match(/^([A-Z0-9]+)([.\-~/])(.+)$/i); return m ? m[3].split('-')[0].toUpperCase() : String(a || '').toUpperCase(); };
const thorKind = a => { const m = String(a || '').match(/^[A-Z0-9]+([.\-~/])/i); return !m ? '' : m[1] === '-' ? 'secured asset' : m[1] === '~' ? 'trade asset' : m[1] === '/' ? 'synth' : ''; };
const thorChainOf = a => String(a || '').split(/[.\-~/]/)[0].toUpperCase();
// Which app sent a THORChain swap: its affiliate THORName (data field, or 5th part of the memo "=:ASSET:dest:limit:AFFILIATE:fee").
const THOR_APPS = {ss: 'ShapeShift', t: 'THORSwap'};
function thorApp(md) {
  const tag = String(md?.affiliateAddress || String(md?.memo || '').split(':')[4] || '').trim().toLowerCase();
  if (!tag) return '';
  return tag.split('/').map(t => THOR_APPS[t] ? `${THOR_APPS[t]}` : `app "${t}"`).join(' + ');
}
async function midgardActions(addr, opt) {
  const acts = []; let token = '', cutoff = null;
  const range = (opt.from ? `&fromTimestamp=${Math.floor(opt.from / 1000)}` : '') + (opt.to ? `&toTimestamp=${Math.floor(opt.to / 1000)}` : '');
  for (let p = 1; p <= opt.maxPages; p++) {
    const j = await getJSON(`${MIDGARD}/actions?address=${addr}&limit=50${range}${token ? '&nextPageToken=' + token : ''}`);
    const list = j.actions || []; acts.push(...list);
    token = j.meta?.nextPageToken || '';
    if (!list.length || !token || list.length < 50) break;
    if (p === opt.maxPages) cutoff = new Date(Number(BigInt(list[list.length - 1].date) / 1000000n));
    await sleep(200);
  }
  return {acts, cutoff};
}
async function fetchThor(chain, addr, opt) {
  const A = addr.toLowerCase(), legOf = (c, dir, cp) => ({dir, amount: units(String(c.amount || '0'), 8), sym: thorSym(c.asset), name: c.asset, token: c.asset === 'THOR.RUNE' ? 'native' : c.asset,
    kind: c.asset === 'THOR.RUNE' ? 'native' : 'token', id: null, cp: cp || '', spam: false});
  const coins = list => list.flatMap(x => (x.coins || []).map(c => ({...c, address: x.address})));
  const fmtC = arr => arr.map(c => `${units(String(c.amount || '0'), 8)} ${thorSym(c.asset)}${thorKind(c.asset) ? ` (${thorKind(c.asset)})` : ''}`).join(' + ');
  // THORChain charges a flat native fee (0.02 RUNE today) for every transaction signed on THORChain itself.
  // Midgard reports it inconsistently, so read the current value from the network.
  let nativeFee = 0.02;
  try { const n = await getJSON('https://gateway.liquify.com/chain/thorchain_api/thorchain/network'); if (+n.native_tx_fee_rune > 0) nativeFee = units(String(n.native_tx_fee_rune), 8); } catch (e) {}
  // 1. download all actions (newest first, 50 per page)
  const {acts, cutoff} = await midgardActions(A, opt);
  // 2. one bucket per transaction; a "send" that only carried a swap/LP request is folded into that action
  const byTx = new Map();
  acts.forEach((a, i) => { const id = (a.in || []).map(x => x.txID).find(t => t && !/^0+$/.test(t)) || `${a.height}-${a.type}-${i}`; if (!byTx.has(id)) byTx.set(id, []); byTx.get(id).push(a); });
  const map = new Map();
  for (const [id, group] of byTx) {
    const main = group.find(a => a.type !== 'send') || group[0];
    const sendFee = group.filter(a => a.type === 'send' && a !== main).flatMap(a => a.metadata?.send?.networkFees || []);
    const b = bucket(map, id); b.ts = new Date(Number(BigInt(main.date) / 1000000n)); b.method = main.type; b.from = (main.in || [])[0]?.address?.toLowerCase() || '';
    const failed = main.status === 'failed'; b.initKnown = true; if (/^\d+-/.test(id)) b.url = `https://runescan.io/address/${A}`;
    const md = main.metadata?.[main.type] || {};
    const ins = coins(main.in || []), outs = coins(main.out || []);
    const myIn = ins.filter(c => c.address?.toLowerCase() === A), myOut = outs.filter(c => c.address?.toLowerCase() === A);
    // Outbound fees are already taken out of what was received — shown in the comment only, never as an extra fee.
    const outFees = (md.networkFees || []).filter(f => +f.amount > 0 && main.type !== 'send');
    const feeTxt = outFees.length ? ` Outbound fee already deducted from the amount received: ${fmtC(outFees)}.` : '';
    // Signed on THORChain by this wallet (not an inbound from Bitcoin/Ethereum etc.) → the native RUNE fee was paid.
    const signedHere = (main.in || []).some(x => x.address?.toLowerCase() === A && x.txID && !/^0+$/.test(x.txID) && (x.coins || []).every(c => !/^[A-Z0-9]+\./i.test(c.asset) || /^THOR\./i.test(c.asset)));
    const fee = signedHere ? {amount: nativeFee, sym: 'RUNE'} : null;
    void sendFee;
    const pool = (main.pools || []).join(', ');
    const pend = main.status === 'pending' ? ' Status: pending (streaming or not yet sent out) — check the explorer.' : '';
    const rows = [], add = (type, cat, buy, sell, lp, comment, f) => rows.push({type, cat, buy, sell, lp: lp || '', comment, fee: f || null});
    const memo = md.memo ? ` Memo: ${md.memo}.` : '';
    if (main.type === 'swap') {
      const dest = outs.filter(c => +c.amount > 0);
      const extDest = dest.filter(c => c.address?.toLowerCase() !== A);
      const liq = md.liquidityFee ? ` Liquidity fee: ${units(String(md.liquidityFee), 8)} (already included in the swap price).` : '';
      if (myIn.length) {
        const n = Math.max(myIn.length, dest.length || 1);
        for (let k = 0; k < n; k++) {
          const s = myIn[k] ? legOf(myIn[k], 'out', pool) : null, o = dest[k] ? legOf(dest[k], 'in', dest[k].address) : null;
          add(s && o ? 'Trade' : s ? 'Withdrawal' : 'Deposit', thorApp(md) ? `DeFi - Swap (THORChain via ${thorApp(md)})` : 'DeFi - Swap', o, s, pool,
            `THORChain swap${thorApp(md) ? ' made in ' + thorApp(md) : ''}: sold ${fmtC(myIn)} for ${dest.length ? fmtC(dest) : 'nothing yet'}${extDest.length ? `, delivered to ${extDest.map(c => `${thorChainOf(c.asset)} address ${short(c.address)}`).join(', ')}` : ''}. Pool(s): ${pool}.${liq}${feeTxt}${pend}${memo}`, k === 0 ? fee : null);
        }
      } else if (myOut.length) {
        myOut.forEach((c, k) => add('Deposit', 'DeFi - Swap (Incoming)', legOf(c, 'in', b.from), null, pool,
          `Received ${fmtC([c])} from a THORChain swap of ${fmtC(ins)} sent by ${short(b.from)} (${thorChainOf(ins[0]?.asset)}). If that sender is your own wallet, record the matching sale there.${pend}${memo}`));
      }
    } else if (main.type === 'refund') {
      if (myIn.length) {
        const back = {}; myOut.forEach(c => back[c.asset] = (back[c.asset] || 0n) + BigInt(c.amount || 0));
        myIn.forEach((c, k) => {
          const lost = BigInt(c.amount || 0) - (back[c.asset] || 0n);
          const cost = myOut.length && lost > 0n ? {amount: units(lost.toString(), 8), sym: thorSym(c.asset), kind: 'token'} : null;
          add('Other Fee', 'DeFi - Swap (Refunded)', null, cost, '', `Swap of ${fmtC([c])} was refunded${md.reason ? ` (${md.reason})` : ''}. ${myOut.length ? `Got back ${fmtC(myOut)}; the difference is the network fee.` : 'Refund not sent out yet — check the explorer.'}${memo}`, k === 0 ? fee : null);
        });
      }
    } else if (main.type === 'addLiquidity') {
      myIn.forEach(c => add('Withdrawal', 'DeFi - Liquidity Pool (Add)', null, legOf(c, 'out', pool), pool, `Added ${fmtC([c])} to THORChain pool ${pool}.${ins.length > myIn.length ? ` Other side: ${fmtC(ins.filter(x => !myIn.includes(x)))} from ${short(ins.find(x => !myIn.includes(x))?.address)}.` : ''}${feeTxt}${pend}${memo}`, rows.length ? null : fee));
      if (!myIn.length) rows.push({type: 'Other Fee', cat: 'DeFi - Liquidity Pool (Add)', buy: null, sell: null, lp: pool, comment: `Liquidity added to ${pool} from another address (${short(b.from)}) with this wallet as the RUNE side.`});
    } else if (main.type === 'withdraw') {
      myOut.forEach((c, k) => add('Deposit', 'DeFi - Liquidity Pool (Remove)', legOf(c, 'in', pool), null, pool, `Withdrew ${fmtC([c])} from THORChain pool ${pool}${md.basisPoints ? ` (${+md.basisPoints / 100}% of the position)` : ''}.${md.impermanentLossProtection && +md.impermanentLossProtection > 0 ? ` Includes impermanent-loss protection ${units(String(md.impermanentLossProtection), 8)} RUNE.` : ''}${feeTxt}${pend}`, k === 0 ? fee : null));
      if (!myOut.length && myIn.length) add('Other Fee', 'DeFi - Liquidity Pool (Remove)', null, null, pool, `Requested a withdrawal from ${pool}; the assets went to ${outs.map(c => short(c.address)).join(', ') || 'another address'}.${memo}`, fee);
    } else if (main.type === 'failed') {
      if (b.from === A) add('Other Fee', 'Failed Transaction', null, fee ? {...fee, kind: 'native'} : null, '', `Failed THORChain transaction${md.reason ? ': ' + md.reason.slice(0, 160) : ''}.${memo} Only the network fee was paid.`);
    } else if (main.type === 'secure' || main.type === 'trade') {
      const what = main.type === 'secure' ? 'Secured Asset' : 'Trade Account';
      if (myIn.length) myIn.forEach(c => { const o = outs.find(x => thorSym(x.asset) === thorSym(c.asset));
        const diff = o ? BigInt(c.amount || 0) - BigInt(o.amount || 0) : 0n;
        add('Withdrawal', `Transfer (${what} → L1)`, null, legOf(c, 'out', o?.address), '', `Moved ${fmtC([c])} out of THORChain to ${thorChainOf(o?.asset || c.asset)} address ${o ? o.address : '?'}${o ? ` (arrived: ${fmtC([o])}${diff > 0n ? `; ${units(diff.toString(), 8)} ${thorSym(c.asset)} outbound fee` : ''})` : ''}. Match with the Deposit on that chain if it is your wallet.${pend}`, fee); });
      else myOut.forEach(c => add('Deposit', `Transfer (L1 → ${what})`, legOf(c, 'in', b.from), null, '', `Deposited ${fmtC(ins)} from ${thorChainOf(ins[0]?.asset)} address ${short(b.from)} and received ${fmtC([c])} on THORChain. Match with the Withdrawal on that chain if it is your wallet.`));
    } else if (main.type === 'send') {
      myIn.forEach((c, k) => { const to = outs.find(x => x.asset === c.asset && x.address?.toLowerCase() !== A)?.address || outs[0]?.address || '';
        b.legs.push(legOf(c, 'out', to)); });
      myOut.forEach(c => { if (!myIn.some(x => x.asset === c.asset)) b.legs.push(legOf(c, 'in', b.from)); });
      if (fee) { b.fee = fee.amount; b.feeCur = 'RUNE'; }
      if (failed) b.ok = false;
      b.to = outs.find(x => x.address?.toLowerCase() !== A)?.address || '';
      continue;
    } else {
      // RUNEPool, TCY, THORName, switch, donate, loans …: record what left and what arrived
      const label = {runePoolDeposit: 'RUNEPool (Deposit)', runePoolWithdraw: 'RUNEPool (Withdraw)', thorname: 'THORName registration', switch: 'RUNE upgrade (switch)', donate: 'Pool donation',
        tcy_stake: 'DeFi - Staking (Stake)', tcy_unstake: 'DeFi - Staking (Unstake)', tcy_claim: 'Airdrop Claim (TCY)'}[main.type] || `THORChain - ${main.type}`;
      if (myIn.length && myOut.length) myIn.forEach((c, k) => add('Trade', label, myOut[k] ? legOf(myOut[k], 'in', '') : null, legOf(c, 'out', ''), pool, `${label}: ${fmtC(myIn)} → ${fmtC(myOut)}.${feeTxt}${pend}${memo}`, k === 0 ? fee : null));
      else { myIn.forEach((c, k) => add(main.type === 'thorname' ? 'Other Fee' : 'Withdrawal', label, null, legOf(c, 'out', ''), pool, `${label}: sent ${fmtC([c])}.${feeTxt}${pend}${memo}`, k === 0 ? fee : null));
        myOut.forEach(c => add(main.type === 'tcy_claim' ? 'Airdrop' : 'Deposit', label, legOf(c, 'in', ''), null, pool, `${label}: received ${fmtC([c])}.${pend}${memo}`)); }
    }
    if (failed && b.from === A) rows.splice(0, rows.length, {type: 'Other Fee', cat: 'Failed Transaction', buy: null, sell: fee ? {...fee, kind: 'native'} : null, lp: '', comment: `Failed THORChain ${main.type}${md.reason ? ': ' + md.reason : ''}.`});
    if (rows.length) b.preRows = rows; else map.delete(id);
  }
  return trimToCutoff([...map.values()], cutoff);
}

/* ---------- Polkadot & Kusama (Statescan — free, no key). History lives on the relay chain until the Asset Hub
   migration (Nov 2025) and on Asset Hub after it, so both are read and merged. ---------- */
const STATESCAN = {
  dot: {dec: 10, sides: [{tag: 'relay', name: 'Polkadot relay chain', api: 'https://polkadot-api.statescan.io', gql: 'https://ddd-gh-api.statescan.io/graphql', site: 'https://polkadot.statescan.io'},
                         {tag: 'ah', name: 'Polkadot Asset Hub', api: 'https://ahp-api.statescan.io', gql: 'https://ahp-gh-api.statescan.io/graphql', site: 'https://assethub-polkadot.statescan.io', assets: true}]},
  ksm: {dec: 12, sides: [{tag: 'relay', name: 'Kusama relay chain', api: 'https://kusama-api.statescan.io', gql: 'https://ksm-gh-api.statescan.io/graphql', site: 'https://kusama.statescan.io'},
                         {tag: 'ah', name: 'Kusama Asset Hub', api: 'https://statemine-api.statescan.io', gql: 'https://statemine-gh-api.statescan.io/graphql', site: 'https://assethub-kusama.statescan.io', assets: true}]},
};
const subBig = v => { try { return BigInt(typeof v === 'number' ? Math.round(v) : String(v ?? '0')); } catch { return 0n; } };
const gqlPost = (url, query, variables = {}) => postJSON(url, {query, variables}).then(j => { if (j.errors?.length) throw new Error(j.errors[0].message); return j.data; });
const evArg = (ev, name) => (ev.args || ev.data || []).find?.(a => a.name === name)?.value;
const SUB_LABEL = {staking: 'Polkadot staking', nominationPools: 'Polkadot staking pool (nomination pool)', polkadotXcm: 'XCM cross-chain transfer (bridge)', xcmPallet: 'XCM cross-chain transfer (bridge)', xTokens: 'XCM cross-chain transfer (bridge)',
  crowdloan: 'Crowdloan', convictionVoting: 'OpenGov voting', democracy: 'Democracy voting', proxy: 'Proxy', utility: 'Batch', assetConversion: 'Asset Hub DEX (asset conversion swap)', vesting: 'Vesting', identity: 'On-chain identity'};
async function scanStatescan(cfg, a) {
  let n = 0, active = false;
  for (const sd of cfg.sides) {
    try { const j = await getJSON(`${sd.api}/accounts/${a}/transfers?page=0&page_size=1`, {}, 2); n += +j.total || 0; } catch (e) {}
    try { const j = await getJSON(`${sd.api}/accounts/${a}/extrinsics?page=0&page_size=1`, {}, 2); n += +j.total || 0; } catch (e) {}
    try { const acc = await getJSON(`${sd.api}/accounts/${a}`, {}, 2); if (subBig(acc?.data?.total) > 0n) active = true; } catch (e) {}
  }
  return {active: active || n > 0, count: n || (active ? '✓' : 0)};
}
async function fetchStatescan(chain, a, opt) {
  const cfg = STATESCAN[chain.id], map = new Map(), dec = cfg.dec, sym = chain.native; let cutoff = null, feeLookups = 0;
  const inRange = ms => !(opt.from && ms < +opt.from) && !(opt.to && ms > +opt.to);
  const assetMeta = new Map(), payoutSeen = new Set();
  for (const sd of cfg.sides) {
    const key = (h, i) => `${sd.tag}:${h}-${i}`;
    const mk = (ix, hash) => { const b = bucket(map, key(ix.blockHeight, ix.extrinsicIndex ?? ix.eventIndex)); if (!b.ts) { b.ts = new Date(ix.blockTime); b.url = ix.extrinsicIndex != null ? `${sd.site}/#/extrinsics/${ix.blockHeight}-${ix.extrinsicIndex}` : `${sd.site}/#/events/${ix.blockHeight}-${ix.eventIndex}`; b.toName = b.toName || ''; b.side = sd.name; } if (hash) b.hash2 = hash; return b; };
    const pages = async (fn, what) => { const out = []; for (let p = 0; p < opt.maxPages; p++) { const {items, total} = await fn(p); out.push(...items); const last = items[items.length - 1];
      if (!items.length || out.length >= total) break; const ts = last?.indexer?.blockTime; if (opt.from && ts && ts < +opt.from) break;
      if (p === opt.maxPages - 1 && ts) { const c = new Date(ts); if (!cutoff || c > cutoff) cutoff = c; log(`   ⚠ ${sd.name} ${what}: page limit reached.`, 'w'); } await sleep(150); } return out; };
    // 1. signed transactions (method, success, fee from their events)
    const exts = await pages(async p => { const j = await getJSON(`${sd.api}/accounts/${a}/extrinsics?page=${p}&page_size=100`); return {items: j.items || [], total: +j.total || 0}; }, 'transactions');
    for (const x of exts) {
      if (!inRange(x.indexer.blockTime)) continue;
      const b = mk(x.indexer, x.hash); b.from = a; b.initKnown = true; b.ok = x.isSuccess !== false; b.method = `${x.section}.${x.method}`;
      b.toName = SUB_LABEL[x.section] || ''; if (x.section === 'utility') { const inner = JSON.stringify(x.args || '').match(/"section":"(\w+)"/); if (inner && SUB_LABEL[inner[1]]) b.toName = SUB_LABEL[inner[1]]; }
      if (feeLookups < 600) {
        feeLookups++; if (feeLookups % 50 === 0) log(`   ${chain.name}: reading fees… ${feeLookups}`);
        try {
          const evs = await getJSON(`${sd.api}/extrinsics/${x.indexer.blockHeight}-${x.indexer.extrinsicIndex}/events`); const list = evs.items || evs || [];
          const fe = list.find(e => e.method === 'TransactionFeePaid' && evArg(e, 'who') === a);
          if (fe) b.fee = units((subBig(evArg(fe, 'actual_fee')) + subBig(evArg(fe, 'tip'))).toString(), dec);
          else { const w = list.find(e => e.section === 'balances' && e.method === 'Withdraw' && evArg(e, 'who') === a); if (w) b.fee = units(subBig(evArg(w, 'amount')).toString(), dec); } // before 2022
          for (const e of list) {
            if (e.section === 'nominationPools' && e.method === 'PaidOut' && evArg(e, 'member') === a && !list.some(t => t.method === 'Transfer')) {
              b.preRows = b.preRows || []; b.preRows.push({type: 'Staking', cat: 'Staking Rewards (nomination pool)', buy: natLeg(chain, 'in', units(subBig(evArg(e, 'payout')).toString(), dec), ''), sell: null, lp: '',
                comment: `Nomination pool #${evArg(e, 'pool_id') ?? evArg(e, 'poolId') ?? '?'} paid out rewards (${sd.name}).`});
            }
          }
          if (/^staking\.(bond|bondExtra|unbond|rebond|nominate|chill|setPayee|withdrawUnbonded)$/.test(b.method) && !list.some(e => e.method === 'Transfer')) {
            const amt = list.find(e => e.section === 'staking' && /Bonded|Unbonded|Withdrawn/.test(e.method)); const v = amt ? units(subBig(evArg(amt, 'amount')).toString(), dec) : 0;
            b.noValue = {cat: `Staking (${x.method})`, comment: `${x.section}.${x.method}${v ? ` ${v} ${sym}` : ''} — the ${sym} stays in your account (locked/unlocked for staking), no transfer. Fee only.`};
          }
          await sleep(80);
        } catch (e) {}
      } else if (feeLookups === 600) { feeLookups++; log(`   ${chain.name}: more than 600 transactions — fees after the first 600 are not read.`, 'w'); }
    }
    // 2. native transfers
    const trs = await pages(async p => { const j = await getJSON(`${sd.api}/accounts/${a}/transfers?page=${p}&page_size=100`); return {items: j.items || [], total: +j.total || 0}; }, 'transfers');
    for (const t of trs) {
      if (t.isNativeAsset === false || !inRange(t.indexer.blockTime)) continue;
      const b = mk(t.indexer); const amt = units(subBig(t.balance).toString(), dec); if (!amt) continue;
      const pool = poolAccount(t.from === a ? t.to : t.from);
      if (pool && t.to === a && pool.type === 'staking') {  // staking reward paid from the era's reward pot
        payoutSeen.add(`${sd.tag}:${t.indexer.blockHeight}:${subBig(t.balance)}`);
        b.preRows = b.preRows || []; b.preRows.push({type: 'Staking', cat: 'Staking Rewards', buy: natLeg(chain, 'in', amt, t.from), sell: null, lp: '', comment: `Staking reward paid out by the ${sd.name} staking reward pot.`});
        continue;
      }
      if (pool && t.to === a && pool.type === 'reward') {   // pool rewards paid out (claimed by you or automatically)
        b.preRows = b.preRows || []; b.preRows.push({type: 'Staking', cat: 'Staking Rewards (nomination pool)', buy: natLeg(chain, 'in', amt, t.from), sell: null, lp: '', comment: `Nomination pool #${pool.id} reward paid out (${sd.name}).`});
        continue;
      }
      if (pool) b.toName = `Polkadot staking pool (nomination pool #${pool.id})`;
      if (t.from === a && t.to !== a) { b.legs.push(natLeg(chain, 'out', amt, t.to)); b.from = a; b.to = b.to || t.to; }
      else if (t.to === a && t.from !== a) { b.legs.push(natLeg(chain, 'in', amt, t.from)); if (!b.from) b.from = t.from; }
      if (!b.method) b.method = 'transfer';
    }
    // 3. tokens on Asset Hub (USDt, USDC, bridged assets)
    if (sd.assets) for (const kind of ['assetTransfers', 'foreignAssetTransfers']) {
      const list = await pages(async p => { const d = await gqlPost(sd.gql, `query($a:String,$o:Int!,$l:Int!){ ${kind}(address:$a, offset:$o, limit:$l) { total transfers { from to balance assetId indexer { blockHeight blockTime extrinsicIndex eventIndex } } } }`, {a, o: p * 100, l: 100});
        return {items: d[kind].transfers || [], total: +d[kind].total || 0}; }, 'token transfers').catch(e => { log(`   ${sd.name} tokens: ${e.message.slice(0, 80)}`, 'w'); return []; });
      for (const t of list) {
        if (!inRange(t.indexer.blockTime)) continue;
        const id = String(t.assetId);
        if (!assetMeta.has(id)) { try { const d = await gqlPost(sd.gql, kind === 'assetTransfers' ? `query($i:Int!){ asset(id:$i) { metadata { symbol decimals } } }` : `query($i:String!){ foreignAsset(id:$i) { metadata { symbol decimals } } }`, {i: kind === 'assetTransfers' ? +id : id});
          assetMeta.set(id, (d.asset || d.foreignAsset)?.metadata || {}); } catch (e) { assetMeta.set(id, {}); } }
        const m = assetMeta.get(id), b = mk(t.indexer), amt = units(subBig(t.balance).toString(), m.decimals ?? 0), tsym = m.symbol || `asset ${id.slice(0, 10)}`;
        const leg = {dir: t.from === a ? 'out' : 'in', amount: amt, sym: tsym, name: tsym, token: id, kind: 'token', id: null, cp: t.from === a ? t.to : t.from, spam: false};
        if (t.from === a && t.to === a) continue; b.legs.push(leg); if (!b.method) b.method = 'transfer';
        if (t.from === a) { b.from = a; b.to = b.to || t.to; } else if (!b.from) b.from = t.from;
      }
    }
    // 4. staking rewards (one row each — the time sets the cost basis)
    const rw = await pages(async p => { const d = await gqlPost(sd.gql, `query($a:String,$o:Int!,$l:Int!){ stakingRewards(address:$a, offset:$o, limit:$l) { total items { amount era validator dest indexer { blockHeight blockTime eventIndex extrinsicIndex } } } }`, {a, o: p * 100, l: 100});
      return {items: d.stakingRewards.items || [], total: +d.stakingRewards.total || 0}; }, 'staking rewards').catch(e => { log(`   ${sd.name} rewards: ${e.message.slice(0, 80)}`, 'w'); return []; });
    for (const r of rw) {
      if (!inRange(r.indexer.blockTime) || subBig(r.amount) === 0n || payoutSeen.has(`${sd.tag}:${r.indexer.blockHeight}:${subBig(r.amount)}`)) continue; // already a row from its payout transfer
      const b = bucket(map, `${sd.tag}:reward-${r.indexer.blockHeight}-${r.indexer.eventIndex}`); b.ts = new Date(r.indexer.blockTime); b.url = `${sd.site}/#/events/${r.indexer.blockHeight}-${r.indexer.eventIndex}`;
      const dest = r.dest?.account ? `paid to ${r.dest.account === a ? 'this account' : r.dest.account}` : r.dest && JSON.stringify(r.dest).includes('Staked') ? 'added to your stake' : 'paid to this account';
      b.preRows = [{type: 'Staking', cat: 'Staking Rewards', buy: natLeg(chain, 'in', units(subBig(r.amount).toString(), dec), r.validator || ''), sell: null, lp: '',
        comment: `Staking reward for era ${r.era} from validator ${short(r.validator || '')} (${sd.name}), ${dest}.`}];
    }
  }
  const out = [...map.values()].filter(b => b.ts).map(b => { if (b.hash2) { b.url = b.url; b.hash = b.hash2; } else if (/^(relay|ah):/.test(b.hash)) b.hash = b.hash.replace(/^relay:/, 'relay-').replace(/^ah:/, 'assethub-'); return b; });
  return trimToCutoff(out, cutoff);
}

/* ---------- Other Substrate chains (Subscan — free API key) ---------- */
// [subdomain, name, code, native symbol, decimals, accounts are 0x (EVM-style)]
const SUBSCAN_NETS = [
  ['astar', 'Astar', 'ASTR', 'ASTR', 18], ['shiden', 'Shiden', 'SDN', 'SDN', 18], ['moonbeam', 'Moonbeam', 'GLMR', 'GLMR', 18, true], ['moonriver', 'Moonriver', 'MOVR', 'MOVR', 18, true],
  ['bifrost', 'Bifrost', 'BNC', 'BNC', 12], ['centrifuge', 'Centrifuge', 'CFG', 'CFG', 18], ['altair', 'Altair', 'AIR', 'AIR', 18], ['avail', 'Avail', 'AVAIL', 'AVAIL', 18],
  ['vara', 'Vara', 'VARA', 'VARA', 12], ['enjin', 'Enjin Relaychain', 'ENJ', 'ENJ', 18], ['matrix', 'Enjin Matrixchain', 'ENJM', 'ENJ', 18], ['peaq', 'peaq', 'PEAQ', 'PEAQ', 18],
  ['mythos', 'Mythos', 'MYTH', 'MYTH', 18, true], ['darwinia', 'Darwinia', 'RING', 'RING', 18, true], ['crust', 'Crust', 'CRU', 'CRU', 12], ['crust-parachain', 'Crust Polkadot', 'CRUP', 'CRU', 12],
  ['autonomys', 'Autonomys', 'AI3', 'AI3', 18], ['humanode', 'Humanode', 'HMND', 'HMND', 18], ['polymesh', 'Polymesh', 'POLYX', 'POLYX', 6], ['energywebx', 'Energy Web X', 'EWX', 'EWT', 18],
  ['people-polkadot', 'Polkadot People', 'PPL', 'DOT', 10], ['coretime-polkadot', 'Polkadot Coretime', 'PCT', 'DOT', 10], ['bridgehub-polkadot', 'Polkadot BridgeHub', 'PBH', 'DOT', 10],
  ['collectives-polkadot', 'Polkadot Collectives', 'PCOL', 'DOT', 10], ['people-kusama', 'Kusama People', 'KPPL', 'KSM', 12], ['coretime-kusama', 'Kusama Coretime', 'KCT', 'KSM', 12],
  ['bridgehub-kusama', 'Kusama BridgeHub', 'KBH', 'KSM', 12],
];
const SUBSCAN_META = new Map(); // network -> {prefix}
async function subscanPost(net, path, body, key) {
  for (let k = 0; k < 6; k++) {
    const r = await fetch(`https://${net}.api.subscan.io${path}`, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-API-Key': key}, body: JSON.stringify(body)});
    const j = await r.json().catch(() => ({}));
    if (r.status === 429 || j.code === 20008) { await sleep(1500 * (k + 1)); continue; }              // free plan: a few requests per second
    if (j.code === 403 || r.status === 401 || r.status === 403) throw new Error('Subscan key rejected: ' + (j.message || r.status));
    if (j.code && j.code !== 0) { if (/not found|record not found/i.test(j.message || '')) return null; throw new Error('Subscan: ' + (j.message || j.code)); }
    return j.data;
  }
  throw new Error('Subscan is busy (rate limit) — try again in a minute');
}
async function subscanAddr(chain, det, key) { // re-encode the key in this chain's own address format
  if (chain.evmAccounts) return det.family === 'evm' ? det.addr : null;
  if (det.family !== 'substrate') return null;
  if (!SUBSCAN_META.has(chain.net)) { try { const m = await subscanPost(chain.net, '/api/scan/metadata', {}, key); SUBSCAN_META.set(chain.net, {prefix: +m?.addressType}); } catch (e) { SUBSCAN_META.set(chain.net, {prefix: NaN}); } }
  const p = SUBSCAN_META.get(chain.net).prefix; return Number.isFinite(p) ? ss58Encode(p, det.pub) : det.addr;
}
async function fetchSubscan(chain, a, opt) {
  const key = opt.subscanKey, net = chain.net, map = new Map(), dec = chain.dec; let cutoff = null;
  const inRange = ms => !(opt.from && ms < +opt.from) && !(opt.to && ms > +opt.to);
  const pages = async (path, listKey, what, extra = {}) => { const out = [];
    for (let p = 0; p < opt.maxPages; p++) { const d = await subscanPost(net, path, {address: a, row: 100, page: p, ...extra}, key); const list = (d && (d[listKey] || d.list)) || []; out.push(...list);
      if (list.length < 100) break; const ts = (list[list.length - 1].block_timestamp || 0) * 1000; if (opt.from && ts < +opt.from) break;
      if (p === opt.maxPages - 1) { const c = new Date(ts); if (!cutoff || c > cutoff) cutoff = c; log(`   ⚠ ${chain.name} ${what}: page limit reached.`, 'w'); } await sleep(250); }
    return out; };
  const exts = await pages('/api/v2/scan/extrinsics', 'extrinsics', 'transactions');
  for (const x of exts) {
    const ts = x.block_timestamp * 1000; if (!inRange(ts)) continue;
    const b = bucket(map, x.extrinsic_hash || x.extrinsic_index); b.ts = new Date(ts); b.from = a; b.initKnown = true; b.ok = x.success !== false;
    b.method = `${x.call_module}.${x.call_module_function}`; b.fee = units(String(x.fee_used || x.fee || '0'), dec); b.url = `https://${net}.subscan.io/extrinsic/${x.extrinsic_hash || x.extrinsic_index}`;
    const mod = String(x.call_module || ''); b.toName = SUB_LABEL[mod] || (/dapp|staking|collator|parachainstaking|delegat/i.test(mod) ? `${chain.name} staking` : /xcm|xtokens|bridge/i.test(mod) ? 'XCM cross-chain transfer (bridge)' : /dex|swap|router|amm|omnipool/i.test(mod) ? `${chain.name} DEX swap` : '');
  }
  const trs = await pages('/api/v2/scan/transfers', 'transfers', 'transfers');
  for (const t of trs) {
    const ts = t.block_timestamp * 1000; if (!inRange(ts) || t.success === false) continue;
    const h = t.hash || t.extrinsic_index; const b = bucket(map, h); if (!b.ts) { b.ts = new Date(ts); b.url = `https://${net}.subscan.io/extrinsic/${h}`; }
    const amt = +t.amount || (t.amount_v2 ? units(String(t.amount_v2), t.decimals ?? dec) : 0); if (!amt) continue;
    const tsym = t.asset_symbol || chain.native, native = !t.asset_symbol || t.asset_symbol === chain.native;
    const fromMe = lc(t.from) === lc(a), toMe = lc(t.to) === lc(a); if (fromMe && toMe) continue;
    const leg = native ? natLeg(chain, fromMe ? 'out' : 'in', amt, fromMe ? t.to : t.from) : {dir: fromMe ? 'out' : 'in', amount: amt, sym: tsym, name: tsym, token: t.asset_unique_id || tsym, kind: 'token', id: null, cp: fromMe ? t.to : t.from, spam: false};
    leg.cpName = (fromMe ? t.to_account_display : t.from_account_display)?.display || '';
    b.legs.push(leg); if (fromMe) { b.from = a; b.to = b.to || t.to; } else if (!b.from) b.from = t.from; if (!b.method) b.method = 'transfer';
  }
  let rw = [];
  try { rw = await pages('/api/v2/scan/account/reward_slash', 'list', 'staking rewards', {category: 'Reward'}); }
  catch (e) { try { rw = await pages('/api/scan/account/reward_slash', 'list', 'staking rewards', {category: 'Reward'}); } catch (e2) { log(`   ${chain.name} rewards: ${e2.message.slice(0, 80)}`, 'w'); } }
  for (const r of rw) {
    const ts = r.block_timestamp * 1000; if (!inRange(ts) || /slash/i.test(r.event_id || '')) continue;
    const b = bucket(map, `reward-${r.event_index || r.extrinsic_hash || ts}`); b.ts = new Date(ts); b.url = `https://${net}.subscan.io/account/${a}?tab=reward`;
    b.preRows = [{type: 'Staking', cat: 'Staking Rewards', buy: natLeg(chain, 'in', units(String(r.amount || '0'), dec), r.validator_stash || r.stash || ''), sell: null, lp: '',
      comment: `${chain.name} staking reward${r.era != null ? ' for era ' + r.era : ''}${r.module_id ? ` (${r.module_id}.${r.event_id})` : ''}.`}];
  }
  return trimToCutoff([...map.values()].filter(b => b.ts), cutoff);
}

/* ---------- XPR Network (Hyperion history API used by explorer.xprnetwork.org) ---------- */
const XPR_HYP = 'https://hyp-xpr.api.mainnet.metalx.com';
const XPR_NAMES = {eosio: 'XPR system (staking/resources)', 'eosio.token': 'XPR token', 'eosio.stake': 'XPR staking', 'eosio.ram': 'XPR RAM', alcor: 'Alcor DEX', dex: 'Metal X DEX',
  'proton.swaps': 'Proton Swap', 'lending.loan': 'Metal X Lending', 'loan.token': 'LOAN token', xtokens: 'Metal X wrapped tokens (bridge)', 'xmd.token': 'XMD stablecoin',
  'xmd.treasury': 'XMD treasury', 'yield.farms': 'Metal X yield farms', 'atomicassets': 'AtomicAssets (NFTs)', 'atomicmarket': 'AtomicMarket (NFT market)', 'otc.p': 'OTC', 'proton.wrap': 'Proton bridge (wrap)', 'snipx': 'Snipcoin'};
const XPR_TRUSTED = new Set(['eosio.token', 'xtokens', 'loan.token', 'xmd.token']); // token contracts with real market prices
function xprHint(acts) {
  const names = acts.map(a => a.act.account + ':' + a.act.name).join(' ');
  if (/eosio:(stakexpr|voteproducer)/.test(names)) return 'stake';
  if (/eosio:(unstakexpr|refundsxpr)/.test(names)) return 'unstake';
  if (/eosio:claimvotexpr|claimrewards|yield\.farms:claim|:claim/.test(names)) return 'claimRewards';
  if (/proton\.swaps:|alcor:swap|:swap|dex:process|dex:placeorder/.test(names)) return 'swap';
  if (/yield\.farms:(stake|deposit)|addliquidity|:deposit/.test(names)) return 'addLiquidity';
  if (/yield\.farms:(unstake|withdraw)|removeliquidity|:withdrawall/.test(names)) return 'removeLiquidity';
  if (/lending\.loan:borrow/.test(names)) return 'borrow';
  if (/lending\.loan:repay/.test(names)) return 'repay';
  if (/lending\.loan:/.test(names)) return 'supply';
  if (/atomicassets:transfer|atomicmarket:/.test(names)) return 'nft';
  return /:transfer$/.test(names.split(' ')[0]) ? 'transfer' : names.split(' ')[0];
}
async function fetchXpr(chain, addr, opt) {
  const all = []; let cutoff = null;
  for (let p = 0; p < opt.maxPages; p++) {
    const j = await getJSON(`${XPR_HYP}/v2/history/get_actions?account=${addr}&limit=500&skip=${p * 500}&sort=desc${opt.from ? '&after=' + opt.from.toISOString().slice(0, 19) : ''}`);
    const list = j.actions || []; all.push(...list);
    if (list.length < 500) break;
    if (p === opt.maxPages - 1) cutoff = new Date(list[list.length - 1]['@timestamp'] + 'Z');
    await sleep(250);
  }
  const byTx = new Map(), seen = new Set();
  for (const a of all) { if (seen.has(a.global_sequence)) continue; seen.add(a.global_sequence); (byTx.get(a.trx_id) || byTx.set(a.trx_id, []).get(a.trx_id)).push(a); }
  const map = new Map();
  for (const [trx, acts] of byTx) {
    acts.sort((x, y) => x.global_sequence - y.global_sequence);
    const b = bucket(map, trx); b.ts = new Date(acts[0]['@timestamp'] + 'Z'); b.ok = true; b.initKnown = true; b.fee = 0;
    const signer = acts.find(a => (a.act.authorization || []).some(x => x.actor === addr));
    b.from = signer ? addr : (acts[0].act.authorization?.[0]?.actor || acts[0].act.data?.from || '');
    b.method = xprHint(acts); b.typesText = [...new Set(acts.map(a => a.act.account + ':' + a.act.name))].join(', ');
    const memos = [];
    for (const a of acts) {
      const d = a.act.data || {};
      if (a.act.name === 'transfer' && d.quantity && (d.from === addr || d.to === addr) && d.from !== d.to && parseFloat(d.quantity) > 0) {
        const [amt, sym] = String(d.quantity).split(' '), dir = d.from === addr ? 'out' : 'in', cp = dir === 'out' ? d.to : d.from;
        if (dir === 'in' && !signer && !b.to) b.to = cp;
        b.legs.push({dir, amount: +amt, sym, name: '', token: a.act.account + ':' + sym, kind: a.act.account === 'eosio.token' && sym === 'XPR' ? 'native' : 'Token',
          cp, cpName: XPR_NAMES[cp], priced: XPR_TRUSTED.has(a.act.account) ? true : undefined, spam: false});
        if (d.memo) memos.push(String(d.memo).slice(0, 50));
        if (dir === 'out' && !b.to) b.to = cp;
        if (dir === 'in' && !signer && d.memo && (SPAM_RX.test(d.memo) || /https?:|\.com|\.io|airdrop|claim/i.test(d.memo)) && !XPR_TRUSTED.has(a.act.account)) b.possibleSpam = `unsolicited ${sym} with an advert memo ("${String(d.memo).slice(0, 40)}")`;
        if (dir === 'in' && !XPR_TRUSTED.has(a.act.account) && sym !== 'XPR' && Object.values(XPR_NAMES).length && ['XPR', 'XUSDC', 'XBTC', 'XETH', 'XMT', 'LOAN', 'XMD'].includes(sym)) { b.flags.push(`fake ${sym} token from contract ${a.act.account} (the real ${sym} is issued by a different contract)`); }
      } else if (a.act.account === 'atomicassets' && a.act.name === 'transfer' && (d.from === addr || d.to === addr)) {
        (d.asset_ids || []).forEach(id => b.legs.push({dir: d.from === addr ? 'out' : 'in', amount: 1, sym: 'XPR NFT', name: '', token: 'atomic:' + id, kind: 'NFT', id, cp: d.from === addr ? d.to : d.from}));
      } else if (!b.to && a.act.account !== 'eosio.token') b.to = a.act.account;
    }
    if (!b.to) b.to = acts[0].act.account;
    b.toName = XPR_NAMES[b.to] || XPR_NAMES[acts[0].act.account] || '';
    if (memos.length) b.desc = 'memo: ' + memos[0];
    if (!b.legs.length && signer) {
      const nv = {stake: 'Staking (Stake / vote)', unstake: 'Staking (Unstake)', claimRewards: 'Staking Rewards (claim)'}[b.method];
      b.noValue = {cat: nv || (/cancel/.test(b.typesText) ? 'DEX Order Cancelled' : /placeorder|buy|sell/.test(b.typesText) ? 'DEX Order Placed' : 'Contract Interaction'),
        comment: `${b.typesText} with no token movement for this account. No network fee on XPR.`};
    }
  }
  // Order-book DEX fills (Metal X, Alcor) become Trade rows; the order deposits/refunds to those
  // contracts are then internal movements, kept out of the Excel file by default.
  const internal = new Set();
  const fills = [];
  try { fills.push(...await xprMetalXTrades(addr, opt)); internal.add('dex'); } catch (e) { log(`   ⚠ Metal X trade history unavailable (${e.message.slice(0, 60)}) — its orders show as deposits/withdrawals`, 'w'); }
  try { fills.push(...await xprAlcorTrades(addr, opt)); internal.add('alcor'); } catch (e) { log(`   ⚠ Alcor trade history unavailable (${e.message.slice(0, 60)}) — its orders show as deposits/withdrawals`, 'w'); }
  for (const f of fills) {
    if (opt.from && f.ts < opt.from) continue;
    const b = bucket(map, f.key); b.hash = f.trx; b.ts = f.ts; b.ok = true; b.fee = 0; b.from = addr; b.url = 'https://explorer.xprnetwork.org/transaction/' + f.trx;
    b.preRows = [{type: 'Trade', cat: `DeFi - Swap (${f.dex} order fill)`, buy: {amount: f.buyAmt, sym: f.buySym, kind: 'Token'}, sell: {amount: f.sellAmt, sym: f.sellSym, kind: 'Token'}, lp: '',
      comment: `${f.dex} order filled: bought ${fmtNum(f.buyAmt)} ${f.buySym} for ${fmtNum(f.sellAmt)} ${f.sellSym} (price ${f.price}, market ${f.market}${f.order ? ', order ' + f.order : ''}).${f.fee ? ` Exchange fee ${fmtNum(f.fee)} ${f.feeSym} is in the Fee column.` : ''}`,
      fee: f.fee ? {amount: f.fee, sym: f.feeSym} : null}];
  }
  for (const b of map.values()) {
    if (!b.legs.length || !internal.size) continue;
    const inner = b.legs.filter(l => internal.has(l.cp)); if (!inner.length) continue;
    b.legs = b.legs.filter(l => !internal.has(l.cp)); b.noValue = null;
    b.preRows = (b.preRows || []).concat(inner.map(l => ({type: l.dir === 'out' ? 'Withdrawal' : 'Deposit', cat: 'Internal - DEX order funds', buy: l.dir === 'in' ? l : null, sell: l.dir === 'out' ? l : null, lp: '', internal: true,
      comment: `${l.dir === 'out' ? 'Sent' : 'Got back'} ${legStr(l)} ${l.dir === 'out' ? 'to' : 'from'} ${XPR_NAMES[l.cp] || l.cp} order book (${b.typesText}). The trade itself is recorded from the exchange's fill history, so this row is left out of the Excel file unless you tick "Include internal DEX order movements".`})));
  }
  return trimToCutoff([...map.values()], cutoff);
}
async function xprMetalXTrades(addr, opt) {
  const B = 'https://dex.api.mainnet.metalx.com/dex/v1';
  const mk = Object.fromEntries(((await getJSON(`${B}/markets/all`)).data || []).map(m => [m.market_id, m]));
  const out = [];
  for (let p = 0; p < opt.maxPages * 5; p++) {
    const j = await getJSON(`${B}/trades/history?account=${addr}&limit=100&offset=${p * 100}`); const list = j.data || [];
    for (const t of list) {
      const m = mk[t.market_id] || {}, base = m.bid_token?.code || 'BASE', quote = m.ask_token?.code || 'QUOTE', buyer = t.bid_user === addr;
      // bid side receives the base token (fee taken in base); ask side receives the quote token (fee taken in quote)
      out.push({key: 'mx:' + t.trade_id, trx: t.trx_id, ts: new Date(t.block_time), dex: 'Metal X DEX', market: m.symbol || t.market_id, price: t.price, order: buyer ? t.bid_user_order_id : t.ask_user_order_id,
        buySym: buyer ? base : quote, buyAmt: buyer ? t.bid_total : t.ask_total, sellSym: buyer ? quote : base, sellAmt: buyer ? t.ask_total : t.bid_total,
        fee: buyer ? t.bid_fee : t.ask_fee, feeSym: buyer ? base : quote});
    }
    if (list.length < 100 || (p + 1) * 100 >= (j.count || 0)) break;
    if (opt.from && list.length && new Date(list[list.length - 1].block_time) < opt.from) break;
    await sleep(200);
  }
  return out;
}
let ALCOR_MARKETS = null;
async function xprAlcorTrades(addr, opt) {
  const B = 'https://proton.alcor.exchange/api';
  if (!ALCOR_MARKETS) ALCOR_MARKETS = getJSON(`${B}/markets`).then(l => Object.fromEntries((l || []).map(m => [m.id, m])));
  const mk = await ALCOR_MARKETS, out = [];
  for (let p = 0; p < opt.maxPages * 5; p++) {
    const list = await getJSON(`${B}/v2/account/${addr}/deals?limit=100&skip=${p * 100}`);
    for (const t of list || []) {
      const m = mk[t.market] || {}, base = m.base_token?.symbol?.name || 'BASE', quote = m.quote_token?.symbol?.name || 'QUOTE', asker = t.asker === addr;
      // the asker sells the quote token ("ask" amount) for the base token ("bid" amount); the bidder does the opposite
      out.push({key: 'alcor:' + t._id, trx: t.trx_id, ts: new Date(t.time), dex: 'Alcor DEX', market: `${quote}/${base}`, price: t.unit_price, order: '',
        buySym: asker ? base : quote, buyAmt: asker ? t.bid : t.ask, sellSym: asker ? quote : base, sellAmt: asker ? t.ask : t.bid, fee: 0, feeSym: ''});
    }
    if (!list || list.length < 100) break;
    if (opt.from && new Date(list[list.length - 1].time) < opt.from) break;
    await sleep(200);
  }
  return out;
}

/* ---------- Moralis (EVM wallet history, already labelled; needs a Moralis API key) ---------- */
const MORALIS = 'https://deep-index.moralis.io/api/v2.2';
const moralisGet = (path, key) => getJSON(MORALIS + path, {headers: {'X-API-Key': key, accept: 'application/json'}});
const MORALIS_ACTIVE = {};
// One call lists every chain the wallet has used (cheap compared with one history call per chain).
function moralisActivity(addr, key, chains) {
  const k = addr + '|' + chains.join(',');
  if (!MORALIS_ACTIVE[k]) MORALIS_ACTIVE[k] = moralisGet(`/wallets/${addr}/chains?${chains.map(c => 'chains=' + encodeURIComponent(c)).join('&')}`, key)
    .then(j => Object.fromEntries((j.active_chains || []).map(c => [c.chain, c])));
  return MORALIS_ACTIVE[k];
}
const MORALIS_HINT = {'token swap': 'swap', 'deposit': 'deposit', 'withdraw': 'withdraw', 'borrow': 'borrow', 'approve': 'approve', 'revoke': 'approve (revoke)',
  'airdrop': 'claim airdrop', 'mint': 'mint', 'burn': 'burn', 'nft purchase': 'buy nft', 'nft sale': 'sell nft', 'send': 'transfer', 'receive': 'transfer',
  'token send': 'transfer', 'token receive': 'transfer', 'nft send': 'transfer', 'nft receive': 'transfer'};
async function fetchMoralis(chain, addr, opt) {
  const a = lc(addr), map = new Map(); let cursor = '', cutoff = null;
  const range = (opt.from ? '&from_date=' + encodeURIComponent(opt.from.toISOString()) : '') + (opt.to ? '&to_date=' + encodeURIComponent(opt.to.toISOString()) : '');
  const all = [];
  for (let p = 0; p < opt.maxPages; p++) {
    const j = await moralisGet(`/wallets/${addr}/history?chain=${encodeURIComponent(chain.moralis)}&order=DESC&limit=100${range}${cursor ? '&cursor=' + encodeURIComponent(cursor) : ''}`, opt.moralisKey);
    const list = j.result || []; all.push(...list); cursor = j.cursor;
    if (!cursor || !list.length) break;
    if (p === opt.maxPages - 1) cutoff = new Date(list[list.length - 1].block_timestamp);
    await sleep(120);
  }
  const yes = v => v === true || v === 'true';
  const name = (x, side) => x[side + '_address_entity'] || x[side + '_address_label'] || '';
  for (const t of all) {
    const b = bucket(map, t.hash);
    b.ts = new Date(t.block_timestamp); b.ok = String(t.receipt_status) !== '0'; b.initKnown = true;
    b.from = lc(t.from_address); b.to = lc(t.to_address); b.toName = name(t, b.from === a ? 'to' : 'from');
    const cat = String(t.category || '').toLowerCase();
    b.method = [MORALIS_HINT[cat] || cat, t.method_label].filter(Boolean).join(' / ');
    b.fee = b.from === a ? +t.transaction_fee || 0 : 0;
    if (t.summary || cat) b.desc = `Moralis: ${cat || '?'}${t.summary ? ' – ' + t.summary : ''}`;
    if (yes(t.possible_spam)) b.flags.push('Moralis marks this transaction as possible spam');
    if (!b.ok) continue;
    for (const n of t.native_transfers || []) {
      const f = lc(n.from_address), to = lc(n.to_address); if (f === to) continue;
      const dir = f === a ? 'out' : to === a ? 'in' : null; if (!dir) continue;
      b.legs.push({...natLeg(chain, dir, +n.value_formatted || units(n.value, 18), dir === 'out' ? to : f), cpName: name(n, dir === 'out' ? 'to' : 'from')});
    }
    for (const x of t.erc20_transfers || []) {
      const f = lc(x.from_address), to = lc(x.to_address); if (f === to) continue;
      const dir = f === a ? 'out' : to === a ? 'in' : null; if (!dir) continue;
      b.legs.push({dir, amount: x.value_formatted != null ? +x.value_formatted : units(x.value, x.token_decimals), sym: x.token_symbol || x.token_name || short(x.address), name: x.token_name || '',
        token: lc(x.address), kind: 'ERC-20', cp: dir === 'out' ? to : f, cpName: name(x, dir === 'out' ? 'to' : 'from'),
        spam: yes(x.possible_spam), priced: yes(x.verified_contract) ? true : undefined, fromZero: f === ZERO, toZero: to === ZERO || to === DEAD});
    }
    for (const x of t.nft_transfers || []) {
      const f = lc(x.from_address), to = lc(x.to_address); if (f === to) continue;
      const dir = f === a ? 'out' : to === a ? 'in' : null; if (!dir) continue;
      const kind = /1155/.test(x.contract_type || '') ? 'ERC-1155' : 'ERC-721';
      b.legs.push({dir, amount: kind === 'ERC-1155' ? +x.amount || 1 : 1, sym: x.token_symbol || x.token_name || x.normalized_metadata?.name || short(x.token_address), name: x.token_name || '',
        token: lc(x.token_address), kind, id: x.token_id, cp: dir === 'out' ? to : f, cpName: name(x, dir === 'out' ? 'to' : 'from'),
        spam: yes(x.possible_spam), fromZero: f === ZERO, toZero: to === ZERO || to === DEAD});
    }
    if (!b.legs.length && b.from === a && /approve/.test(b.method)) b.noValue = {cat: 'Approval', comment: `Token approval/revoke${b.toName ? ' on ' + b.toName : ''}. Gas fee only.`};
  }
  return trimToCutoff([...map.values()], cutoff);
}

/* ---------- Bittensor / TAO (Taostats API; needs a Taostats API key) ---------- */
const TAOSTATS = 'https://api.taostats.io/v1';
// Known Bittensor exchange addresses (labels as shown on bittensor.ai; Taostats has no label for them).
const TAO_LABELS = {'5DvmxKhxVKmuRFyH1cifSm5CyfoNFU9xzFtDgRuPphpWV5z7': 'MEXC (exchange)'};
// Taostats' free tier rate-limits without telling us the limit, so space requests out and wait longer on "slow down".
let TAO_LAST = 0;
async function taoGet(path, key) {
  for (let tries = 0; ; tries++) {
    if (STOP) throw new Error('Stopped');
    const wait = TAO_LAST + 1300 - Date.now(); if (wait > 0) await sleep(wait);
    TAO_LAST = Date.now();
    const r = await fetch(TAOSTATS + path, {headers: {Authorization: key, accept: 'application/json'}});
    if (r.status === 429 || r.status >= 500) {
      if (tries >= 5) throw new Error(`Taostats is rate-limiting (HTTP ${r.status}); wait a minute and fetch again`);
      const secs = [10, 20, 30, 45, 60][tries]; log(`   … Taostats asked us to slow down; waiting ${secs}s`, 'w'); await sleep(secs * 1000); continue;
    }
    if (r.status === 404) throw new Error('HTTP 404');
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(`Taostats HTTP ${r.status}: ${(j.message || j.error || '').slice(0, 120)}`);
    return j;
  }
}
const rao = v => units(String(v || '0'), 9);
async function taoPages(path, key, opt) {
  const out = []; let cutoff = null;
  const range = (opt.from ? '&timestamp_start=' + Math.floor(+opt.from / 1000) : '') + (opt.to ? '&timestamp_end=' + Math.floor(+opt.to / 1000) : '');
  for (let p = 1; p <= opt.maxPages; p++) {
    const j = await taoGet(`${path}${path.includes('?') ? '&' : '?'}limit=200&page=${p}&order_by=timestamp&order_dir=desc${range}`, key);
    const list = j.data || []; out.push(...list);
    if (!j.pagination?.next_page || !list.length) break;
    if (p === opt.maxPages) cutoff = new Date(list[list.length - 1].timestamp);
  }
  return {list: out, cutoff};
}
async function fetchTao(chain, addr, opt) {
  const key = opt.taostatsKey; if (!key) throw new Error('paste a Taostats API key (taostats.io) to use Bittensor');
  const map = new Map(); let cutoff = null;
  const take = c => { if (c && (!cutoff || c > cutoff)) cutoff = c; };
  const link = id => id ? `https://taostats.io/extrinsic/${id}` : '';
  // 1) TAO transfers
  const tr = await taoPages(`/transfers?network=finney&address=${addr}`, key, opt); take(tr.cutoff);
  for (const t of tr.list) {
    const b = bucket(map, t.extrinsic_id || t.transaction_hash || t.id); b.ts = new Date(t.timestamp); b.ok = true; b.initKnown = true; b.method = 'transfer'; b.url = link(t.extrinsic_id);
    if (t.from === t.to) continue;
    if (t.from === addr) { b.from = addr; b.to = t.to; if (!b.feeSet) { b.fee = rao(t.fee); b.feeSet = true; } b.legs.push({...natLeg(chain, 'out', rao(t.amount), t.to), cpName: TAO_LABELS[t.to]}); }
    else if (t.to === addr) { if (!b.from) b.from = t.from; b.legs.push({...natLeg(chain, 'in', rao(t.amount), t.from), cpName: TAO_LABELS[t.from]}); }
  }
  // 2) Staking events, old (pre-dTAO, before Feb 2025) and new (dTAO), processed oldest-first so we can track
  //    how much is staked and split every unstake into "your stake coming back" + "rewards".
  const se = await taoPages(`/subnets/stake-events?coldkey=${addr}`, key, opt); take(se.cutoff);
  let hist = [];
  try { const hs = await taoPages(`/historic/stake-events?coldkey=${addr}`, key, opt); take(hs.cutoff); hist = hs.list; }
  catch (e) { if (e.message === 'Stopped') throw e; log(`   ⚠ Bittensor pre-dTAO stake history unavailable (${e.message.slice(0, 60)})`, 'w'); }
  const events = [...hist.map(e => ({...e, old: true, netuid: 0})), ...se.list].sort((x, y) => new Date(x.timestamp) - new Date(y.timestamp));
  const partial = !!(cutoff || opt.from);
  const est = partial ? ' Estimate: earlier history was not loaded (page limit or From date), so part of this may be your own earlier stake coming back.' : '';
  let taoStaked = 0; const alphaHeld = {};
  const EPS = 1e-9;
  for (const e of events) {
    const b = bucket(map, (e.old ? 'hist:' : 'stake:') + e.id); b.hash = e.extrinsic_id || e.id; b.ts = new Date(e.timestamp); b.ok = true; b.initKnown = true; b.from = addr; b.url = link(e.extrinsic_id);
    const stake = e.action === 'stake', tao = rao(e.amount), net = e.netuid || 0, who = e.hotkey_name || short(e.hotkey);
    const fee = e.fee ? rao(e.fee) : 0, feeObj = fee ? {amount: fee, sym: 'TAO'} : null;
    const alpha = rao(e.alpha), aSym = `SN${net}-α`;
    const tLeg = (dir, amt) => natLeg(chain, dir, amt, e.hotkey);
    const aLeg = (dir, amt) => ({dir, amount: amt, sym: aSym, name: `Subnet ${net} alpha`, token: 'alpha:' + net, kind: 'Alpha', cp: e.hotkey, cpName: who});
    const era = e.old ? ' (pre-dTAO)' : net ? '' : ' (root network)';
    b.preRows = [];
    if (e.validator_swap) {
      b.preRows.push({type: 'Other Fee', cat: 'Staking (Move between validators)', buy: null, sell: feeObj ? {amount: fee, sym: 'TAO', kind: 'native'} : null, lp: '', feeIsSell: true,
        comment: `Moved stake between validators on subnet ${net} (${fmtNum(net ? alpha : tao)} ${net ? aSym : 'TAO'}, validator ${who}). Fee only.`});
      continue;
    }
    if (e.is_transfer) {
      const amt = net ? alpha : tao, dir = stake ? 'in' : 'out';
      if (net) alphaHeld[net] = Math.max(0, (alphaHeld[net] || 0) + (stake ? amt : -amt)); else taoStaked = Math.max(0, taoStaked + (stake ? amt : -amt));
      const leg = net ? aLeg(dir, amt) : tLeg(dir, amt);
      b.preRows.push({type: stake ? 'Deposit' : 'Withdrawal', cat: 'Staking (Stake transfer)', buy: stake ? leg : null, sell: stake ? null : leg, lp: '',
        comment: `${stake ? 'Received stake transferred from' : 'Transferred stake to'} ${short(e.transfer_address || '')} on subnet ${net}: ${fmtNum(amt)} ${net ? aSym : 'TAO'} (validator ${who}).`});
      continue;
    }
    if (!net) {
      // Root / pre-dTAO staking: TAO leaves the wallet into stake, and comes back on unstake (with rewards on top)
      if (stake) {
        taoStaked += tao;
        b.preRows.push({type: 'Withdrawal', cat: 'Staking (Stake)', buy: null, sell: tLeg('out', tao), lp: '', fee: feeObj,
          comment: `Staked ${fmtNum(tao)} TAO${era} with validator ${who}. Moves from the wallet into stake (still yours); it comes back as a Deposit when unstaked.`});
      } else {
        const back = Math.min(tao, taoStaked), reward = tao - back; taoStaked -= back;
        if (back > EPS) b.preRows.push({type: 'Deposit', cat: 'Staking (Unstake - stake returned)', buy: tLeg('in', back), sell: null, lp: '', fee: feeObj,
          comment: `Unstaked${era} from validator ${who}: ${fmtNum(back)} TAO of your earlier stake returned to the wallet (total unstaked ${fmtNum(tao)} TAO).`});
        if (reward > EPS) b.preRows.push({type: 'Staking', cat: 'Staking Rewards (from unstake)', buy: tLeg('in', reward), sell: null, lp: '', fee: back > EPS ? null : feeObj,
          comment: `Staking rewards: ${fmtNum(reward)} TAO of this ${fmtNum(tao)} TAO unstake${era} is more than you had staked, so it is counted as rewards earned (validator ${who}).${est}`});
      }
      continue;
    }
    // Subnet staking (dTAO): TAO is swapped for the subnet's alpha; extra alpha on unstake is rewards
    if (stake) {
      alphaHeld[net] = (alphaHeld[net] || 0) + alpha;
    } else {
      const held = alphaHeld[net] || 0, rewardA = Math.max(0, alpha - held); alphaHeld[net] = Math.max(0, held - alpha);
      if (rewardA > EPS) b.preRows.push({type: 'Staking', cat: 'Staking Rewards (subnet alpha)', buy: aLeg('in', rewardA), sell: null, lp: '',
        comment: `Staking rewards: ${fmtNum(rewardA)} ${aSym} of the ${fmtNum(alpha)} ${aSym} unstaked is more than the alpha you had bought, so it is counted as rewards earned (validator ${who}).${est}`});
    }
    b.preRows.push({type: 'Trade', cat: stake ? 'DeFi - Staking (dTAO subnet stake)' : 'DeFi - Staking (dTAO subnet unstake)',
      buy: stake ? aLeg('in', alpha) : tLeg('in', tao), sell: stake ? tLeg('out', tao) : aLeg('out', alpha), lp: '', fee: feeObj,
      comment: `${stake ? 'Staked' : 'Unstaked'} on subnet ${net} with validator ${who}: ${stake ? `${fmtNum(tao)} TAO → ${fmtNum(alpha)} ${aSym}` : `${fmtNum(alpha)} ${aSym} → ${fmtNum(tao)} TAO`}${e.alpha_price_in_tao ? ` (price ${(+e.alpha_price_in_tao).toPrecision(4)} TAO per alpha)` : ''}${e.slippage ? `, slippage ${e.slippage}` : ''}. In dTAO, subnet staking swaps TAO for the subnet's alpha token.`});
  }
  if (taoStaked > EPS || Object.values(alphaHeld).some(v => v > EPS)) log(`   ℹ Still staked at the end of the period: ${fmtNum(taoStaked)} TAO${Object.entries(alphaHeld).filter(([, v]) => v > EPS).map(([n, v]) => `, ${fmtNum(v)} SN${n}-α`).join('')} (not counted as rewards until unstaked)`);
  return trimToCutoff([...map.values()].filter(b => b.ts), cutoff);
}

/* ---------- XRP names (XRPScan well-known accounts) ---------- */
let XRP_NAMES = null;
async function xrpNames() {
  if (!XRP_NAMES) XRP_NAMES = getJSON('https://api.xrpscan.com/api/v1/names/well-known').then(l => Object.fromEntries((l || []).map(n => [n.account, n.name + (n.desc && n.desc.length < 20 ? ' ' + n.desc : '')]))).catch(() => ({}));
  return XRP_NAMES;
}

/* ---------- Non-EVM chain registry ---------- */
const NONEVM_CHAINS = [
  {id: 'sol', name: 'Solana', code: 'SOL', native: 'SOL', family: 'sol', group: 'Solana', def: true, label: 'Helius · free key',
    txUrl: h => 'https://solscan.io/tx/' + h,
    scan: async (a, o) => { if (!o.heliusKey) return {status: 'needs key', note: 'Helius key'}; const r = await heliusRpc(o.heliusKey, 'getSignaturesForAddress', [a, {limit: 1000}]); const n = r.result?.length || 0; return {active: n > 0, count: n >= 1000 ? '1000+' : n}; },
    fetch: (a, o) => fetchSolana(NONEVM_BY_ID.sol, a, o)},
  {id: 'btc', name: 'Bitcoin', code: 'BTC', native: 'BTC', family: 'btc', group: 'Bitcoin & co.', def: true, label: 'mempool.space · free (xpub/ypub/zpub too)',
    txUrl: h => 'https://mempool.space/tx/' + h,
    // xpub: the addresses are worked out in the browser; Trezor Blockbook (via the helper) is only a faster extra when the helper runs.
    scan: async (a) => {
      if (/^[xyz]pub/.test(a)) {
        if (HELPER) { try { const f = await xpubForms(a); const n = f.reduce((s2, x) => s2 + x.txs, 0); return {active: n > 0, count: n, note: f.length ? f.map(x => XPUB_TYPE(x.form)).join(', ') : ''}; } catch (e) {} }
        const all = await xpubAddresses(a, typeof log === 'function' ? log : null); const used = all.filter(x => x.n); return {active: used.length > 0, count: used.length ? `${used.length} addresses` : 0, note: 'worked out in the browser (no helper)'};
      }
      return scanEsplora('https://mempool.space/api', a); },
    via: a => /^[xyz]pub/.test(a) ? (HELPER ? 'Trezor Blockbook' : 'mempool.space (xpub addresses worked out in the browser)') : 'mempool.space',
    fetch: async (a, o) => {
      if (!/^[xyz]pub/.test(a)) return fetchEsplora(NONEVM_BY_ID.btc, 'https://mempool.space/api', a, o);
      if (HELPER) { try { return await fetchXpub(NONEVM_BY_ID.btc, a, o); } catch (e) { log(`   Trezor Blockbook unavailable (${e.message.slice(0, 60)}) — working out the addresses in the browser instead.`, 'w'); } }
      return fetchXpubLocal(NONEVM_BY_ID.btc, a, o); }},
  {id: 'ltc', name: 'Litecoin', code: 'LTC', native: 'LTC', family: 'ltc', group: 'Bitcoin & co.', def: true, label: 'litecoinspace.org · free',
    txUrl: h => 'https://litecoinspace.org/tx/' + h,
    scan: a => scanEsplora('https://litecoinspace.org/api', a), fetch: (a, o) => fetchEsplora(NONEVM_BY_ID.ltc, 'https://litecoinspace.org/api', a, o)},
  {id: 'doge', name: 'Dogecoin', code: 'DOGE', native: 'DOGE', family: 'doge', group: 'Bitcoin & co.', def: true, label: 'BlockCypher · free (100 calls/hour)',
    txUrl: h => 'https://blockchair.com/dogecoin/transaction/' + h,
    scan: async a => { const j = await getJSON(`https://api.blockcypher.com/v1/doge/main/addrs/${a}/balance`); return {active: (j.final_n_tx || 0) > 0, count: j.final_n_tx || 0}; },
    fetch: (a, o) => fetchDoge(NONEVM_BY_ID.doge, a, o)},
  {id: 'trx', name: 'Tron', code: 'TRX', native: 'TRX', family: 'trx', group: 'Tron', def: true, label: 'TronGrid · free',
    txUrl: h => 'https://tronscan.org/#/transaction/' + h,
    scan: async a => { const j = await getJSON(`https://api.trongrid.io/v1/accounts/${a}`); const d = j.data?.[0]; return {active: !!d, count: d ? '✓' : 0, note: d?.create_time ? 'since ' + new Date(d.create_time).toISOString().slice(0, 10) : ''}; },
    fetch: (a, o) => fetchTron(NONEVM_BY_ID.trx, a, o)},
  ...COSMOS.map(c => ({...c, native: c.sym || c.code, family: 'cosmos', group: 'Cosmos', def: true, label: c.evm ? 'cosmos.directory · free (also checks your 0x addresses; native coin only)' : 'cosmos.directory · free',
    txUrl: h => `https://www.mintscan.io/${c.ms}/tx/${h}`,
    scan: async a => { try { await getJSON(`https://rest.cosmos.directory/${c.dir}/cosmos/auth/v1beta1/accounts/${a}`); return {active: true, count: '✓'}; } catch (e) { if (notFound(e)) return {active: false, count: 0}; throw e; } },
    fetch: (a, o) => fetchCosmos(NONEVM_BY_ID[c.id], a, o)})),
  {id: 'ton', name: 'TON', code: 'TON', native: 'TON', family: 'ton', group: 'Other chains', def: true, label: 'tonapi.io · free (slow: 1 call/sec)',
    txUrl: h => 'https://tonviewer.com/transaction/' + h,
    scan: async a => { const j = await getJSON(`https://tonapi.io/v2/accounts/${encodeURIComponent(a)}`); return {active: j.status !== 'nonexist', count: j.status === 'nonexist' ? 0 : '✓', note: j.status}; },
    fetch: (a, o) => fetchTon(NONEVM_BY_ID.ton, a, o)},
  {id: 'xrp', name: 'XRP Ledger', code: 'XRP', native: 'XRP', family: 'xrp', group: 'Other chains', def: true, label: 'XRPL + XRPScan names · free',
    txUrl: h => 'https://xrpscan.com/tx/' + h,
    scan: async a => { const r = await xrpRpc('account_info', {account: a, ledger_index: 'validated'}); return {active: !r.error, count: r.error ? 0 : '✓', note: r.error === 'actNotFound' ? 'not activated' : ''}; },
    fetch: (a, o) => fetchXrp(NONEVM_BY_ID.xrp, a, o)},
  {id: 'ada', name: 'Cardano', code: 'ADA', native: 'ADA', family: 'ada', group: 'Other chains', def: true, label: 'Koios · free (needs helper)',
    txUrl: h => 'https://cardanoscan.io/transaction/' + h,
    scan: async a => { const s = await adaStake(a); return {active: s.exists, count: s.exists ? '✓' : 0, note: s.stake ? 'whole wallet via ' + short(s.stake) : ''}; },
    fetch: (a, o) => fetchCardano(NONEVM_BY_ID.ada, a, o)},
  {id: 'xlm', name: 'Stellar', code: 'XLM', native: 'XLM', family: 'xlm', group: 'Other chains', def: true, label: 'Horizon + StellarExpert · free',
    txUrl: h => 'https://stellar.expert/explorer/public/tx/' + h,
    scan: async a => { try { const j = await getJSON(`${HORIZON}/accounts/${a}`); return {active: true, count: '✓', note: (j.balances || []).length + ' balances'}; } catch (e) { if (notFound(e)) return {active: false, count: 0}; throw e; } },
    fetch: (a, o) => fetchStellar(NONEVM_BY_ID.xlm, a, o)},
  {id: 'hbar', name: 'Hedera', code: 'HBAR', native: 'HBAR', family: 'hbar', group: 'Other chains', def: true, label: 'Hedera Mirror Node · free',
    txUrl: h => 'https://hashscan.io/mainnet/transaction/' + h,
    scan: async a => {
      try {
        // Accepts 0.0.123 or the account's 0x… EVM address; the result carries the 0.0.x account ID to fetch with.
        const acc = await getJSON(`${HEDERA}/api/v1/accounts/${a}?transactions=false`); const id = acc.account || a;
        // Oldest-first from the creation date finds the first transaction without walking empty windows.
        const created = Math.floor(+acc.created_timestamp || 0);
        const j = await getJSON(`${HEDERA}/api/v1/transactions?account.id=${id}&limit=1&order=asc${created ? '&timestamp=gte:' + created : ''}`);
        const found = (j.transactions || []).length > 0 || (+acc.balance?.balance || 0) > 0;
        return {active: found, count: found ? '✓' : 0, resolved: id, note: id !== a ? 'account ' + id : ''};
      } catch (e) { if (notFound(e)) return {active: false, count: 0}; throw e; }
    },
    fetch: (a, o) => fetchHedera(NONEVM_BY_ID.hbar, a, o)},
  {id: 'algo', name: 'Algorand', code: 'ALGO', native: 'ALGO', family: 'algo', group: 'Other chains', def: true, label: 'Nodely indexer · free',
    txUrl: h => 'https://allo.info/tx/' + h,
    scan: async a => { const j = await getJSON(`${ALGO_IDX}/accounts/${a}/transactions?limit=1`); return {active: (j.transactions || []).length > 0, count: (j.transactions || []).length ? '✓' : 0}; },
    fetch: (a, o) => fetchAlgorand(NONEVM_BY_ID.algo, a, o)},
  {id: 'fil', name: 'Filecoin', code: 'FIL', native: 'FIL', family: 'fil', group: 'Other chains', def: true, label: 'Filfox · free',
    txUrl: h => 'https://filfox.info/en/message/' + h,
    scan: async a => { try { const j = await getJSON(`https://filfox.info/api/v1/address/${a}/transfers?pageSize=1&page=0`); return {active: (j.totalCount || 0) > 0, count: j.totalCount || 0}; } catch (e) { if (notFound(e)) return {active: false, count: 0}; throw e; } },
    fetch: (a, o) => fetchFilecoin(NONEVM_BY_ID.fil, a, o)},
  {id: 'iota', name: 'IOTA', code: 'IOTA', native: 'IOTA', family: 'iota', group: 'Other chains', def: true, label: 'IOTA public RPC · free',
    txUrl: h => `https://explorer.iota.org/txblock/${h}?network=mainnet`,
    scan: async a => { const r = await iotaRpc('iotax_queryTransactionBlocks', [{filter: {FromAddress: a}}, null, 1, true]); const r2 = r.data?.length ? r : await iotaRpc('iotax_queryTransactionBlocks', [{filter: {ToAddress: a}}, null, 1, true]); return {active: (r2.data || []).length > 0, count: (r2.data || []).length ? '✓' : 0}; },
    fetch: (a, o) => fetchIota(NONEVM_BY_ID.iota, a, o)},
  {id: 'cspr', name: 'Casper', code: 'CSPR', native: 'CSPR', family: 'cspr', group: 'Other chains', def: true, label: 'CSPR.cloud · free token (needs helper)',
    txUrl: h => 'https://cspr.live/deploy/' + h,
    scan: async (a, o) => { if (!o.csprKey) return {status: 'needs key', note: 'CSPR.cloud token'}; try { const j = await csprGet(`/accounts/${a}/transfers?page=1&page_size=1`, o.csprKey); const d = await csprGet(`/accounts/${a}/deploys?page=1&page_size=1`, o.csprKey); const n = (j.item_count || 0) + (d.item_count || 0); return {active: n > 0 || (j.data || []).length > 0 || (d.data || []).length > 0, count: n || '✓'}; } catch (e) { if (notFound(e)) return {active: false, count: 0}; throw e; } },
    fetch: (a, o) => fetchCasper(NONEVM_BY_ID.cspr, a, o)},
  {id: 'xpr', name: 'XPR Network', code: 'XPR', native: 'XPR', family: 'xpr', group: 'Other chains', def: true, label: 'XPR Hyperion (explorer.xprnetwork.org) · free',
    txUrl: h => 'https://explorer.xprnetwork.org/transaction/' + h,
    scan: async a => {
      try {
        await getJSON(`${XPR_HYP}/v2/state/get_account?account=${a}`);
        const j = await getJSON(`${XPR_HYP}/v2/history/get_actions?account=${a}&limit=1`);
        const n = j.total?.value || 0; return {active: n > 0, count: n >= 10000 ? '10000+' : n};
      } catch (e) { if (/HTTP 4|HTTP 5/.test(e.message)) return {active: false, count: 0, note: 'no such account'}; throw e; }
    },
    fetch: (a, o) => fetchXpr(NONEVM_BY_ID.xpr, a, o)},
  {id: 'dot', name: 'Polkadot', code: 'DOT', native: 'DOT', family: 'substrate', ss58: 0, group: 'Polkadot & Substrate', def: true, label: 'Statescan · free, no key (relay chain + Asset Hub)',
    txUrl: h => 'https://assethub-polkadot.statescan.io/#/extrinsics/' + h,
    scan: async a => scanStatescan(STATESCAN.dot, a), fetch: (a, o) => fetchStatescan(NONEVM_BY_ID.dot, a, o)},
  {id: 'ksm', name: 'Kusama', code: 'KSM', native: 'KSM', family: 'substrate', ss58: 2, group: 'Polkadot & Substrate', def: true, label: 'Statescan · free, no key (relay chain + Asset Hub)',
    txUrl: h => 'https://assethub-kusama.statescan.io/#/extrinsics/' + h,
    scan: async a => scanStatescan(STATESCAN.ksm, a), fetch: (a, o) => fetchStatescan(NONEVM_BY_ID.ksm, a, o)},
  {id: 'tao', name: 'Bittensor', code: 'TAO', native: 'TAO', family: 'substrate', ss58: 42, group: 'Polkadot & Substrate', def: true, label: 'Taostats · needs Taostats key',
    txUrl: h => 'https://taostats.io/extrinsic/' + h,
    scan: async (a, o) => {
      if (!o.taostatsKey) return {status: 'needs key', note: 'Taostats key'};
      try { const j = await taoGet(`/accounts/${a}`, o.taostatsKey); const d = Array.isArray(j.data) ? j.data[0] : j.data; return d ? {active: true, count: '✓', note: d.created_on_date ? 'since ' + String(d.created_on_date).slice(0, 10) : ''} : {active: false, count: 0}; }
      catch (e) { if (notFound(e)) return {active: false, count: 0}; throw e; }
    },
    fetch: (a, o) => fetchTao(NONEVM_BY_ID.tao, a, o)},
  {id: 'thor', name: 'THORChain', code: 'RUNE', native: 'RUNE', family: 'thor', group: 'Other chains', def: true, label: 'Midgard (THORChain) · free, no key',
    txUrl: h => 'https://runescan.io/tx/' + h,
    scan: async a => { const j = await getJSON(`${MIDGARD}/actions?address=${a}&limit=1`); const n = +j.count || (j.actions || []).length; return {active: n > 0, count: n}; },
    fetch: (a, o) => fetchThor(NONEVM_BY_ID.thor, a, o)},
];
NONEVM_CHAINS.push(...SUBSCAN_NETS.map(([net, name, code, sym, dec, evm]) => ({id: 'ss_' + net, net, name, code, native: sym, dec, family: 'substrate', evmAccounts: !!evm, group: 'Polkadot & Substrate', def: true,
  label: `Subscan · free key${evm ? ' · 0x accounts' : ''}`, txUrl: h => `https://${net}.subscan.io/extrinsic/${h}`,
  addrFor: (det, o) => subscanAddr(NONEVM_BY_ID['ss_' + net], det, o.subscanKey),
  scan: async (a, o) => { if (!o.subscanKey) return {status: 'needs key', note: 'Subscan key'};
    const d = await subscanPost(net, '/api/v2/scan/search', {key: a}, o.subscanKey); const acc = d?.account; if (!acc) return {active: false, count: 0};
    const n = (+acc.count_extrinsic || 0) + (+acc.transfer_count || 0); return {active: n > 0 || +acc.balance > 0, count: n || '✓'}; },
  fetch: (a, o) => fetchSubscan(NONEVM_BY_ID['ss_' + net], a, o)})));
const NONEVM_BY_ID = Object.fromEntries(NONEVM_CHAINS.map(c => [c.id, c]));

/* ---------- Bridge / NFT / DeFi explorers (add detail to rows by transaction hash) ---------- */
const CHAIN_NAMES = {1: 'Ethereum', 10: 'Optimism', 56: 'BNB Chain', 100: 'Gnosis', 137: 'Polygon', 146: 'Sonic', 250: 'Fantom', 324: 'zkSync', 5000: 'Mantle', 8453: 'Base', 42161: 'Arbitrum',
  43114: 'Avalanche', 59144: 'Linea', 81457: 'Blast', 534352: 'Scroll', 7565164: 'Solana', 100000001: 'Neon', 100000002: 'Gnosis', 100000003: 'Lightlink', 100000004: 'Metis',
  100000005: 'Bitrock', 100000006: 'Sonic', 100000008: 'Abstract', 100000010: 'Flow', 100000013: 'Story', 100000014: 'Sonic', 100000017: 'HyperEVM', 100000020: 'Plasma'};
const WH_CHAINS = {1: 'Solana', 2: 'Ethereum', 4: 'BNB Chain', 5: 'Polygon', 6: 'Avalanche', 10: 'Fantom', 14: 'Celo', 16: 'Moonbeam', 21: 'Sui', 22: 'Aptos', 23: 'Arbitrum', 24: 'Optimism',
  30: 'Base', 32: 'Sei', 34: 'Scroll', 35: 'Mantle', 36: 'Blast', 37: 'X Layer', 38: 'Linea', 39: 'Berachain', 44: 'Unichain', 45: 'World Chain', 46: 'Ink'};
const cname = (m, id) => m[id] || 'chain ' + id;
const big = o => o?.bigIntegerValue ?? o?.stringValue ?? '0';
const ZERION_CAT = {trade: 'DeFi - Swap', deposit: 'DeFi - Deposit', withdraw: 'DeFi - Withdraw', claim: 'DeFi - Rewards Claim', stake: 'DeFi - Staking (Stake)', unstake: 'DeFi - Staking (Unstake)',
  borrow: 'DeFi - Lending', repay: 'DeFi - Lending', approve: 'Approval', mint: 'Mint', burn: 'Burn'};
/* ---------- Address labels (exchanges, instant-swap services) — Blockscout metadata service, via the helper ---------- */
const LABEL_API = 'https://metadata.services.blockscout.com/api/v1/metadata';
const INSTANT_RX = /changenow|simpleswap|fixedfloat|ff\.io|sideshift|stealthex|exolix|letsexchange|changelly|godex|swapzone|trocador|majestic ?bank|shapeshift|changehero|quickex|switchain|nexchange|coinswitch|exch\.cx|fixed ?float/i;
// addrsByChain: Map(chainId -> Set(lowercase 0x addresses)) → Map(lowercase address -> {name, instant, exchange})
async function lookupLabels(addrsByChain) {
  const out = new Map();
  for (const [cid, set] of addrsByChain) {
    const list = [...set];
    for (let i = 0; i < list.length; i += 40) {
      const j = await getJSON(proxied(`${LABEL_API}?addresses=${list.slice(i, i + 40).join(',')}&chainId=${cid}&tags=name,protocol,generic`));
      for (const [a, v] of Object.entries(j.addresses || {})) {
        if (/^0x0{40}$/i.test(a)) continue;
        const tags = v.tags || [], gen = tags.filter(t => t.tagType === 'generic').map(t => t.slug || lc(t.name));
        if (gen.some(g => /^(dex|router|bridge|burn|miner)$/.test(g))) continue;                     // DEX routers, bridges: not exchanges
        const instant = INSTANT_RX.test(tags.map(t => t.name).join(' '));
        if (!instant && !gen.some(g => /^(exchange|hot-wallet|cex)$/.test(g))) continue;            // only real exchanges / swap services
        const proto = tags.find(t => t.tagType === 'protocol')?.name, nm = tags.find(t => t.tagType === 'name')?.name || '';
        const name = (proto || nm.split(':')[0].replace(/\s+\d+$/, '')).trim(); if (!name) continue;
        out.set(a.toLowerCase(), {name, full: nm || name, instant, exchange: true});
      }
      await sleep(200);
    }
  }
  return out;
}
// One cross-chain movement → a note on the sending tx and one on the arrival tx (both carry the same xfer object).
function xferNotes(x) {
  const name = side => side.chainName ? String(side.chainName).replace(/^\w/, c => c.toUpperCase()) : (CHAIN_NAMES[side.chainId] || (side.chainId ? 'chain ' + side.chainId : '?'));
  x.srcName = name(x.src || {}); x.dstName = name(x.dst || {});
  const comment = `${x.via}: ${x.srcName} → ${x.dstName}${x.inp ? `, sent ${fmtNum(x.inp.amount)} ${x.inp.sym}` : ''}${x.out ? `, received ${fmtNum(x.out.amount)} ${x.out.sym}` : ''}${x.status && !/^(done|filled|executed|success|fulfilled|completed?)$/i.test(x.status) ? ` (status: ${x.status})` : ''}.`;
  x.comment = comment;
  const n = [];
  if (x.src?.hash) n.push({hash: x.src.hash, xfer: x, role: 'src', cat: 'Bridge (Outgoing)', comment});
  if (x.dst?.hash) n.push({hash: x.dst.hash, xfer: x, role: 'dst', cat: 'Bridge (Incoming)', comment});
  return n;
}
const EXPLORERS = [
  {id: 'labels', name: 'Exchange & instant-swap labels', families: ['evm'], label: 'ChangeNOW, SimpleSwap, FixedFloat, SideShift, Binance… · free (helper)', def: true, post: true,
    scan: async () => HELPER ? 'after fetch' : 'needs helper', fetch: async () => []},
  // THORChain swaps/liquidity started from (or paid out to) an EVM wallet: Ethereum only shows "sent X to the router".
  // Midgard knows both sides, so the Ethereum rows are relabelled in place (no extra rows). Two passes:
  // phase 1 turns the wallet's own outgoing row into a Trade / LP add; phase 2 handles payouts and the thor1 side.
  {id: 'thorchain', name: 'THORChain (Midgard)', families: ['evm'], label: 'swaps & liquidity via THORChain · free', def: true,
    scan: async a => { const j = await getJSON(`${MIDGARD}/actions?address=${a.toLowerCase()}&limit=1`, {}, 1); return +j.count || (j.actions || []).length; },
    fetch: async (a, o) => {
      const A = a.toLowerCase(), out = [], hx = t => t && !/^0+$/.test(t) ? t.toLowerCase() : '';
      const {acts} = await midgardActions(A, o);
      const sum = list => { const m = {}; list.forEach(c => { const k = thorSym(c.asset); m[k] = (m[k] || 0n) + BigInt(c.amount || 0); }); return Object.entries(m).map(([sym, v]) => ({sym, amount: units(v.toString(), 8)})); };
      const fmt = list => sum(list).map(x => `${fmtNum(x.amount)} ${x.sym}`).join(' + ');
      const where = list => [...new Set(list.map(c => c.address))].map(x => x.toLowerCase() === A ? 'this wallet' : `${thorChainOf(list.find(c => c.address === x)?.asset)} address ${short(x)}`).join(', ');
      for (const act of acts) {
        const md = act.metadata?.[act.type] || {}, pool = (act.pools || []).join(', ');
        const ins = (act.in || []).flatMap(x => (x.coins || []).map(c => ({...c, address: x.address || '', txID: x.txID})));
        const outs = (act.out || []).flatMap(x => (x.coins || []).map(c => ({...c, address: x.address || '', txID: x.txID}))).filter(c => +c.amount > 0);
        const sender = (act.in || [])[0]?.address?.toLowerCase() || '';
        const inTx = hx((act.in || []).find(x => x.address?.toLowerCase() === A)?.txID || (act.in || [])[0]?.txID);
        const pend = act.status === 'pending' ? ' Status: pending on THORChain — check the explorer.' : '';
        const label = {swap: 'swap', addLiquidity: 'liquidity add', withdraw: 'liquidity withdrawal', refund: 'refunded swap', secure: 'secured-asset deposit/withdrawal', trade: 'trade-account deposit/withdrawal'}[act.type] || act.type;
        // phase 1 — this wallet started it
        if (sender === A && inTx) {
          const got = sum(outs), sold = sum(ins);
          out.push({hash: inTx, phase: 1, apply: (r, ctx) => {
            if (r.Chain === 'THORChain') return false;
            if (!r['Sell Currency'] || r['Buy Currency'] || ctx.done.has('in:' + inTx)) return false;
            if (act.type === 'swap' && got.length === 1 && r.Type === 'Withdrawal') {
              r.Type = 'Trade'; r.Category = thorApp(md) ? `DeFi - Swap (THORChain via ${thorApp(md)})` : 'DeFi - Swap (THORChain)'; r['Buy Amount'] = got[0].amount; r['Buy Currency'] = got[0].sym; r['Liquidity Pool Address'] = pool;
              r.Comments = `THORChain swap${thorApp(md) ? ' made in ' + thorApp(md) : ''} via pool ${pool}: sold ${fmt(ins)}, received ${fmt(outs)} at ${where(outs)}.${pend} (Sent to the THORChain router on ${r.Chain}.)`;
            } else if (act.type === 'swap') {
              r.Category = 'DeFi - Swap (THORChain)'; r.Comments += ` THORChain swap via ${pool}: sold ${fmt(ins)}; ${outs.length ? `received ${fmt(outs)} at ${where(outs)}` : 'nothing paid out yet'} — check before importing.${pend}`;
            } else if (act.type === 'addLiquidity') {
              r.Category = 'DeFi - Liquidity Pool (Add)'; r['Liquidity Pool Address'] = pool; r.Comments = `Added ${fmt(ins)} to THORChain pool ${pool} (sent to the THORChain router on ${r.Chain}).${pend}`;
            } else if (act.type === 'withdraw') {
              r.Category = 'DeFi - Liquidity Pool (Remove request)'; r['Liquidity Pool Address'] = pool; r.Comments = `Withdrawal request for THORChain pool ${pool}${md.basisPoints ? ` (${+md.basisPoints / 100}% of the position)` : ''}; the small amount sent only triggers it and is returned. Payout: ${outs.length ? fmt(outs) + ' at ' + where(outs) : 'see the following rows'}.${pend}`;
            } else if (act.type === 'refund') {
              r.Category = 'DeFi - Swap (Refunded)'; r.Comments = `THORChain swap of ${fmt(ins)} was refunded${md.reason ? ` (${md.reason})` : ''}; ${outs.length ? `${fmt(outs)} came back` : 'refund not paid out yet'}.${pend}`;
            } else if (act.type === 'secure' || act.type === 'trade') {
              r.Category = `Transfer (L1 → ${act.type === 'secure' ? 'Secured Asset' : 'Trade Account'})`; r.Comments = `Moved ${fmt(ins)} into THORChain as a ${act.type === 'secure' ? 'secured asset' : 'trade-account balance'} for ${where(outs) || 'a THORChain address'}. Match with the Deposit there if it is your wallet.${pend}`;
            } else { r.Comments += ` THORChain ${act.type} via ${pool || 'THORChain'}.${pend}`; }
            ctx.done.add('in:' + inTx); return true;
          }});
        }
        // phase 2 — payouts to this wallet, and the thor1 copy of a swap this wallet started
        for (const c of outs.filter(x => x.address.toLowerCase() === A && hx(x.txID))) {
          const tx = hx(c.txID);
          out.push({hash: tx, phase: 2, apply: (r, ctx) => {
            if (r.Chain === 'THORChain' || !r['Buy Currency'] || r['Sell Currency']) return false;
            const counted = (act.type === 'swap' && ctx.done.has('in:' + hx((act.in || [])[0]?.txID))) || (sender && sender !== A && ctx.thorRun.has(sender) && act.type === 'swap');
            if (counted) {
              r.Category = 'Internal - THORChain swap output'; r._internal = true;
              r.Comments = `Output of the THORChain swap of ${fmt(ins)} started by ${sender === A ? 'this wallet' : short(sender)} — already counted as the Buy side of that Trade, so it is left out of the Excel file. (${fmt([c])} arrived here.)`;
            } else if (act.type === 'swap') {
              r.Category = 'DeFi - Swap (THORChain, incoming)'; r.Comments = `Received ${fmt([c])} from a THORChain swap of ${fmt(ins)} sent by ${thorChainOf(ins[0]?.asset)} address ${short(sender)}. If that sender is your own wallet, record the matching sale there.${pend}`;
            } else if (act.type === 'withdraw') {
              r.Category = 'DeFi - Liquidity Pool (Remove)'; r['Liquidity Pool Address'] = pool; r.Comments = `Withdrew ${fmt([c])} from THORChain pool ${pool}${md.basisPoints ? ` (${+md.basisPoints / 100}% of the position)` : ''}.`;
            } else if (act.type === 'refund') {
              r.Category = 'DeFi - Swap (Refunded)'; r.Comments = `Refund of a THORChain swap of ${fmt(ins)}${md.reason ? ` (${md.reason})` : ''}: ${fmt([c])} came back.`;
            } else if (act.type === 'secure' || act.type === 'trade') {
              r.Category = `Transfer (${act.type === 'secure' ? 'Secured Asset' : 'Trade Account'} → L1)`; r.Comments = `Received ${fmt([c])} withdrawn from THORChain by ${short(sender)}. Match with the Withdrawal there if it is your wallet.`;
            } else { r.Comments += ` Paid out by THORChain (${label}).`; }
            return true;
          }});
        }
        // the thor1 wallet's "Swap (Incoming)" row for a swap this wallet sold into → already a Trade here
        if (sender === A && inTx && act.type === 'swap') out.push({hash: inTx, phase: 2, apply: (r, ctx) => {
          if (r.Chain !== 'THORChain' || r.Category !== 'DeFi - Swap (Incoming)' || !ctx.done.has('in:' + inTx)) return false;
          r.Category = 'Internal - THORChain swap output'; r._internal = true;
          r.Comments = `Output of the THORChain swap started by ${short(A)} — already counted as the Buy side of that Trade, so it is left out of the Excel file. ` + r.Comments;
          return true;
        }});
      }
      return out;
    }},
  // Cross-chain services: each record names the sending tx, the arrival tx/chain and what arrived ("xfer").
  // The page pairs them with your rows: same coin → Bridge pair; different coin → Trade (arrival marked internal).
  {id: 'lifi', name: 'LI.FI (Jumper & wallets)', families: ['evm', 'sol'], label: 'cross-chain swaps & bridges · free', def: true,
    scan: async a => (await getJSON(`https://li.quest/v1/analytics/transfers?wallet=${a}`)).transfers?.length || 0,
    fetch: async (a, o) => {
      const j = await getJSON(`https://li.quest/v1/analytics/transfers?wallet=${a}`), out = [];
      for (const t of j.transfers || []) {
        const sd = t.sending || {}, rc = t.receiving || {};
        const amt = side => side.token && side.amount ? {amount: units(String(side.amount), side.token.decimals ?? 18), sym: side.token.symbol} : null;
        out.push(...xferNotes({id: 'lifi-' + (t.transactionId || sd.txHash), via: `LI.FI${t.tool ? ' / ' + t.tool : ''}`, status: t.status,
          src: {hash: sd.txHash, chainId: sd.chainId}, dst: {hash: rc.txHash, chainId: rc.chainId}, inp: amt(sd), out: amt(rc)}));
      }
      return out;
    }},
  {id: 'across', name: 'Across', families: ['evm'], label: 'bridge deposits · free', def: true,
    scan: async a => { const j = await getJSON(`https://app.across.to/api/deposits?depositor=${a}&limit=100`); return (j || []).length >= 100 ? '100+' : (j || []).length; },
    fetch: async (a, o) => {
      const out = [], seen = new Set();
      for (const who of ['depositor', 'recipient']) {
        for (let p = 0; p < o.maxPages; p++) {
          const list = await getJSON(`https://app.across.to/api/deposits?${who}=${a}&limit=100&skip=${p * 100}`) || [];
          for (const d of list) {
            if (seen.has(d.id)) continue; seen.add(d.id);
            out.push(...xferNotes({id: 'across-' + d.id, via: 'Across', status: d.status,
              src: {hash: d.depositTxHash || d.depositTxnRef, chainId: d.originChainId}, dst: {hash: d.fillTx || d.fillTxnRef, chainId: d.destinationChainId},
              inp: null, out: null}));
          }
          if (list.length < 100) break; await sleep(250);
        }
      }
      return out;
    }},
  {id: 'axelar', name: 'Axelarscan (Squid)', families: ['evm'], label: 'cross-chain swaps · free', def: true,
    scan: async a => (await getJSON(`https://api.axelarscan.io/gmp/searchGMP?address=${a}&size=1`)).total || 0,
    fetch: async (a, o) => {
      const out = [];
      for (let p = 0; p < o.maxPages; p++) {
        const j = await getJSON(`https://api.axelarscan.io/gmp/searchGMP?address=${a}&size=100&from=${p * 100}`), list = j.data || [];
        for (const d of list) {
          const c = d.call || {}, ex = d.executed || {};
          out.push(...xferNotes({id: 'axelar-' + (c._id || c.transactionHash), via: /squid/i.test(JSON.stringify(c.returnValues?.destinationContractAddress || '')) ? 'Squid (Axelar)' : 'Axelar' + (d.symbol ? ' / Squid' : ''),
            status: d.simplified_status || d.status, src: {hash: c.transactionHash, chainName: c.chain}, dst: {hash: ex.transactionHash, chainName: ex.chain || c.returnValues?.destinationChain},
            inp: d.symbol && d.amount ? {amount: +d.amount, sym: d.symbol.replace(/^axl/, '')} : null, out: null}));
        }
        if (list.length < 100) break; await sleep(250);
      }
      return out;
    }},
  {id: 'debridge', name: 'deBridge', families: ['evm', 'sol'], label: 'cross-chain orders · free', def: true,
    scan: async a => (await postJSON('https://stats-api.dln.trade/api/Orders/filteredList', {creator: a, skip: 0, take: 1})).totalCount || 0,
    fetch: async (a, o) => {
      const out = []; let skip = 0, total = 1;
      while (skip < total && skip < o.maxPages * 100) {
        const j = await postJSON('https://stats-api.dln.trade/api/Orders/filteredList', {creator: a, skip, take: 100});
        total = j.totalCount || 0; const list = j.orders || []; if (!list.length) break; skip += list.length;
        for (const x of list) {
          const g = x.giveOfferWithMetadata || {}, t = x.takeOfferWithMetadata || {};
          const gs = g.metadata?.symbol || g.symbol || '?', ts = t.metadata?.symbol || t.symbol || '?';
          const ga = units(big(g.amount), g.metadata?.decimals ?? g.decimals ?? 18), ta = units(big(t.finalAmount || t.amount), t.metadata?.decimals ?? t.decimals ?? 18);
          out.push(...xferNotes({id: 'debridge-' + (x.orderId?.stringValue || x.createEventTransactionHash?.stringValue), via: 'deBridge', status: x.state, src: {hash: x.createEventTransactionHash?.stringValue, chainId: +big(g.chainId)},
            dst: {hash: null, chainId: +big(t.chainId)}, inp: {amount: ga, sym: gs}, out: {amount: ta, sym: ts}}));
        }
        await sleep(250);
      }
      return out;
    }},
  {id: 'layerzero', name: 'LayerZero Scan', families: ['evm'], label: 'bridge messages · free', def: true,
    scan: async a => { try { const j = await getJSON(`https://scan.layerzero-api.com/v1/messages/wallet/${a}?limit=100`); return (j.data || []).length >= 100 ? '100+' : (j.data || []).length; } catch (e) { if (notFound(e)) return 0; throw e; } },
    fetch: async (a, o) => {
      const out = []; let next = '';
      for (let p = 0; p < o.maxPages; p++) {
        let j; try { j = await getJSON(`https://scan.layerzero-api.com/v1/messages/wallet/${a}?limit=100${next ? '&nextToken=' + encodeURIComponent(next) : ''}`); } catch (e) { if (notFound(e)) break; throw e; }
        for (const m of j.data || []) {
          const pw = m.pathway || {}, app = pw.sender?.name ? ` via ${pw.sender.name}` : '';
          const txt = `LayerZero${app}: ${pw.sender?.chain || pw.srcEid} → ${pw.receiver?.chain || pw.dstEid} (${m.status?.name || m.status || ''}).`;
          out.push(...xferNotes({id: 'lz-' + (m.guid || m.source?.tx?.txHash), via: `LayerZero${app}`, status: m.status?.name || m.status,
            src: {hash: m.source?.tx?.txHash, chainName: pw.sender?.chain || String(pw.srcEid)}, dst: {hash: m.destination?.tx?.txHash, chainName: pw.receiver?.chain || String(pw.dstEid)}, inp: null, out: null}));
          void txt;
        }
        next = j.nextToken; if (!next) break; await sleep(250);
      }
      return out;
    }},
  {id: 'wormhole', name: 'Wormholescan', families: ['evm', 'sol'], label: 'bridge transfers · free', def: true,
    scan: async a => { const j = await getJSON(`https://api.wormholescan.io/api/v1/operations?address=${a}&page=0&pageSize=50`); return (j.operations || []).length >= 50 ? '50+' : (j.operations || []).length; },
    fetch: async (a, o) => {
      const out = [];
      for (let p = 0; p < o.maxPages; p++) {
        const j = await getJSON(`https://api.wormholescan.io/api/v1/operations?address=${a}&page=${p}&pageSize=50`); const ops = j.operations || [];
        for (const op of ops) {
          const sp = op.content?.standarizedProperties || {}, app = (sp.appIds || []).join('/');
          const txt = `Wormhole${app ? ' (' + app + ')' : ''}: ${cname(WH_CHAINS, op.sourceChain?.chainId ?? op.emitterChain)} → ${cname(WH_CHAINS, op.targetChain?.chainId ?? sp.toChain)}${op.data?.tokenAmount ? `, ${op.data.tokenAmount} ${op.data.symbol || ''}` : ''}.`;
          const tok = op.data?.tokenAmount ? {amount: +op.data.tokenAmount, sym: op.data.symbol || '?'} : null;
          out.push(...xferNotes({id: 'wh-' + op.id, via: `Wormhole${app ? ' (' + app + ')' : ''}`, status: op.targetChain?.status || '',
            src: {hash: op.sourceChain?.transaction?.txHash, chainName: cname(WH_CHAINS, op.sourceChain?.chainId ?? op.emitterChain)},
            dst: {hash: op.targetChain?.transaction?.txHash, chainName: cname(WH_CHAINS, op.targetChain?.chainId ?? sp.toChain)}, inp: tok, out: null, sameToken: true}));
          void txt;
        }
        if (ops.length < 50) break; await sleep(250);
      }
      return out;
    }},
  {id: 'opensea', name: 'OpenSea', families: ['evm'], label: 'NFT sales · free key', def: true, key: 'openseaKey',
    scan: async (a, o) => { if (!o.openseaKey) return 'needs key'; const j = await getJSON(`https://api.opensea.io/api/v2/events/accounts/${a}?event_type=sale&limit=50`, {headers: {'X-API-KEY': o.openseaKey, accept: 'application/json'}}); return (j.asset_events || []).length >= 50 ? '50+' : (j.asset_events || []).length; },
    fetch: async (a, o) => {
      if (!o.openseaKey) return []; const out = []; let next = '';
      for (let p = 0; p < o.maxPages; p++) {
        const j = await getJSON(`https://api.opensea.io/api/v2/events/accounts/${a}?event_type=sale&limit=50${next ? '&next=' + encodeURIComponent(next) : ''}`, {headers: {'X-API-KEY': o.openseaKey, accept: 'application/json'}});
        for (const e of j.asset_events || []) {
          const buyer = lc(e.buyer) === lc(a), n = e.nft || {}, pay = e.payment || {};
          out.push({hash: e.transaction, cat: buyer ? 'NFT - Buy' : 'NFT - Sale', comment: `OpenSea: ${buyer ? 'bought' : 'sold'} ${n.name || (n.collection + ' #' + n.identifier)} (collection ${n.collection}) for ${fmtNum(units(pay.quantity || '0', pay.decimals ?? 18))} ${pay.symbol || ''} on ${e.chain || ''}.`});
        }
        next = j.next; if (!next) break; await sleep(300);
      }
      return out;
    }},
  {id: 'zerion', name: 'Zerion', families: ['evm'], label: 'DeFi protocol labels · free dev key', def: true, key: 'zerionKey',
    scan: async (a, o) => { if (!o.zerionKey) return 'needs key'; const j = await getJSON(`https://api.zerion.io/v1/wallets/${a}/transactions/?currency=usd&page%5Bsize%5D=100`, {headers: {Authorization: 'Basic ' + btoa(o.zerionKey + ':'), accept: 'application/json'}}); return (j.data || []).length >= 100 ? '100+' : (j.data || []).length; },
    fetch: async (a, o) => {
      if (!o.zerionKey) return []; const out = []; let url = `https://api.zerion.io/v1/wallets/${a}/transactions/?currency=usd&page%5Bsize%5D=100&filter%5Btrash%5D=no_filter`;
      for (let p = 0; p < o.maxPages && url; p++) {
        const j = await getJSON(url, {headers: {Authorization: 'Basic ' + btoa(o.zerionKey + ':'), accept: 'application/json'}});
        for (const d of j.data || []) {
          const at = d.attributes || {}, op = at.operation_type || '', app = at.application_metadata?.name || d.relationships?.dapp?.data?.id || '', trash = !!at.flags?.is_trash;
          out.push({hash: at.hash, cat: trash ? 'Possible Spam (review)' : ZERION_CAT[op], comment: `Zerion: ${op}${app ? ' on ' + app : ''}${trash ? ' — Zerion marks this as spam' : ''}.`, trash});
        }
        url = j.links?.next || ''; await sleep(300);
      }
      return out;
    }},
];
