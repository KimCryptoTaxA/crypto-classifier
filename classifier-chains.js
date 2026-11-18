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
  // Bittensor uses Substrate SS58 addresses with the generic prefix 42: 48 characters starting with 5
  if (/^5[1-9A-HJ-NP-Za-km-z]{47}$/.test(s)) { const d = b58decode(s); if (d && d.length === 35 && d[0] === 42) return {family: 'tao', addr: s, label: 'Bittensor (SS58)'}; }
  if (/^@?[a-z1-5.]{1,12}$/.test(s) && !/\.$/.test(s)) return {family: 'xpr', addr: s.replace(/^@/, ''), label: 'XPR Network account'};
  if (/^[xyz]pub[1-9A-HJ-NP-Za-km-z]{100,112}$/.test(s)) return {family: 'btc', addr: s, xpub: true, label: 'Bitcoin ' + s.slice(0, 4)};
  if (/^(addr1|stake1)[0-9a-z]{40,}$/.test(s)) return {family: 'ada', addr: s, label: 'Cardano'};
  if (/^(EQ|UQ|Ef|Uf|kQ|0Q)[A-Za-z0-9_-]{46}$/.test(s) || /^-?[01]:[0-9a-fA-F]{64}$/.test(s)) return {family: 'ton', addr: s, label: 'TON'};
  const bech = bech32Decode(s);
  if (bech) {
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
const BLOCKBOOK = 'https://btc1.trezor.io/api/v2';
async function fetchXpub(chain, x, opt) {
  const own = new Set(), raw = []; let cutoff = null, pages = 1;
  for (let p = 1; p <= Math.min(pages, opt.maxPages); p++) {
    const j = await getJSON(proxied(`${BLOCKBOOK}/xpub/${x}?details=txs&tokens=used&page=${p}&pageSize=100`));
    (j.tokens || []).forEach(t => own.add(t.name)); pages = j.totalPages || 1;
    raw.push(...(j.transactions || []));
    const last = raw[raw.length - 1];
    if (opt.from && last && last.blockTime * 1000 < +opt.from) break;
    if (p === opt.maxPages && pages > p && last) cutoff = new Date(last.blockTime * 1000);
    await sleep(300);
  }
  const mark = io => { const a = io.addresses?.[0] || ''; if (io.isOwn) own.add(a); return {addr: a, value: (+io.value || 0) / 1e8}; };
  const txs = raw.filter(t => t.blockTime).map(t => ({hash: t.txid, ts: new Date(t.blockTime * 1000), fee: (+t.fees || 0) / 1e8, ins: t.vin.map(mark), outs: t.vout.map(mark)}));
  return trimToCutoff(utxoBuckets(chain, txs, own, x), cutoff);
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
  let cutoff = null;
  const pages = async path => {
    const out = [];
    for (let p = 1; p <= opt.maxPages; p++) {
      const j = await csprGet(`${path}${path.includes('?') ? '&' : '?'}page=${p}&page_size=250`, key); const list = j.data || []; out.push(...list);
      if (p >= (j.page_count || 1) || !list.length) break;
      const ts = new Date(list[list.length - 1].timestamp);
      if (opt.from && ts < opt.from) break;
      if (p === opt.maxPages && (!cutoff || ts > cutoff)) cutoff = ts;
      await sleep(300);
    }
    return out;
  };
  const map = new Map();
  for (const d of await pages(`/accounts/${pk}/deploys`)) {
    const b = bucket(map, d.deploy_hash); b.ts = new Date(d.timestamp); b.from = pk; b.initKnown = true;
    b.ok = !d.error_message && d.status !== 'expired'; b.fee = units(d.cost || '0', 9);
    const ep = d.entry_point?.name || d.entry_point_name || '';
    b.method = ep || (d.execution_type_id === 6 ? 'transfer' : 'contract call');
    if (/^delegate$/.test(ep)) b.noValue = {cat: 'Staking (Delegate)', comment: 'Delegated CSPR to a validator (still yours; no balance change recorded). Fee only.'};
    if (/^undelegate$/.test(ep)) b.noValue = {cat: 'Staking (Undelegate)', comment: 'Started undelegating CSPR (tokens unlock after the unbonding period). Fee only.'};
    if (/^redelegate$/.test(ep)) b.noValue = {cat: 'Staking (Redelegate)', comment: 'Moved delegated CSPR to another validator. Fee only.'};
  }
  for (const t of await pages(`/accounts/${pk}/transfers`)) {
    const b = bucket(map, t.deploy_hash); if (!b.ts) b.ts = new Date(t.timestamp);
    const out = t.from_purse_public_key === pk || (t.initiator_public_key === pk && t.to_public_key !== pk && t.to_purse_public_key !== pk);
    const inn = (t.to_purse_public_key === pk || t.to_public_key === pk) && t.from_purse_public_key !== pk;
    if (!b.from) b.from = t.initiator_public_key || '';
    const amt = units(t.amount || '0', 9);
    if (out) { b.to = t.to_public_key || t.to_purse_public_key || t.to_account_hash || ''; b.legs.push({...natLeg(chain, 'out', amt, b.to), cpName: t.to_purse_centralized_account_info?.name || t.to_purse_cspr_name}); }
    else if (inn) b.legs.push({...natLeg(chain, 'in', amt, t.from_purse_public_key || t.initiator_public_key || ''), cpName: t.from_purse_centralized_account_info?.name});
    if (b.method === 'contract call' || !b.method) b.method = 'transfer';
  }
  // Delegation rewards arrive every era (~2h); combine them into one row per day.
  const daily = {};
  for (const r of await pages(`/accounts/${pk}/delegation-rewards`)) { const day = String(r.timestamp).slice(0, 10); daily[day] = daily[day] || {amt: 0n, n: 0, ts: r.timestamp}; daily[day].amt += BigInt(r.amount || 0); daily[day].n++; }
  for (const [day, v] of Object.entries(daily)) {
    const b = bucket(map, 'rewards-' + day); b.ts = new Date(day + 'T23:59:59Z'); b.url = `https://cspr.live/account/${pk}`;
    const leg = natLeg(chain, 'in', units(v.amt.toString(), 9), '');
    b.preRows = [{type: 'Staking', cat: 'Staking Rewards', buy: leg, sell: null, lp: '', comment: `Delegation rewards for ${day} (${v.n} era${v.n > 1 ? 's' : ''}, auto-compounded into your stake).`}];
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
  {id: 'btc', name: 'Bitcoin', code: 'BTC', native: 'BTC', family: 'btc', group: 'Bitcoin & co.', def: true, label: 'mempool.space · xpub via Trezor (helper)',
    txUrl: h => 'https://mempool.space/tx/' + h,
    scan: async (a) => { if (/^[xyz]pub/.test(a)) { const j = await getJSON(proxied(`${BLOCKBOOK}/xpub/${a}?details=basic`)); return {active: j.txs > 0, count: j.txs}; } return scanEsplora('https://mempool.space/api', a); },
    via: a => /^[xyz]pub/.test(a) ? 'Trezor Blockbook' : 'mempool.space',
    fetch: (a, o) => /^[xyz]pub/.test(a) ? fetchXpub(NONEVM_BY_ID.btc, a, o) : fetchEsplora(NONEVM_BY_ID.btc, 'https://mempool.space/api', a, o)},
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
  {id: 'tao', name: 'Bittensor', code: 'TAO', native: 'TAO', family: 'tao', group: 'Other chains', def: true, label: 'Taostats · needs Taostats key',
    txUrl: h => 'https://taostats.io/extrinsic/' + h,
    scan: async (a, o) => {
      if (!o.taostatsKey) return {status: 'needs key', note: 'Taostats key'};
      try { const j = await taoGet(`/accounts/${a}`, o.taostatsKey); const d = Array.isArray(j.data) ? j.data[0] : j.data; return d ? {active: true, count: '✓', note: d.created_on_date ? 'since ' + String(d.created_on_date).slice(0, 10) : ''} : {active: false, count: 0}; }
      catch (e) { if (notFound(e)) return {active: false, count: 0}; throw e; }
    },
    fetch: (a, o) => fetchTao(NONEVM_BY_ID.tao, a, o)},
];
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
const EXPLORERS = [
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
          out.push({hash: x.createEventTransactionHash?.stringValue, cat: 'Bridge (Outgoing)', comment: `deBridge: ${fmtNum(ga)} ${gs} on ${cname(CHAIN_NAMES, big(g.chainId))} → ${fmtNum(ta)} ${ts} on ${cname(CHAIN_NAMES, big(t.chainId))} (${x.state}). The matching Deposit on the destination chain shows as Transfer In.`});
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
          if (m.source?.tx?.txHash) out.push({hash: m.source.tx.txHash, cat: 'Bridge (Outgoing)', comment: txt});
          if (m.destination?.tx?.txHash) out.push({hash: m.destination.tx.txHash, cat: 'Bridge (Incoming)', comment: txt});
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
          if (op.sourceChain?.transaction?.txHash) out.push({hash: op.sourceChain.transaction.txHash, cat: 'Bridge (Outgoing)', comment: txt});
          if (op.targetChain?.transaction?.txHash) out.push({hash: op.targetChain.transaction.txHash, cat: 'Bridge (Incoming)', comment: txt});
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
