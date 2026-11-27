/*
 * Crypto Transaction Classifier — "View transactions" window.
 * openTxViewer({rows, cols, wallets, title, closable})
 *   rows    – objects with the CoinTracking columns (same as the Excel Transactions sheet)
 *   cols    – column order
 *   wallets – [{wallet, chain, addr, rows, note}] for the Wallets sheet (optional)
 * Search filters while you type (hash, currency, type, category, wallet name, comments, chain, address);
 * dropdowns narrow by type, category, wallet, currency and group; "Date from / Date to" open a calendar.
 * Buttons download every row, or only the rows that match, as an Excel file (excel-export.js).
 */
(function () {
  const GROUPS = () => window.CLASSIFIER_GROUPS || ['Transfers', 'DeFi & Swaps', 'Bridges', 'Staking', 'NFTs', 'Spam', 'Fees & other'];
  const groupOf = r => (window.classifierGroupOf ? window.classifierGroupOf(r) : 'Other');
  const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]));
  const short = a => !a ? '' : a.length <= 16 ? a : a.slice(0, 6) + '…' + a.slice(-4);
  const fmtNum = n => (n === 0 ? '0' : Math.abs(n) >= 1 ? n.toLocaleString('en-US', {maximumFractionDigits: 6}) : Number(n).toPrecision(6).replace(/0+$/, '').replace(/\.$/, ''));
  // Date column is "MM-DD-YYYY HH:MM:SS" → "YYYY-MM-DD" (compares with <input type=date> values)
  // Date column is "MM-DD-YYYY HH:MM:SS" → "YYYY-MM-DD HH:MM:SS" (sorts and compares as text)
  const isoKey = d => { d = String(d || ''); const m = /^(\d{2})-(\d{2})-(\d{4})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?/.exec(d); if (m) return `${m[3]}-${m[1]}-${m[2]} ${m[4] || '00'}:${m[5] || '00'}:${m[6] || '00'}`; const i = /^(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?/.exec(d); return i ? `${i[1]} ${i[2] || '00'}:${i[3] || '00'}:${i[4] || '00'}` : ''; };
  const p2 = n => String(n).padStart(2, '0');
  // typed / picked value "MM/DD/YYYY HH:MM:SS" (time optional) → "YYYY-MM-DD HH:MM:SS"; null when it can't be read
  const parseField = (v, end) => {
    v = String(v || '').trim(); if (!v) return '';
    const m = /^(\d{1,2})[\/.-](\d{1,2})[\/.-](\d{4})(?:[ T,]+(\d{1,2})(?::(\d{1,2}))?(?::(\d{1,2}))?)?$/.exec(v); if (!m) return null;
    const [mo, d, y] = [+m[1], +m[2], +m[3]]; if (mo < 1 || mo > 12 || d < 1 || d > 31) return null;
    const t = m[4] == null ? (end ? ['23', '59', '59'] : ['00', '00', '00']) : [m[4], m[5] ?? (end ? 59 : 0), m[6] ?? (end ? 59 : 0)].map(p2);
    if (+t[0] > 23 || +t[1] > 59 || +t[2] > 59) return null;
    return `${y}-${p2(mo)}-${p2(d)} ${t.join(':')}`;
  };
  const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const CAL_ICON = '<svg viewBox="0 0 20 20" width="18" height="18" aria-hidden="true"><rect x="2.5" y="4" width="15" height="13" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M2.5 8h15M6.5 2.5v3M13.5 2.5v3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><rect x="11.5" y="11" width="3" height="3" rx=".5" fill="currentColor"/></svg>';

  /* Pop-up calendar with Hour / Minute / Second sliders, "Now" and "Done". Writes MM/DD/YYYY HH:MM:SS into the input. */
  function openPicker(input, anchor, {end, minYear, maxYear, fallback, onChange}) {
    document.querySelector('.txv-pick')?.remove();
    const key = parseField(input.value, end) || fallback || '';
    const now = new Date();
    let [y, mo, d, h, mi, se] = key ? [+key.slice(0, 4), +key.slice(5, 7) - 1, +key.slice(8, 10), +key.slice(11, 13), +key.slice(14, 16), +key.slice(17, 19)]
      : [now.getFullYear(), now.getMonth(), now.getDate(), end ? 23 : 0, end ? 59 : 0, end ? 59 : 0];
    let vy = y, vm = mo; // month shown
    const lo = Math.min(minYear, y, now.getFullYear()) - 1, hi = Math.max(maxYear, y, now.getFullYear()) + 1;
    const el = document.createElement('div'); el.className = 'txv-pick'; el.setAttribute('role', 'dialog'); el.setAttribute('aria-label', 'Choose date and time');
    el.innerHTML = `<div class="tp-nav"><button type="button" class="tp-arrow" data-step="-1" aria-label="Previous month">&#9664;</button>
      <select class="tp-m" aria-label="Month">${MONTHS.map((n, i) => `<option value="${i}">${n}</option>`).join('')}</select>
      <select class="tp-y" aria-label="Year">${Array.from({length: hi - lo + 1}, (_, i) => `<option>${lo + i}</option>`).join('')}</select>
      <button type="button" class="tp-arrow" data-step="1" aria-label="Next month">&#9654;</button></div>
      <div class="tp-grid"></div>
      <div class="tp-time"><span>Time</span><b class="tp-tv"></b></div>
      <label class="tp-sl"><span>Hour</span><input type="range" min="0" max="23" class="tp-h"></label>
      <label class="tp-sl"><span>Minute</span><input type="range" min="0" max="59" class="tp-mi"></label>
      <label class="tp-sl"><span>Second</span><input type="range" min="0" max="59" class="tp-s"></label>
      <div class="tp-foot"><button type="button" class="tp-now">Now</button><button type="button" class="tp-clear">Clear</button><button type="button" class="tp-done">Done</button></div>`;
    document.body.appendChild(el);
    const $p = c => el.querySelector(c);
    const write = () => { input.value = `${p2(mo + 1)}/${p2(d)}/${y} ${p2(h)}:${p2(mi)}:${p2(se)}`; input.classList.remove('bad'); onChange(); };
    const draw = () => {
      $p('.tp-m').value = vm; $p('.tp-y').value = vy;
      const first = new Date(vy, vm, 1).getDay(), n = new Date(vy, vm + 1, 0).getDate();
      $p('.tp-grid').innerHTML = ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa'].map(w => `<span class="tp-wd">${w}</span>`).join('') + '<span></span>'.repeat(first) +
        Array.from({length: n}, (_, i) => `<button type="button" class="tp-d${vy === y && vm === mo && i + 1 === d ? ' on' : ''}" data-d="${i + 1}">${i + 1}</button>`).join('');
      $p('.tp-h').value = h; $p('.tp-mi').value = mi; $p('.tp-s').value = se; $p('.tp-tv').textContent = `${p2(h)}:${p2(mi)}:${p2(se)}`;
    };
    const place = () => { const r = anchor.getBoundingClientRect(), w = el.offsetWidth, ht = el.offsetHeight;
      let top = r.bottom + 4; if (top + ht > innerHeight - 8) top = Math.max(8, r.top - ht - 4);
      el.style.top = top + 'px'; el.style.left = Math.max(8, Math.min(r.left, innerWidth - w - 8)) + 'px'; };
    const shift = k => { vm += k; if (vm < 0) { vm = 11; vy--; } if (vm > 11) { vm = 0; vy++; } draw(); };
    el.addEventListener('click', e => {
      const a = e.target.closest('.tp-arrow'); if (a) return shift(+a.dataset.step);
      const b = e.target.closest('.tp-d'); if (b) { y = vy; mo = vm; d = +b.dataset.d; draw(); write(); }
    });
    $p('.tp-m').onchange = e => { vm = +e.target.value; draw(); };
    $p('.tp-y').onchange = e => { vy = +e.target.value; draw(); };
    [['.tp-h', v => h = v], ['.tp-mi', v => mi = v], ['.tp-s', v => se = v]].forEach(([c, set]) => $p(c).addEventListener('input', e => { set(+e.target.value); $p('.tp-tv').textContent = `${p2(h)}:${p2(mi)}:${p2(se)}`; write(); }));
    const close = () => { el.remove(); document.removeEventListener('mousedown', outside, true); document.removeEventListener('keydown', esc, true); removeEventListener('resize', place); };
    const outside = e => { if (!el.contains(e.target) && !anchor.contains(e.target)) close(); };
    const esc = e => { if (e.key === 'Escape') { e.stopPropagation(); close(); input.focus(); } };
    $p('.tp-now').onclick = () => { const t = new Date(); [y, mo, d, h, mi, se] = [t.getFullYear(), t.getMonth(), t.getDate(), t.getHours(), t.getMinutes(), t.getSeconds()]; vy = y; vm = mo; draw(); write(); };
    $p('.tp-clear').onclick = () => { input.value = ''; input.classList.remove('bad'); onChange(); close(); input.focus(); };
    $p('.tp-done').onclick = () => { write(); close(); input.focus(); };
    draw(); place();
    setTimeout(() => { document.addEventListener('mousedown', outside, true); document.addEventListener('keydown', esc, true); addEventListener('resize', place); });
    $p('.tp-d.on, .tp-d')?.focus();
    return close;
  }
  const SEARCH_COLS = ['Transaction Hash', 'Buy Currency', 'Sell Currency', 'Fee Currency', 'Type', 'Category', 'Exchange/Wallet Name', 'Comments', 'Chain', 'Wallet Address', 'Liquidity Pool Address', 'Date'];
  const PAGE = 300;
  // exchange named in the category by the exchange-label lookup → {name, dir: 'to' | 'from'}
  const exchangeOf = r => {
    const c = String(r.Category || '');
    let m = /^Transfer (from|to) (?:Instant )?Exchange \(([^)]+)\)/.exec(c); if (m) return {name: m[2].trim(), dir: m[1]};
    m = /^Instant Exchange (Swap|Payout) \(([^)]+)\)/.exec(c); if (m) return {name: m[2].trim(), dir: m[1] === 'Swap' ? 'to' : 'from'};
    m = /^Internal - (.+) payout$/.exec(c); if (m && !/swap|order/i.test(m[1])) return {name: m[1].trim(), dir: 'from'};
    return null;
  };
  // received (green) / sent (red) / trade (navy) / fee only (grey), from the amounts in the row
  const amt = v => v !== '' && v != null && Number(v) !== 0;
  const kindOf = r => { if (/fee/i.test(r.Type)) return 'fee'; const b = amt(r['Buy Amount']), s = amt(r['Sell Amount']); return b && s ? 'tr' : b ? 'rx' : s ? 'tx' : /trade/i.test(r.Type) ? 'tr' : 'fee'; };

  const CSS = `
.txv-back{position:fixed;inset:0;background:rgba(10,14,20,.55);z-index:1000;display:flex;align-items:stretch;justify-content:center;padding:clamp(8px,2vh,24px) clamp(8px,1.5vw,24px)}
.txv,.txv-pick{--bg:#f4f6fa;--card:#fff;--ink:#17202b;--mute:#566170;--line:#d9dfe7;--acc:#2f5bd3;--accInk:#fff;--bad:#b42318;--chip:#eaeff6;--head:#f6f8fc;--thBg:#eef2f8;--hover:#f5f8ff;--rx:#15803d;--rxBg:#e3f4e9;--tx:#c0262d;--txBg:#fce8e8;--tr:#1f2a44;--trInk:#fff;--mark:#ffe58a;color-scheme:light}\n[data-theme="dark"] .txv,[data-theme="dark"] .txv-pick{--bg:#121417;--card:#1b1e22;--ink:#e7e9ec;--mute:#9aa3ad;--line:#2d3238;--acc:#6f93ff;--accInk:#0c0e10;--bad:#ff7b72;--chip:#252a30;--head:#20242a;--thBg:#23282f;--hover:#232a35;--rx:#4ac08a;--rxBg:rgba(74,192,138,.16);--tx:#ff7b72;--txBg:rgba(255,123,114,.16);--tr:#a9bcff;--trInk:#0c0e10;--mark:#7a6420;color-scheme:dark}\n@media (prefers-color-scheme:dark){[data-theme="auto"] .txv,[data-theme="auto"] .txv-pick{--bg:#121417;--card:#1b1e22;--ink:#e7e9ec;--mute:#9aa3ad;--line:#2d3238;--acc:#6f93ff;--accInk:#0c0e10;--bad:#ff7b72;--chip:#252a30;--head:#20242a;--thBg:#23282f;--hover:#232a35;--rx:#4ac08a;--rxBg:rgba(74,192,138,.16);--tx:#ff7b72;--txBg:rgba(255,123,114,.16);--tr:#a9bcff;--trInk:#0c0e10;--mark:#7a6420;color-scheme:dark}}
.txv{background:var(--card,#fff);color:var(--ink,#1b1f24);border:1px solid var(--line,#dde1e6);border-radius:12px;width:100%;max-width:2200px;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.3);font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.txv-head{display:flex;align-items:center;gap:12px;padding:14px 18px;border-bottom:1px solid var(--line,#dde1e6);flex-wrap:wrap;background:var(--head)}
.txv-head h2{margin:0;font-size:17px;flex:1;min-width:200px}
.txv .themesw{display:inline-flex;border:1px solid var(--line);border-radius:999px;background:var(--card);padding:3px;gap:2px}
.txv .themesw button{border:0;background:transparent;color:var(--mute);padding:5px 10px;border-radius:999px;font-weight:600;font-size:12px}
.txv .themesw button[aria-pressed="true"]{background:var(--acc);color:var(--accInk)}
.txv-body{overflow-x:hidden}
.txv-wrap{max-width:100%}
.txv-x{background:transparent;border:0;color:var(--mute,#5d6570);font-size:22px;cursor:pointer;padding:2px 8px;line-height:1}
.txv-body{overflow:auto;padding:14px 18px 14px;flex:1;min-height:0;display:flex;flex-direction:column}
.txv-body>*{flex:none}
.txv-body>.txv-tbl{flex:1 1 0;min-height:clamp(260px,45vh,420px)}
.txv-matwrap{max-height:min(28vh,330px)}
.txv-matwrap th{position:sticky;top:0}
.txv-mat tr.tot td{position:sticky;bottom:0;background:var(--thBg);z-index:1}
.txv-toth{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap}
.txv-toth button.link{margin-left:auto;text-transform:none;letter-spacing:0;font-size:13px}
.txv-filters{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;align-items:end}
.txv-filters>div{min-width:0}
.txv-filters .txv-q{grid-column:span 2}
@media (max-width:1100px){.txv-filters{grid-template-columns:repeat(2,minmax(0,1fr))}.txv-filters .txv-q{grid-column:1/-1}}
@media (max-width:560px){.txv-back{padding:0}.txv{border-radius:0}.txv-filters{grid-template-columns:minmax(0,1fr)}}
.txv-filters label{display:block;font-size:12px;font-weight:600;color:var(--mute,#5d6570);margin:0 0 3px}
.txv-filters input,.txv-filters select{width:100%;padding:7px 9px;border:1px solid var(--line,#dde1e6);border-radius:7px;background:var(--bg,#f6f7f9);color:var(--ink,#1b1f24);font:inherit;font-size:13px}
.txv-filters input:focus,.txv-filters select:focus{outline:2px solid var(--acc,#2f5bd3);outline-offset:-1px}
.txv-q input{font-size:14px;padding:8px 10px}
.txv-bar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:12px 0}
.txv-count{font-weight:600;flex:1;min-width:200px}
.txv-count small{font-weight:400;color:var(--mute,#5d6570)}
.txv button{font:inherit;font-weight:600;padding:8px 14px;border-radius:7px;border:1px solid var(--acc,#2f5bd3);background:var(--acc,#2f5bd3);color:var(--accInk,#fff);cursor:pointer}
.txv button.sec{background:transparent;color:var(--acc,#2f5bd3)}
.txv button.link{border:0;background:transparent;color:var(--acc,#2f5bd3);padding:4px 6px;font-weight:500}
.txv button:disabled{opacity:.45;cursor:not-allowed}
.txv h3{font-size:13px;margin:16px 0 6px;text-transform:uppercase;letter-spacing:.04em;color:var(--mute,#5d6570)}
.txv-wrap{overflow:auto;border:1px solid var(--line,#dde1e6);border-radius:8px}
.txv table{border-collapse:collapse;font-size:12px;width:100%}
.txv th,.txv td{padding:5px 8px;border-bottom:1px solid var(--line,#dde1e6);text-align:left;vertical-align:top;white-space:nowrap}
.txv th{position:sticky;top:0;background:var(--thBg);z-index:1;font-weight:700;color:var(--ink)}\n.txv tbody tr:hover td{background:var(--hover)}
.txv td.cm{white-space:nowrap;max-width:460px;overflow:hidden;text-overflow:ellipsis;cursor:pointer}
.txv td.cm.open{white-space:normal;min-width:320px}
.txv td{vertical-align:middle}
.txv th,.txv td{padding:4px 8px}
.txv td.num{text-align:right;font-variant-numeric:tabular-nums}
.txv tr.spam td{color:var(--mute,#5d6570)}
.txv mark{background:var(--mark);color:inherit;border-radius:2px}
.txv-mat td,.txv-mat th{text-align:center}
.txv-mat td:first-child,.txv-mat th:first-child,.txv-mat td:nth-child(2),.txv-mat th:nth-child(2){text-align:left}
.txv-mat td.c{cursor:pointer}
.txv-mat td.c:hover{background:var(--chip,#eef1f5)}
.txv-mat td.on{outline:2px solid var(--acc,#2f5bd3);outline-offset:-2px}
.txv-mat td.z{color:var(--mute,#5d6570)}
.txv-mat td.spam{color:var(--bad,#b42318);font-weight:700}
.txv-mat tr.tot td{font-weight:700;border-top:2px solid var(--acc,#2f5bd3)}
.txv-tbl{max-height:none}
.txv-empty-wrap{max-width:640px;margin:6vh auto;display:flex;flex-direction:column;gap:12px;text-align:center}
.txv-drop{border:2px dashed var(--line);border-radius:14px;background:var(--bg);padding:48px 20px;display:flex;flex-direction:column;align-items:center;gap:8px;cursor:pointer;color:var(--acc);transition:border-color .15s,background .15s}
.txv-drop:hover,.txv-drop.over,.txv-drop:focus-visible{border-color:var(--acc);outline:none;background:var(--hover)}
.txv-drop b{color:var(--ink);font-size:17px}
.txv-drop span{color:var(--mute)}
.txv-upmsg.bad{color:var(--bad)}
.txv td.rx{color:var(--rx);font-weight:600}
.txv td.tx{color:var(--tx);font-weight:600}
.txv tr.k-rx td:first-child{box-shadow:inset 3px 0 0 var(--rx)}
.txv tr.k-tx td:first-child{box-shadow:inset 3px 0 0 var(--tx)}
.txv tr.k-tr td:first-child{box-shadow:inset 3px 0 0 var(--tr)}
.txv tr.k-fee td:first-child{box-shadow:inset 3px 0 0 #9aa3ad}
.txv-pill{display:inline-block;border-radius:10px;padding:1px 8px;font-weight:700;font-size:11.5px}
.txv-pill.rx{background:var(--rxBg);color:var(--rx)}
.txv-pill.tx{background:var(--txBg);color:var(--tx)}
.txv-pill.tr{background:var(--tr);color:var(--trInk)}
.txv-pill.fee{background:var(--chip);color:var(--mute)}
.txv-legend{display:inline-flex;gap:12px;margin-left:10px;text-transform:none;letter-spacing:0;font-weight:400}
.txv tr.spam td.rx,.txv tr.spam td.tx{opacity:.6}
.txv td.mono{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;cursor:copy}
.txv td.mono:hover{background:var(--hover);outline:1px dashed var(--acc);outline-offset:-2px}
.txv tr.band td{background:var(--chip,#eef1f5)}
.txv-badge{font-family:system-ui,sans-serif;font-size:11px;font-weight:700;color:var(--accInk,#fff);background:var(--acc,#2f5bd3);border-radius:10px;padding:0 6px;margin-left:4px;user-select:none}
.txv button.sec.on{background:var(--acc,#2f5bd3);color:var(--accInk,#fff)}
.txv-dtf{position:relative}
.txv-dtf input{padding-right:36px!important;font-variant-numeric:tabular-nums}
.txv-dtf input.bad{outline:2px solid var(--bad,#b42318);outline-offset:-1px}
.txv .txv-cal{position:absolute;right:3px;top:50%;transform:translateY(-50%);background:transparent;border:0;color:var(--acc,#2f5bd3);padding:4px 6px;display:flex}
.txv-pick{position:fixed;z-index:1100;width:300px;background:var(--card,#fff);color:var(--ink,#1b1f24);border:1px solid var(--line,#dde1e6);border-radius:12px;box-shadow:0 12px 40px rgba(0,0,0,.35);padding:10px;font:14px/1.4 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.txv-pick button{font:inherit;cursor:pointer;color:inherit}
.tp-nav{display:flex;gap:6px;align-items:center;background:var(--chip,#eef1f5);border-radius:8px;padding:6px}
.tp-nav select{flex:1;min-width:0;padding:4px 6px;border:1px solid var(--line,#dde1e6);border-radius:6px;background:var(--card,#fff);color:var(--ink,#1b1f24);font:inherit}
.tp-arrow{border:0;background:var(--ink,#1b1f24);color:var(--card,#fff)!important;border-radius:50%;width:24px;height:24px;font-size:10px;display:grid;place-items:center;padding:0}
.tp-grid{display:grid;grid-template-columns:repeat(7,1fr);gap:4px;margin:10px 0}
.tp-wd{text-align:center;font-weight:700;font-size:12px;color:var(--mute,#5d6570)}
.tp-d{border:0;background:var(--chip,#eef1f5);border-radius:7px;padding:6px 0;font-weight:600;font-size:13px}
.tp-d:hover{outline:1px solid var(--acc,#2f5bd3)}
.tp-d.on{background:var(--acc,#2f5bd3);color:var(--accInk,#fff)!important}
.tp-time{display:flex;justify-content:space-between;padding:6px 2px;border-top:1px solid var(--line,#dde1e6)}
.tp-time b{font-variant-numeric:tabular-nums;font-size:16px;letter-spacing:.04em}
.tp-sl{display:grid;grid-template-columns:64px 1fr;align-items:center;gap:8px;margin:4px 2px;font-weight:400;font-size:13px}
.tp-sl input{width:100%;accent-color:var(--acc,#2f5bd3)}
.tp-foot{display:flex;gap:8px;justify-content:space-between;margin-top:10px;padding-top:8px;border-top:1px solid var(--line,#dde1e6)}
.tp-foot button{border:1px solid var(--line,#dde1e6);background:transparent;border-radius:7px;padding:6px 14px}
.tp-foot .tp-done{font-weight:700;background:var(--acc,#2f5bd3);border-color:var(--acc,#2f5bd3);color:var(--accInk,#fff)!important;margin-left:auto}
.txv-empty{padding:24px;text-align:center;color:var(--mute,#5d6570)}
.txv-hint{color:var(--mute,#5d6570);font-size:12px}
`;

  function injectCss() { if (document.getElementById('txv-css')) return; const s = document.createElement('style'); s.id = 'txv-css'; s.textContent = CSS; document.head.appendChild(s); }

  async function download(rows, cols, wallets, suffix) {
    const d = new Date(), p = x => String(x).padStart(2, '0');
    const name = `crypto-transactions-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}${suffix ? '-' + suffix : ''}.xlsx`;
    const plain = rows.map(r => { const o = {}; cols.forEach(c => o[c] = r[c]); return o; });
    if (window.ExcelJS && window.exportClassifierWorkbook) return window.exportClassifierWorkbook(plain, cols, wallets || [], name);
    if (window.XLSX) { const wb = XLSX.utils.book_new(); XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(plain, {header: cols}), 'Transactions'); return XLSX.writeFile(wb, name); }
    alert('The Excel library did not load (offline?). Reload the page when online and try again.');
  }

  const CT_COLS = ['Type', 'Category', 'Buy Amount', 'Buy Currency', 'Sell Amount', 'Sell Currency', 'Fee Amount', 'Fee Currency',
    'Exchange/Wallet Name', 'Comments', 'Date', 'Liquidity Pool Address', 'Transaction Hash', 'Chain', 'Wallet Address', 'Explorer Link'];
  // Excel date cells come back as serial numbers (days since 1899-12-30): turn them back into MM-DD-YYYY HH:MM:SS
  function fixDates(rows) {
    const p = n => String(n).padStart(2, '0');
    rows.forEach(r => { const v = r.Date; if (typeof v === 'number' && v > 20000 && v < 80000) { const d = new Date(Math.round((v - 25569) * 86400) * 1000); r.Date = `${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}-${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`; } });
    return rows;
  }
  // Read an Excel file the classifier downloaded earlier (Transactions sheet + Wallets sheet). Read in the browser only.
  async function readClassifierExcel(file) {
    if (typeof XLSX === 'undefined') throw new Error('the Excel reader did not load (offline?) — reload the page when online');
    const wb = XLSX.read(await file.arrayBuffer(), {type: 'array'});
    const name = wb.SheetNames.find(n => /^transactions$/i.test(n)) || wb.SheetNames[0];
    const rows = XLSX.utils.sheet_to_json(wb.Sheets[name], {defval: ''});
    if (!rows.length) throw new Error(`no rows found in the "${name}" sheet`);
    fixDates(rows);
    const cols = CT_COLS.every(c => c in rows[0]) ? CT_COLS : Object.keys(rows[0]);
    const ws = wb.SheetNames.find(n => /^wallets$/i.test(n));
    const wallets = ws ? XLSX.utils.sheet_to_json(wb.Sheets[ws], {defval: ''}).map(w => ({wallet: w['Exchange/Wallet Name'], chain: w.Chain, addr: w['Wallet Address'], rows: w.Rows, note: w.Notes})) : [];
    return {rows, cols, wallets};
  }
  // Wire an "Upload previous data" button (+ optional drop area) inside the window
  function wireUpload(root, closable, dropEl) {
    const inp = document.createElement('input'); inp.type = 'file'; inp.accept = '.xlsx,.xls'; inp.hidden = true; root.appendChild(inp);
    const msg = root.querySelector('.txv-upmsg');
    const load = async f => {
      if (!f) return; if (msg) { msg.textContent = 'Reading ' + f.name + '…'; msg.classList.remove('bad'); }
      try { const d = await readClassifierExcel(f); openTxViewer({...d, title: `${f.name} — ${d.rows.length.toLocaleString()} rows`, closable}); }
      catch (e) { if (msg) { msg.textContent = `Could not read "${f.name}": ${e.message}`; msg.classList.add('bad'); } else alert(`Could not read "${f.name}": ${e.message}`); }
    };
    inp.onchange = () => { const f = inp.files[0]; inp.value = ''; load(f); };
    root.querySelectorAll('[data-upload]').forEach(b => b.onclick = () => inp.click());
    if (dropEl) {
      ['dragenter', 'dragover'].forEach(t => dropEl.addEventListener(t, e => { e.preventDefault(); dropEl.classList.add('over'); }));
      ['dragleave', 'drop'].forEach(t => dropEl.addEventListener(t, e => { e.preventDefault(); dropEl.classList.remove('over'); }));
      dropEl.addEventListener('drop', e => load(e.dataTransfer.files[0]));
      dropEl.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); inp.click(); } });
    }
    return load;
  }
  function closeHandlers(back, closable) {
    const close = () => { document.querySelector('.txv-pick')?.remove(); back.remove(); document.removeEventListener('keydown', onKey); document.body.style.overflow = ''; };
    const onKey = e => { if (e.key === 'Escape' && !document.querySelector('.txv-pick') && closable && document.contains(back)) close(); };
    if (closable) {
      back.querySelector('.txv-x').onclick = close;
      back.addEventListener('mousedown', e => { if (e.target === back) close(); });
      document.addEventListener('keydown', onKey);
      document.body.style.overflow = 'hidden';
    }
    return close;
  }
  // Nothing fetched yet: the same window, with an upload area for a previous fetch's Excel file
  function openEmpty({title = 'View transactions', closable = true, note = ''}) {
    const back = document.createElement('div'); back.className = 'txv-back';
    back.innerHTML = `<div class="txv" role="dialog" aria-modal="true" aria-labelledby="txv-title">
  <div class="txv-head"><h2 id="txv-title">${esc(title)}</h2>
    <div class="themesw txv-theme" role="group" aria-label="Colour theme"></div>
    ${closable ? '<button class="txv-x" aria-label="Close" title="Close (Esc)">×</button>' : ''}</div>
  <div class="txv-body" id="txv-body"><div class="txv-empty-wrap">
    <div class="txv-drop" tabindex="0" role="button" data-upload aria-label="Upload an Excel file from a previous fetch">
      <svg viewBox="0 0 24 24" width="40" height="40" aria-hidden="true"><path d="M12 15V4m0 0-4 4m4-4 4 4M5 15v3a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-3" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
      <b>Upload previous data</b>
      <span>Drop an Excel file from a previous fetch here, or click to choose it.</span>
    </div>
    <p class="txv-upmsg txv-hint">${esc(note || 'No transactions fetched yet. Fetch wallets first, or upload an Excel file the classifier downloaded before.')}</p>
    <p class="txv-hint">The file is read in this browser only. Nothing is uploaded to a server.</p>
  </div></div></div>`;
    document.body.appendChild(back);
    const close = closeHandlers(back, closable);
    if (window.mountThemeSwitch) mountThemeSwitch(back.querySelector('.txv-theme'));
    wireUpload(back, closable, back.querySelector('.txv-drop'));
    back.querySelector('.txv-drop').focus();
    return {close, element: back};
  }

  function openTxViewer({rows, cols, wallets = [], title = 'Transactions', closable = true, mount = null}) {
    injectCss();
    document.querySelector('.txv-back')?.remove(); document.body.style.overflow = '';
    if (!rows || !rows.length) return openEmpty({closable});
    const G = GROUPS();
    // pre-compute search text, day and group once
    const data = rows.map(r => ({r, hay: SEARCH_COLS.map(c => r[c] ?? '').join(' ').toLowerCase(), day: isoKey(r.Date), h: String(r['Transaction Hash'] || '').trim().toLowerCase(), g: groupOf(r), ex: exchangeOf(r)}));
    const hashN = {}; data.forEach(x => { if (x.h) hashN[x.h] = (hashN[x.h] || 0) + 1; });
    const dupRows = data.filter(x => x.h && hashN[x.h] > 1).length, dupHashes = Object.values(hashN).filter(n => n > 1).length;
    const uniq = f => [...new Set(data.flatMap(f).filter(v => v !== '' && v != null).map(String))].sort((a, b) => a.localeCompare(b));
    const lists = {
      type: uniq(x => [x.r.Type]), cat: uniq(x => [x.r.Category]), wal: uniq(x => [x.r['Exchange/Wallet Name']]),
      cur: uniq(x => [x.r['Buy Currency'], x.r['Sell Currency'], x.r['Fee Currency']]),
    };
    const days = data.map(x => x.day.slice(0, 10)).filter(Boolean).sort();
    const exCount = {}; data.forEach(x => { if (!x.ex) return; const e = exCount[x.ex.name] = exCount[x.ex.name] || {to: 0, from: 0}; e[x.ex.dir]++; });
    const exNames = Object.keys(exCount).sort((a, b) => a.localeCompare(b)), exAll = {to: 0, from: 0}; exNames.forEach(n => { exAll.to += exCount[n].to; exAll.from += exCount[n].from; });
    const exLine = (val, label, n) => `<option value="${esc(val)}"${n ? '' : ' disabled'}>${esc(label)} (${n})</option>`;
    const exOpts = '<option value="">All rows</option>' + (exNames.length
      ? exLine('*|', 'Any exchange', exAll.to + exAll.from) + exNames.map(n => exLine(n + '|', n, exCount[n].to + exCount[n].from)).join('')
      : '<option value="" disabled>No exchange transfers found</option>');
    const opt = (arr, all) => `<option value="">${all}</option>` + arr.map(v => `<option>${esc(v)}</option>`).join('');

    const back = document.createElement('div'); back.className = 'txv-back';
    back.innerHTML = `<div class="txv" role="dialog" aria-modal="true" aria-labelledby="txv-title">
  <div class="txv-head"><h2 id="txv-title">${esc(title)}</h2>
    <button class="sec" data-upload title="Open an Excel file from a previous fetch in this window (read in this browser only)">Upload previous data</button>
    <button class="sec" data-dl="all">Download all results (${rows.length.toLocaleString()})</button>
    <button data-dl="some">Download these results</button>
    <div class="themesw txv-theme" role="group" aria-label="Colour theme"></div>
    ${closable ? '<button class="txv-x" aria-label="Close" title="Close (Esc)">×</button>' : ''}</div>
  <div class="txv-body" id="txv-body">
    <div class="txv-filters">
      <div class="txv-q"><label for="txv-q">Search</label><input id="txv-q" type="search" placeholder="Hash, currency, type, category, wallet, comment…" autocomplete="off"></div>
      <div><label for="txv-type">Type</label><select id="txv-type">${opt(lists.type, 'All types')}</select></div>
      <div><label for="txv-cat">Category</label><select id="txv-cat">${opt(lists.cat, 'All categories')}</select></div>
      <div><label for="txv-wal">Exchange/Wallet</label><select id="txv-wal">${opt(lists.wal, 'All wallets')}</select></div>
      <div><label for="txv-cur">Currency</label><select id="txv-cur">${opt(lists.cur, 'All currencies')}</select></div>
      <div><label for="txv-grp">Group</label><select id="txv-grp">${opt(G, 'All groups')}</select></div>
      <div><label for="txv-ex">Exchange transfers</label><select id="txv-ex" ${exNames.length ? '' : 'title="No transfers to or from a known exchange were found"'}>${exOpts}</select></div>
      <div><label for="txv-from">Date &amp; time from</label><div class="txv-dtf"><input id="txv-from" type="text" inputmode="numeric" placeholder="MM/DD/YYYY HH:MM:SS" autocomplete="off" title="Click the calendar, or type e.g. 08/03/2025 11:47:10 (time is optional)"><button type="button" class="txv-cal" data-for="from" aria-label="Choose date and time from">${CAL_ICON}</button></div></div>
      <div><label for="txv-to">Date &amp; time to</label><div class="txv-dtf"><input id="txv-to" type="text" inputmode="numeric" placeholder="MM/DD/YYYY HH:MM:SS" autocomplete="off" title="Click the calendar, or type e.g. 08/31/2025 23:59:59 (time is optional)"><button type="button" class="txv-cal" data-for="to" aria-label="Choose date and time to">${CAL_ICON}</button></div></div>
    </div>
    <div class="txv-bar"><span class="txv-count" id="txv-count"></span>
      <button class="sec" id="txv-dup" aria-pressed="false" ${dupHashes ? '' : 'disabled'} title="Show only rows whose transaction hash appears more than once">Duplicate hashes (${dupHashes.toLocaleString()} hash${dupHashes === 1 ? '' : 'es'} · ${dupRows.toLocaleString()} rows)</button>
      <button class="link" id="txv-clear">Clear search</button></div>
    <p class="txv-hint" id="txv-dupnote" hidden>Showing rows that share a transaction hash, grouped together. Some are normal — one transaction can give several rows (e.g. a swap plus its fee, or a multi-token transfer). Look for groups where the same amount and currency appear twice: those are real duplicates.</p>
    <h3 class="txv-toth">Totals <span class="txv-hint" style="text-transform:none;letter-spacing:0">— of the rows shown; click a number to show those rows</span><button type="button" class="link" id="txv-tottoggle" aria-expanded="true" aria-controls="txv-matwrap">Hide</button></h3>
    <div class="txv-wrap txv-matwrap" id="txv-matwrap"><table class="txv-mat" id="txv-mat"></table></div>
    <h3>Transactions <span class="txv-legend"><span class="txv-pill rx">Received</span><span class="txv-pill tx">Sent</span><span class="txv-pill tr">Trade</span><span class="txv-pill fee">Fee only</span></span></h3>
    <div class="txv-wrap txv-tbl" id="txv-tblwrap"><table><thead><tr>${cols.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody id="txv-tbody"></tbody></table></div>
    <div class="txv-bar"><span class="txv-hint" id="txv-more-note"></span><button class="sec" id="txv-more" hidden>Show more</button></div>
  </div></div>`;
    (mount || document.body).appendChild(back);
    const q = id => back.querySelector('#txv-' + id);
    const F = {q: q('q'), type: q('type'), cat: q('cat'), wal: q('wal'), cur: q('cur'), grp: q('grp'), ex: q('ex'), from: q('from'), to: q('to')};
    let shown = PAGE, current = data, dupOnly = false;

    function filter() {
      const words = F.q.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
      const exSel = F.ex.value, t = F.type.value, c = F.cat.value, w = F.wal.value, cu = F.cur.value, g = F.grp.value;
      let from = parseField(F.from.value, false), to = parseField(F.to.value, true);
      F.from.classList.toggle('bad', from === null); F.to.classList.toggle('bad', to === null); from = from || ''; to = to || '';
      if (from && to && from > to) [from, to] = [to, from];
      const out = data.filter(x => {
        if (dupOnly && !(x.h && hashN[x.h] > 1)) return false;
        const r = x.r;
        if (t && r.Type !== t) return false;
        if (c && r.Category !== c) return false;
        if (w && r['Exchange/Wallet Name'] !== w) return false;
        if (cu && r['Buy Currency'] !== cu && r['Sell Currency'] !== cu && r['Fee Currency'] !== cu) return false;
        if (g && x.g !== g) return false;
        if (exSel) { if (!x.ex) return false; const [en, ed] = exSel.split('|'); if (en !== '*' && x.ex.name !== en) return false; if (ed && x.ex.dir !== ed) return false; }
        if (from && (!x.day || x.day < from)) return false;
        if (to && (!x.day || x.day > to)) return false;
        for (const wd of words) if (!x.hay.includes(wd)) return false;
        return true;
      });
      if (dupOnly) { const first = {}; out.forEach((x, i) => { if (!(x.h in first)) first[x.h] = i; }); out.sort((a, b) => first[a.h] - first[b.h]); }
      return out;
    }
    const hl = (s, words) => { let h = esc(s); for (const wd of words) if (wd.length > 1) h = h.replace(new RegExp(esc(wd).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), m => `<mark>${m}</mark>`); return h; };

    function renderMatrix() {
      const M = {}, tot = {}; current.forEach(x => { const w = x.r['Exchange/Wallet Name'] || '(none)'; (M[w] = M[w] || {})[x.g] = (M[w][x.g] || 0) + 1; tot[x.g] = (tot[x.g] || 0) + 1; });
      const chainOf = w => (wallets.find(x => x.wallet === w) || data.find(x => x.r['Exchange/Wallet Name'] === w)?.r || {}).chain || (data.find(x => x.r['Exchange/Wallet Name'] === w)?.r.Chain) || '';
      const cell = (w, g, n) => `<td class="c${n ? '' : ' z'}${g === 'Spam' && n ? ' spam' : ''}${F.wal.value === w && F.grp.value === g ? ' on' : ''}" data-w="${esc(w)}" data-g="${esc(g)}">${n.toLocaleString()}</td>`;
      const ws = Object.keys(M).sort();
      q('mat').innerHTML = `<thead><tr><th>Exchange/Wallet Name</th><th>Chain</th>${G.map(g => `<th>${esc(g)}</th>`).join('')}<th>Total</th></tr></thead><tbody>` +
        (ws.length ? ws.map(w => `<tr><td>${esc(w)}</td><td>${esc(chainOf(w))}</td>${G.map(g => cell(w, g, (M[w] || {})[g] || 0)).join('')}<td class="c" data-w="${esc(w)}" data-g=""><b>${Object.values(M[w]).reduce((a, b) => a + b, 0).toLocaleString()}</b></td></tr>`).join('') : '') +
        `<tr class="tot"><td>TOTAL</td><td></td>${G.map(g => cell('', g, tot[g] || 0)).join('')}<td>${current.length.toLocaleString()}</td></tr></tbody>`;
    }

    function renderRows() {
      const words = F.q.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
      const show = current.slice(0, shown);
      let band = 0, prev = null;
      q('tbody').innerHTML = show.length ? show.map(({r, h}) => { if (dupOnly && h !== prev) { band ^= 1; prev = h; } const k = kindOf(r); return `<tr class="k-${k}${r.Category === 'Scam/Spam' ? ' spam' : ''}${dupOnly && band ? ' band' : ''}">` + cols.map(c => {
        const v = r[c];
        if (c === 'Type') return `<td><span class="txv-pill ${k}">${hl(v, words)}</span></td>`;
        if (c === 'Buy Amount' || c === 'Buy Currency' || c === 'Sell Amount' || c === 'Sell Currency') {
          const cls = c.startsWith('Buy') ? 'rx' : 'tx', num = typeof v === 'number';
          return `<td class="${cls}${num ? ' num' : ''}">${num ? fmtNum(v) : hl(v, words)}</td>`;
        }
        if (c === 'Explorer Link') return `<td>${v ? `<a href="${esc(v)}" target="_blank" rel="noopener">open</a>` : ''}</td>`;
        if (c === 'Transaction Hash' || c === 'Liquidity Pool Address' || c === 'Wallet Address') {
          return `<td class="mono" data-copy="${esc(v)}" title="Click to copy">${hl(v, words)}${c === 'Transaction Hash' && dupOnly && v ? ` <span class="txv-badge">×${hashN[String(v).trim().toLowerCase()]}</span>` : ''}</td>`;
        }
        if (typeof v === 'number') return `<td class="num">${fmtNum(v)}</td>`;
        return c === 'Comments' ? `<td class="cm" title="${esc(v)}">${hl(v, words)}</td>` : `<td>${hl(v, words)}</td>`;
      }).join('') + '</tr>'; }).join('') : `<tr><td colspan="${cols.length}" class="txv-empty">No matching transactions. Try fewer words or clear a box.</td></tr>`;
      const more = current.length - show.length;
      q('more').hidden = more <= 0; q('more').textContent = `Show ${Math.min(more, PAGE * 5).toLocaleString()} more`;
      q('more-note').textContent = more > 0 ? `Showing ${show.length.toLocaleString()} of ${current.length.toLocaleString()} rows; more load as you scroll the table. Downloads always include all of them.` : (current.length > 12 ? 'Click a comment to see all of it.' : '');
    }

    function update() {
      current = filter(); shown = PAGE;
      const any = dupOnly || Object.values(F).some(el => el.value);
      q('count').innerHTML = any ? `${current.length.toLocaleString()} matching <small>of ${data.length.toLocaleString()} transactions</small>` : `${data.length.toLocaleString()} transactions <small>— type or pick something to narrow them down</small>`;
      const btn = back.querySelector('[data-dl="some"]'); btn.disabled = !current.length || !any; btn.textContent = `Download these results (${current.length.toLocaleString()})`;
      q('clear').hidden = !any;
      renderMatrix(); renderRows(); q('tblwrap').scrollTop = 0;
    }

    let timer; F.q.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(update, 80); });
    ['type', 'cat', 'wal', 'cur', 'grp', 'ex'].forEach(k => F[k].addEventListener('change', update));
    const years = days.map(x => +x.slice(0, 4)), nowY = new Date().getFullYear();
    let dtTimer;
    const showPick = k => openPicker(F[k], F[k].parentElement, {end: k === 'to', minYear: years[0] || nowY, maxYear: years[years.length - 1] || nowY,
      fallback: days.length ? (k === 'to' ? days[days.length - 1] + ' 23:59:59' : days[0] + ' 00:00:00') : '', onChange: () => { clearTimeout(dtTimer); dtTimer = setTimeout(update, 60); }});
    ['from', 'to'].forEach(k => {
      F[k].addEventListener('input', () => { clearTimeout(dtTimer); dtTimer = setTimeout(update, 250); });
      F[k].addEventListener('keydown', e => { if (e.key === 'ArrowDown' || (e.key === 'Enter' && !F[k].value)) { e.preventDefault(); showPick(k); } });
    });
    back.querySelectorAll('.txv-cal').forEach(b => b.onclick = () => document.querySelector('.txv-pick') ? document.querySelector('.txv-pick').remove() : showPick(b.dataset.for));
    q('body').addEventListener('scroll', () => document.querySelector('.txv-pick')?.remove());
    const setDup = on => { dupOnly = on; q('dup').setAttribute('aria-pressed', on); q('dup').classList.toggle('on', on); q('dupnote').hidden = !on; };
    q('dup').onclick = () => { setDup(!dupOnly); update(); };
    q('clear').onclick = () => { Object.values(F).forEach(el => el.value = ''); setDup(false); update(); F.q.focus(); };
    const setTot = open => { q('matwrap').hidden = !open; q('tottoggle').textContent = open ? 'Hide' : 'Show'; q('tottoggle').setAttribute('aria-expanded', open); try { localStorage.setItem('cls_totals', open ? '1' : '0'); } catch {} };
    q('tottoggle').onclick = () => setTot(q('matwrap').hidden);
    try { if (localStorage.getItem('cls_totals') === '0') setTot(false); } catch {}
    const loadMore = () => { if (shown >= current.length) return; const w = q('tblwrap'), top = w.scrollTop; shown += PAGE * 5; renderRows(); w.scrollTop = top; };
    q('more').onclick = loadMore;
    q('tblwrap').addEventListener('scroll', () => { const w = q('tblwrap'); if (w.scrollTop + w.clientHeight > w.scrollHeight - 400) loadMore(); });
    q('tbody').addEventListener('click', e => { const td = e.target.closest('td.cm'); if (td && !getSelection().toString()) td.classList.toggle('open'); });
    q('mat').addEventListener('click', e => {
      const td = e.target.closest('td.c'); if (!td) return;
      const same = F.wal.value === td.dataset.w && F.grp.value === td.dataset.g;
      F.wal.value = same ? '' : td.dataset.w; F.grp.value = same ? '' : td.dataset.g; update();
    });
    back.querySelectorAll('[data-dl]').forEach(b => b.onclick = async () => {
      const all = b.dataset.dl === 'all', old = b.textContent; b.disabled = true; b.textContent = 'Preparing…';
      try { await download(all ? rows : current.map(x => x.r), cols, wallets, all ? '' : 'search'); }
      catch (e) { alert('Excel download failed: ' + e.message); }
      b.textContent = old; b.disabled = false; if (!all) update();
    });
    const close = closeHandlers(back, closable);
    wireUpload(back, closable, null);
    if (window.mountThemeSwitch) mountThemeSwitch(back.querySelector('.txv-theme'));
    update(); F.q.focus();
    return {close, element: back};
  }

  // Light / Dark / Auto switch: sets <html data-theme>, remembered in this browser
  function mountThemeSwitch(el) {
    if (!el) return;
    const cur = () => document.documentElement.dataset.theme || 'light';
    const opts = [['light', '☀ Light'], ['dark', '☾ Dark'], ['auto', 'Auto']];
    el.innerHTML = opts.map(([v, t]) => `<button type="button" data-theme-set="${v}" title="${v === 'auto' ? 'Follow the computer setting' : t.slice(2) + ' colours'}">${t}</button>`).join('');
    const sync = () => el.querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', b.dataset.themeSet === cur()));
    el.onclick = e => { const b = e.target.closest('[data-theme-set]'); if (!b) return; document.documentElement.dataset.theme = b.dataset.themeSet; try { localStorage.setItem('cls_theme', b.dataset.themeSet); } catch {} document.dispatchEvent(new Event('cls-theme')); };
    document.addEventListener('cls-theme', sync);
    sync();
  }
  window.mountThemeSwitch = mountThemeSwitch;

  // Click a hash / address cell → copy exactly that one value (plain text, so Excel pastes one cell).
  function copyValue(text, near) {
    text = String(text || '').trim(); if (!text) return;
    const done = ok => {
      let t = document.getElementById('cls-copied');
      if (!t) { t = document.createElement('div'); t.id = 'cls-copied'; t.setAttribute('role', 'status'); t.style.cssText = 'position:fixed;z-index:2000;padding:6px 10px;border-radius:7px;font:600 12px system-ui,sans-serif;background:#17202b;color:#fff;box-shadow:0 4px 14px rgba(0,0,0,.25);pointer-events:none;transition:opacity .2s'; document.body.appendChild(t); }
      t.textContent = ok ? 'Copied: ' + (text.length > 22 ? text.slice(0, 10) + '…' + text.slice(-8) : text) : 'Press Cmd/Ctrl+C to copy';
      const r = near?.getBoundingClientRect?.() || {left: innerWidth / 2, top: 20, bottom: 40};
      t.style.left = Math.max(8, Math.min(r.left, innerWidth - 260)) + 'px'; t.style.top = (r.bottom + 6 > innerHeight - 40 ? r.top - 34 : r.bottom + 6) + 'px'; t.style.opacity = '1';
      clearTimeout(t._h); t._h = setTimeout(() => { t.style.opacity = '0'; }, 1400);
    };
    const fallback = () => { const ta = document.createElement('textarea'); ta.value = text; ta.style.cssText = 'position:fixed;opacity:0'; document.body.appendChild(ta); ta.select(); let ok = false; try { ok = document.execCommand('copy'); } catch {} ta.remove(); done(ok); };
    if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(() => done(true), fallback); else fallback();
  }
  // one delegated handler for every table with data-copy cells (viewer + classifier results)
  document.addEventListener('click', e => {
    const td = e.target.closest('td[data-copy]'); if (!td) return;
    const sel = getSelection(); if (sel && !sel.isCollapsed && sel.toString().trim()) return; // user is selecting text on purpose
    copyValue(td.dataset.copy, td);
  });
  window.copyValue = copyValue;
  window.openTxViewer = openTxViewer;
  window.readClassifierExcel = readClassifierExcel;
  window.fixClassifierDates = fixDates;
  window.downloadClassifierRows = download;
})();
