/*
 * Crypto Transaction Classifier — Excel export (ExcelJS).
 * Sheets:
 *   Transactions  – CoinTracking columns, unchanged order (import this sheet)
 *   Totals        – matrix: wallets × groups (Transfers, DeFi, Bridges, Staking, NFTs, Spam, Fees & other), plus category breakdown
 *   Summary       – rows per wallet and category
 *   Wallets       – wallet names, chains, addresses, notes
 * Searching is done in the "View transactions" window (tx-viewer.js), which can download all rows or only the matching ones.
 */
(function () {
  const GROUPS = ['Transfers', 'DeFi & Swaps', 'Bridges', 'Staking', 'NFTs', 'Spam', 'Fees & other'];
  const COLORS = {head: 'FF0F766E', headFont: 'FFFFFFFF', input: 'FFFFF7CC', inputBorder: 'FFE0B400', band: 'FFF1F5F9', total: 'FFE6F4F1', spam: 'FFFDE2E2', note: 'FF52606D'};

  function groupOf(r) {
    const t = String(r.Type || ''), c = String(r.Category || '');
    if (/Scam\/Spam|poisoning|scam address/i.test(c)) return 'Spam';
    if (/^NFT/i.test(c)) return 'NFTs';
    if (/Bridge/i.test(c)) return 'Bridges';
    if (/Stak|Reward|Unbond|Delegat|Nominat|Validator|Mining|Block Reward/i.test(c) || /^(Staking|Mining)$/i.test(t)) return 'Staking';
    if (/DeFi|Swap|Liquidity|Lending|Borrow|Repay|Collateral|Trade/i.test(c) || /^Trade$/i.test(t)) return 'DeFi & Swaps';
    if (/Transfer|Exchange|Deposit|Withdraw|Payment|Airdrop|Gift|Income/i.test(c) || /^(Deposit|Withdrawal|Income|Airdrop)$/i.test(t)) return 'Transfers';
    return 'Fees & other';
  }

  const colLetter = n => { let s = ''; while (n > 0) { const m = (n - 1) % 26; s = String.fromCharCode(65 + m) + s; n = Math.floor((n - 1) / 26); } return s; };
  const headStyle = cell => { cell.font = {bold: true, color: {argb: COLORS.headFont}}; cell.fill = {type: 'pattern', pattern: 'solid', fgColor: {argb: COLORS.head}}; cell.alignment = {vertical: 'middle'}; };
  const box = cell => { cell.fill = {type: 'pattern', pattern: 'solid', fgColor: {argb: COLORS.input}}; const b = {style: 'thin', color: {argb: COLORS.inputBorder}}; cell.border = {top: b, left: b, bottom: b, right: b}; };

  async function buildWorkbook(rows, COLS, WALLETS) {
    const wb = new ExcelJS.Workbook(); wb.creator = 'Crypto Transaction Classifier'; wb.created = new Date();
    const N = rows.length, last = Math.max(N + 1, 2), col = name => colLetter(COLS.indexOf(name) + 1);

    /* ---- Transactions (CoinTracking import sheet: same columns, same order) ---- */
    const tx = wb.addWorksheet('Transactions', {views: [{state: 'frozen', ySplit: 1}]});
    tx.columns = COLS.map(c => ({header: c, key: c, width: {Comments: 90, 'Transaction Hash': 68, 'Liquidity Pool Address': 44, 'Wallet Address': 44, 'Explorer Link': 50, Date: 20, Category: 26, Type: 14}[c] || 15}));
    rows.forEach(r => tx.addRow(COLS.map(c => r[c] ?? '')));
    tx.getRow(1).eachCell(headStyle);
    tx.autoFilter = {from: 'A1', to: `${colLetter(COLS.length)}1`};
    const catCol = COLS.indexOf('Category') + 1;
    for (let i = 2; i <= N + 1; i++) if (tx.getCell(i, catCol).value === 'Scam/Spam') tx.getRow(i).eachCell(c => { c.fill = {type: 'pattern', pattern: 'solid', fgColor: {argb: COLORS.spam}}; });

    const wallets = [...new Set(rows.map(r => r['Exchange/Wallet Name']).filter(Boolean).map(String))].sort();

    /* ---- Totals (matrix) ---- */
    const t = wb.addWorksheet('Totals');
    t.getCell('A1').value = 'Totals by wallet and group'; t.getCell('A1').font = {bold: true, size: 16, color: {argb: COLORS.head}};
    t.getCell('A2').value = `Number of rows in the Transactions sheet (${N.toLocaleString()} rows). Groups: DeFi & Swaps = swaps, liquidity, lending; Staking = rewards, delegations, mining; Spam = scam/spam and address poisoning.`;
    t.getCell('A2').font = {italic: true, color: {argb: COLORS.note}};
    const M = {}; rows.forEach(r => { const w = r['Exchange/Wallet Name'] || '(none)', g = groupOf(r); (M[w] = M[w] || {})[g] = (M[w][g] || 0) + 1; });
    const hdr = ['Exchange/Wallet Name', 'Chain', ...GROUPS, 'Total'];
    hdr.forEach((h, i) => { const c = t.getCell(4, i + 1); c.value = h; headStyle(c); c.alignment = {horizontal: i > 1 ? 'center' : 'left'}; });
    const chainOf = w => (WALLETS.find(x => x.wallet === w) || {}).chain || '';
    wallets.forEach((w, j) => {
      const row = 5 + j; t.getCell(row, 1).value = w; t.getCell(row, 2).value = chainOf(w);
      GROUPS.forEach((g, k) => { const c = t.getCell(row, 3 + k); c.value = (M[w] || {})[g] || 0; c.alignment = {horizontal: 'center'}; if (g === 'Spam' && c.value) c.font = {color: {argb: 'FFB42318'}, bold: true}; });
      const tc = t.getCell(row, 3 + GROUPS.length); tc.value = {formula: `SUM(C${row}:${colLetter(2 + GROUPS.length)}${row})`, result: Object.values(M[w] || {}).reduce((a, b) => a + b, 0)}; tc.font = {bold: true}; tc.alignment = {horizontal: 'center'};
      if (j % 2) for (let k = 1; k <= hdr.length; k++) t.getCell(row, k).fill = {type: 'pattern', pattern: 'solid', fgColor: {argb: COLORS.band}};
    });
    const tr = 5 + wallets.length; t.getCell(tr, 1).value = 'TOTAL';
    for (let k = 3; k <= hdr.length; k++) { const L = colLetter(k), c = t.getCell(tr, k); c.value = {formula: `SUM(${L}5:${L}${tr - 1})`, result: 0}; c.alignment = {horizontal: 'center'}; }
    for (let k = 1; k <= hdr.length; k++) { const c = t.getCell(tr, k); c.font = {bold: true}; c.fill = {type: 'pattern', pattern: 'solid', fgColor: {argb: COLORS.total}}; c.border = {top: {style: 'medium', color: {argb: COLORS.head}}}; }
    t.getColumn(1).width = 26; t.getColumn(2).width = 16; for (let k = 3; k <= hdr.length; k++) t.getColumn(k).width = 13;

    // breakdown: which categories make up each group
    let br = tr + 3; t.getCell(br, 1).value = 'What is in each group'; t.getCell(br, 1).font = {bold: true, size: 13, color: {argb: COLORS.head}}; br++;
    ['Group', 'Category', 'Rows'].forEach((h, i) => headStyle(Object.assign(t.getCell(br, i + 1), {value: h}))); br++;
    const byCat = {}; rows.forEach(r => { const k = groupOf(r) + '|' + r.Category; byCat[k] = (byCat[k] || 0) + 1; });
    GROUPS.forEach(g => Object.entries(byCat).filter(([k]) => k.startsWith(g + '|')).sort((a, b) => b[1] - a[1]).forEach(([k, v]) => {
      t.getCell(br, 1).value = g; t.getCell(br, 2).value = k.split('|')[1]; t.getCell(br, 3).value = v; t.getCell(br, 3).alignment = {horizontal: 'center'}; br++;
    }));

    /* ---- Summary + Wallets (as before) ---- */
    const su = wb.addWorksheet('Summary'); su.columns = [{header: 'Exchange/Wallet Name', width: 24}, {header: 'Category', width: 36}, {header: 'Rows', width: 8}];
    const sum = {}; rows.forEach(r => { const k = r['Exchange/Wallet Name'] + '|' + r.Category; sum[k] = (sum[k] || 0) + 1; });
    Object.entries(sum).map(([k, v]) => [...k.split('|'), v]).sort((x, y) => x[0].localeCompare(y[0]) || y[2] - x[2]).forEach(r => su.addRow(r)); su.getRow(1).eachCell(headStyle);
    const ww = wb.addWorksheet('Wallets'); ww.columns = [{header: 'Exchange/Wallet Name', width: 22}, {header: 'Chain', width: 18}, {header: 'Wallet Address', width: 50}, {header: 'Rows', width: 8}, {header: 'Notes', width: 80}];
    WALLETS.forEach(w => ww.addRow([w.wallet, w.chain, w.addr, w.rows, w.note])); ww.getRow(1).eachCell(headStyle);

    // Transactions stays the first sheet (CoinTracking imports it); the file opens on it.
    wb.views = [{activeTab: 0}];
    return wb;
  }

  async function exportClassifierWorkbook(rows, COLS, WALLETS, filename) {
    const wb = await buildWorkbook(rows, COLS, WALLETS);
    const buf = await wb.xlsx.writeBuffer();
    const url = URL.createObjectURL(new Blob([buf], {type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}));
    const a = document.createElement('a'); a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    return buf;
  }

  window.buildClassifierWorkbook = buildWorkbook;
  window.exportClassifierWorkbook = exportClassifierWorkbook;
  window.classifierGroupOf = groupOf;
  window.CLASSIFIER_GROUPS = GROUPS;
})();
