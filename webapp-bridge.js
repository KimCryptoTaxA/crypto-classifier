/*
 * Bridge between the Crypto Transaction Classifier and the Crypto Validation Database web app.
 *
 * Only does anything when the classifier is shown INSIDE the web app (an iframe whose parent is an
 * Apps Script page on *.googleusercontent.com). Opened on its own, the classifier behaves exactly as before.
 *
 * Inside the web app it:
 *  - answers the classifier's "/helper-health" check, so the helper-only features switch on
 *    (Blockscout PRO, Cardano, Casper, exchange labels; Bitcoin xpub is faster);
 *  - sends the requests the classifier would send to the local helper (/proxy/..., /bsproxy/...)
 *    to the web app, which forwards them from Google's servers to the allowed hosts;
 *  - fills in the wallet addresses and dates when the web app opens it for a client.
 */
(function () {
  if (window.parent === window) return;

  var realFetch = window.fetch.bind(window);
  var parentOrigin = null, seq = 0, pending = {};
  var isAppsScript = function (origin) {
    try { return /\.googleusercontent\.com$/.test(new URL(origin).hostname); } catch (e) { return false; }
  };
  var needsBridge = function (u) { return /^\/(helper-health|proxy\/|bsproxy\/)/.test(u); };

  function note(text) {
    var go = function () {
      if (!document.body) return setTimeout(go, 100);
      var el = document.getElementById('cvdBridgeNote');
      if (!el) {
        el = document.createElement('div');
        el.id = 'cvdBridgeNote';
        el.style.cssText = 'position:sticky;top:0;z-index:50;background:#0f766e;color:#fff;font:13px/1.4 system-ui,sans-serif;padding:8px 14px';
        document.body.insertBefore(el, document.body.firstChild);
      }
      el.textContent = text;
    };
    go();
  }

  function applyPrefill(d) {
    var go = function () {
      var a = document.getElementById('addrs');
      if (!a) return setTimeout(go, 150);
      if (d.addresses && d.addresses.length) a.value = d.addresses.join('\n');
      if (d.from && document.getElementById('dFrom')) document.getElementById('dFrom').value = d.from;
      if (d.to && document.getElementById('dTo')) document.getElementById('dTo').value = d.to;
      note('Connected to the Crypto Validation Database · ' + (d.label || '') + ' · ' + (d.addresses ? d.addresses.length : 0) +
        ' wallet address(es) loaded' + (d.from ? ' · ' + d.from + ' to ' + d.to : '') + '. Press ① Scan to start.');
      a.scrollIntoView({ block: 'center' });
    };
    go();
  }

  window.addEventListener('message', function (e) {
    var d = e.data;
    if (!d || d.cvd !== 1 || e.source !== window.parent) return;
    if (d.type === 'hello-ack' && !parentOrigin && isAppsScript(e.origin)) {
      parentOrigin = e.origin;
      note('Connected to the Crypto Validation Database: helper features (Blockscout PRO, Cardano, Casper, exchange labels) are on.');
    }
    if (e.origin !== parentOrigin) return;
    if (d.type === 'proxy-res' && pending[d.id]) { pending[d.id](d); delete pending[d.id]; }
    if (d.type === 'prefill') applyPrefill(d);
  });

  window.fetch = function (input, init) {
    var url = typeof input === 'string' ? input : (input && input.url) || '';
    if (!needsBridge(url) || !parentOrigin) return realFetch(input, init);
    if (url.indexOf('/helper-health') === 0) {
      return Promise.resolve(new Response('{"ok":true,"version":2,"via":"web app"}', { status: 200, headers: { 'Content-Type': 'application/json' } }));
    }
    return new Promise(function (resolve, reject) {
      var id = ++seq;
      var timer = setTimeout(function () { delete pending[id]; reject(new Error('The web app did not answer in time')); }, 120000);
      pending[id] = function (d) {
        clearTimeout(timer);
        if (d.error) reject(new Error(d.error));
        else resolve(new Response(d.body, { status: d.status, headers: { 'Content-Type': d.ctype || 'application/json' } }));
      };
      var headers = {};
      if (init && init.headers) {
        var h = new Headers(init.headers);
        if (h.get('Authorization')) headers.Authorization = h.get('Authorization');
        if (h.get('Content-Type')) headers['Content-Type'] = h.get('Content-Type');
        if (h.get('X-Api-Key')) headers['X-Api-Key'] = h.get('X-Api-Key');
      }
      window.parent.postMessage({ cvd: 1, type: 'proxy', id: id, path: url, method: (init && init.method) || 'GET',
        body: init && typeof init.body === 'string' ? init.body : null, headers: headers }, parentOrigin);
    });
  };

  window.parent.postMessage({ cvd: 1, type: 'hello' }, '*');
})();
