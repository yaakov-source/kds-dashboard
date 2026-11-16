/* KDS Law dashboard sign-in gate: decrypts data.enc.js (data + renderer) and runs it. */
(function () {
  var E = window.KDS_ENC, S = window.crypto && window.crypto.subtle;
  var form = document.querySelector('#gate form'), err = document.querySelector('#gate .err');
  var btn = form.querySelector('button[type="submit"]'), KEY = 'kds_k_v1';
  function ub(s) { var b = atob(s), u = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
  function bu(u) { var s = ''; for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); }
  function forgetSaved() { try { sessionStorage.removeItem(KEY); } catch (e) {} }
  function reset(message) { btn.disabled = false; btn.textContent = 'View dashboard'; err.textContent = message || ''; }
  function open(K) {
    return S.importKey('raw', K, 'AES-GCM', false, ['decrypt'])
      .then(function (k) { return S.decrypt({ name: 'AES-GCM', iv: ub(E.iv) }, k, ub(E.ct)); })
      .then(function (pt) {
        document.body.classList.remove('is-locked');
        (0, eval)(new TextDecoder().decode(pt));
      })
      .then(function () { try { sessionStorage.setItem(KEY, bu(K)); } catch (e) {} });
  }
  function unwrap(u, p) {
    var a = E.users[u]; if (!a) return Promise.reject(new Error('bad'));
    return S.importKey('raw', new TextEncoder().encode(u + ':' + p), 'PBKDF2', false, ['deriveKey'])
      .then(function (base) { return S.deriveKey({ name: 'PBKDF2', salt: ub(a.salt), iterations: E.iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']); })
      .then(function (kek) { return S.decrypt({ name: 'AES-GCM', iv: ub(a.iv) }, kek, ub(a.wk)); })
      .then(function (K) { return new Uint8Array(K); });
  }
  // Install the guard before checking dependencies: failed scripts or unavailable
  // WebCrypto must never submit credentials as a normal form navigation.
  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    if (!E || !S || btn.disabled) return;
    err.textContent = '';
    var u = document.getElementById('gate-u').value.trim().toLowerCase(), p = document.getElementById('gate-p').value.trim().toUpperCase();
    if (!u || !p) { reset('Enter your dashboard username and password.'); return; }
    if (u.indexOf('@') !== -1) { reset('Use your dashboard username, not your email address.'); document.getElementById('gate-u').focus(); return; }
    btn.disabled = true; btn.textContent = 'Checking…';
    Promise.resolve().then(function () { return unwrap(u, p); }).then(function (K) {
      return open(K).catch(function (e) { document.body.classList.add('is-locked'); reset('Signed in, but the dashboard failed to load (' + (e && (e.name || e.message) || 'error') + '). Refresh and try again.'); });
    }, function () { reset('That username and password don\u2019t match.'); document.getElementById('gate-p').select(); });
  });
  var show = document.getElementById('gate-show');
  if (show) show.addEventListener('click', function () {
    var input = document.getElementById('gate-p'), visible = input.type === 'password';
    input.type = visible ? 'text' : 'password'; show.textContent = visible ? 'Hide' : 'Show';
    show.setAttribute('aria-pressed', String(visible)); show.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
  });
  if (!E || !E.users || !S) {
    btn.disabled = true;
    err.textContent = !S ? 'A secure connection is required. Open https://kds.haicreative.com/ in Safari or Chrome.' : 'The sign-in files could not load. Refresh this page and try again.';
    return;
  }
  reset();
  var saved = null; try { saved = sessionStorage.getItem(KEY); } catch (e) {}
  // Decode inside the promise boundary: a damaged saved key must not prevent
  // a fresh sign-in or leave the form without its submit handler.
  if (saved) {
    btn.disabled = true;
    Promise.resolve().then(function () { return open(ub(saved)); }).then(function () { reset(); }, function () {
      forgetSaved(); document.body.classList.add('is-locked'); reset('Your saved session could not be restored. Please sign in again.');
    });
  } else if (document.activeElement === document.body) {
    // Do not steal focus from a password manager or someone already typing.
    document.getElementById('gate-u').focus();
  }
})();
