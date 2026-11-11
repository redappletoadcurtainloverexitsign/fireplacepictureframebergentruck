// Sign-in gate: Google (when CLIENT_ID is set) or username + password.
(function () {
  var CLIENT_ID = ''; // <-- paste your Google OAuth Web Client ID here to add the Google button
  var ALLOWED_EMAILS = []; // optional Google restriction
  var ALLOWED_DOMAINS = []; // optional Google restriction
  // Admin account: only this username + password unlocks the admin panel (stored as a salted PBKDF2 hash, not the password).
  var ADMIN_USER = 'gecko', ADMIN_SALT = 'de0b41140e6d2c8e4988b6128ed68462', ADMIN_HASH = 'bd6caf8fe087aac20b3d8b7da3b344aab354ce324ae207fee0c91be23fe8e586';
  // Firebase web config (paste the object from Firebase console > Project settings > Your apps). Empty = device-only accounts.
  var FIREBASE_CONFIG = {};
  var SESSION = 'novaAuth', USERS = 'novaUsers', DAYS = 7;
  // ---------- Online mode (Firebase): shared accounts, sign-in tracking, delete, lockdown ----------
  function fbMode(cfg) {
    var root = document.documentElement;
    root.style.visibility = 'hidden';
    var ADMIN_EMAIL = 'gecko@nova-games.local', DOMAIN = '@nova-games.local';
    var base = 'https://www.gstatic.com/firebasejs/10.12.2/';
    var S = { user: null, admin: false, verified: false, authReady: false, lockReady: false, locked: false, msg: '' };
    var auth, db, FV, overlay, mode = 'in', adminBtn, adminPanel, usersView, unsubUsers;

    function ready(f) { if (document.body) f(); else document.addEventListener('DOMContentLoaded', f); }
    function el(tag, css, txt) { var e = document.createElement(tag); if (css) e.style.cssText = css; if (txt != null) e.textContent = txt; return e; }
    function stop(text) {
      ready(function () {
        var o = el('div', 'position:fixed;inset:0;z-index:2147483647;background:#000;color:#fff;display:flex;align-items:center;justify-content:center;font-family:sans-serif;text-align:center;visibility:visible;padding:16px', text);
        document.body.appendChild(o); root.style.visibility = 'visible';
      });
    }
    function load(list, done) {
      var i = 0;
      (function next() {
        if (i >= list.length) return done();
        var s = document.createElement('script'); s.src = base + list[i++];
        s.onload = next; s.onerror = function () { stop('Could not reach the sign-in service. Check your connection and reload.'); };
        document.head.appendChild(s);
      })();
    }
    function friendly(e) {
      var c = e && e.code || '';
      if (c === 'auth/email-already-in-use') return 'That username is taken.';
      if (c === 'auth/invalid-credential' || c === 'auth/wrong-password' || c === 'auth/user-not-found' || c === 'auth/invalid-email') return 'Wrong username or password.';
      if (c === 'auth/too-many-requests') return 'Too many tries. Wait a minute and try again.';
      if (c === 'auth/weak-password') return 'Password must be at least 6 characters.';
      if (c === 'auth/popup-closed-by-user' || c === 'auth/cancelled-popup-request') return '';
      if (c === 'auth/operation-not-allowed') return 'This sign-in method is not turned on yet.';
      if (c === 'auth/unauthorized-domain') return 'This website is not authorized for Google sign-in yet.';
      return 'Something went wrong. Try again.';
    }
    function record(user, username, method) {
      var ref = db.doc('users/' + user.uid);
      return ref.get().then(function (s) {
        if (s.exists) {
          if (s.data().deleted) return 'deleted';
          return ref.update({ lastLogin: FV.serverTimestamp(), signInCount: FV.increment(1) }).then(function () { return 'ok'; });
        }
        return ref.set({ username: username, method: method, createdAt: FV.serverTimestamp(), lastLogin: FV.serverTimestamp(), signInCount: 1, deleted: false }).then(function () { return 'ok'; });
      });
    }

    function buildGate() {
      var o = el('div', 'position:fixed;inset:0;z-index:2147483647;background:#000;color:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:sans-serif;text-align:center;visibility:visible;padding:16px;overflow:auto');
      var inp = 'display:block;width:260px;max-width:100%;box-sizing:border-box;margin:8px auto;padding:10px;border-radius:6px;border:1px solid #444;background:#111;color:#fff;font-size:16px';
      var btn = 'margin-top:8px;padding:10px 28px;border-radius:6px;border:0;background:#2d6cff;color:#fff;font-size:16px;cursor:pointer';
      var title = el('p', 'margin:0 0 16px;color:#aaa', 'Sign in to continue');
      var banner = el('p', 'margin:0 0 12px;color:#ffb347;display:none', 'The site is under lockdown. Only the admin can sign in right now.');
      var form = el('form'); var user = el('input', inp), pass = el('input', inp), pass2 = el('input', inp + ';display:none');
      user.placeholder = 'Username'; user.autocomplete = 'username'; user.autocapitalize = 'off'; user.setAttribute('autocorrect', 'off');
      pass.type = 'password'; pass.placeholder = 'Password'; pass.autocomplete = 'current-password';
      pass2.type = 'password'; pass2.placeholder = 'Confirm password'; pass2.autocomplete = 'new-password';
      var go = el('button', btn, 'Sign in'); go.type = 'submit';
      form.appendChild(user); form.appendChild(pass); form.appendChild(pass2); form.appendChild(go);
      var gbtn = el('button', 'margin-top:12px;padding:10px 20px;border-radius:6px;border:1px solid #444;background:#fff;color:#222;font-size:15px;cursor:pointer', 'Sign in with Google'); gbtn.type = 'button';
      var swap = el('a', 'color:#7aa7ff;cursor:pointer', 'New here? Create an account');
      var rec = el('a', 'color:#7aa7ff;cursor:pointer', 'Recover account');
      var msg = el('p', 'color:#f66;margin:12px 0 0;min-height:1.2em;max-width:300px');
      var p1 = el('p', 'margin:14px 0 0'); p1.appendChild(swap);
      var p2 = el('p', 'margin:8px 0 0'); p2.appendChild(rec);
      [el('h1', 'margin:0 0 6px', 'Nova Games'), title, banner, form, gbtn, p1, p2, msg].forEach(function (n) { o.appendChild(n); });
      function render() {
        var up = mode === 'up';
        title.textContent = up ? 'Create your account' : 'Sign in to continue';
        pass2.style.display = up ? 'block' : 'none'; pass.autocomplete = up ? 'new-password' : 'current-password';
        go.textContent = up ? 'Create account' : 'Sign in'; swap.textContent = up ? 'Back to sign in' : 'New here? Create an account';
        gbtn.style.display = up ? 'none' : ''; p2.style.display = up ? 'none' : '';
        msg.textContent = '';
      }
      swap.onclick = function () { mode = mode === 'in' ? 'up' : 'in'; render(); };
      rec.onclick = function () { msg.textContent = 'Forgot your password? Use "Sign in with Google" if you linked it, or ask the admin for help.'; };
      form.onsubmit = function (e) {
        e.preventDefault(); msg.textContent = '';
        var name = user.value.trim().toLowerCase(), pw = pass.value;
        if (!/^[a-z0-9_]{3,20}$/.test(name)) { msg.textContent = 'Username: 3-20 letters, numbers or _ only.'; return; }
        if (pw.length < 6) { msg.textContent = 'Password must be at least 6 characters.'; return; }
        go.disabled = true;
        var p;
        if (mode === 'up') {
          if (name === 'gecko') { msg.textContent = 'That username is taken.'; go.disabled = false; return; }
          if (pass2.value !== pw) { msg.textContent = 'Passwords do not match.'; go.disabled = false; return; }
          p = auth.createUserWithEmailAndPassword(name + DOMAIN, pw).then(function (c) { return record(c.user, name, 'password'); });
        } else {
          p = auth.signInWithEmailAndPassword(name + DOMAIN, pw).then(function (c) { return c.user.email === ADMIN_EMAIL ? 'ok' : record(c.user, name, 'password'); });
        }
        p.then(function (r) { if (r === 'deleted') { S.msg = 'This account was removed by the admin.'; auth.signOut(); } })
         .catch(function (er) { msg.textContent = friendly(er); })
         .then(function () { go.disabled = false; });
      };
      gbtn.onclick = function () {
        msg.textContent = '';
        auth.signInWithPopup(new firebase.auth.GoogleAuthProvider()).then(function (c) {
          return record(c.user, c.user.displayName || c.user.email || 'google user', 'google');
        }).then(function (r) { if (r === 'deleted') { S.msg = 'This account was removed by the admin.'; auth.signOut(); } })
          .catch(function (er) { msg.textContent = friendly(er); });
      };
      o._banner = banner; o._msg = msg; render();
      return o;
    }

    function adminUI() {
      if (adminBtn) return;
      adminBtn = el('button', 'position:fixed;right:12px;bottom:12px;z-index:2147483000;padding:8px 14px;border-radius:8px;border:1px solid #444;background:#111;color:#fff;font:14px sans-serif;cursor:pointer;opacity:.9', 'Admin');
      adminPanel = el('div', 'display:none;position:fixed;right:12px;bottom:56px;z-index:2147483000;width:260px;max-width:calc(100vw - 24px);padding:14px;border-radius:10px;border:1px solid #444;background:#111;color:#fff;font:14px sans-serif');
      var bs = 'display:block;width:100%;margin:6px 0;padding:9px;border-radius:6px;border:0;color:#fff;font-size:14px;cursor:pointer;background:#2d6cff';
      var users = el('button', bs, 'Users & sign-ins'), lock = el('button', bs, ''), out = el('button', bs + ';background:#555', 'Sign out');
      adminPanel.appendChild(el('div', 'font-weight:bold;margin-bottom:6px', 'Admin panel'));
      [users, lock, out].forEach(function (b) { adminPanel.appendChild(b); });
      adminPanel._lock = lock; adminPanel._sync = function () { lock.textContent = S.locked ? 'Lockdown is ON - tap to end' : 'Start lockdown'; lock.style.background = S.locked ? '#c33' : '#2d6cff'; };
      adminPanel._sync();
      adminBtn.onclick = function () { adminPanel.style.display = adminPanel.style.display === 'none' ? 'block' : 'none'; };
      users.onclick = openUsers;
      lock.onclick = function () {
        var on = !S.locked;
        if (!confirm(on ? 'Lock the whole website for everyone except you?' : 'End the lockdown and let everyone back in?')) return;
        db.doc('config/site').set({ locked: on }, { merge: true }).catch(function () { alert('Could not change lockdown. Check the Firestore rules.'); });
      };
      out.onclick = function () { auth.signOut(); };
      document.body.appendChild(adminBtn); document.body.appendChild(adminPanel);
    }
    function removeAdminUI() {
      [adminBtn, adminPanel, usersView].forEach(function (n) { if (n && n.parentNode) n.parentNode.removeChild(n); });
      adminBtn = adminPanel = usersView = null; if (unsubUsers) { unsubUsers(); unsubUsers = null; }
    }
    function openUsers() {
      if (usersView) return;
      usersView = el('div', 'position:fixed;inset:0;z-index:2147483001;background:#000;color:#fff;font:14px sans-serif;overflow:auto;padding:16px');
      var top = el('div', 'display:flex;justify-content:space-between;align-items:center;margin-bottom:12px');
      var h = el('h2', 'margin:0', 'Users & sign-ins'); var close = el('button', 'padding:8px 14px;border-radius:6px;border:0;background:#555;color:#fff;cursor:pointer', 'Close');
      top.appendChild(h); top.appendChild(close);
      var info = el('p', 'color:#aaa;margin:0 0 10px', 'Loading...'); var list = el('div');
      usersView.appendChild(top); usersView.appendChild(info); usersView.appendChild(list); document.body.appendChild(usersView);
      close.onclick = function () { if (unsubUsers) { unsubUsers(); unsubUsers = null; } usersView.parentNode.removeChild(usersView); usersView = null; };
      function fmt(t) { try { return t && t.toDate ? t.toDate().toLocaleString() : '-'; } catch (e) { return '-'; } }
      unsubUsers = db.collection('users').orderBy('lastLogin', 'desc').limit(500).onSnapshot(function (snap) {
        info.textContent = snap.size + ' account' + (snap.size === 1 ? '' : 's');
        list.textContent = '';
        snap.forEach(function (d) {
          var x = d.data(), row = el('div', 'border:1px solid #333;border-radius:8px;padding:10px;margin:8px 0;display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap');
          var left = el('div', 'min-width:200px');
          left.appendChild(el('div', 'font-weight:bold;word-break:break-all', (x.username || '?') + (x.deleted ? '  (deleted)' : '')));
          left.appendChild(el('div', 'color:#aaa', 'via ' + (x.method || '?') + ' | signed in ' + (x.signInCount || 0) + ' time(s)'));
          left.appendChild(el('div', 'color:#aaa', 'created ' + fmt(x.createdAt)));
          left.appendChild(el('div', 'color:#aaa', 'last sign-in ' + fmt(x.lastLogin)));
          var b = el('button', 'padding:8px 14px;border-radius:6px;border:0;color:#fff;cursor:pointer;background:' + (x.deleted ? '#2d6cff' : '#c33'), x.deleted ? 'Restore' : 'Delete');
          b.onclick = function () {
            if (!x.deleted && !confirm('Delete the account "' + x.username + '"? They will be signed out and blocked.')) return;
            d.ref.update({ deleted: !x.deleted }).catch(function () { alert('Could not update. Check the Firestore rules.'); });
          };
          row.appendChild(left); row.appendChild(b); list.appendChild(row);
        });
      }, function () { info.textContent = 'Could not load users. Check the Firestore rules.'; });
    }

    function render() {
      if (!S.authReady || !S.lockReady) return;
      ready(function () {
        var allowed = S.user && S.verified && (S.admin || !S.locked);
        if (S.user && S.verified && S.locked && !S.admin) { S.msg = 'The site is under lockdown. Only the admin can sign in right now.'; auth.signOut(); return; }
        if (S.user && !S.verified) return; // still checking the account
        if (allowed) {
          if (overlay) { overlay.parentNode.removeChild(overlay); overlay = null; }
          root.style.visibility = 'visible';
          if (S.admin) { adminUI(); if (adminPanel) adminPanel._sync(); } else removeAdminUI();
        } else {
          removeAdminUI();
          if (!overlay) { mode = 'in'; overlay = buildGate(); document.body.appendChild(overlay); }
          root.style.visibility = 'visible';
          overlay._banner.style.display = S.locked ? 'block' : 'none';
          if (S.msg) { overlay._msg.textContent = S.msg; S.msg = ''; }
        }
      });
    }

    load(['firebase-app-compat.js', 'firebase-auth-compat.js', 'firebase-firestore-compat.js'], function () {
      try {
        firebase.initializeApp(cfg); auth = firebase.auth(); db = firebase.firestore(); FV = firebase.firestore.FieldValue;
      } catch (e) { return stop('Sign-in service is not set up correctly.'); }
      try { auth.setPersistence(firebase.auth.Auth.Persistence.SESSION); } catch (e) {}
      db.doc('config/site').onSnapshot(function (s) { S.locked = !!(s.exists && s.data().locked); S.lockReady = true; render(); },
        function () { S.locked = true; S.lockReady = true; render(); }); // fail closed
      var unsubSelf = null;
      auth.onAuthStateChanged(function (u) {
        if (unsubSelf) { unsubSelf(); unsubSelf = null; }
        S.user = u; S.admin = !!u && u.email === ADMIN_EMAIL; S.verified = false; S.authReady = true;
        if (!u) { render(); return; }
        if (S.admin) { S.verified = true; render(); return; }
        var ref = db.doc('users/' + u.uid), first = true;
        unsubSelf = ref.onSnapshot(function (s) {
          if (s.exists && s.data().deleted) { S.msg = 'This account was removed by the admin.'; auth.signOut(); return; }
          if (first) { first = false; S.verified = true; render(); }
        }, function () { if (first) { first = false; S.verified = true; render(); } });
      });
    });
  }
  if (FIREBASE_CONFIG && FIREBASE_CONFIG.apiKey) { fbMode(FIREBASE_CONFIG); return; }
  function get(k) { try { return JSON.parse(localStorage.getItem(k) || 'null'); } catch (e) { return null; } }
  function set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch (e) { return false; } }
  // Sign-in lasts only for this browser tab/session; reopening the site asks again.
  try { localStorage.removeItem(SESSION); } catch (e) {}
  var a = null;
  try { a = JSON.parse(sessionStorage.getItem(SESSION) || 'null'); } catch (e) {}
  if (a && a.exp * 1000 > Date.now()) {
    if (a.admin && a.user === ADMIN_USER) {
      var addBtn = function () { adminUI(); };
      if (document.body) addBtn(); else document.addEventListener('DOMContentLoaded', addBtn);
    }
    return;
  }
  var root = document.documentElement;
  root.style.visibility = 'hidden';

  function adminUI() {
    if (document.getElementById('novaAdminBtn')) return;
    var b = document.createElement('button');
    b.id = 'novaAdminBtn'; b.textContent = 'Admin';
    b.style.cssText = 'position:fixed;right:12px;bottom:12px;z-index:2147483000;padding:8px 14px;border-radius:8px;border:1px solid #444;background:#111;color:#fff;font:14px sans-serif;cursor:pointer;opacity:.85';
    var p = document.createElement('div');
    p.style.cssText = 'display:none;position:fixed;right:12px;bottom:56px;z-index:2147483000;width:280px;max-width:calc(100vw - 24px);padding:14px;border-radius:10px;border:1px solid #444;background:#111;color:#fff;font:14px sans-serif';
    p.innerHTML = '<div style="font-weight:bold;margin-bottom:8px">Admin panel</div><p id="novaAdminBody" style="color:#aaa;margin:0 0 10px">Buttons coming soon.</p><button id="novaAdminOut" style="padding:8px 14px;border-radius:6px;border:0;background:#c33;color:#fff;cursor:pointer">Sign out</button>';
    b.onclick = function () { p.style.display = p.style.display === 'none' ? 'block' : 'none'; };
    document.body.appendChild(b); document.body.appendChild(p);
    document.getElementById('novaAdminOut').onclick = function () { try { sessionStorage.removeItem(SESSION); } catch (e) {} location.reload(); };
  }
  function adminHash(pw) {
    return crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']).then(function (k) {
      return crypto.subtle.deriveBits({ name: 'PBKDF2', salt: new TextEncoder().encode(ADMIN_SALT), iterations: 200000, hash: 'SHA-256' }, k, 256);
    }).then(hex);
  }
  function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); }
  function hash(salt, pw) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(salt + ':' + pw)).then(hex);
  }
  function newCode() {
    var al = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789', r = crypto.getRandomValues(new Uint8Array(16)), c = '';
    for (var i = 0; i < 16; i++) { c += al[r[i] % al.length]; if (i % 4 === 3 && i < 15) c += '-'; }
    return c;
  }
  function normCode(c) { return c.toUpperCase().replace(/[^A-Z0-9]/g, ''); }
  function login(name, admin) {
    try { sessionStorage.setItem(SESSION, JSON.stringify({ user: name, admin: !!admin, exp: Date.now() / 1000 + DAYS * 86400 })); } catch (e) {}
    location.reload();
  }

  function build() {
    var mode = 'in';
    var o = document.createElement('div');
    o.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:#000;color:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:sans-serif;text-align:center;visibility:visible;padding:16px';
    var inp = 'display:block;width:260px;max-width:100%;box-sizing:border-box;margin:8px auto;padding:10px;border-radius:6px;border:1px solid #444;background:#111;color:#fff;font-size:16px';
    o.innerHTML =
      '<h1 style="margin:0 0 6px">Nova Games</h1>' +
      '<p id="nTitle" style="margin:0 0 16px;color:#aaa">Sign in to continue</p>' +
      '<div id="nGoogle"></div>' +
      '<form id="nForm" autocomplete="on">' +
      '<input id="nUser" style="' + inp + '" placeholder="Username" autocomplete="username" autocapitalize="off" autocorrect="off">' +
      '<input id="nPass" type="password" style="' + inp + '" placeholder="Password" autocomplete="current-password">' +
      '<input id="nPass2" type="password" style="' + inp + ';display:none" placeholder="Confirm password" autocomplete="new-password">' +
      '<input id="nCode" style="' + inp + ';display:none" placeholder="Recovery code (XXXX-XXXX-XXXX-XXXX)" autocomplete="off" autocapitalize="characters" autocorrect="off">' +
      '<button id="nGo" type="submit" style="margin-top:8px;padding:10px 28px;border-radius:6px;border:0;background:#2d6cff;color:#fff;font-size:16px;cursor:pointer">Sign in</button>' +
      '</form>' +
      '<p style="margin:14px 0 0"><a id="nSwap" href="#" style="color:#7aa7ff">New here? Create an account</a></p>' +
      '<p style="margin:8px 0 0"><a id="nRec" href="#" style="color:#7aa7ff">Recover account</a></p>' +
      '<p id="nMsg" style="color:#f66;margin:12px 0 0;min-height:1.2em"></p>';
    document.body.appendChild(o);
    root.style.visibility = 'visible';
    function $(id) { return document.getElementById(id); }
    function msg(t) { $('nMsg').textContent = t; }
    function render() {
      var c = mode === 'up', r = mode === 'rec';
      $('nForm').style.display = '';
      $('nTitle').textContent = c ? 'Create your account' : r ? 'Recover your account' : 'Sign in to continue';
      $('nPass2').style.display = (c || r) ? 'block' : 'none';
      $('nCode').style.display = r ? 'block' : 'none';
      $('nPass').placeholder = r ? 'New password' : 'Password';
      $('nPass').autocomplete = (c || r) ? 'new-password' : 'current-password';
      $('nGo').textContent = c ? 'Create account' : r ? 'Reset password' : 'Sign in';
      $('nSwap').textContent = mode === 'in' ? 'New here? Create an account' : 'Back to sign in';
      $('nRec').style.display = mode === 'in' ? '' : 'none';
      msg('');
    }
    $('nSwap').onclick = function (e) { e.preventDefault(); mode = mode === 'in' ? 'up' : 'in'; render(); };
    $('nRec').onclick = function (e) { e.preventDefault(); mode = 'rec'; render(); };
    $('nForm').onsubmit = function (e) {
      e.preventDefault();
      var name = $('nUser').value.trim().toLowerCase(), pw = $('nPass').value;
      if (!window.crypto || !crypto.subtle) { msg('This browser cannot sign in securely. Use HTTPS.'); return; }
      if (name.length < 3) { msg('Username must be at least 3 characters.'); return; }
      if (pw.length < 6) { msg('Password must be at least 6 characters.'); return; }
      var users = get(USERS) || {};
      if (mode === 'up') {
        if ($('nPass2').value !== pw) { msg('Passwords do not match.'); return; }
        if (name === ADMIN_USER || users[name]) { msg('That username is taken. Sign in instead.'); return; }
        var salt = hex(crypto.getRandomValues(new Uint8Array(16)));
        var code = newCode();
        Promise.all([hash(salt, pw), hash(salt, 'rec:' + normCode(code))]).then(function (hs) {
          users[name] = { salt: salt, hash: hs[0], rec: hs[1] };
          if (!set(USERS, users)) { msg('Could not save your account (private mode?).'); return; }
          $('nForm').style.display = 'none'; $('nSwap').parentNode.style.display = 'none'; $('nRec').parentNode.style.display = 'none';
          $('nTitle').textContent = 'Account created! Save your recovery code:';
          var box = document.createElement('div');
          box.innerHTML = '<div style="font-size:24px;letter-spacing:2px;font-family:monospace;background:#111;border:1px solid #444;border-radius:6px;padding:14px;margin:8px 0">' + code + '</div><p style="color:#aaa;max-width:300px;margin:8px auto">Write this down or screenshot it. It is the only way to reset your password if you forget it. It will not be shown again.</p><button id="nDone" style="margin-top:8px;padding:10px 28px;border-radius:6px;border:0;background:#2d6cff;color:#fff;font-size:16px;cursor:pointer">I saved it, continue</button>';
          $('nTitle').parentNode.insertBefore(box, $('nMsg'));
          $('nDone').onclick = function () { login(name); };
        });
      } else if (mode === 'rec') {
        var u2 = users[name];
        if (!u2 || !u2.rec) { msg('No recovery code is set up for that username on this device.'); return; }
        if ($('nPass2').value !== pw) { msg('Passwords do not match.'); return; }
        hash(u2.salt, 'rec:' + normCode($('nCode').value)).then(function (h) {
          if (h !== u2.rec) { msg('Wrong recovery code.'); return; }
          return hash(u2.salt, pw).then(function (ph) { u2.hash = ph; set(USERS, users); login(name); });
        });
      } else {
        if (name === ADMIN_USER) {
          adminHash(pw).then(function (h) { if (h === ADMIN_HASH) login(name, true); else msg('Wrong password.'); });
          return;
        }
        var u = users[name];
        if (!u) { msg('No account with that username on this device. Create one.'); return; }
        hash(u.salt, pw).then(function (h) { if (h === u.hash) login(name); else msg('Wrong password.'); });
      }
    };
    if (CLIENT_ID) {
      var s = document.createElement('script');
      s.src = 'https://accounts.google.com/gsi/client';
      s.onload = function () {
        google.accounts.id.initialize({
          client_id: CLIENT_ID,
          callback: function (r) {
            try {
              var p = JSON.parse(atob(r.credential.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
              var dom = (p.email || '').split('@')[1];
              if ((ALLOWED_EMAILS.length && ALLOWED_EMAILS.indexOf(p.email) < 0) ||
                  (ALLOWED_DOMAINS.length && ALLOWED_DOMAINS.indexOf(dom) < 0)) { msg('That Google account is not allowed.'); return; }
              login(p.email);
            } catch (err) { msg('Google sign-in failed. Try again.'); }
          }
        });
        google.accounts.id.renderButton($('nGoogle'), { theme: 'filled_blue', size: 'large' });
        $('nGoogle').style.marginBottom = '12px';
      };
      document.head.appendChild(s);
    }
  }
  if (document.body) build(); else document.addEventListener('DOMContentLoaded', build);
})();
