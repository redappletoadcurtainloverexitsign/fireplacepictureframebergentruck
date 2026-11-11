// Sign-in gate: Google (when CLIENT_ID is set) or username + password.
(function () {
  var CLIENT_ID = ''; // <-- paste your Google OAuth Web Client ID here to add the Google button
  var ALLOWED_EMAILS = []; // optional Google restriction
  var ALLOWED_DOMAINS = []; // optional Google restriction
  // Admin account: only this username + password unlocks the admin panel (stored as a salted PBKDF2 hash, not the password).
  var ADMIN_USER = 'gecko', ADMIN_SALT = 'de0b41140e6d2c8e4988b6128ed68462', ADMIN_HASH = 'bd6caf8fe087aac20b3d8b7da3b344aab354ce324ae207fee0c91be23fe8e586';
  // Supabase (free shared database). Paste the Project URL and the anon/publishable key. Empty = accounts live on each device only.
  var SUPABASE_URL = 'https://gnvblyqmjqasdumgtdzb.supabase.co', SUPABASE_KEY = 'sb_publishable_X7C0MaI1NjhlDRt-En-G8A_nTV8sZDV';
  var SESSION = 'novaAuth', USERS = 'novaUsers', DAYS = 7;
  // ---------- Online mode (Supabase): shared accounts, sign-in tracking, delete, lockdown ----------
  function sbMode(API, KEY) {
    var root = document.documentElement;
    root.style.visibility = 'hidden';
    var TOK = 'novaTok', MSG = 'novaMsg';
    var MSGS = {
      badname: 'Username: 3-20 letters, numbers or _ only.', badpass: 'Password must be 6-72 characters.',
      locked: 'The site is under lockdown. Only the admin can sign in right now.', taken: 'That username is taken.',
      bad: 'Wrong username or password.', wait: 'Too many wrong tries. Wait 5 minutes and try again.',
      deleted: 'This account was removed by the admin.', badcode: 'Wrong recovery code.', invalid: ''
    };
    var token = null, adminBtn, adminPanel, usersView, usersTimer, locked = false, lockBtn;
    function ready(f) { if (document.body) f(); else document.addEventListener('DOMContentLoaded', f); }
    function el(tag, css, txt) { var e = document.createElement(tag); if (css) e.style.cssText = css; if (txt != null) e.textContent = txt; return e; }
    function ss(k, v) { try { if (v === undefined) return sessionStorage.getItem(k); if (v === null) sessionStorage.removeItem(k); else sessionStorage.setItem(k, v); } catch (e) {} return null; }
    function rpc(fn, args) {
      var h = { 'Content-Type': 'application/json', apikey: KEY };
      if (KEY.indexOf('eyJ') === 0) h.Authorization = 'Bearer ' + KEY;
      var ctl = window.AbortController ? new AbortController() : null, t = setTimeout(function () { if (ctl) ctl.abort(); }, 12000);
      return fetch(API.replace(/\/$/, '') + '/rest/v1/rpc/' + fn, { method: 'POST', headers: h, body: JSON.stringify(args || {}), signal: ctl ? ctl.signal : undefined })
        .then(function (r) { clearTimeout(t); if (!r.ok) throw new Error('http ' + r.status); return r.json(); });
    }
    function stop(text) {
      ready(function () {
        var o = el('div', 'position:fixed;inset:0;z-index:2147483647;background:#000;color:#fff;display:flex;align-items:center;justify-content:center;font-family:sans-serif;text-align:center;padding:16px;visibility:visible');
        o.appendChild(el('p', 'max-width:320px', text)); document.body.appendChild(o); root.style.visibility = 'visible';
      });
    }

    function gate(note) {
      ready(function () {
        var mode = 'in';
        var o = el('div', 'position:fixed;inset:0;z-index:2147483647;background:#000;color:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:sans-serif;text-align:center;visibility:visible;padding:16px;overflow:auto');
        var inp = 'display:block;width:260px;max-width:100%;box-sizing:border-box;margin:8px auto;padding:10px;border-radius:6px;border:1px solid #444;background:#111;color:#fff;font-size:16px';
        var title = el('p', 'margin:0 0 16px;color:#aaa', 'Sign in to continue');
        var banner = el('p', 'margin:0 0 12px;color:#ffb347;display:none', MSGS.locked);
        var form = el('form'), user = el('input', inp), pass = el('input', inp), pass2 = el('input', inp + ';display:none'), code = el('input', inp + ';display:none');
        user.placeholder = 'Username'; user.autocomplete = 'username'; user.autocapitalize = 'off'; user.setAttribute('autocorrect', 'off');
        pass.type = 'password'; pass.placeholder = 'Password'; pass.autocomplete = 'current-password';
        pass2.type = 'password'; pass2.placeholder = 'Confirm password'; pass2.autocomplete = 'new-password';
        code.placeholder = 'Recovery code (XXXX-XXXX-XXXX-XXXX)'; code.autocomplete = 'off'; code.autocapitalize = 'characters'; code.setAttribute('autocorrect', 'off');
        var go = el('button', 'margin-top:8px;padding:10px 28px;border-radius:6px;border:0;background:#2d6cff;color:#fff;font-size:16px;cursor:pointer', 'Sign in'); go.type = 'submit';
        [user, pass, pass2, code, go].forEach(function (n) { form.appendChild(n); });
        var swap = el('a', 'color:#7aa7ff;cursor:pointer', 'New here? Create an account'), rec = el('a', 'color:#7aa7ff;cursor:pointer', 'Recover account');
        var msg = el('p', 'color:#f66;margin:12px 0 0;min-height:1.2em;max-width:300px', note || '');
        var p1 = el('p', 'margin:14px 0 0'), p2 = el('p', 'margin:8px 0 0'); p1.appendChild(swap); p2.appendChild(rec);
        [el('h1', 'margin:0 0 6px', 'Nova Games'), title, banner, form, p1, p2, msg].forEach(function (n) { o.appendChild(n); });
        document.body.appendChild(o); root.style.visibility = 'visible';
        function render() {
          var up = mode === 'up', rc = mode === 'rec';
          title.textContent = up ? 'Create your account' : rc ? 'Recover your account' : 'Sign in to continue';
          pass2.style.display = (up || rc) ? 'block' : 'none'; code.style.display = rc ? 'block' : 'none';
          pass.placeholder = rc ? 'New password' : 'Password'; pass.autocomplete = (up || rc) ? 'new-password' : 'current-password';
          go.textContent = up ? 'Create account' : rc ? 'Reset password' : 'Sign in';
          swap.textContent = mode === 'in' ? 'New here? Create an account' : 'Back to sign in'; p2.style.display = mode === 'in' ? '' : 'none';
          msg.textContent = '';
        }
        swap.onclick = function () { mode = mode === 'in' ? 'up' : 'in'; render(); };
        rec.onclick = function () { mode = 'rec'; render(); };
        rpc('nova_status').then(function (s) { if (s && s.locked) banner.style.display = 'block'; }).catch(function () {});
        function done(r) {
          if (!r || !r.ok) { msg.textContent = (r && MSGS[r.error]) || 'Something went wrong. Try again.'; go.disabled = false; return; }
          ss(TOK, r.token);
          if (r.recovery) {
            form.style.display = 'none'; p1.style.display = 'none'; p2.style.display = 'none';
            title.textContent = 'Account created! Save your recovery code:';
            var box = el('div');
            box.appendChild(el('div', 'font-size:24px;letter-spacing:2px;font-family:monospace;background:#111;border:1px solid #444;border-radius:6px;padding:14px;margin:8px 0', r.recovery));
            box.appendChild(el('p', 'color:#aaa;max-width:300px;margin:8px auto', 'Write this down or screenshot it. It is the only way to reset your password if you forget it. It will not be shown again.'));
            var ok = el('button', 'margin-top:8px;padding:10px 28px;border-radius:6px;border:0;background:#2d6cff;color:#fff;font-size:16px;cursor:pointer', 'I saved it, continue');
            ok.onclick = function () { location.reload(); }; box.appendChild(ok); o.insertBefore(box, msg);
          } else location.reload();
        }
        form.onsubmit = function (e) {
          e.preventDefault(); msg.textContent = '';
          var name = user.value.trim().toLowerCase(), pw = pass.value;
          if (name.length < 3) { msg.textContent = MSGS.badname; return; }
          if (pw.length < 6) { msg.textContent = MSGS.badpass; return; }
          if (mode !== 'in' && pass2.value !== pw) { msg.textContent = 'Passwords do not match.'; return; }
          go.disabled = true;
          var call = mode === 'up' ? rpc('nova_signup', { p_user: name, p_pass: pw })
            : mode === 'rec' ? rpc('nova_recover', { p_user: name, p_code: code.value, p_pass: pw })
            : rpc('nova_login', { p_user: name, p_pass: pw });
          call.then(done).catch(function () { msg.textContent = 'Could not reach the server. Check your connection.'; go.disabled = false; });
        };
      });
    }

    function adminUI() {
      var bs = 'display:block;width:100%;margin:6px 0;padding:9px;border-radius:6px;border:0;color:#fff;font-size:14px;cursor:pointer;background:#2d6cff';
      adminBtn = el('button', 'position:fixed;right:12px;bottom:12px;z-index:2147483000;padding:8px 14px;border-radius:8px;border:1px solid #444;background:#111;color:#fff;font:14px sans-serif;cursor:pointer;opacity:.85', 'Admin');
      adminPanel = el('div', 'display:none;position:fixed;right:12px;bottom:56px;z-index:2147483000;width:260px;max-width:calc(100vw - 24px);padding:14px;border-radius:10px;border:1px solid #444;background:#111;color:#fff;font:14px sans-serif');
      var users = el('button', bs, 'Users & sign-ins'); lockBtn = el('button', bs, ''); var out = el('button', bs + ';background:#555', 'Sign out');
      adminPanel.appendChild(el('div', 'font-weight:bold;margin-bottom:6px', 'Admin panel'));
      [users, lockBtn, out].forEach(function (b) { adminPanel.appendChild(b); });
      syncLock();
      adminBtn.onclick = function () { adminPanel.style.display = adminPanel.style.display === 'none' ? 'block' : 'none'; };
      users.onclick = openUsers;
      lockBtn.onclick = function () {
        var on = !locked;
        if (!confirm(on ? 'Lock the whole website for everyone except you?' : 'End the lockdown and let everyone back in?')) return;
        rpc('nova_admin_set_lock', { p_token: token, p_locked: on }).then(function (r) { if (r && r.ok) { locked = on; syncLock(); } else alert('Could not change lockdown.'); })
          .catch(function () { alert('Could not reach the server.'); });
      };
      out.onclick = function () { ss(TOK, null); location.reload(); };
      document.body.appendChild(adminBtn); document.body.appendChild(adminPanel);
    }
    function syncLock() { if (!lockBtn) return; lockBtn.textContent = locked ? 'Lockdown is ON - tap to end' : 'Start lockdown'; lockBtn.style.background = locked ? '#c33' : '#2d6cff'; }
    function fmt(t) { try { return t ? new Date(t).toLocaleString() : '-'; } catch (e) { return '-'; } }
    function openUsers() {
      if (usersView) return;
      usersView = el('div', 'position:fixed;inset:0;z-index:2147483001;background:#000;color:#fff;font:14px sans-serif;overflow:auto;padding:16px');
      var top = el('div', 'display:flex;justify-content:space-between;align-items:center;margin-bottom:12px');
      var close = el('button', 'padding:8px 14px;border-radius:6px;border:0;background:#555;color:#fff;cursor:pointer', 'Close');
      top.appendChild(el('h2', 'margin:0', 'Users & sign-ins')); top.appendChild(close);
      var info = el('p', 'color:#aaa;margin:0 0 10px', 'Loading...'), list = el('div');
      usersView.appendChild(top); usersView.appendChild(info); usersView.appendChild(list); document.body.appendChild(usersView);
      function load() {
        rpc('nova_admin_users', { p_token: token }).then(function (r) {
          if (!r || !r.ok) { info.textContent = 'Could not load users.'; return; }
          info.textContent = r.users.length + ' account' + (r.users.length === 1 ? '' : 's');
          list.textContent = '';
          r.users.forEach(function (x) {
            var row = el('div', 'border:1px solid #333;border-radius:8px;padding:10px;margin:8px 0;display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap');
            var left = el('div', 'min-width:200px');
            left.appendChild(el('div', 'font-weight:bold;word-break:break-all', x.username + (x.admin ? '  (admin)' : '') + (x.deleted ? '  (deleted)' : '')));
            left.appendChild(el('div', 'color:#aaa', 'signed in ' + x.count + ' time(s)'));
            left.appendChild(el('div', 'color:#aaa', 'created ' + fmt(x.created)));
            left.appendChild(el('div', 'color:#aaa', 'last sign-in ' + fmt(x.last)));
            row.appendChild(left);
            if (!x.admin) {
              var b = el('button', 'padding:8px 14px;border-radius:6px;border:0;color:#fff;cursor:pointer;background:' + (x.deleted ? '#2d6cff' : '#c33'), x.deleted ? 'Restore' : 'Delete');
              b.onclick = function () {
                if (!x.deleted && !confirm('Delete the account "' + x.username + '"? They will be signed out and blocked.')) return;
                rpc('nova_admin_set_deleted', { p_token: token, p_user: x.username, p_deleted: !x.deleted }).then(load).catch(function () { alert('Could not reach the server.'); });
              };
              row.appendChild(b);
            }
            list.appendChild(row);
          });
        }).catch(function () { info.textContent = 'Could not reach the server.'; });
      }
      load(); usersTimer = setInterval(load, 5000);
      close.onclick = function () { clearInterval(usersTimer); usersView.parentNode.removeChild(usersView); usersView = null; };
    }

    function recheck() {
      rpc('nova_check', { p_token: token }).then(function (r) {
        if (!r || !r.ok) { ss(MSG, MSGS[r && r.error] || ''); ss(TOK, null); location.reload(); }
        else if (r.admin) { locked = !!r.locked; syncLock(); }
      }).catch(function () {});
    }
    token = ss(TOK);
    if (!token) { gate(ss(MSG) || ''); ss(MSG, null); return; }
    rpc('nova_check', { p_token: token }).then(function (r) {
      if (r && r.ok) {
        root.style.visibility = 'visible';
        if (r.admin) { locked = !!r.locked; ready(adminUI); }
        setInterval(recheck, 15000);
      } else { ss(TOK, null); gate(MSGS[r && r.error] || ''); }
    }).catch(function () { stop('Could not reach the sign-in server. Check your connection and reload.'); });
  }
  if (SUPABASE_URL && SUPABASE_KEY) { sbMode(SUPABASE_URL, SUPABASE_KEY); return; }
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
