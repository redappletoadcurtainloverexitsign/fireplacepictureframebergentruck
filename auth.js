// Sign-in gate: Google (when CLIENT_ID is set) or username + password.
(function () {
  var CLIENT_ID = ''; // <-- paste your Google OAuth Web Client ID here to add the Google button
  var ALLOWED_EMAILS = []; // optional Google restriction
  var ALLOWED_DOMAINS = []; // optional Google restriction
  var SESSION = 'novaAuth', USERS = 'novaUsers', DAYS = 7;
  function get(k) { try { return JSON.parse(localStorage.getItem(k) || 'null'); } catch (e) { return null; } }
  function set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch (e) { return false; } }
  // Sign-in lasts only for this browser tab/session; reopening the site asks again.
  try { localStorage.removeItem(SESSION); } catch (e) {}
  var a = null;
  try { a = JSON.parse(sessionStorage.getItem(SESSION) || 'null'); } catch (e) {}
  if (a && a.exp * 1000 > Date.now()) return;
  var root = document.documentElement;
  root.style.visibility = 'hidden';

  function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); }
  function hash(salt, pw) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(salt + ':' + pw)).then(hex);
  }
  function login(name) {
    try { sessionStorage.setItem(SESSION, JSON.stringify({ user: name, exp: Date.now() / 1000 + DAYS * 86400 })); } catch (e) {}
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
      '<button id="nGo" type="submit" style="margin-top:8px;padding:10px 28px;border-radius:6px;border:0;background:#2d6cff;color:#fff;font-size:16px;cursor:pointer">Sign in</button>' +
      '</form>' +
      '<p style="margin:14px 0 0"><a id="nSwap" href="#" style="color:#7aa7ff">New here? Create an account</a></p>' +
      '<p id="nMsg" style="color:#f66;margin:12px 0 0;min-height:1.2em"></p>';
    document.body.appendChild(o);
    root.style.visibility = 'visible';
    function $(id) { return document.getElementById(id); }
    function msg(t) { $('nMsg').textContent = t; }
    function render() {
      var c = mode === 'up';
      $('nTitle').textContent = c ? 'Create your account' : 'Sign in to continue';
      $('nPass2').style.display = c ? 'block' : 'none';
      $('nPass').autocomplete = c ? 'new-password' : 'current-password';
      $('nGo').textContent = c ? 'Create account' : 'Sign in';
      $('nSwap').textContent = c ? 'Already have an account? Sign in' : 'New here? Create an account';
      msg('');
    }
    $('nSwap').onclick = function (e) { e.preventDefault(); mode = mode === 'in' ? 'up' : 'in'; render(); };
    $('nForm').onsubmit = function (e) {
      e.preventDefault();
      var name = $('nUser').value.trim().toLowerCase(), pw = $('nPass').value;
      if (!window.crypto || !crypto.subtle) { msg('This browser cannot sign in securely. Use HTTPS.'); return; }
      if (name.length < 3) { msg('Username must be at least 3 characters.'); return; }
      if (pw.length < 6) { msg('Password must be at least 6 characters.'); return; }
      var users = get(USERS) || {};
      if (mode === 'up') {
        if ($('nPass2').value !== pw) { msg('Passwords do not match.'); return; }
        if (users[name]) { msg('That username is taken. Sign in instead.'); return; }
        var salt = hex(crypto.getRandomValues(new Uint8Array(16)));
        hash(salt, pw).then(function (h) {
          users[name] = { salt: salt, hash: h };
          if (!set(USERS, users)) { msg('Could not save your account (private mode?).'); return; }
          login(name);
        });
      } else {
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
