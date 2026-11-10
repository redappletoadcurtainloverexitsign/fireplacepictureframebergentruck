// Google sign-in gate. Set CLIENT_ID (see below) to turn it on; empty = gate off.
(function () {
  var CLIENT_ID = ''; // <-- paste your Google OAuth Web Client ID here
  var ALLOWED_EMAILS = []; // optional: e.g. ['a@gmail.com']; empty = any Google account
  var ALLOWED_DOMAINS = []; // optional: e.g. ['belenwolverines.org']; empty = any domain
  if (!CLIENT_ID) return;
  var KEY = 'novaAuth';
  function ok() {
    try {
      var a = JSON.parse(localStorage.getItem(KEY) || 'null');
      return a && a.exp * 1000 > Date.now();
    } catch (e) { return false; }
  }
  if (ok()) return;
  document.documentElement.style.visibility = 'hidden';
  var root = document.documentElement;
  function build() {
    var o = document.createElement('div');
    o.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:#000;color:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:sans-serif;text-align:center;visibility:visible';
    o.innerHTML = '<h1 style="margin:0 0 8px">Nova Games</h1><p style="margin:0 0 20px;color:#aaa">Sign in with Google to continue</p><div id="novaBtn"></div><p id="novaMsg" style="color:#f66;margin-top:16px"></p>';
    document.body.appendChild(o);
    root.style.visibility = 'visible';
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
                (ALLOWED_DOMAINS.length && ALLOWED_DOMAINS.indexOf(dom) < 0)) {
              document.getElementById('novaMsg').textContent = 'That account is not allowed.'; return;
            }
            localStorage.setItem(KEY, JSON.stringify({ exp: Math.min(p.exp, Date.now() / 1000 + 7 * 86400) }));
            location.reload();
          } catch (e) { document.getElementById('novaMsg').textContent = 'Sign-in failed. Try again.'; }
        }
      });
      google.accounts.id.renderButton(document.getElementById('novaBtn'), { theme: 'filled_blue', size: 'large' });
    };
    document.head.appendChild(s);
  }
  if (document.body) build(); else document.addEventListener('DOMContentLoaded', build);
})();
