// Tab cloak: applies the saved tab title/icon, and updates instantly when it changes.
(function () {
  var ORIG_TITLE = document.title;
  var me = document.currentScript && document.currentScript.src;
  var NOVA = (me ? new URL('favicon.png', me).href : 'favicon.png') + '?v=2';
  var CLOAKS = {
    google: { title: 'Google', icon: 'https://www.google.com/favicon.ico' },
    vocab: { title: 'My Learning | Vocabulary.com', icon: 'https://www.vocabulary.com/favicon.ico' },
    canvas: { title: 'Canvas', icon: 'https://canvas.instructure.com/favicon.ico' }
  };
  function setIcon(href) {
    // Replace the icon element instead of editing it, so browsers like Safari refresh the tab icon.
    var old = document.querySelectorAll("link[rel~='icon']");
    for (var i = 0; i < old.length; i++) old[i].parentNode.removeChild(old[i]);
    var link = document.createElement('link');
    link.rel = 'icon';
    link.href = href;
    document.head.appendChild(link);
  }
  function apply(value) {
    var c = CLOAKS[value];
    if (c) {
      document.title = c.title;
      setIcon(c.icon);
    } else {
      document.title = ORIG_TITLE;
      setIcon(NOVA + '&t=' + Date.now());
    }
  }
  var saved = 'default';
  try { saved = localStorage.getItem('tabCloaker') || 'default'; } catch (e) {}
  apply(saved);
  window.addEventListener('storage', function (e) {
    if (e.key === 'tabCloaker') apply(e.newValue || 'default');
  });
  window.addEventListener('pageshow', function (e) {
    if (e.persisted) {
      var v = 'default';
      try { v = localStorage.getItem('tabCloaker') || 'default'; } catch (err) {}
      apply(v);
    }
  });
  window.applyTabCloak = apply;
})();
