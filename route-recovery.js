(function () {
  var path = location.pathname.replace(/\/+$/, '') || '/';
  if (path === '/login') {
    // Never carry legacy URL parameters: they may contain obsolete credentials.
    location.replace('/');
  } else if (path === '/admin' || path.indexOf('/admin/') === 0) {
    document.getElementById('recovery-title').textContent = 'The report editor is not available here.';
    document.getElementById('recovery-message').textContent = 'This address belonged to the previous portal. Your dashboard login opens the current report; an editing workspace is not connected to this version.';
  }
})();
