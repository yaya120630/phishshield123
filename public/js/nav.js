// Sidebar nav: Dashboard shows everything; every other tab shows only its own section.
//
// This used to live in an inline <script> tag directly inside
// dashboard.html. Manifest V3 extension pages enforce a strict default
// Content Security Policy (script-src 'self') that silently blocks ALL
// inline scripts, so it has to be loaded via <script src="js/nav.js">.
var PS_NAV_TARGETS = ['dashboard-top', 'section-vendor', 'section-details', 'section-relations', 'section-community', 'section-recent'];

(function setGreeting() {
  var el = document.getElementById('greeting-h1');
  if (!el) return;
  var hour = new Date().getHours();
  var text = 'Hello';
  if (hour >= 5 && hour < 12) text = 'Good morning';
  else if (hour >= 12 && hour < 17) text = 'Good afternoon';
  else if (hour >= 17 && hour < 22) text = 'Good evening';
  el.textContent = text + ' \uD83D\uDC4B';
})();

function showView(targetId) {
  var isDashboard = targetId === 'dashboard-top';

  // Dashboard = show everything. Other tab = show only that section.
  PS_NAV_TARGETS.forEach(function (id) {
    var el = document.getElementById(id);
    if (el) el.classList.toggle('page-hidden', !isDashboard && id !== targetId);
  });

  // Hide the empty wrapper so there is no blank gap
  // (only needed for Recent Detections, which sits outside .section-list)
  var list = document.querySelector('.section-list');
  if (list) list.classList.toggle('page-hidden', !isDashboard && targetId === 'section-recent');

  document.querySelectorAll('.nav-item').forEach(function (n) {
    n.classList.toggle('active', n.dataset.target === targetId);
  });

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Lets other scripts (e.g. index.js after a scan) switch tabs.
window.psShowView = showView;

function initNav() {
  document.querySelectorAll('.nav-item[data-target]').forEach(function (item) {
    item.addEventListener('click', function () {
      showView(item.dataset.target);
    });
  });
  showView('dashboard-top'); // default view on load
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initNav);
} else {
  initNav();
}