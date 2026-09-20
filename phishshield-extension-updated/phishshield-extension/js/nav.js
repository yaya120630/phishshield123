// Sidebar nav: shows only the selected section, hides the rest.
//
// This used to live in an inline <script> tag directly inside
// dashboard.html. Manifest V3 extension pages enforce a strict default
// Content Security Policy (script-src 'self') that silently blocks ALL
// inline scripts — no error shown to the user, the click handlers just
// never attached. Moving this to its own file loaded via <script
// src="js/nav.js"> is required for it to run at all inside the
// extension context.
var PS_NAV_TARGETS = ['dashboard-top', 'section-vendor', 'section-details', 'section-relations', 'section-community', 'section-recent'];

// The header used to always say "Good morning" no matter the actual
// time — replaced with a greeting based on the user's real local hour,
// falling back to a plain "Hello" around the edges of the day.
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

document.querySelectorAll('.nav-item[data-target]').forEach(function (item) {
  item.addEventListener('click', function () {
    PS_NAV_TARGETS.forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.classList.toggle('page-hidden', id !== item.dataset.target);
    });

    document.querySelectorAll('.nav-item').forEach(function (n) { n.classList.remove('active'); });
    item.classList.add('active');

    var target = document.getElementById(item.dataset.target);
    if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
});
