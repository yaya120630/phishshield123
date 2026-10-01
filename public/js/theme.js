// theme.js - shared dark mode toggle for popup.html and dashboard.html
// Preference is stored under chrome.storage.local key 'darkMode' so the
// popup and the full dashboard always agree on the current theme.
(function () {
  function applyTheme(isDark) {
    document.body.classList.toggle('dark', !!isDark);
    var toggleBtn = document.getElementById('themeToggle');
    if (toggleBtn) toggleBtn.textContent = isDark ? '☀️' : '🌙';
  }

  function init() {
    try {
      chrome.storage.local.get(['darkMode'], function (result) {
        applyTheme(!!(result && result.darkMode));
      });
    } catch (error) {
      console.error('theme.js: error reading darkMode', error);
    }

    var toggleBtn = document.getElementById('themeToggle');
    if (toggleBtn && !toggleBtn.dataset.themeWired) {
      toggleBtn.dataset.themeWired = 'true';
      toggleBtn.addEventListener('click', function () {
        var nowDark = !document.body.classList.contains('dark');
        applyTheme(nowDark);
        try {
          chrome.storage.local.set({ darkMode: nowDark });
        } catch (error) {
          console.error('theme.js: error saving darkMode', error);
        }
      });
    }

    // Keep popup and dashboard in sync if the theme is changed in the
    // other surface while this one is open.
    try {
      chrome.storage.onChanged.addListener(function (changes, area) {
        if (area === 'local' && changes.darkMode) {
          applyTheme(!!changes.darkMode.newValue);
        }
      });
    } catch (error) {
      console.error('theme.js: error wiring storage listener', error);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();