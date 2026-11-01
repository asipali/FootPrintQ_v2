(function () {
  "use strict";

  function applyTheme(theme, persist) {
    document.documentElement.dataset.theme = theme;
    var toggle = document.getElementById("theme-toggle");
    if (toggle) {
      var isDark = theme === "dark";
      toggle.setAttribute("aria-pressed", String(isDark));
      toggle.setAttribute("aria-label", "Switch to " + (isDark ? "light" : "dark") + " theme");
      var label = toggle.querySelector("[data-theme-label]");
      if (label) {
        label.textContent = isDark ? "Light mode" : "Dark mode";
      }
      var icon = toggle.querySelector(".theme-toggle-icon");
      if (icon) {
        icon.textContent = isDark ? "☼" : "◐";
      }
    }

    if (persist) {
      try {
        localStorage.setItem("footprintiq-theme", theme);
      } catch (error) {
        // The current page still uses the selected theme if storage is unavailable.
      }
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    var currentTheme = document.documentElement.dataset.theme || "dark";
    applyTheme(currentTheme, false);

    var toggle = document.getElementById("theme-toggle");
    if (toggle) {
      toggle.addEventListener("click", function () {
        var nextTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
        applyTheme(nextTheme, true);
      });
    }

    var mobileMenu = document.querySelector(".mobile-menu");
    if (mobileMenu) {
      mobileMenu.addEventListener("click", function (event) {
        if (event.target.closest("a")) {
          mobileMenu.open = false;
        }
      });
    }
  });
}());
