/* main.js — Site-wide UI helpers (currently just the sidebar toggle). */

(function () {
  const toggle = document.getElementById("nav-toggle");
  if (!toggle) return;
  toggle.addEventListener("click", function () {
    document.body.classList.toggle("sidebar-open");
  });
})();
