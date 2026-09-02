/* scanner.js — wires up the Vulnerability Scanner form.
   Vanilla JS, no framework. Mirrors analyzer.js conventions:
     - IIFE that bails if the form isn't on the page
     - CSRF read from the rendered form's hidden input
     - silent error swallowing on network failures
*/

(function () {
  const form = document.getElementById("scanner-form");
  if (!form) return;

  const consent = form.querySelector('input[name="consent"]');
  const submit = form.querySelector('button[type="submit"]');
  const localhostOnly = form.querySelector('input[name="localhost_only"]');
  const targetInput = document.getElementById("target-input");

  /* ---- consent gating: submit stays disabled until the user ticks ---- */
  function syncSubmitState() {
    if (consent && submit) {
      submit.disabled = !consent.checked;
    }
  }

  if (consent) {
    consent.addEventListener("change", syncSubmitState);
    syncSubmitState();
  }

  /* ---- loopback hint: nudge the user to enable localhost-only when
         the target looks local ---- */
  function isLoopbackUrl(url) {
    if (!url) return false;
    try {
      const u = new URL(url);
      const host = u.hostname.toLowerCase();
      return (
        host === "localhost" ||
        host === "127.0.0.1" ||
        host === "::1" ||
        host === "0.0.0.0" ||
        host.endsWith(".local") ||
        /^10\./.test(host) ||
        /^192\.168\./.test(host) ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(host)
      );
    } catch (e) {
      return false;
    }
  }

  if (targetInput && localhostOnly) {
    const hint = document.getElementById("localhost-hint");
    targetInput.addEventListener("input", function () {
      if (isLoopbackUrl(targetInput.value) && !localhostOnly.checked && hint) {
        hint.hidden = false;
      } else if (hint) {
        hint.hidden = true;
      }
    });
  }
})();
