/* analyzer.js — Wires up live password-strength feedback.
   Talks to two server endpoints:
     POST /analyzer/ajax/check/   — strength evaluation
     POST /analyzer/ajax/suggest/ — strong password suggestions
   Vanilla JS, no framework. */

(function () {
  const form = document.getElementById("analyzer-form");
  if (!form) return;

  const input = document.getElementById("password-input");
  const consent = form.querySelector('input[name="consent"]');
  const submit = form.querySelector('button[type="submit"]');
  const suggestBtn = document.getElementById("suggest-btn");
  const csrfTokenInput = form.querySelector('input[name="csrfmiddlewaretoken"]');
  const csrf = csrfTokenInput ? csrfTokenInput.value : "";

  const meterApi = window.SecureCyberMeter;

  /* ----- helpers ----- */
  function debounce(fn, ms) {
    let t;
    return function () {
      const args = arguments;
      clearTimeout(t);
      t = setTimeout(function () { fn.apply(null, args); }, ms);
    };
  }

  function postJSON(url, body) {
    return fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrf,
      },
      body: JSON.stringify(body),
      credentials: "same-origin",
    });
  }

  function renderEmpty() {
    if (meterApi) meterApi.render({ length: 0, score: 0, label: "weak", checks: [], bits: 0 });
  }

  /* ----- live feedback ----- */
  const fetchEval = debounce(async function (pw) {
    if (!pw) { renderEmpty(); return; }
    try {
      const res = await postJSON("/analyzer/ajax/check/", { password: pw });
      if (!res.ok) return;
      const data = await res.json();
      if (meterApi) meterApi.render(data);
    } catch (e) {
      // Network errors are silently swallowed — the user can still
      // submit the form for a server-side fallback.
    }
  }, 180);

  input.addEventListener("input", function (e) {
    fetchEval(e.target.value);
  });

  /* ----- consent gating ----- */
  if (consent && submit) {
    consent.addEventListener("change", function () {
      submit.disabled = !consent.checked;
    });
  }

  /* ----- suggest button ----- */
  if (suggestBtn) {
    suggestBtn.addEventListener("click", async function () {
      try {
        const res = await postJSON("/analyzer/ajax/suggest/", {
          base: input.value || "",
          count: 3,
        });
        if (!res.ok) return;
        const data = await res.json();
        renderSuggestions(data.suggestions || []);
      } catch (e) {
        // silent
      }
    });
  }

  function renderSuggestions(items) {
    const wrap = document.getElementById("suggestions");
    const list = document.getElementById("suggestions-list");
    if (!wrap || !list) return;
    list.innerHTML = "";
    items.forEach(function (s) {
      const li = document.createElement("li");
      const code = document.createElement("code");
      code.textContent = s.value;
      const meta = document.createElement("span");
      meta.className = "muted";
      meta.textContent = " (" + (s.label || "").replace(/_/g, " ") + ", " + s.score + "/100)";
      li.appendChild(code);
      li.appendChild(meta);
      list.appendChild(li);
    });
    wrap.hidden = items.length === 0;
  }
})();
