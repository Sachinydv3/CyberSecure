/* meter.js — Renders the strength meter from a server response.
   Kept as a small helper so analyzer.js can stay focused on event wiring. */

(function () {
  function renderMeter(data) {
    const meter = document.getElementById("meter");
    const bar = meter.querySelector(".meter__bar");
    const fill = document.getElementById("meter-fill");
    const label = document.getElementById("meter-label");
    const score = document.getElementById("meter-score");
    const bits = document.getElementById("meter-bits");
    const checks = document.getElementById("checks");

    if (!data || !data.length) {
      meter.hidden = true;
      return;
    }
    meter.hidden = false;
    fill.style.width = data.score + "%";
    bar.dataset.label = data.label;
    label.textContent = (data.label || "").replace(/_/g, " ");
    score.textContent = data.score + " / 100";
    bits.textContent = (data.bits ?? 0) + " bits";

    checks.innerHTML = "";
    (data.checks || []).forEach(function (c) {
      const li = document.createElement("li");
      li.textContent = c.label;
      li.className = c.passed ? "pass" : "fail";
      checks.appendChild(li);
    });
  }

  // Expose for analyzer.js (vanilla module pattern).
  window.SecureCyberMeter = { render: renderMeter };
})();
