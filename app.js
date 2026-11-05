// Front-end behaviour. Everything here is allowed by the strict Content-Security-Policy (no inline scripts).
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  var themeBtn = $("#theme-toggle");
  if (themeBtn) themeBtn.addEventListener("click", function () {
    var next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("buk-theme", next); } catch (e) {}
  });

  // show / hide password (the eye button)
  $$("[data-toggle-password]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.getAttribute("data-toggle-password"));
      if (!input) return;
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.setAttribute("aria-pressed", show ? "true" : "false");
      btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
    });
  });

  // caps lock warning
  $$("input[data-meter], .pw-field input").forEach(function (input) {
    var warn = $('[data-caps-for="' + input.id + '"]');
    if (!warn) return;
    function check(e) { if (e.getModifierState) warn.hidden = !e.getModifierState("CapsLock"); }
    input.addEventListener("keydown", check); input.addEventListener("keyup", check);
    input.addEventListener("blur", function () { warn.hidden = true; });
  });

  // password strength meter
  var levels = [["Too weak", "#c0392b"], ["Weak", "#e67e22"], ["Fair", "#d4a017"], ["Good", "#4caf50"], ["Strong", "#0f8a4b"]];
  function scorePassword(v) {
    var rules = { length: v.length >= 10, lower: /[a-z]/.test(v), upper: /[A-Z]/.test(v), digit: /\d/.test(v), symbol: /[^A-Za-z0-9]/.test(v) };
    var passed = Object.keys(rules).filter(function (k) { return rules[k]; }).length;
    var bonus = v.length >= 14 ? 1 : 0;
    return { rules: rules, level: Math.min(4, Math.max(0, passed - 1 + (passed >= 4 ? bonus : 0))), empty: v.length === 0 };
  }
  $$("input[data-meter]").forEach(function (input) {
    var box = document.getElementById(input.getAttribute("data-meter"));
    if (!box) return;
    var fill = $(".meter-fill", box), label = $(".meter-label strong", box);
    input.addEventListener("input", function () {
      var r = scorePassword(input.value);
      box.hidden = r.empty;
      fill.style.width = ((r.level + 1) * 20) + "%";
      fill.style.background = levels[r.level][1];
      label.textContent = levels[r.level][0];
      Object.keys(r.rules).forEach(function (k) { var li = $('[data-rule="' + k + '"]', box); if (li) li.classList.toggle("ok", r.rules[k]); });
      checkMatch();
    });
  });

  var note = $("#match-note");
  function checkMatch() {
    if (!note) return;
    var first = $("input[data-meter]"), second = $("#confirm");
    if (!first || !second || !second.value) { note.hidden = true; return; }
    var ok = first.value === second.value;
    note.hidden = false; note.textContent = ok ? "Passwords match" : "Passwords do not match yet";
    note.className = "match-note " + (ok ? "good" : "bad");
  }
  var confirmInput = $("#confirm"); if (confirmInput) confirmInput.addEventListener("input", checkMatch);

  // generate a strong password (admin)
  $$("[data-generate-password]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.getAttribute("data-generate-password"));
      var sets = ["abcdefghjkmnpqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "#$%&*+=?@"], all = sets.join(""), out = [];
      function rnd(n) { var a = new Uint32Array(1); crypto.getRandomValues(a); return a[0] % n; }
      sets.forEach(function (s) { out.push(s[rnd(s.length)]); });
      while (out.length < 14) out.push(all[rnd(all.length)]);
      for (var i = out.length - 1; i > 0; i--) { var j = rnd(i + 1), t = out[i]; out[i] = out[j]; out[j] = t; }
      input.value = out.join(""); input.type = "text";
      var eye = $('[data-toggle-password="' + input.id + '"]'); if (eye) eye.setAttribute("aria-pressed", "true");
      input.dispatchEvent(new Event("input"));
    });
  });

  // animated counters
  $$("[data-count]").forEach(function (el) {
    var target = parseInt(el.getAttribute("data-count"), 10) || 0, start = null;
    if (!target) { el.textContent = "0"; return; }
    function tick(ts) {
      if (start === null) start = ts;
      var p = Math.min(1, (ts - start) / 900);
      el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3)));
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  });

  // messages: close button and auto-hide
  $$(".flash").forEach(function (f) {
    function close() { f.classList.add("leaving"); setTimeout(function () { f.remove(); }, 400); }
    var x = $(".flash-x", f); if (x) x.addEventListener("click", close);
    if (f.classList.contains("ok")) setTimeout(close, 6000);
  });

  // button ripple
  document.addEventListener("click", function (e) {
    var b = e.target.closest ? e.target.closest(".btn") : null;
    if (!b) return;
    var r = b.getBoundingClientRect(), s = document.createElement("span"), d = Math.max(r.width, r.height);
    s.className = "ripple"; s.style.width = s.style.height = d + "px";
    s.style.left = (e.clientX - r.left - d / 2) + "px"; s.style.top = (e.clientY - r.top - d / 2) + "px";
    b.appendChild(s); setTimeout(function () { s.remove(); }, 650);
  });

  // new complaint form
  var category = $$("input[name=category]"), box = $("#subtype-box");
  if (category.length && box) {
    var syncType = function () {
      var chosen = category.filter(function (r) { return r.checked; })[0];
      var show = chosen && chosen.value === "academic";
      box.hidden = !show;
      var sel = $("#subcategory"); if (sel) { sel.required = !!show; if (!show) sel.value = ""; }
    };
    category.forEach(function (r) { r.addEventListener("change", syncType); }); syncType();
  }
  $$("[data-counter]").forEach(function (el) {
    var out = document.getElementById(el.getAttribute("data-counter"));
    function u() { if (out) out.textContent = el.value.length; }
    el.addEventListener("input", u); u();
  });
  var files = $("#attachments"), fileNote = $("#file-note");
  if (files && fileNote) files.addEventListener("change", function () {
    var max = parseInt(files.getAttribute("data-max-files"), 10) || 3, problems = [];
    if (files.files.length > max) problems.push("Choose at most " + max + " files.");
    Array.prototype.forEach.call(files.files, function (f) { if (f.size > 2 * 1024 * 1024) problems.push(f.name + " is larger than 2 MB."); });
    fileNote.hidden = problems.length === 0; fileNote.textContent = problems.join(" ");
  });

  // staff: quick replies, copy, print
  $$(".quick-select").forEach(function (sel) {
    sel.addEventListener("change", function () {
      var t = document.getElementById(sel.getAttribute("data-target"));
      if (t && sel.value) { t.value = (t.value ? t.value + "\n" : "") + sel.value; t.focus(); sel.value = ""; }
    });
  });
  $$("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var src = document.getElementById(btn.getAttribute("data-copy"));
      if (!src) return;
      (navigator.clipboard ? navigator.clipboard.writeText(src.innerText.trim()) : Promise.reject()).then(function () {
        var old = btn.textContent; btn.textContent = "Copied"; setTimeout(function () { btn.textContent = old; }, 1500);
      }).catch(function () {});
    });
  });
  $$("[data-print]").forEach(function (b) { b.addEventListener("click", function () { window.print(); }); });

  // idle timeout warning
  var idle = parseInt(document.body.getAttribute("data-idle"), 10), modal = $("#idle-modal");
  if (idle && modal) {
    var limit = idle * 60 * 1000, warnAt = limit - 120 * 1000, last = Date.now(), countdown = null;
    var csrf = ($('meta[name="csrf-token"]') || {}).content, count = $("#idle-count");
    function reset() { last = Date.now(); }
    ["click", "keydown", "touchstart", "scroll"].forEach(function (ev) { document.addEventListener(ev, function () { if (modal.hidden) reset(); }, { passive: true }); });
    var stayBtn = $("#idle-stay");
    if (stayBtn) stayBtn.addEventListener("click", function () {
      fetch("/session/ping", { method: "POST", headers: { "X-CSRF-Token": csrf }, credentials: "same-origin" }).then(function () {
        modal.hidden = true; reset(); clearInterval(countdown); countdown = null;
      });
    });
    setInterval(function () {
      var idleFor = Date.now() - last;
      if (idleFor >= limit) { window.location.href = "/login?expired=1"; }
      else if (idleFor >= warnAt && modal.hidden) {
        modal.hidden = false;
        countdown = setInterval(function () { count.textContent = Math.max(0, Math.round((limit - (Date.now() - last)) / 1000)); }, 500);
      }
    }, 5000);
  }
})();
