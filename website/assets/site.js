// Copy buttons, search, mobile menu and the "on this page" highlight.
(function () {
  "use strict";

  // Copy buttons on code blocks and the install line.
  document.addEventListener("click", function (e) {
    var b = e.target.closest(".copy");
    if (!b) return;
    var src = b.dataset.copy || (b.parentElement.querySelector("pre") || b.parentElement).innerText;
    navigator.clipboard.writeText(src.replace(/\n$/, "")).then(function () {
      var t = b.textContent;
      b.textContent = "Copied";
      b.classList.add("done");
      setTimeout(function () { b.textContent = t; b.classList.remove("done"); }, 1400);
    });
  });

  // Mobile menu.
  var menu = document.querySelector(".menu"), nav = document.getElementById("nav");
  if (menu && nav) {
    menu.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      menu.setAttribute("aria-expanded", String(open));
    });
  }

  // Highlight the current section in "On this page".
  var tocLinks = Array.prototype.slice.call(document.querySelectorAll(".toc a"));
  if (tocLinks.length && "IntersectionObserver" in window) {
    var byId = {};
    tocLinks.forEach(function (a) { byId[a.getAttribute("href").slice(1)] = a; });
    var visible = {};
    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { visible[en.target.id] = en.isIntersecting; });
      var first = tocLinks.find(function (a) { return visible[a.getAttribute("href").slice(1)]; });
      if (first) {
        tocLinks.forEach(function (a) { a.classList.toggle("on", a === first); });
      }
    }, { rootMargin: "-70px 0px -60% 0px" });
    Object.keys(byId).forEach(function (id) { var h = document.getElementById(id); if (h) obs.observe(h); });
  }

  // Search over a prebuilt index.
  var q = document.getElementById("q"), out = document.getElementById("results");
  if (!q || !out) return;
  var root = q.dataset.root || "", index = null, sel = -1;

  function load() {
    if (index) return Promise.resolve(index);
    return fetch(root + "assets/search.json").then(function (r) { return r.json(); }).then(function (d) { index = d; return d; });
  }
  function esc(s) { return s.replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
  function mark(s, terms) {
    var h = esc(s);
    terms.forEach(function (t) {
      if (t.length < 2) return;
      h = h.replace(new RegExp("(" + t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "ig"), "<mark>$1</mark>");
    });
    return h;
  }
  function snippet(x, terms) {
    var lx = x.toLowerCase(), at = -1;
    terms.some(function (t) { at = lx.indexOf(t); return at >= 0; });
    var start = Math.max(0, at - 50);
    return (start > 0 ? "…" : "") + x.slice(start, start + 150) + (x.length > start + 150 ? "…" : "");
  }
  function search(text) {
    var terms = text.toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) { out.hidden = true; return; }
    load().then(function (idx) {
      var scored = [];
      idx.forEach(function (e) {
        var t = e.t.toLowerCase(), h = e.h.toLowerCase(), x = e.x.toLowerCase(), s = 0;
        for (var i = 0; i < terms.length; i++) {
          var term = terms[i], hit = 0;
          if (h.indexOf(term) >= 0) hit += 6;
          if (t.indexOf(term) >= 0) hit += 4;
          if (x.indexOf(term) >= 0) hit += 1;
          if (!hit) return;
          s += hit;
        }
        scored.push([s, e]);
      });
      scored.sort(function (a, b) { return b[0] - a[0]; });
      out.replaceChildren();
      if (!scored.length) {
        var li = document.createElement("li");
        li.className = "none";
        li.textContent = "Nothing found for “" + text + "”.";
        out.append(li);
      }
      scored.slice(0, 8).forEach(function (pair) {
        var e = pair[1], li = document.createElement("li"), a = document.createElement("a");
        a.href = root + e.u;
        a.innerHTML = '<div class="rt">' + mark(e.h, terms) + "</div>" +
          (e.h !== e.t ? '<div class="rh">' + esc(e.t) + "</div>" : "") +
          '<div class="rx">' + mark(snippet(e.x, terms), terms) + "</div>";
        li.append(a);
        out.append(li);
      });
      sel = -1;
      out.hidden = false;
    });
  }
  q.addEventListener("input", function () { search(q.value); });
  q.addEventListener("focus", function () { if (q.value) search(q.value); });
  q.addEventListener("keydown", function (e) {
    var links = out.querySelectorAll("a");
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (!links.length) return;
      sel = (sel + (e.key === "ArrowDown" ? 1 : -1) + links.length) % links.length;
      links.forEach(function (a, i) { a.classList.toggle("sel", i === sel); });
    } else if (e.key === "Enter" && links.length) {
      e.preventDefault();
      (links[sel >= 0 ? sel : 0]).click();
    } else if (e.key === "Escape") {
      out.hidden = true;
      q.blur();
    }
  });
  document.addEventListener("click", function (e) { if (!e.target.closest(".search")) out.hidden = true; });
  document.addEventListener("keydown", function (e) {
    if (e.key === "/" && document.activeElement !== q && !/input|textarea|select/i.test(document.activeElement.tagName)) {
      e.preventDefault();
      q.focus();
    }
  });
})();
