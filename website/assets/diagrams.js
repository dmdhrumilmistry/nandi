// Draws the Mermaid diagrams of a documentation page in the site's own
// fonts and colours, and redraws them when the colour scheme changes.
(function () {
  "use strict";
  if (!window.mermaid) return;
  var blocks = Array.prototype.slice.call(document.querySelectorAll("pre.mermaid"));
  var sources = blocks.map(function (b) { return b.textContent; });
  var scheme = window.matchMedia("(prefers-color-scheme: dark)");

  function v(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

  function draw() {
    var sans = v("--sans");
    window.mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: "base",
      fontFamily: sans,
      flowchart: { curve: "basis", padding: 12, nodeSpacing: 34, rankSpacing: 46 },
      sequence: { mirrorActors: false, messageAlign: "left", actorMargin: 56 },
      themeVariables: {
        darkMode: scheme.matches,
        fontFamily: sans,
        fontSize: "14px",
        background: v("--surface"),
        mainBkg: v("--surface-2"),
        primaryColor: v("--surface-2"),
        primaryBorderColor: v("--line-2"),
        primaryTextColor: v("--ink"),
        secondaryColor: v("--accent-weak"),
        secondaryBorderColor: v("--accent"),
        secondaryTextColor: v("--ink"),
        tertiaryColor: v("--surface"),
        tertiaryBorderColor: v("--line"),
        lineColor: v("--muted"),
        textColor: v("--ink"),
        nodeBorder: v("--line-2"),
        clusterBkg: v("--bg"),
        clusterBorder: v("--line-2"),
        edgeLabelBackground: v("--surface"),
        noteBkgColor: v("--mark"),
        noteTextColor: v("--ink"),
        noteBorderColor: v("--line-2"),
        actorBkg: v("--surface-2"),
        actorBorder: v("--line-2"),
        actorTextColor: v("--ink"),
        actorLineColor: v("--line-2"),
        signalColor: v("--ink-2"),
        signalTextColor: v("--ink"),
        labelBoxBkgColor: v("--surface-2"),
        labelBoxBorderColor: v("--line-2"),
        labelTextColor: v("--ink"),
        loopTextColor: v("--ink-2"),
        activationBkgColor: v("--accent-weak"),
        activationBorderColor: v("--accent")
      }
    });
    blocks.forEach(function (b, i) {
      b.removeAttribute("data-processed");
      b.textContent = sources[i];
    });
    window.mermaid.run({ nodes: blocks }).catch(function (e) { console.error("diagram:", e); });
  }

  draw();
  if (scheme.addEventListener) scheme.addEventListener("change", draw);
})();
