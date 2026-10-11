// Applies the saved appearance before the page paints, so it never flashes
// the wrong colors. src/lib/appearance.ts keeps it current afterwards.
(function () {
  var saved = {};
  try {
    saved = JSON.parse(localStorage.getItem("dg-appearance") || "{}") || {};
  } catch (error) {}
  var mode = saved.mode === "light" || saved.mode === "dark" ? saved.mode : window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  document.documentElement.dataset.mode = mode;
  if (saved.theme && saved.theme !== "indigo") document.documentElement.dataset.theme = saved.theme;
})();
