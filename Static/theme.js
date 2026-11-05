// Runs before the page is drawn so dark mode does not flash.
(function () {
  try {
    var saved = localStorage.getItem("buk-theme");
    var dark = saved ? saved === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
    document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
  } catch (e) { document.documentElement.setAttribute("data-theme", "light"); }
})();
