// Confirmation prompts for destructive forms.
//
// A form opts in with data-confirm="<question>". This replaces inline
// onsubmit handlers so the portal's Content-Security-Policy can forbid inline
// script outright.
document.addEventListener("submit", function (ev) {
  var form = ev.target;
  if (!(form instanceof HTMLFormElement)) {
    return;
  }
  var question = form.getAttribute("data-confirm");
  if (question && !window.confirm(question)) {
    ev.preventDefault();
  }
}, true);
