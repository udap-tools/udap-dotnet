// Native-client loading page: follow the redirect as soon as the script runs (the meta refresh
// is the no-script fallback).
const meta = document.querySelector("meta[http-equiv=refresh]");
if (meta) {
    window.location.href = meta.getAttribute("data-url");
}
