// Logged-out page with AutomaticRedirectAfterSignOut: return to the app once the page (and any
// front-channel sign-out iframes) have loaded.
window.addEventListener("load", () => {
    const link = document.querySelector("a.PostLogoutRedirectUri");
    if (link) {
        window.location = link.href;
    }
});
