// Plain language / Technical: the same two views shin-gate-console offers, for the consent list.
// The choice is a per-browser convenience (localStorage). Without script the page stays in plain
// language and the toggle stays hidden.
const KEY = "securedcontrols-labels";
const root = document.documentElement;

function read() {
    try {
        return localStorage.getItem(KEY) === "technical" ? "technical" : "plain";
    } catch {
        return "plain";
    }
}

function apply(mode, toggles) {
    root.dataset.labels = mode;
    for (const toggle of toggles) {
        for (const button of toggle.querySelectorAll("button[data-labels]")) {
            button.setAttribute("aria-pressed", String(button.dataset.labels === mode));
        }
    }
}

const toggles = [...document.querySelectorAll("[data-labels-toggle]")];
apply(read(), toggles);

for (const toggle of toggles) {
    toggle.hidden = false;
    toggle.addEventListener("click", event => {
        const button = event.target.closest("button[data-labels]");
        if (!button) {
            return;
        }
        const mode = button.dataset.labels;
        try {
            localStorage.setItem(KEY, mode);
        } catch {
            // private window or blocked storage: the switch still works for this page
        }
        apply(mode, toggles);
    });
}
