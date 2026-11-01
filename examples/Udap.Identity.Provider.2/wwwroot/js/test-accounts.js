// Fills the login form from a test-account helper button. Lives in a static file because the
// login page's Content-Security-Policy (default-src 'self') blocks inline scripts.
(function () {
    "use strict";

    function fill(button) {
        var username = document.getElementById("Input_Username");
        var password = document.getElementById("Input_Password");

        if (!username || !password) {
            return;
        }

        username.value = button.getAttribute("data-username") || "";
        password.value = button.getAttribute("data-password") || "";

        var login = document.querySelector('button[name="Input.Button"][value="login"]');
        if (login) {
            login.focus();
        }
    }

    document.addEventListener("DOMContentLoaded", function () {
        var buttons = document.querySelectorAll("[data-test-account]");

        for (var i = 0; i < buttons.length; i++) {
            buttons[i].addEventListener("click", function (event) {
                fill(event.currentTarget);
            });
        }
    });
})();
