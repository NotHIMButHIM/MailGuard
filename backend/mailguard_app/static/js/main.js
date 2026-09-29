window.initTheme = function() {
    const saved = localStorage.getItem("mailguard_theme") || "dark";
    document.documentElement.setAttribute("data-theme", saved);
    document.documentElement.setAttribute("data-bs-theme", saved);
    const icons = document.querySelectorAll(".theme-toggle-icon");
    icons.forEach(icon => {
        icon.className = "theme-toggle-icon bi " + (saved === "light" ? "bi-moon-fill" : "bi-sun-fill");
    });
};

window.toggleTheme = function() {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    const next = current === "light" ? "dark" : "light";
    localStorage.setItem("mailguard_theme", next);
    document.documentElement.setAttribute("data-theme", next);
    document.documentElement.setAttribute("data-bs-theme", next);
    const icons = document.querySelectorAll(".theme-toggle-icon");
    icons.forEach(icon => {
        icon.className = "theme-toggle-icon bi " + (next === "light" ? "bi-moon-fill" : "bi-sun-fill");
    });
};

window.initTheme();

window.getAuthToken = function() {
    let token = localStorage.getItem("mailguard_token");
    if (!token) {
        const match = document.cookie.match(new RegExp("(^| )mailguard_token=([^;]+)"));
        if (match) token = match[2];
    }
    return token;
};

window.getAuthRole = function() {
    return localStorage.getItem("mailguard_role") || "EMPLOYEE";
};

window.setAuthSession = function(token, role, user) {
    localStorage.setItem("mailguard_token", token);
    localStorage.setItem("mailguard_role", role);
    if (user) {
        localStorage.setItem("mailguard_user", typeof user === "string" ? user : JSON.stringify(user));
    }
    document.cookie = "mailguard_token=" + token + "; path=/; SameSite=Lax";
};

window.logout = function() {
    const token = window.getAuthToken();
    if (token) {
        fetch("/api/v1/auth/logout", {
            method: "POST",
            headers: { "Authorization": "Bearer " + token }
        }).finally(() => {
            localStorage.clear();
            document.cookie = "mailguard_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
            window.location.href = "/login";
        });
    } else {
        localStorage.clear();
        document.cookie = "mailguard_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
        window.location.href = "/login";
    }
};

window.apiRequest = async function(url, options = {}) {
    const token = window.getAuthToken();
    const headers = options.headers || {};
    if (token) {
        headers["Authorization"] = "Bearer " + token;
    }
    if (!headers["Content-Type"] && !(options.body instanceof FormData)) {
        headers["Content-Type"] = "application/json";
    }
    options.headers = headers;

    const res = await fetch(url, options);
    if (res.status === 401) {
        window.logout();
        throw new Error("Session expired. Please log in again.");
    }
    return res;
};
