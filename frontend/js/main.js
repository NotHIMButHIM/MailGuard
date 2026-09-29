/**
 * Mailguard Client-Side Framework & Session Manager
 */

// Initialize Theme
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

// Auth Session Helpers
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

window.getAuthUser = function() {
    try {
        const u = localStorage.getItem("mailguard_user");
        return u ? JSON.parse(u) : null;
    } catch (e) {
        return null;
    }
};

window.setAuthSession = function(token, role, user) {
    if (token) {
        localStorage.setItem("mailguard_token", token);
        document.cookie = "mailguard_token=" + token + "; path=/; SameSite=Lax";
    }
    if (role) {
        localStorage.setItem("mailguard_role", role);
    }
    if (user) {
        localStorage.setItem("mailguard_user", typeof user === "string" ? user : JSON.stringify(user));
    }
};

window.clearAuthSession = function() {
    localStorage.removeItem("mailguard_token");
    localStorage.removeItem("mailguard_role");
    localStorage.removeItem("mailguard_user");
    document.cookie = "mailguard_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
};

// Check for OAuth token in URL fragment or search params (e.g. from Google OAuth callback)
window.handleOAuthUrlParams = function() {
    const hash = window.location.hash ? window.location.hash.substring(1) : "";
    const search = window.location.search ? window.location.search.substring(1) : "";
    const params = new URLSearchParams(hash || search);

    const token = params.get("token");
    const role = params.get("role") || "EMPLOYEE";
    const userStr = params.get("user");

    if (token) {
        let userObj = null;
        if (userStr) {
            try { userObj = JSON.parse(decodeURIComponent(userStr)); } catch(e) {}
        }
        window.setAuthSession(token, role, userObj);

        // Remove token params from URL for clean address bar
        const cleanUrl = window.location.pathname;
        window.history.replaceState({}, document.title, cleanUrl);
        return true;
    }
    return false;
};

// Run OAuth check immediately
window.handleOAuthUrlParams();

// Global Logout
window.logout = function() {
    const token = window.getAuthToken();
    const logoutUrl = (window.MAILGUARD_CONFIG ? window.MAILGUARD_CONFIG.apiUrl("/api/v1/auth/logout") : "/api/v1/auth/logout");

    if (token) {
        fetch(logoutUrl, {
            method: "POST",
            headers: { "Authorization": "Bearer " + token }
        }).catch(() => {}).finally(() => {
            window.clearAuthSession();
            window.location.href = window.location.pathname.includes("/portal/") ? "../index.html" : "/index.html";
        });
    } else {
        window.clearAuthSession();
        window.location.href = window.location.pathname.includes("/portal/") ? "../index.html" : "/index.html";
    }
};

// Unified API Request Wrapper
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

    // Resolve full endpoint URL using MAILGUARD_CONFIG
    let fullUrl = url;
    if (window.MAILGUARD_CONFIG && (url.startsWith("/api") || url.startsWith("api"))) {
        fullUrl = window.MAILGUARD_CONFIG.apiUrl(url);
    }

    try {
        const res = await fetch(fullUrl, options);
        if (res.status === 401) {
            window.clearAuthSession();
            alert("Your session has expired. Please sign in again.");
            const loginPath = window.location.pathname.includes("/portal/") ? "../index.html" : "/index.html";
            window.location.href = loginPath;
            throw new Error("Session expired");
        }
        return res;
    } catch (err) {
        if (err.message === "Failed to fetch") {
            console.error(`[Mailguard Network Error] Unable to connect to backend at: ${fullUrl}`);
            throw new Error(`Unable to reach the Mailguard Security Gateway backend at ${fullUrl}. Please check backend server status.`);
        }
        throw err;
    }
};

// UI helpers
window.formatScore = function(score) {
    if (score === null || score === undefined) return "0%";
    let s = parseFloat(score);
    if (isNaN(s)) return "0%";
    if (s > 0 && s <= 1.0) s = s * 100;
    return Math.round(s) + "%";
};

window.renderUserBadge = function() {
    const user = window.getAuthUser();
    const role = window.getAuthRole();
    const badge = document.getElementById("user-badge");
    if (badge) {
        if (user && user.email) {
            badge.innerText = `${user.email} (${role})`;
        } else {
            badge.innerText = role;
        }
    }
};

document.addEventListener("DOMContentLoaded", () => {
    window.renderUserBadge();
});
