/**
 * Mailguard Frontend Central Configuration
 * Supports Localhost, Netlify, and Render deployments.
 */
(function() {
    // Determine default API Base URL
    const isLocalhost = window.location.hostname === "localhost" || 
                          window.location.hostname === "127.0.0.1" || 
                          window.location.hostname === "0.0.0.0";
    
    // In local development, default to local FastAPI server on 8000
    // In production on Netlify, defaults to Render backend
    let defaultApiBase = isLocalhost ? "http://localhost:8000" : "https://mailguard-backend-ewuc.onrender.com";

    // Allow overriding from localStorage for easy switching in the browser
    const storedApiBase = localStorage.getItem("mailguard_api_base_url");
    const activeApiBase = storedApiBase !== null ? storedApiBase : defaultApiBase;

    window.MAILGUARD_CONFIG = {
        // Base URL for the FastAPI Backend (empty string means relative to current domain / Netlify proxy)
        API_BASE_URL: activeApiBase.replace(/\/+$/, ""),

        // Google OAuth defaults (can be loaded dynamically from /api/v1/auth/config)
        GOOGLE_CLIENT_ID: "",
        GOOGLE_REDIRECT_URI: "",

        // Method to update backend URL at runtime
        setApiBaseUrl: function(url) {
            const cleanUrl = (url || "").trim().replace(/\/+$/, "");
            if (cleanUrl) {
                localStorage.setItem("mailguard_api_base_url", cleanUrl);
                this.API_BASE_URL = cleanUrl;
            } else {
                localStorage.removeItem("mailguard_api_base_url");
                this.API_BASE_URL = defaultApiBase;
            }
            return this.API_BASE_URL;
        },

        // Helper to construct full API URLs
        apiUrl: function(path) {
            const cleanPath = path.startsWith("/") ? path : "/" + path;
            if (this.API_BASE_URL) {
                return `${this.API_BASE_URL}${cleanPath}`;
            }
            return cleanPath;
        },

        // Dynamically fetch runtime config from backend
        fetchRuntimeConfig: async function() {
            try {
                const targetUrl = this.apiUrl("/api/v1/auth/config");
                const res = await fetch(targetUrl);
                if (res.ok) {
                    const data = await res.json();
                    if (data.google_client_id) {
                        this.GOOGLE_CLIENT_ID = data.google_client_id;
                    }
                    if (data.google_redirect_uri) {
                        this.GOOGLE_REDIRECT_URI = data.google_redirect_uri;
                    }
                    return data;
                }
            } catch (err) {
                console.warn("[Mailguard] Could not auto-fetch auth config from backend:", err);
            }
            return null;
        }
    };
})();
