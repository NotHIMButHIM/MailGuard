# Mailguard Frontend (Netlify Deployment)

This directory contains the standalone, decoupled frontend for the **Mailguard Security Gateway**. It is pre-configured for static hosting on **Netlify** or any modern web host.

---

## Architecture & Features

- **No Server Dependencies**: Pure HTML5, Vanilla JavaScript, CSS3 with Bootstrap 5, Bootstrap Icons, and Glassmorphism styling.
- **Dynamic Configuration**: Automatically discovers backend URL or connects to your Render backend via `js/config.js` or via UI settings modal.
- **Unified Portals**:
  - `index.html`: Employee & Admin Login with Google OAuth support and corporate credential auth.
  - `portal/employee.html`: Employee Spam Pre-Blocking Rules, Inspected Inbox, Gmail Sync, Deep Email Review Modal, and Admin Release Request Tickets.
  - `portal/admin.html`: SOC Security Operations Dashboard, Real-Time KPI Cards, Active Employee Sessions & Revocation, Quarantine/Isolation Manager, Release Request Approvals, ML Tuning & Retraining, DLP Incidents, and Audit Logs.
- **Theme Switcher**: Dark & Light mode toggle with persistent state.

---

## Deployment to Netlify

### Option 1: Drag & Drop (Fastest, 10 Seconds)
1. Go to [app.netlify.com](https://app.netlify.com/) and log in.
2. Navigate to **Sites** -> **Add new site** -> **Deploy manually**.
3. Drag and drop the `frontend` folder directly onto the Netlify upload area.
4. Your site will instantly go live with a `.netlify.app` URL!

---

### Option 2: Connect via GitHub / Git
1. Push your repository to GitHub.
2. In Netlify, click **Add new site** -> **Import an existing project**.
3. Select your GitHub repository.
4. Configure build settings:
   - **Base directory**: `frontend`
   - **Build command**: *(leave blank)*
   - **Publish directory**: `.` (or `frontend`)
5. Click **Deploy Site**.

---

## Connecting Frontend to Your Render Backend

There are two ways to connect this frontend to your Render backend:

### Way A: Set Backend URL in `js/config.js` (Recommended)
Open `frontend/js/config.js` and edit line 15:
```javascript
let defaultApiBase = isLocalhost ? "http://localhost:8000" : "https://your-backend-name.onrender.com";
```
*(Replace `https://your-backend-name.onrender.com` with your live Render backend URL).*

### Way B: In the Web Browser UI
On the login page (`index.html`), click the **Backend API** button at the top-right corner, enter your Render backend URL, and click **Save & Reload**.

### Way C: Netlify Proxy Rewrite (Zero CORS)
In `frontend/netlify.toml`, uncomment the proxy rule:
```toml
[[redirects]]
  from = "/api/*"
  to = "https://your-backend-name.onrender.com/api/:splat"
  status = 200
  force = true
```

---

## Google OAuth Setup for Netlify Domain
If you use Google OAuth:
1. Open the [Google Cloud Console](https://console.cloud.google.com/apis/credentials).
2. Under **Authorized JavaScript origins**, add your Netlify domain:
   - `https://your-site-name.netlify.app`
3. Under **Authorized redirect URIs**, add your Render callback URL:
   - `https://your-backend-name.onrender.com/api/v1/auth/google/callback`
