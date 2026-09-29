# Mailguard Backend (Render Deployment)

This directory contains the standalone FastAPI backend for the **Mailguard Security Gateway**. It is pre-configured for deployment on **Render** (or any cloud container / VPS).

---

## Key Features

- **FastAPI Core**: Async REST API endpoints for authentication, spam prevention rules, threat quarantine, admin audit, DLP detection, and ML inference.
- **Dual ML Threat Engine**: Scikit-Learn TF-IDF Naive Bayes spam classifier and Logistic Regression phishing detector.
- **Cross-Domain CORS Support**: Native support for decoupled Netlify frontends (`FRONTEND_URL`, Netlify previews, localhost).
- **Auto-Initialization**: Automatic database migration and default administrator account seeding upon startup.
- **Health Check**: Dedicated `/health` endpoint for Render zero-downtime health monitoring.

---

## Local Development

From the `backend` directory:
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
API Documentation will be available at `http://localhost:8000/docs`.

---

## Deployment to Render

### Method 1: Using Render Blueprint (Automatic, 1 Click)
1. In [Render Dashboard](https://dashboard.render.com/), click **New** -> **Blueprint**.
2. Connect your GitHub repository.
3. Render will detect `render.yaml` and configure the Web Service automatically.
4. Click **Apply**.

---

### Method 2: Manual Web Service Setup
1. In [Render Dashboard](https://dashboard.render.com/), click **New +** -> **Web Service**.
2. Connect your GitHub repository.
3. Configure the service settings:
   - **Name**: `mailguard-backend`
   - **Root Directory**: `backend` (if deploying from monorepo) or leave empty if repository is just the backend.
   - **Runtime**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port 10000`
   - **Plan**: Free
4. Under **Advanced** -> **Health Check Path**, enter: `/health`.
5. Under **Environment Variables**, add the following:

| Key | Example Value | Description |
|---|---|---|
| `PORT` | `10000` | Render port |
| `PYTHONUNBUFFERED` | `1` | Stream console logs |
| `PROJECT_NAME` | `Mailguard` | Application title |
| `ENVIRONMENT` | `production` | Run environment |
| `SECRET_KEY` | *(Click "Generate" on Render)* | JWT encryption key |
| `CORS_ORIGINS` | `["*"]` | Allowed CORS origins |
| `FRONTEND_URL` | `https://your-site.netlify.app` | Netlify frontend URL |
| `ADMIN_EMAIL` | `admin@mailguard.enterprise` | Initial Admin Email |
| `ADMIN_PASSWORD` | `AdminPass@2026!` | Initial Admin Password |
| `ADMIN_NAME` | `System Administrator` | Admin Display Name |

*(Optional PostgreSQL Database)*:
If using Render PostgreSQL instead of SQLite, create a PostgreSQL database on Render, copy the **Internal Database URL**, and set `DATABASE_URL` in your backend environment variables (Render's `postgres://` URLs are automatically converted to async `postgresql+asyncpg://`).

6. Click **Create Web Service**.

---

## Default Administrator Credentials
Once deployed, the backend automatically provisions the SOC Administrator account:
- **Email**: `admin@mailguard.enterprise` (or your configured `ADMIN_EMAIL`)
- **Password**: `AdminPass@2026!` (or your configured `ADMIN_PASSWORD`)
- **Portal**: Sign in via the Admin Portal tab on your Netlify frontend.
