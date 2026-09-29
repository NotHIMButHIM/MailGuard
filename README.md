# Mailguard 🛡️
> Enterprise-Grade Secure Email Gateway (SEG) with Multi-Layered Threat Defense, Machine Learning Classifiers, and Real-Time Inbox Threat Neutralization.

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.11%20|%203.12%20|%203.14-blue.svg?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.4+-orange.svg?logo=scikit-learn)](https://scikit-learn.org)

Mailguard is a next-generation Secure Email Gateway that intercepts, analyzes, and isolates malicious emails before they reach employee inboxes. It combines rule-based firewalling, RFC 8601 cryptographic domain authentication, heuristic NLP analysis, Scikit-Learn Machine Learning models, heuristic file sandbox inspection, and Data Loss Prevention (DLP) into an end-to-end security pipeline.

---

## 🌟 Key Features

### 1. Multi-Layered Security Pipeline
Every incoming email passes through 6 sequential defense layers:
- **Zero-Tolerance Pre-Blocking Rules:** Customizable employee & system firewall rules for domains, specific senders, keyword phrases, and regular expressions.
- **Cryptographic Domain Authentication:** Live DNS-based SPF (`v=spf1`) and DMARC (`v=DMARC1`) verification combined with RFC 8601 `Authentication-Results` / `DKIM-Signature` verification.
- **Natural Language Threat Heuristics:** Scans for high-urgency language, financial extortion, gift card scams, credential harvesting, and VIP impersonation indicators.
- **Trained Machine Learning Models:**
  - **Spam Classifier:** Multinomial Naive Bayes trained on real-world email datasets.
  - **Phishing Classifier:** Logistic Regression with TF-IDF vectorization and cross-validated metrics.
- **Attachment Sandbox Analyzer:** Real-time MD5 / SHA256 hashing, MIME verification, magic bytes inspection (detecting Windows `MZ` or Linux `ELF` executables disguised as documents), and double-extension detection.
- **Data Loss Prevention (DLP):** Automatic pattern inspection and redaction for sensitive corporate/financial data (Credit Cards, Indian PAN cards, Aadhaar numbers, and US SSNs).

### 2. Dual Enterprise Portals
- **Security Operations Center (SOC) Admin Portal:**
  - Real-time threat metrics and scanned email counters.
  - Active session monitor with one-click revocation.
  - Live ML Model Registry with real cross-validated Accuracy, Precision, Recall, and F1 scores.
  - Live Interactive Threat Tester & one-click model retrain pipeline.
  - Quarantine & Isolation Manager with safe release workflow.
  - DLP Incident tracker and tamper-evident audit trail.
- **Employee Prevention Portal:**
  - Personal Inspected Inbox with real-time status and threat verdicts.
  - Self-service Spam Pre-Blocking Rules management.
  - Manual Email Scanner and Gmail sync controls.
  - Email inspection modal with isolated plain-text preview and sandboxed HTML rendering.

### 3. Active Gmail Synchronization & Threat Isolation
- Seamless Google OAuth2 integration (`https://mail.google.com/`).
- Aggressive background auto-filtering (5s polling cycle) that intercepts threats and permanently deletes them before employees open their mail.

---

## 🏗️ Architecture

```
                    ┌─────────────────────────┐
                    │  Inbound Email Stream   │
                    │  (Gmail API / SMTP)     │
                    └────────────┬────────────┘
                                 │
                                 ▼
                     Layer 1: Pre-Blocking Rules
                    (Domain, Sender, Regex, Hits)
                                 │
                                 ▼
                    Layer 2: Domain Auth Checker
                   (SPF, DKIM, DMARC via DNS / RFC)
                                 │
                                 ▼
                     Layer 3: NLP Threat Engine
                 (Urgency, Financial, Impersonation)
                                 │
                                 ▼
                    Layer 4: ML Classifiers (TF-IDF)
                 (Spam MultinomialNB & Phish LogReg)
                                 │
                                 ▼
                     Layer 5: Attachment Sandbox
                 (Magic Bytes, Hashes, Extension Spoof)
                                 │
                                 ▼
                     Layer 6: DLP Engine
                 (PAN, Aadhaar, SSN, Credit Cards)
                                 │
                  ┌──────────────┴──────────────┐
                  ▼                             ▼
            CLEAN EMAIL                  THREAT DETECTED
      (Delivered to Inbox)         (Quarantined & Gmail Deleted)
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.11+
- Virtual environment (`venv`)

### 1. Clone & Setup
```bash
git clone https://github.com/your-username/mailguard.git
cd mailguard

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Environment Configuration
Copy the template configuration file:
```bash
cp .env.example .env
```
Edit `.env` to configure your database, secret key, and Google OAuth credentials (if connecting to live Gmail).

### 3. Initialize Database & Admin User
```bash
python scripts/seed_admin.py admin@mailguard.enterprise AdminPass@2026! "System Administrator"
```

### 4. Run the Gateway Server
```bash
uvicorn main:app --reload --port 8000
```
Open your browser and navigate to:
- **Portals:** [http://localhost:8000](http://localhost:8000)
- **API Documentation (Swagger UI):** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Alternative Docs (ReDoc):** [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## 🧪 Running the Test Suite

Mailguard includes comprehensive automated tests covering all architecture phases:
```bash
# Run all tests
pytest

# Run phase-specific tests
pytest tests/test_phase1.py
pytest tests/test_phase2_models.py
pytest tests/test_phase3_engines.py
pytest tests/test_phase4_api.py
pytest tests/test_phase5_tasks.py
pytest tests/test_phase6_views.py
pytest tests/test_phase7_enterprise.py
```

---

## 🐳 Containerized Deployment (Docker & Docker Compose)

Mailguard includes production-grade container orchestration with PostgreSQL 16 and Redis 7:

```bash
# Build and launch all services (Mailguard Gateway, PostgreSQL, Redis)
docker-compose up -d --build

# Inspect logs
docker-compose logs -f mailguard

# Stop services
docker-compose down
```

---

## ☁️ Cloud Deployment (Render & Vercel)

### Option A: Deploy Backend on Render (Recommended for Background Workers)
Render hosts the persistent FastAPI service, background Gmail threat neutralizer, and ML models:

1. **Push your code to GitHub**.
2. Go to [Render Dashboard](https://dashboard.render.com/) and click **New+** → **Web Service**.
3. Connect your GitHub repository.
4. Render will auto-detect settings, or configure:
   - **Environment:** `Python`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Under **Environment Variables**, add:
   - `SECRET_KEY`: (any long random hex string)
   - `ENVIRONMENT`: `production`
   - `ACCESS_TOKEN_EXPIRE_MINUTES`: `120`
   - `ADMIN_EMAIL`: `admin@mailguard.enterprise`
   - `ADMIN_PASSWORD`: `AdminPass@2026!`
   - *(Optional)* `GOOGLE_CLIENT_ID` & `GOOGLE_CLIENT_SECRET`: for live Gmail OAuth sync
6. Click **Deploy Web Service**.
   *On first launch, Mailguard automatically runs database migrations and seeds the default administrator.*

## 🚀 Separate Frontend & Backend Deployment

Mailguard is fully decoupled into independent **Backend** (for **Render**) and **Frontend** (for **Netlify**) directories:

```
Mailguard/
├── backend/                  # Standalone FastAPI Backend (Deploy to Render)
│   ├── main.py               # Application entrypoint & CORS middleware
│   ├── mailguard_app/        # Core models, services, ML registry, routers
│   ├── ml_models/            # Pre-trained spam & phishing pickle models
│   ├── scripts/              # Seed admin & maintenance utilities
│   ├── requirements.txt      # Python dependencies
│   ├── render.yaml           # Render Web Service Blueprint spec
│   ├── Dockerfile            # Container deployment spec
│   └── README.md             # Render deployment walkthrough
│
├── frontend/                 # Standalone Client Portal (Deploy to Netlify)
│   ├── index.html            # Unified Employee & Admin Login
│   ├── portal/
│   │   ├── employee.html     # Employee Prevention & Inspected Inbox Portal
│   │   └── admin.html        # SOC Security Operations Center Portal
│   ├── css/main.css          # Glassmorphism cyber-security design system
│   ├── js/config.js          # Central configuration & dynamic API routing
│   ├── js/main.js            # Auth session, OAuth token capture & API client
│   ├── netlify.toml          # Netlify build spec & security headers
│   ├── _redirects            # Netlify routing and clean URLs
│   └── README.md             # Netlify deployment walkthrough
```

---

### Step 1: Deploy Backend to Render

1. Go to [Render Dashboard](https://dashboard.render.com/) -> **New +** -> **Web Service** (or use **Blueprint** with `render.yaml`).
2. Select your repository.
3. Configure the settings:
   - **Root Directory**: `backend` (if deploying from monorepo)
   - **Runtime**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port 10000`
   - **Health Check Path**: `/health`
4. Set Environment Variables:
   - `SECRET_KEY`: *(Generate a secure key)*
   - `CORS_ORIGINS`: `["*"]`
   - `FRONTEND_URL`: `https://your-site.netlify.app` *(Your Netlify URL)*
   - `ADMIN_EMAIL`: `admin@mailguard.enterprise`
   - `ADMIN_PASSWORD`: `AdminPass@2026!`
5. Click **Create Web Service**. Your backend will be live at `https://your-backend.onrender.com`.

---

### Step 2: Deploy Frontend to Netlify

#### Option A: Drag & Drop (10 Seconds)
1. Go to [Netlify Dashboard](https://app.netlify.com/) -> **Sites** -> **Add new site** -> **Deploy manually**.
2. Drag and drop the `frontend` folder.
3. Your site is instantly live!

#### Option B: Connect Git Repository
1. In Netlify, click **Import from Git** and choose this repository.
2. Set **Base directory**: `frontend` and **Publish directory**: `.` (or `frontend`).
3. Click **Deploy Site**.

#### Option C: Point Frontend to Render Backend
In `frontend/js/config.js`, set your Render backend URL:
```javascript
let defaultApiBase = isLocalhost ? "http://localhost:8000" : "https://your-backend.onrender.com";
```
*(Or simply click the **Backend API** button on the top right of the login screen in your browser and enter the Render URL).*


## 🔑 Default Credentials

For instant demonstration and evaluation:
* **Admin Security Portal:**
  * **Email:** `admin@mailguard.enterprise`
  * **Password:** `AdminPass@2026!`
* **Employee Portal:**
  * Employees can be provisioned directly by the Admin, or logged in seamlessly using any corporate Google account.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
