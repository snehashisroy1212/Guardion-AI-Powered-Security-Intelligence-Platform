# 🛡️ Guardion — AI-Powered Security Intelligence Platform

Guardion is a full-stack security intelligence platform that combines AI-powered code analysis, prompt safety testing, and repository vulnerability scanning into a single dashboard — backed by real-time CVE enrichment via the NVD API and Google Gemini for AI-driven insights.

---

## ✨ Features

- 🔐 **JWT-based authentication** — secure signup/login with bcrypt password hashing
- 🧪 **Prompt Tester** — evaluate prompts against AI safety/security heuristics
- 🧠 **Secure Code Panel** — scan code snippets, get AI-powered vulnerability detection & fixes
- 📦 **Repo Scanner** — scan full repositories for security issues
- 📊 **Analytics Dashboard** — 8 key security metrics, 4-panel charts, recent activity feed
- 🏆 **OWASP Top 10 Trending** — hover widget surfacing trending vulnerability classes
- 👤 **Admin Dashboard** — admin-only analytics and oversight
- 🧩 **Browser Extension** — Manifest V3 extension that intercepts AI chat pages for inline security checks
- 🗃️ **CVE Caching** — NVD API enrichment cached in MongoDB for fast repeated lookups

---

## 🏗️ Tech Stack

| Layer          | Technology                                   |
|----------------|-----------------------------------------------|
| Frontend       | React (Vite), Recharts                        |
| Backend        | FastAPI (Python), Uvicorn                     |
| Database       | MongoDB (PyMongo)                              |
| Auth           | JWT (python-jose / PyJWT) + Passlib (bcrypt)  |
| AI Integration | Google Gemini (`google-genai`)                |
| Vulnerability Data | NVD (National Vulnerability Database) API |
| Browser Extension | Chrome Extension (Manifest V3)             |

---

## 🖇️ System Architecture

```
┌─────────────────────┐        ┌──────────────────────┐
│   React Frontend     │        │  Browser Extension    │
│  (Vite, port 5173)   │        │  (Manifest V3)         │
│                       │        │  content.js/popup.js  │
└──────────┬────────────┘        └───────────┬───────────┘
           │  REST (JWT Bearer)               │  REST (JWT Bearer)
           ▼                                  ▼
┌───────────────────────────────────────────────────────────┐
│                  FastAPI Backend (port 8000)                │
│  ─────────────────────────────────────────────────────────│
│   /auth        → auth_routes.py     (signup/login/JWT)      │
│   /admin       → admin_routes.py    (admin-only analytics)  │
│   /dashboard   → dashboard_routes.py(metrics, activity)     │
│   /prompt      → prompt_routes.py   (prompt safety testing) │
│   /code-scan   → code_scan_routes.py(code vuln scanning)    │
│   /repo-scan   → repo_routes.py     (repo vuln scanning)     │
└───────┬───────────────────────┬─────────────────┬───────────┘
        │                       │                 │
        ▼                       ▼                 ▼
┌───────────────┐     ┌──────────────────┐  ┌──────────────────┐
│   MongoDB       │     │  Google Gemini    │  │   NVD API         │
│  (users,        │     │  (AI code review, │  │  (CVE lookup &     │
│  prompt_logs,   │     │  fix suggestions, │  │  enrichment,       │
│  code_scans,    │     │  prompt scoring)  │  │  cached in Mongo)  │
│  repo_scans,    │     └──────────────────┘  └──────────────────┘
│  cve_cache)     │
└───────────────┘
```

**Flow summary:**
1. User authenticates via `/auth` → receives JWT.
2. Frontend/extension attaches JWT on all subsequent requests.
3. Scan/prompt requests hit FastAPI → forwarded to Gemini for AI analysis.
4. Any CVE references found are enriched via the NVD API, cached in `cve_cache` to avoid repeat lookups.
5. Results are logged (`prompt_logs`, `code_scans`, `repo_scans`) and surfaced on the Dashboard/Admin Dashboard.

---

## 📁 Project Structure

```
guardion/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── admin_routes.py       # Admin-only analytics endpoints
│   │   │   ├── auth_routes.py        # Signup / login / JWT issuance
│   │   │   ├── code_scan_routes.py   # Code vulnerability scanning
│   │   │   ├── dashboard_routes.py   # Dashboard metrics & activity
│   │   │   ├── prompt_routes.py      # Prompt safety testing
│   │   │   └── repo_routes.py        # Repository scanning
│   │   ├── db/
│   │   │   └── mongodb.py            # MongoDB connection & collection accessors
│   │   ├── models/                   # Pydantic models / schemas
│   │   ├── services/
│   │   │   ├── auth_service.py       # Password hashing, JWT creation/verification
│   │   │   └── gemini_integration.py # Google Gemini AI integration
│   │   ├── config.py                 # Environment-based settings
│   │   └── main.py                   # FastAPI app entrypoint
│   ├── .env                          # Environment variables (not committed)
│   ├── env.example                   # Environment variable template
│   ├── requirements.txt
│   └── run.py                        # Local dev entrypoint (auto-opens browser)
│
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Landing.jsx           # Animated SaaS landing page
│   │   │   ├── Login.jsx             # User login
│   │   │   ├── Signup.jsx            # User registration
│   │   │   ├── Dashboard.jsx         # Main dashboard (3 tabs)
│   │   │   └── AdminDashboard.jsx    # Admin-only analytics
│   │   ├── components/
│   │   │   ├── SecurityPipeline.jsx  # 3-stage security pipeline UI
│   │   │   ├── Charts.jsx            # 4-panel analytics charts (Recharts)
│   │   │   ├── MetricsCards.jsx      # 8 security metric cards
│   │   │   ├── PromptTester.jsx      # Interactive prompt tester
│   │   │   ├── SecureCodePanel.jsx   # Code scanner + AI fix suggestions
│   │   │   ├── RepoScanner.jsx       # Repo scan interface
│   │   │   ├── OwaspTrending.jsx     # OWASP Top 10 hover widget
│   │   │   ├── RecentActivity.jsx    # Activity feed
│   │   │   ├── Header.jsx            # Dashboard header
│   │   │   └── Navbar.jsx            # Landing page navbar
│   │   ├── api.js                    # API client (Axios/fetch + JWT interceptor)
│   │   ├── App.jsx                   # Root component + routing
│   │   └── main.jsx                  # Entry point
│   ├── package.json
│   └── vite.config.js
│
├── extension/
│   ├── manifest.json                 # Manifest V3 config
│   ├── background.js                 # Service worker
│   ├── content.js                    # AI chat page interceptor
│   ├── popup.html / popup.js         # Extension popup UI
│   └── guardion.css                  # Overlay styles
│
└── README.md
```

---

## ⚙️ Getting Started

### Prerequisites
- Python 3.12+
- Node.js 18+
- MongoDB (local or Atlas)
- Google Gemini API key
- NVD API key (optional, for higher rate limits)

### 1. Backend Setup

```bash
cd guardion/backend
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux

pip install -r requirements.txt
copy env.example .env           # Windows
# cp env.example .env           # macOS/Linux
```

Fill in `.env` with your values:
```env
MONGO_URI=mongodb://localhost:27017
MONGO_DB_NAME=guardion
JWT_SECRET=your-super-secret-key
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=1440
GEMINI_API_KEY=your-gemini-api-key
NVD_API_KEY=your-nvd-api-key
```

Run the backend:
```bash
python run.py
```
This starts the server at `http://127.0.0.1:8000` and auto-opens `/docs` (Swagger UI) in your browser.

### 2. Frontend Setup

```bash
cd guardion/frontend
npm install
npm run dev
```
This starts the frontend at `http://localhost:5173`.

> ⚠️ Make sure CORS in `backend/app/main.py` includes `http://localhost:5173` as an allowed origin.

### 3. Browser Extension (optional)

1. Go to `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder

---

## 🔑 Environment Variables

| Variable             | Description                              | Default                        |
|-----------------------|-------------------------------------------|----------------------------------|
| `MONGO_URI`           | MongoDB connection string                | `mongodb://localhost:27017`     |
| `MONGO_DB_NAME`       | Database name                             | `guardion`                       |
| `JWT_SECRET`          | Secret key for signing JWTs               | —                                 |
| `JWT_ALGORITHM`       | JWT signing algorithm                     | `HS256`                          |
| `JWT_EXPIRE_MINUTES`  | Token expiry time (minutes)               | `1440`                           |
| `GEMINI_API_KEY`      | Google Gemini API key                     | —                                 |
| `NVD_API_KEY`         | NVD API key for CVE enrichment            | —                                 |

---

## 📡 Core API Endpoints

| Method | Endpoint            | Description                     |
|--------|----------------------|----------------------------------|
| POST   | `/auth/signup`       | Register a new user             |
| POST   | `/auth/login`        | Authenticate and receive JWT    |
| GET    | `/dashboard/*`       | Dashboard metrics & activity    |
| POST   | `/prompt/*`          | Test prompts for safety issues  |
| POST   | `/code-scan/*`       | Scan code for vulnerabilities   |
| POST   | `/repo-scan/*`       | Scan repositories               |
| GET    | `/admin/*`           | Admin-only analytics            |

Full interactive API docs available at `http://127.0.0.1:8000/docs` once the backend is running.

---

## 🗺️ Roadmap

- [ ] Complete frontend integration with all backend routes
- [ ] Deploy backend + frontend
- [ ] Add CI/CD pipeline
- [ ] Extend browser extension to more AI chat platforms

---

## 📄 License

This project is for academic/major project purposes. Add your chosen license here (MIT, Apache 2.0, etc.).
