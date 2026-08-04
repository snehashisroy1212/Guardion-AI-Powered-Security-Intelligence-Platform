# Guardion-AI-Powered-Security-Intelligence-Platform

Guardion is a full-stack cybersecurity SaaS platform that protects developers across three critical surfaces:

1.AI Prompt Security — Intercepts and scans prompts sent to ChatGPT, Claude & Gemini for leaked secrets, PII, and prompt injection attacks
2.Repository Vulnerability Scanning — Scans GitHub repos for vulnerable dependencies via OSV/NVD databases with AI-powered remediation
3.Static Code Analysis — Detects hardcoded credentials, command injection, SQL injection, weak cryptography, and more — with AI-powered fix suggestions



## 🧩 Project Structure

```
Guardion/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── auth_routes.py         # Signup, login, user profile
│   │   │   ├── prompt_routes.py       # Prompt analysis & ML comparison
│   │   │   ├── repo_routes.py         # Repo scanning & AI remediation
│   │   │   ├── code_scan_routes.py    # Static analysis & AI fix code
│   │   │   ├── dashboard_routes.py    # User-scoped dashboard metrics
│   │   │   └── admin_routes.py        # Admin platform analytics
│   │   ├── services/
│   │   │   ├── prompt_analyzer.py     # Regex + ML + Gemini pipeline
│   │   │   ├── gemini_integration.py  # Gemini AI analysis & code fixing
│   │   │   ├── gemini_service.py      # AI vulnerability remediation
│   │   │   ├── gemini_cache.py        # LRU cache + rate limiter
│   │   │   ├── repo_scanner.py        # Git clone, dep parsing, OSV queries
│   │   │   ├── code_scanner.py        # Static code analysis engine
│   │   │   ├── nvd_service.py         # NVD API enrichment + caching
│   │   │   ├── owasp_service.py       # OWASP Top 10 classification
│   │   │   └── auth_service.py        # JWT + bcrypt + role guards
│   │   ├── db/
│   │   │   └── mongodb.py             # MongoDB Atlas connection
│   │   ├── config.py                  # Environment settings
│   │   └── main.py                    # FastAPI entry point
│   ├── guardion_ai_model/
│   │   ├── dataset_generator.py       # Synthetic training data (~500 samples)
│   │   ├── train_model.py             # ML model training pipeline
│   │   ├── inference.py               # Model inference & classification
│   │   └── gemini_compare.py          # ML vs Gemini comparison
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Landing.jsx            # Animated SaaS landing page
│   │   │   ├── Login.jsx              # User login
│   │   │   ├── Signup.jsx             # User registration
│   │   │   ├── Dashboard.jsx          # Main dashboard (3 tabs)
│   │   │   └── AdminDashboard.jsx     # Admin-only analytics
│   │   ├── components/
│   │   │   ├── SecurityPipeline.jsx   # 3-stage security pipeline UI
│   │   │   ├── Charts.jsx             # 4-panel analytics (Recharts)
│   │   │   ├── MetricsCards.jsx       # 8 security metric cards
│   │   │   ├── PromptTester.jsx       # Interactive prompt tester
│   │   │   ├── SecureCodePanel.jsx    # Code scanner + AI fix
│   │   │   ├── RepoScanner.jsx        # Repo scan interface
│   │   │   ├── OwaspTrending.jsx      # OWASP Top 10 hover widget
│   │   │   ├── RecentActivity.jsx     # Activity feed
│   │   │   ├── Header.jsx             # Dashboard header
│   │   │   └── Navbar.jsx             # Landing page navbar
│   │   ├── api.js                     # API client
│   │   ├── App.jsx                    # Root + routing
│   │   └── main.jsx                   # Entry point
│   ├── package.json
│   └── vite.config.js
├── extension/
│   ├── manifest.json                  # Manifest V3 config
│   ├── background.js                  # Service worker
│   ├── content.js                     # AI chat page interceptor
│   ├── popup.html / popup.js          # Extension popup UI
│   └── guardion.css                   # Overlay styles
└── README.md
```

