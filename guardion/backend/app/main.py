"""
Guardion — Main Application Entry Point
FastAPI server with CORS, route registration, and database initialization.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from .db.mongodb import init_mongodb
from app.api.prompt_routes import router as prompt_router
from app.api.repo_routes import router as repo_router
from app.api.dashboard_routes import router as dashboard_router
from app.api.code_scan_routes import router as code_scan_router
from app.api.auth_routes import router as auth_router
from app.api.admin_routes import router as admin_router

# ──────────────────── App Initialization ────────────────────

app = FastAPI(
    title="Guardion",
    description="AI Prompt Security + Repository Vulnerability Scanner",
    version="1.0.0",
    docs_url="/docs",          # Swagger UI at /docs
    redoc_url="/redoc",        # ReDoc at /redoc
)

# ──────────────────── CORS Configuration ────────────────────
# Allow requests from the React dashboard and Chrome extension

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # Permissive for hackathon; tighten for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────── Register Routers ────────────────────

app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(prompt_router)
app.include_router(repo_router)
app.include_router(dashboard_router)
app.include_router(code_scan_router)

# ──────────────────── Startup Events ────────────────────


@app.on_event("startup")
async def startup():
    """Initialize MongoDB on server start."""
    init_mongodb()
    print("Guardion backend started — MongoDB initialized")


# ──────────────────── Health Check ────────────────────


@app.get("/", tags=["Health"])
async def root():
    """Root endpoint — confirms the server is running."""
    return {
        "service": "Guardion",
        "status": "operational",
        "version": "2.0.0",
        "endpoints": {
            "signup": "POST /auth/signup",
            "login": "POST /auth/login",
            "analyze_prompt": "POST /api/analyze_prompt",
            "scan_repo": "POST /api/scan_repo",
            "scan_code": "POST /api/scan_code",
            "dashboard": "GET /api/dashboard",
            "admin": "GET /admin/stats",
            "docs": "GET /docs",
        },
    }


# ──────────────────── Direct Run ────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True,
    )