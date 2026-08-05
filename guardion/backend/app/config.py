"""
Guardion Configuration
Loads environment variables and defines app-wide settings.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application settings loaded from environment variables."""

    # Gemini AI API key for vulnerability remediation
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")

    # Gemini model to use (change if one model's quota is exhausted)
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite")

    # Fallback model chain: tried in order when primary model's quota is exhausted
    GEMINI_FALLBACK_MODELS: list[str] = os.getenv(
        "GEMINI_FALLBACK_MODELS",
        "gemini-2.5-flash-lite,gemini-2.5-flash,gemma-3-4b-it,gemini-2.0-flash-lite"
    ).split(",")

    # Economy mode: when True, Gemini is only called when explicitly requested
    # Default True to protect free-tier quota
    ECONOMY_MODE: bool = os.getenv("ECONOMY_MODE", "true").lower() in ("true", "1", "yes")

    # Max Gemini calls per minute (free tier allows ~15 RPM)
    GEMINI_RPM_LIMIT: int = int(os.getenv("GEMINI_RPM_LIMIT", "10"))

    # Server configuration
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))

    # CORS allowed origins (extension + dashboard)
    CORS_ORIGINS: list[str] = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:3000,http://localhost:5173,chrome-extension://*"
    ).split(",")

    # Temp directory for cloning repos
    TEMP_DIR: str = os.getenv("TEMP_DIR", "./tmp_repos")

    # OSV API endpoint for vulnerability lookups
    OSV_API_URL: str = "https://api.osv.dev/v1/query"

    # NVD (National Vulnerability Database) API key for CVE enrichment
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")

    # ── MongoDB ──
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    MONGO_DB_NAME: str = os.getenv("MONGO_DB_NAME", "guardion")

    # ── JWT Authentication ──
    JWT_SECRET: str = os.getenv("JWT_SECRET", "guardion-super-secret-key-change-in-production")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "1440"))  # 24 hours


settings = Settings()