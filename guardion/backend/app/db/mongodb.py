"""
Guardion MongoDB Connection
Connects to MongoDB Atlas and provides collection accessors.
Falls back to local MongoDB if Atlas URI is not configured.
"""

import logging
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

from app.config import settings

logger = logging.getLogger("guardion.mongodb")

# ──────────────────── Connection ────────────────────

_client: MongoClient | None = None
_db = None


def get_mongo_client() -> MongoClient:
    """Get or create the MongoDB client singleton."""
    global _client
    if _client is None:
        _client = MongoClient(
            settings.MONGO_URI,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
        )
    return _client


def get_db():
    """Get the Guardion database instance."""
    global _db
    if _db is None:
        client = get_mongo_client()
        _db = client[settings.MONGO_DB_NAME]
    return _db


def init_mongodb():
    """
    Initialize MongoDB connection and create indexes.
    Called on application startup.
    """
    try:
        client = get_mongo_client()
        # Verify connection
        client.admin.command("ping")
        db = get_db()

        # ── Create indexes for performance ──
        # Users: unique email, index on role
        db.users.create_index("email", unique=True)
        db.users.create_index("role")

        # Prompt logs: index on user_id + timestamp for dashboard queries
        db.prompt_logs.create_index([("user_id", 1), ("created_at", -1)])
        db.prompt_logs.create_index("decision")

        # Code scans: index on user_id + timestamp
        db.code_scans.create_index([("user_id", 1), ("created_at", -1)])

        # Repo scans: index on user_id + timestamp
        db.repo_scans.create_index([("user_id", 1), ("created_at", -1)])

        # CVE cache: unique CVE ID index for NVD enrichment
        db.cve_cache.create_index("cve", unique=True)

        logger.info("MongoDB connected and indexes created")
        print("[OK] MongoDB connected successfully")
        return True
    except ConnectionFailure as e:
        logger.error(f"MongoDB connection failed: {e}")
        print(f"[WARN] MongoDB connection failed: {e}")
        return False
    except Exception as e:
        logger.error(f"MongoDB init error: {e}")
        print(f"[WARN] MongoDB init error: {e}")
        return False


# ──────────────────── Collection Accessors ────────────────────
# Convenience functions for accessing collections.

def users_collection():
    return get_db().users


def prompt_logs_collection():
    return get_db().prompt_logs


def code_scans_collection():
    return get_db().code_scans


def repo_scans_collection():
    return get_db().repo_scans


def cve_cache_collection():
    return get_db().cve_cache