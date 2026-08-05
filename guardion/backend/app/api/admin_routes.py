"""
Guardion Admin Routes
All endpoints require admin role.

GET  /admin/users        — list all registered users
GET  /admin/stats        — aggregated platform statistics
GET  /admin/prompt_logs  — all prompt analysis logs
GET  /admin/repo_scans   — all repo scan logs
GET  /admin/code_scans   — all code scan logs
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import List, Optional

from app.services.auth_service import require_admin
from app.db.mongodb import (
    users_collection,
    prompt_logs_collection,
    repo_scans_collection,
    code_scans_collection,
)

router = APIRouter(prefix="/admin", tags=["Admin"])


# ──────────────────── Response Schemas ────────────────────

class AdminUserItem(BaseModel):
    id: str
    name: str
    email: str
    role: str
    created_at: str
    prompt_count: int = 0
    repo_scan_count: int = 0
    code_scan_count: int = 0


class AdminStatsResponse(BaseModel):
    total_users: int
    total_prompts: int
    total_repo_scans: int
    total_code_scans: int
    threats_detected: int
    avg_risk_score: float
    active_users_30d: int


class PaginatedResponse(BaseModel):
    items: list
    total: int
    page: int
    per_page: int


# ──────────────────── Endpoints ────────────────────

@router.get("/users", response_model=List[AdminUserItem])
def list_users(admin: dict = Depends(require_admin)):
    """List all registered users with usage counts."""
    col = users_collection()
    users = list(col.find({}, {"password_hash": 0}).sort("created_at", -1))

    result = []
    for u in users:
        uid = str(u["_id"])
        prompt_count = prompt_logs_collection().count_documents({"user_id": uid})
        repo_count = repo_scans_collection().count_documents({"user_id": uid})
        code_count = code_scans_collection().count_documents({"user_id": uid})

        result.append(AdminUserItem(
            id=uid,
            name=u.get("name", ""),
            email=u.get("email", ""),
            role=u.get("role", "client"),
            created_at=u["created_at"].isoformat() if isinstance(u.get("created_at"), datetime) else str(u.get("created_at", "")),
            prompt_count=prompt_count,
            repo_scan_count=repo_count,
            code_scan_count=code_count,
        ))

    return result


@router.get("/stats", response_model=AdminStatsResponse)
def admin_stats(admin: dict = Depends(require_admin)):
    """Aggregated platform statistics for the admin dashboard."""
    from datetime import timedelta

    total_users = users_collection().count_documents({})
    total_prompts = prompt_logs_collection().count_documents({})
    total_repo = repo_scans_collection().count_documents({})
    total_code = code_scans_collection().count_documents({})

    # Threats detected = prompts flagged as threats
    threats_detected = prompt_logs_collection().count_documents({
        "result.is_threat": True
    })

    # Average risk score
    pipeline = [
        {"$match": {"result.risk_score": {"$exists": True}}},
        {"$group": {"_id": None, "avg_score": {"$avg": "$result.risk_score"}}},
    ]
    agg = list(prompt_logs_collection().aggregate(pipeline))
    avg_risk = round(agg[0]["avg_score"], 1) if agg and agg[0].get("avg_score") else 0.0

    # Active users in last 30 days (users who have any log entry)
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    active_prompt_users = prompt_logs_collection().distinct("user_id", {"created_at": {"$gte": thirty_days_ago}})
    active_repo_users = repo_scans_collection().distinct("user_id", {"created_at": {"$gte": thirty_days_ago}})
    active_code_users = code_scans_collection().distinct("user_id", {"created_at": {"$gte": thirty_days_ago}})
    active_users = len(set(active_prompt_users + active_repo_users + active_code_users))

    return AdminStatsResponse(
        total_users=total_users,
        total_prompts=total_prompts,
        total_repo_scans=total_repo,
        total_code_scans=total_code,
        threats_detected=threats_detected,
        avg_risk_score=avg_risk,
        active_users_30d=active_users,
    )


@router.get("/prompt_logs", response_model=PaginatedResponse)
def admin_prompt_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    admin: dict = Depends(require_admin),
):
    """Paginated list of all prompt analysis logs."""
    col = prompt_logs_collection()
    total = col.count_documents({})
    items = list(
        col.find({})
        .sort("created_at", -1)
        .skip((page - 1) * per_page)
        .limit(per_page)
    )

    # Convert ObjectIds to strings
    for item in items:
        item["_id"] = str(item["_id"])

    return PaginatedResponse(items=items, total=total, page=page, per_page=per_page)


@router.get("/repo_scans", response_model=PaginatedResponse)
def admin_repo_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    admin: dict = Depends(require_admin),
):
    """Paginated list of all repo scan logs."""
    col = repo_scans_collection()
    total = col.count_documents({})
    items = list(
        col.find({})
        .sort("created_at", -1)
        .skip((page - 1) * per_page)
        .limit(per_page)
    )

    for item in items:
        item["_id"] = str(item["_id"])

    return PaginatedResponse(items=items, total=total, page=page, per_page=per_page)


@router.get("/code_scans", response_model=PaginatedResponse)
def admin_code_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    admin: dict = Depends(require_admin),
):
    """Paginated list of all code scan logs."""
    col = code_scans_collection()
    total = col.count_documents({})
    items = list(
        col.find({})
        .sort("created_at", -1)
        .skip((page - 1) * per_page)
        .limit(per_page)
    )

    for item in items:
        item["_id"] = str(item["_id"])

    return PaginatedResponse(items=items, total=total, page=page, per_page=per_page)