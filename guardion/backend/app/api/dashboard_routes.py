"""
Dashboard API Routes
Provides aggregated metrics and recent activity for the React dashboard.
Supports both user-scoped (client) and global (admin) views.
"""

from fastapi import APIRouter, Depends

from app.models.schemas import DashboardResponse, PromptMetrics, RepoMetrics
from app.services.auth_service import get_current_user, get_optional_user
from app.db.mongodb import prompt_logs_collection, repo_scans_collection, code_scans_collection

from typing import Optional

router = APIRouter(prefix="/api", tags=["Dashboard"])


@router.get("/dashboard", response_model=DashboardResponse)
async def get_dashboard(
    current_user: Optional[dict] = Depends(get_optional_user),
):
    """
    Return aggregated security metrics for the dashboard.
    If authenticated, returns user-scoped data from MongoDB.
    Otherwise returns global data from MongoDB.
    """
    user_id = current_user["_id"] if current_user else None
    return _dashboard_from_mongo(user_id)


def _dashboard_from_mongo(user_id: Optional[str] = None) -> DashboardResponse:
    """Build dashboard response from MongoDB for a specific user."""
    pl = prompt_logs_collection()
    rs = repo_scans_collection()

    # Prompt metrics
    query_filter = {"user_id": user_id} if user_id else {}
    total_prompts = pl.count_documents(query_filter)
    blocked = pl.count_documents({**query_filter, "decision": "block"})
    warnings = pl.count_documents({**query_filter, "decision": "warn"})
    allowed = pl.count_documents({**query_filter, "decision": "allow"})

    credential_cats = ["api_key", "password", "auth_token", "private_key", "aws_key", "github_token", "generic_secret"]
    credential_leaks = pl.count_documents({
        **query_filter,
        "detected_categories": {"$in": credential_cats},
    })

    prompt_metrics = PromptMetrics(
        total_prompts=total_prompts,
        blocked=blocked,
        warnings=warnings,
        allowed=allowed,
        credential_leaks=credential_leaks,
    )

    # Repo metrics
    total_scans = rs.count_documents(query_filter)
    pipeline = [
        {"$match": query_filter},
        {"$group": {
            "_id": None,
            "total_vulns": {"$sum": "$total_vulnerabilities"},
            "critical": {"$sum": "$critical_count"},
            "high": {"$sum": "$high_count"},
            "medium": {"$sum": "$medium_count"},
            "low": {"$sum": "$low_count"},
        }},
    ]
    agg = list(rs.aggregate(pipeline))
    repo_agg = agg[0] if agg else {}

    repo_metrics = RepoMetrics(
        total_scans=total_scans,
        total_vulnerabilities=repo_agg.get("total_vulns", 0),
        critical=repo_agg.get("critical", 0),
        high=repo_agg.get("high", 0),
        medium=repo_agg.get("medium", 0),
        low=repo_agg.get("low", 0),
    )

    # Recent prompts
    recent_prompts_docs = list(
        pl.find(query_filter).sort("created_at", -1).limit(10)
    )
    recent_prompts = [
        {
            "id": str(p["_id"]),
            "prompt_preview": (p.get("prompt_text", "")[:100] + "...") if len(p.get("prompt_text", "")) > 100 else p.get("prompt_text", ""),
            "risk_score": p.get("risk_score", 0),
            "decision": p.get("decision", ""),
            "categories": ",".join(p.get("detected_categories", [])) if isinstance(p.get("detected_categories"), list) else p.get("detected_categories", ""),
            "source": p.get("source_site", ""),
            "created_at": p["created_at"].isoformat() if p.get("created_at") else "",
        }
        for p in recent_prompts_docs
    ]

    # Recent repo scans
    recent_scans_docs = list(
        rs.find(query_filter).sort("created_at", -1).limit(10)
    )
    recent_scans = [
        {
            "id": str(s["_id"]),
            "repo_url": s.get("repo_url", ""),
            "dependencies_scanned": s.get("dependencies_scanned", 0),
            "total_vulnerabilities": s.get("total_vulnerabilities", 0),
            "security_score": s.get("security_score", 0),
            "critical": s.get("critical_count", 0),
            "high": s.get("high_count", 0),
            "medium": s.get("medium_count", 0),
            "low": s.get("low_count", 0),
            "created_at": s["created_at"].isoformat() if s.get("created_at") else "",
        }
        for s in recent_scans_docs
    ]

    return DashboardResponse(
        prompt_metrics=prompt_metrics,
        repo_metrics=repo_metrics,
        recent_prompts=recent_prompts,
        recent_scans=recent_scans,
    )