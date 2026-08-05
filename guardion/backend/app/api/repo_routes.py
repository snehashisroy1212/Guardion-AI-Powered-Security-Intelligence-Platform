"""
Repository Scanner API Routes
Handles repository vulnerability scanning and AI remediation requests.
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends

from app.models.schemas import (
    RepoScanRequest, RepoScanResponse, VulnerabilityItem,
    RemediationRequest, RemediationResponse,
)
from app.services.repo_scanner import scan_repository
from app.services.gemini_service import get_remediation
from app.services.auth_service import get_optional_user
from app.services.owasp_service import get_owasp_top10_reference, OWASP_TOP_10
from app.db.mongodb import repo_scans_collection

router = APIRouter(prefix="/api", tags=["Repository Scanner"])


@router.post("/scan_repo", response_model=RepoScanResponse)
async def scan_repo_endpoint(
    request: RepoScanRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    """
    Scan a GitHub repository for dependency vulnerabilities.

    Pipeline:
      1. Clone the repo (shallow)
      2. Extract dependencies from package.json, requirements.txt, pom.xml
      3. Query OSV API for each dependency
      4. Calculate security score
      5. Store results in database
      6. Return full vulnerability report
    """
    # Run the scan pipeline
    result = await scan_repository(request.repo_url)

    # Store in MongoDB
    try:
        import logging
        repo_scans_collection().insert_one({
            "user_id": current_user["_id"] if current_user else "anonymous",
            "repo_url": result["repo_url"],
            "dependencies_scanned": result["dependencies_scanned"],
            "total_vulnerabilities": len(result["vulnerabilities"]),
            "vulnerabilities": result["vulnerabilities"],
            "critical_count": result["critical_count"],
            "high_count": result["high_count"],
            "medium_count": result["medium_count"],
            "low_count": result["low_count"],
            "security_score": result["security_score"],
            "created_at": datetime.now(timezone.utc),
        })
    except Exception as e:
        logging.getLogger(__name__).warning(f"MongoDB repo log failed: {e}")

    # Build response
    vuln_items = [
        VulnerabilityItem(
            package=v["package"],
            version=v.get("version", "unknown"),
            cve=v.get("cve_id", "N/A"),
            cvss=v.get("cvss_score", 0.0),
            severity=v.get("severity", "UNKNOWN"),
            description=v.get("description", ""),
            attack_vector=v.get("attack_vector", ""),
            attack_complexity=v.get("attack_complexity", ""),
            nvd_description=v.get("nvd_description", ""),
            references=v.get("references", []),
            owasp_id=v.get("owasp_id", ""),
            owasp_category=v.get("owasp_category", ""),
        )
        for v in result["vulnerabilities"]
    ]

    return RepoScanResponse(
        repo_url=result["repo_url"],
        dependencies_scanned=result["dependencies_scanned"],
        vulnerabilities=vuln_items,
        critical_count=result["critical_count"],
        high_count=result["high_count"],
        medium_count=result["medium_count"],
        low_count=result["low_count"],
        security_score=result["security_score"],
    )


@router.post("/remediate", response_model=RemediationResponse)
async def remediation_endpoint(request: RemediationRequest):
    """
    Get AI-powered remediation suggestions for a specific vulnerability.

    Pipeline:
      1. Try Gemini context-aware analysis (gemini-1.5-flash)
      2. Fall back to template if Gemini is unavailable
    """
    result = await get_remediation(
        package_name=request.package_name,
        cve_id=request.cve_id,
        description=request.description,
        version=getattr(request, 'version', 'unknown'),
        cvss_score=getattr(request, 'cvss_score', 0.0),
    )

    return RemediationResponse(
        explanation=result["explanation"],
        suggested_fix=result["suggested_fix"],
        recommended_version=result.get("recommended_version", "latest"),
        summary=result.get("summary", ""),
        impact=result.get("impact", ""),
        remediation=result.get("remediation", ""),
        recommended_upgrade=result.get("recommended_upgrade", ""),
    )


# ──────────────────── OWASP Top 10 Endpoints ────────────────────


@router.get("/owasp_top10")
async def get_owasp_reference():
    """Return the OWASP Top 10 (2021) reference list with descriptions."""
    return get_owasp_top10_reference()


@router.get("/owasp_trending")
async def get_owasp_trending(
    current_user: Optional[dict] = Depends(get_optional_user),
):
    """
    Return trending OWASP vulnerability categories from scan history.
    Aggregates all scanned vulnerabilities and ranks by OWASP category frequency.
    """
    rs = repo_scans_collection()

    # Aggregate OWASP categories across all scans
    pipeline = [
        {"$unwind": "$vulnerabilities"},
        {"$match": {"vulnerabilities.owasp_id": {"$exists": True, "$ne": ""}}},
        {"$group": {
            "_id": "$vulnerabilities.owasp_id",
            "category": {"$first": "$vulnerabilities.owasp_category"},
            "count": {"$sum": 1},
            "avg_cvss": {"$avg": "$vulnerabilities.cvss_score"},
            "max_cvss": {"$max": "$vulnerabilities.cvss_score"},
            "sample_cves": {"$addToSet": "$vulnerabilities.cve_id"},
            "affected_packages": {"$addToSet": "$vulnerabilities.package"},
        }},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]

    results = list(rs.aggregate(pipeline))

    trending = []
    for r in results:
        owasp_code = r["_id"].split(":")[0] if ":" in r["_id"] else r["_id"]
        info = OWASP_TOP_10.get(owasp_code, {})
        trending.append({
            "owasp_id": r["_id"],
            "owasp_category": r.get("category", info.get("name", "")),
            "description": info.get("description", ""),
            "color": info.get("color", "#718096"),
            "vuln_count": r["count"],
            "avg_cvss": round(r.get("avg_cvss", 0) or 0, 1),
            "max_cvss": round(r.get("max_cvss", 0) or 0, 1),
            "sample_cves": r.get("sample_cves", [])[:5],
            "affected_packages": r.get("affected_packages", [])[:8],
        })

    # Fill in any missing OWASP categories with zero counts
    seen_ids = {t["owasp_id"] for t in trending}
    for code, info in OWASP_TOP_10.items():
        owasp_id = info["id"]
        if owasp_id not in seen_ids:
            trending.append({
                "owasp_id": owasp_id,
                "owasp_category": info["name"],
                "description": info["description"],
                "color": info["color"],
                "vuln_count": 0,
                "avg_cvss": 0,
                "max_cvss": 0,
                "sample_cves": [],
                "affected_packages": [],
            })

    return trending