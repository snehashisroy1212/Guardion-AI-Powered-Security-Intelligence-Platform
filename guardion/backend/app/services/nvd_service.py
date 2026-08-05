"""
Guardion NVD (National Vulnerability Database) Service
Enriches OSV results with detailed CVE data from the NVD API.

Features:
  - Query NVD API v2.0 by CVE ID
  - Extract CVSS v3.1 metrics (score, attack vector, attack complexity)
  - MongoDB caching to avoid repeated API calls
  - Batch enrichment of vulnerability lists
"""

import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger("guardion.nvd")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ──────────────────── MongoDB Cache ────────────────────

def _get_cache_collection():
    """Get the cve_cache MongoDB collection."""
    from app.db.mongodb import get_db
    return get_db().cve_cache


def _get_cached(cve_id: str) -> Optional[dict]:
    """Look up a CVE in the MongoDB cache."""
    try:
        doc = _get_cache_collection().find_one({"cve": cve_id})
        if doc:
            doc.pop("_id", None)
            return doc
    except Exception as e:
        logger.debug(f"Cache read failed for {cve_id}: {e}")
    return None


def _set_cached(data: dict):
    """Store a CVE result in the MongoDB cache (upsert)."""
    try:
        _get_cache_collection().update_one(
            {"cve": data["cve"]},
            {"$set": data},
            upsert=True,
        )
    except Exception as e:
        logger.debug(f"Cache write failed for {data.get('cve')}: {e}")


# ──────────────────── NVD API Query ────────────────────

async def fetch_cve_from_nvd(cve_id: str, client: httpx.AsyncClient) -> Optional[dict]:
    """
    Query the NVD API for a single CVE ID.

    Returns a dict with:
      cve, cvss_score, severity, attack_vector, attack_complexity,
      description, references
    """
    if not settings.NVD_API_KEY:
        logger.debug("NVD_API_KEY not configured — skipping NVD lookup")
        return None

    headers = {"apiKey": settings.NVD_API_KEY}
    params = {"cveId": cve_id}

    try:
        resp = await client.get(NVD_API_BASE, headers=headers, params=params)
        if resp.status_code == 403:
            logger.warning("NVD API key rejected (403)")
            return None
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            logger.debug(f"NVD API returned {resp.status_code} for {cve_id}")
            return None

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        cve_item = vulnerabilities[0].get("cve", {})
        return _parse_nvd_cve(cve_id, cve_item)

    except httpx.HTTPError as e:
        logger.debug(f"NVD HTTP error for {cve_id}: {e}")
        return None
    except Exception as e:
        logger.debug(f"NVD parse error for {cve_id}: {e}")
        return None


def _parse_nvd_cve(cve_id: str, cve_item: dict) -> dict:
    """Parse the NVD CVE item into a clean dict."""
    # Extract description (English preferred)
    description = ""
    for desc in cve_item.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    if not description:
        descriptions = cve_item.get("descriptions", [])
        if descriptions:
            description = descriptions[0].get("value", "")

    # Extract CVSS v3.1 metrics (preferred) then v3.0 fallback
    cvss_score = 0.0
    severity = "UNKNOWN"
    attack_vector = ""
    attack_complexity = ""

    metrics = cve_item.get("metrics", {})

    # Try CVSS v3.1 first, then v3.0
    cvss_data = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            break

    if cvss_data:
        cvss_score = cvss_data.get("baseScore", 0.0)
        severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
        attack_vector = cvss_data.get("attackVector", "")
        attack_complexity = cvss_data.get("attackComplexity", "")

    # Fallback: CVSS v2
    if cvss_score == 0.0:
        v2_list = metrics.get("cvssMetricV2", [])
        if v2_list:
            v2_data = v2_list[0].get("cvssData", {})
            cvss_score = v2_data.get("baseScore", 0.0)
            attack_vector = v2_data.get("accessVector", "")
            attack_complexity = v2_data.get("accessComplexity", "")
            # Derive severity from v2 score
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            elif cvss_score > 0:
                severity = "LOW"

    # Extract references
    references = []
    for ref in cve_item.get("references", [])[:5]:
        references.append(ref.get("url", ""))

    return {
        "cve": cve_id,
        "cvss_score": cvss_score,
        "severity": severity,
        "attack_vector": attack_vector,
        "attack_complexity": attack_complexity,
        "description": description[:800],
        "references": references,
        "cached_at": datetime.now(timezone.utc).isoformat(),
    }


# ──────────────────── Batch Enrichment ────────────────────

async def enrich_vulnerabilities(vulns: list[dict]) -> list[dict]:
    """
    Enrich a list of vulnerability dicts with NVD data.

    For each vuln with a valid CVE ID:
      1. Check MongoDB cache first
      2. If not cached, query NVD API
      3. Cache the result
      4. Merge NVD data into the vuln dict

    Returns the same list with enriched fields:
      nvd_cvss_score, nvd_severity, attack_vector, attack_complexity,
      nvd_description, references
    """
    if not settings.NVD_API_KEY:
        logger.info("NVD_API_KEY not set — skipping NVD enrichment")
        return vulns

    # Collect unique CVE IDs that need lookup
    cve_ids = set()
    for v in vulns:
        cve_id = v.get("cve_id", "N/A")
        if cve_id and cve_id != "N/A" and cve_id.startswith("CVE-"):
            cve_ids.add(cve_id)

    if not cve_ids:
        return vulns

    logger.info(f"Enriching {len(cve_ids)} unique CVEs via NVD")

    # Resolve each CVE (cache first, then API)
    nvd_data: dict[str, dict] = {}

    # Phase 1: Check cache
    uncached = []
    for cve_id in cve_ids:
        cached = _get_cached(cve_id)
        if cached:
            nvd_data[cve_id] = cached
        else:
            uncached.append(cve_id)

    logger.info(f"NVD cache hits: {len(nvd_data)}, misses: {len(uncached)}")

    # Phase 2: Query NVD API for uncached CVEs (rate-limited batches)
    if uncached:
        async with httpx.AsyncClient(timeout=15.0) as client:
            for cve_id in uncached:
                result = await fetch_cve_from_nvd(cve_id, client)
                if result:
                    nvd_data[cve_id] = result
                    _set_cached(result)

    # Phase 3: Merge NVD data into vulnerability dicts
    for v in vulns:
        cve_id = v.get("cve_id", "N/A")
        nvd = nvd_data.get(cve_id)
        if nvd:
            # NVD data enriches (but doesn't overwrite existing non-zero scores)
            if nvd.get("cvss_score", 0) > 0:
                v["cvss_score"] = nvd["cvss_score"]
            if nvd.get("severity", "UNKNOWN") != "UNKNOWN":
                v["severity"] = nvd["severity"]
            v["attack_vector"] = nvd.get("attack_vector", "")
            v["attack_complexity"] = nvd.get("attack_complexity", "")
            if nvd.get("description"):
                v["nvd_description"] = nvd["description"]
            v["references"] = nvd.get("references", [])

    return vulns