"""
Repository Vulnerability Scanner Service
Clones a GitHub repo, extracts dependencies, and queries OSV API for CVEs.
"""

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import httpx

from app.config import settings
from app.services.nvd_service import enrich_vulnerabilities
from app.services.owasp_service import tag_vulnerabilities_owasp

logger = logging.getLogger("guardion.scanner")


# ──────────────────── Dependency Extraction ────────────────────

def extract_dependencies(repo_path: str) -> list[dict]:
    """
    Walk the cloned repo and extract dependencies from supported files.
    Returns a list of dicts: {"name": "pkg", "version": "1.0.0", "ecosystem": "npm"}
    """
    deps: list[dict] = []
    repo = Path(repo_path)

    # ── package.json (npm/yarn) ──
    for pj in repo.rglob("package.json"):
        # Skip node_modules
        if "node_modules" in str(pj):
            continue
        try:
            data = json.loads(pj.read_text(encoding="utf-8", errors="ignore"))
            for section in ("dependencies", "devDependencies"):
                for name, version in data.get(section, {}).items():
                    # Strip version prefixes like ^, ~, >=
                    clean_ver = re.sub(r"^[~^>=<]*", "", str(version)).strip()
                    deps.append({
                        "name": name,
                        "version": clean_ver,
                        "ecosystem": "npm",
                    })
        except (json.JSONDecodeError, OSError):
            continue

    # ── requirements.txt (Python / pip) ──
    for req in repo.rglob("requirements*.txt"):
        try:
            for line in req.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Handle name==version, name>=version, plain name
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:[><=!~]+\s*(.+))?$", line)
                if match:
                    deps.append({
                        "name": match.group(1),
                        "version": (match.group(2) or "").strip(),
                        "ecosystem": "PyPI",
                    })
        except OSError:
            continue

    # ── pom.xml (Maven / Java) — basic extraction ──
    for pom in repo.rglob("pom.xml"):
        try:
            content = pom.read_text(encoding="utf-8", errors="ignore")
            # Simple regex extraction (not a full XML parser for hackathon speed)
            artifact_re = re.finditer(
                r"<dependency>\s*"
                r"<groupId>([^<]+)</groupId>\s*"
                r"<artifactId>([^<]+)</artifactId>\s*"
                r"(?:<version>([^<]*)</version>)?",
                content,
                re.DOTALL,
            )
            for m in artifact_re:
                group_id = m.group(1).strip()
                artifact_id = m.group(2).strip()
                version = (m.group(3) or "").strip()
                deps.append({
                    "name": f"{group_id}:{artifact_id}",
                    "version": version,
                    "ecosystem": "Maven",
                })
        except OSError:
            continue

    # Deduplicate
    seen = set()
    unique: list[dict] = []
    for d in deps:
        key = (d["name"], d["version"], d["ecosystem"])
        if key not in seen:
            seen.add(key)
            unique.append(d)

    return unique


# ──────────────────── OSV API Lookup ────────────────────

async def query_osv(client: httpx.AsyncClient, package_name: str, version: str, ecosystem: str) -> list[dict]:
    """
    Query the OSV.dev API for known vulnerabilities of a specific package.
    Uses a shared httpx client for connection pooling.

    Returns a list of vulnerability dicts with:
      - cve_id, cvss_score, severity, description
    """
    payload: dict = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        }
    }
    # Only include version if we have one
    if version:
        payload["version"] = version

    results: list[dict] = []

    try:
        resp = await client.post(settings.OSV_API_URL, json=payload)
        if resp.status_code != 200:
            return results

        data = resp.json()
        vulns = data.get("vulns", [])

        for vuln in vulns:
            # Extract CVE ID from aliases
            cve_id = "N/A"
            for alias in vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break

            # Extract CVSS score and severity from severity list
            cvss_score = 0.0
            severity_label = "UNKNOWN"
            for sev in vuln.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    score_str = sev.get("score", "")
                    # Try to extract numeric score from CVSS vector
                    try:
                        # OSV sometimes gives the vector string; parse base score
                        if "/" in score_str:
                            # It's a vector string, not a raw score
                            pass
                        else:
                            cvss_score = float(score_str)
                    except (ValueError, TypeError):
                        pass

            # Derive severity from CVSS score if available
            if cvss_score >= 9.0:
                severity_label = "CRITICAL"
            elif cvss_score >= 7.0:
                severity_label = "HIGH"
            elif cvss_score >= 4.0:
                severity_label = "MEDIUM"
            elif cvss_score > 0:
                severity_label = "LOW"
            else:
                # Fallback: check database_specific severity
                db_specific = vuln.get("database_specific", {})
                raw_sev = db_specific.get("severity", "").upper()
                if raw_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    severity_label = raw_sev
                    # Assign estimated score
                    cvss_score = {
                        "CRITICAL": 9.5, "HIGH": 7.5,
                        "MEDIUM": 5.0, "LOW": 2.5
                    }.get(severity_label, 0.0)

            description = vuln.get("summary", vuln.get("details", ""))[:500]

            results.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "severity": severity_label,
                "description": description,
            })

    except httpx.HTTPError as e:
        logger.debug(f"OSV query failed for {package_name}: {e}")

    return results


# ──────────────────── Clone Repository ────────────────────

def clone_repo(repo_url: str) -> str:
    """
    Clone a GitHub repo to a temp directory. Returns the local path.
    Uses shallow clone (depth=1) for speed. Falls back to git CLI.
    """
    temp_dir = tempfile.mkdtemp(prefix="guardion_", dir=None)
    logger.info(f"Cloning {repo_url} → {temp_dir}")

    # Try GitPython first
    try:
        import git
        git.Repo.clone_from(
            repo_url,
            temp_dir,
            depth=1,
            single_branch=True,
        )
        logger.info("Clone completed (GitPython)")
        return temp_dir
    except Exception as e:
        logger.warning(f"GitPython clone failed: {e}, trying git CLI")

    # Fallback: git CLI (works on both Windows and Linux)
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", repo_url, temp_dir],
            capture_output=True,
            text=True,
            timeout=120,  # 2 minute timeout
        )
        if result.returncode == 0:
            logger.info("Clone completed (git CLI)")
        else:
            logger.error(f"git CLI clone failed: {result.stderr}")
    except subprocess.TimeoutExpired:
        logger.error("git clone timed out after 120 seconds")
    except FileNotFoundError:
        logger.error("git command not found — install git")

    return temp_dir


def cleanup_repo(path: str):
    """Remove the cloned repo temp directory."""
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass


# ──────────────────── Security Score ────────────────────

def calculate_security_score(vulnerabilities: list[dict]) -> tuple[int, dict]:
    """
    Calculate a security score (0–100) based on vulnerability severities.

    Scoring:
      - Start at 100
      - Critical = -20 each
      - High     = -10 each
      - Medium   = -5  each
      - Low      = -2  each

    Returns:
      (score, severity_counts_dict)
    """
    severity_penalties = {
        "CRITICAL": 20,
        "HIGH": 10,
        "MEDIUM": 5,
        "LOW": 2,
    }

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    total_penalty = 0

    for vuln in vulnerabilities:
        sev = vuln.get("severity", "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1
        total_penalty += severity_penalties.get(sev, 1)

    score = max(0, 100 - total_penalty)
    return score, counts


# ──────────────────── Full Scan Pipeline ────────────────────

async def scan_repository(repo_url: str) -> dict:
    """
    End-to-end repository vulnerability scan:
      1. Clone repo
      2. Extract dependencies
      3. Query OSV for each dependency (parallelized)
      4. Compute security score
      5. Cleanup

    Returns a dict matching RepoScanResponse schema.
    """
    logger.info(f"Starting scan for {repo_url}")
    repo_path = clone_repo(repo_url)

    try:
        # Step 2: Extract dependencies
        deps = extract_dependencies(repo_path)
        logger.info(f"Found {len(deps)} dependencies")

        if not deps:
            logger.warning("No dependencies found in the repository")
            return {
                "repo_url": repo_url,
                "dependencies_scanned": 0,
                "vulnerabilities": [],
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "security_score": 100,
            }

        # Step 3: Query OSV for vulnerabilities (parallel, batched)
        all_vulns: list[dict] = []
        BATCH_SIZE = 10  # Query 10 deps at a time to avoid overwhelming OSV

        async with httpx.AsyncClient(timeout=15.0) as client:
            for i in range(0, len(deps), BATCH_SIZE):
                batch = deps[i : i + BATCH_SIZE]
                tasks = [
                    query_osv(client, dep["name"], dep["version"], dep["ecosystem"])
                    for dep in batch
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for dep, result in zip(batch, results):
                    if isinstance(result, Exception):
                        logger.debug(f"OSV query error for {dep['name']}: {result}")
                        continue
                    for vuln in result:
                        all_vulns.append({
                            "package": dep["name"],
                            "version": dep["version"],
                            **vuln,
                        })

        logger.info(f"Found {len(all_vulns)} vulnerabilities across {len(deps)} deps")

        # Step 3b: Enrich with NVD data (CVSS scores, attack vectors, descriptions)
        all_vulns = await enrich_vulnerabilities(all_vulns)

        # Step 4: Calculate security score
        score, counts = calculate_security_score(all_vulns)

        return {
            "repo_url": repo_url,
            "dependencies_scanned": len(deps),
            "vulnerabilities": all_vulns,
            "critical_count": counts.get("CRITICAL", 0),
            "high_count": counts.get("HIGH", 0),
            "medium_count": counts.get("MEDIUM", 0),
            "low_count": counts.get("LOW", 0),
            "security_score": score,
        }

    finally:
        # Step 5: Always cleanup
        cleanup_repo(repo_path)