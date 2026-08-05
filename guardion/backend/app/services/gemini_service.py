"""
Gemini AI Remediation Service
Uses Google's Gemini API to generate human-friendly vulnerability fix suggestions.
Falls back to a template-based response if the API key is missing or the call fails.

Now uses context-aware analysis via gemini_integration module (gemini-1.5-flash).
"""

from app.services.gemini_integration import generate_vulnerability_remediation


async def get_remediation(
    package_name: str,
    cve_id: str,
    description: str = "",
    version: str = "unknown",
    cvss_score: float = 0.0,
) -> dict:
    """
    Generate AI-powered remediation advice for a vulnerability.

    Pipeline:
      1. Try Gemini context-aware analysis (gemini-1.5-flash)
      2. Fall back to template if Gemini is unavailable

    Args:
        package_name: The vulnerable package (e.g. "lodash")
        cve_id: The CVE identifier (e.g. "CVE-2021-23337")
        description: Brief description of the vulnerability
        version: Current package version
        cvss_score: CVSS score of the vulnerability

    Returns:
        Dict with keys: explanation, suggested_fix, recommended_version,
                        summary, impact, remediation (when Gemini provides them)
    """
    # Try context-aware Gemini analysis first
    try:
        gemini_result = await generate_vulnerability_remediation({
            "package_name": package_name,
            "version": version,
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "description": description,
        })
    except Exception:
        gemini_result = None

    if gemini_result:
        # Map Gemini's context-aware output to the existing response format
        # while also including the richer fields
        return {
            "explanation": gemini_result.get("summary", ""),
            "suggested_fix": gemini_result.get("remediation", ""),
            "recommended_version": gemini_result.get("recommended_upgrade", "latest"),
            # Extended context-aware fields
            "summary": gemini_result.get("summary", ""),
            "impact": gemini_result.get("impact", ""),
            "remediation": gemini_result.get("remediation", ""),
            "recommended_upgrade": gemini_result.get("recommended_upgrade", "latest"),
        }

    # Fallback: template-based response (works without API key)
    return _template_remediation(package_name, cve_id, description)


def _template_remediation(package_name: str, cve_id: str, description: str) -> dict:
    """Generate a basic template remediation when Gemini is unavailable."""
    desc = description or f"Security vulnerability {cve_id}"

    return {
        "explanation": (
            f"The package '{package_name}' has a known vulnerability ({cve_id}). "
            f"{desc}. This could allow attackers to exploit your application."
        ),
        "suggested_fix": (
            f"Upgrade '{package_name}' to the latest patched version. "
            f"Run the appropriate update command for your package manager "
            f"(e.g., `npm update {package_name}` or `pip install --upgrade {package_name}`)."
        ),
        "recommended_version": "latest",
    }