"""
Guardion Pydantic Schemas
Request/response models for API validation and serialization.
"""

from pydantic import BaseModel
from typing import Optional
from datetime import datetime


# ──────────────────── Prompt Analysis ────────────────────

class PromptAnalysisRequest(BaseModel):
    """Incoming prompt to analyze for sensitive data."""
    prompt: str
    source: str = "unknown"  # e.g. "chat.openai.com"
    use_gemini: bool = False  # Set True to include Gemini analysis (costs API quota)


class PromptAnalysisResponse(BaseModel):
    """Result of prompt security analysis."""
    risk_score: float
    decision: str            # allow / warn / block
    detected_categories: list[str]
    sanitized_prompt: str | None = None  # optional redacted version
    reason: str = ""         # Gemini contextual explanation (empty if regex-only)
    ml_prediction: Optional[dict] = None  # ML model output: {prediction, confidence, all_scores}


# ──────────────────── Repo Scanning ────────────────────

class RepoScanRequest(BaseModel):
    """Request to scan a GitHub repository."""
    repo_url: str


class VulnerabilityItem(BaseModel):
    """Single vulnerability in scan results."""
    package: str
    version: str = "unknown"
    cve: str = "N/A"
    cvss: float = 0.0
    severity: str = "UNKNOWN"
    description: str = ""
    fix_suggestion: str = ""
    attack_vector: str = ""
    attack_complexity: str = ""
    nvd_description: str = ""
    references: list[str] = []
    owasp_id: str = ""
    owasp_category: str = ""


class RepoScanResponse(BaseModel):
    """Full repository scan report."""
    repo_url: str
    dependencies_scanned: int
    vulnerabilities: list[VulnerabilityItem]
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    security_score: int = 100


# ──────────────────── Dashboard Metrics ────────────────────

class PromptMetrics(BaseModel):
    """Aggregated prompt analysis statistics."""
    total_prompts: int
    blocked: int
    warnings: int
    allowed: int
    credential_leaks: int


class RepoMetrics(BaseModel):
    """Aggregated repository scan statistics."""
    total_scans: int
    total_vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int


class DashboardResponse(BaseModel):
    """Combined dashboard data for the frontend."""
    prompt_metrics: PromptMetrics
    repo_metrics: RepoMetrics
    recent_prompts: list[dict]
    recent_scans: list[dict]


# ──────────────────── Remediation ────────────────────

class RemediationRequest(BaseModel):
    """Request AI-powered fix for a vulnerability."""
    package_name: str
    cve_id: str
    description: str = ""
    version: str = "unknown"
    cvss_score: float = 0.0


class RemediationResponse(BaseModel):
    """AI-generated remediation advice."""
    explanation: str
    suggested_fix: str
    recommended_version: str = ""
    # Context-aware fields from Gemini (empty if template fallback)
    summary: str = ""
    impact: str = ""
    remediation: str = ""
    recommended_upgrade: str = ""


# ──────────────────── ML Model Comparison ────────────────────

class MLCompareRequest(BaseModel):
    """Request to classify a prompt with both local ML model and Gemini."""
    prompt: str
    use_gemini: bool = False


class MLCompareResponse(BaseModel):
    """Side-by-side comparison of local ML model and Gemini classifications."""
    prompt: str
    local_model: dict          # {prediction, confidence, all_scores}
    gemini_analysis: Optional[dict] = None  # {prediction, confidence, explanation} — None when Gemini OFF
    decision: str              # ALLOW / WARN / BLOCK
    agreement: Optional[bool] = None  # Whether both models agree (None when Gemini OFF)