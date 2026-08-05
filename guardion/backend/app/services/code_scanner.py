"""
Pre-Push Code Vulnerability Scanner
Scans source code for common security vulnerabilities using regex pattern analysis.
Supports Python, JavaScript/Node.js, and Java.

Vulnerability categories:
  1. Hardcoded credentials  (HIGH)
  2. Private keys            (CRITICAL)
  3. Command injection       (CRITICAL)
  4. Unsafe eval usage       (HIGH)
  5. SQL injection risk      (HIGH)
  6. Insecure deserialization (HIGH)
  7. Path traversal          (MEDIUM)
  8. Weak cryptography       (MEDIUM)

Security score: starts at 100, deducted per finding based on severity.
"""

import re
from dataclasses import dataclass, field


# ──────────────────── Severity Weights ────────────────────
# Points deducted from the security score per vulnerability found.

SEVERITY_PENALTY = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 5,
}


# ──────────────────── Vulnerability Patterns ────────────────────
# Each entry: (category_name, severity, compiled_regex, human-readable description)
# Patterns are applied line-by-line so we can report exact line numbers.

VULN_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    # ── 1. Hardcoded Credentials ──
    (
        "hardcoded_secret",
        "HIGH",
        re.compile(
            r"""(?:password|passwd|pwd|api_key|apikey|api[_\-]?secret|secret_key"""
            r"""|access_key|auth_token|token|client_secret|private_key_value)"""
            r"""\s*[:=]\s*['"][^'"]{4,}['"]""",
            re.IGNORECASE,
        ),
        "Hardcoded credential or secret assigned to a variable",
    ),
    # ── 2. Private Keys (PEM format) ──
    (
        "private_key",
        "CRITICAL",
        re.compile(
            r"-----\s*BEGIN.*PRIVATE\s+KEY\s*-----",
            re.IGNORECASE,
        ),
        "Embedded private key in PEM format",
    ),
    # ── 3. Command Injection ──
    (
        "command_injection",
        "CRITICAL",
        re.compile(
            r"""(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen"""
            r"""|Runtime\.getRuntime\(\)\.exec|child_process\.exec"""
            r"""|child_process\.spawn|execSync|spawnSync)"""
            r"""\s*\(""",
            re.IGNORECASE,
        ),
        "Potential command injection via shell execution function",
    ),
    # Also catch bare exec() with a variable (not a string literal)
    (
        "command_injection",
        "CRITICAL",
        re.compile(
            r"""\bexec\s*\(\s*(?!['"])""",
        ),
        "exec() called with a non-literal argument (possible code injection)",
    ),
    # system() call (C-style / PHP-style)
    (
        "command_injection",
        "CRITICAL",
        re.compile(
            r"""\bsystem\s*\(\s*(?!['"])""",
        ),
        "system() called with a non-literal argument",
    ),
    # ── 4. Unsafe eval / Function constructor ──
    (
        "unsafe_eval",
        "HIGH",
        re.compile(
            r"""\beval\s*\(""",
        ),
        "eval() usage — can execute arbitrary code",
    ),
    (
        "unsafe_eval",
        "HIGH",
        re.compile(
            r"""new\s+Function\s*\(""",
        ),
        "new Function() — equivalent to eval()",
    ),
    # ── 5. SQL Injection Risk ──
    (
        "sql_injection",
        "HIGH",
        re.compile(
            r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+.*"""
            r"""(?:\+\s*\w|\%s|\{.*\}|f['"]|\.format\s*\()""",
            re.IGNORECASE,
        ),
        "SQL query built with string concatenation/interpolation (SQL injection risk)",
    ),
    (
        "sql_injection",
        "HIGH",
        re.compile(
            r"""(?:cursor\.execute|db\.execute|connection\.execute)\s*\(\s*(?:f['"]|['"].*\%|.*\+)""",
            re.IGNORECASE,
        ),
        "SQL execute() with dynamic string (use parameterized queries)",
    ),
    # ── 6. Insecure Deserialization ──
    (
        "insecure_deserialization",
        "HIGH",
        re.compile(
            r"""\bpickle\.loads?\s*\(|\byaml\.load\s*\((?!.*Loader)|\beval\s*\(\s*request""",
            re.IGNORECASE,
        ),
        "Insecure deserialization (pickle.load / yaml.load without safe Loader)",
    ),
    # ── 7. Path Traversal ──
    (
        "path_traversal",
        "MEDIUM",
        re.compile(
            r"""(?:open|readFile|readFileSync|createReadStream)\s*\(.*(?:req\.|request\.|user_input|params|query)""",
            re.IGNORECASE,
        ),
        "File operation with user-controlled path (path traversal risk)",
    ),
    # ── 8. Weak Cryptography ──
    (
        "weak_crypto",
        "MEDIUM",
        re.compile(
            r"""\b(?:md5|sha1|DES|RC4)\b""",
            re.IGNORECASE,
        ),
        "Use of weak/deprecated cryptographic algorithm",
    ),
    # ── 9. Hardcoded IP / localhost in production code ──
    (
        "hardcoded_config",
        "MEDIUM",
        re.compile(
            r"""(?:https?://)?(?:127\.0\.0\.1|0\.0\.0\.0|localhost)\s*[:'")\s,]""",
        ),
        "Hardcoded localhost/IP address (may not be production-ready)",
    ),
    # ── 10. AWS / cloud keys ──
    (
        "cloud_key_leak",
        "CRITICAL",
        re.compile(
            r"""(?:AKIA|ASIA)[0-9A-Z]{16}""",
        ),
        "AWS access key ID detected in source code",
    ),
    (
        "cloud_key_leak",
        "HIGH",
        re.compile(
            r"""(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}""",
        ),
        "GitHub personal access token detected in source code",
    ),
]


# ──────────────────── Data Classes ────────────────────

@dataclass
class VulnerabilityFinding:
    """Single vulnerability detected in the code."""
    type: str
    severity: str
    line: int
    code_snippet: str  # The offending line (truncated)
    description: str


@dataclass
class CodeScanResult:
    """Aggregated result of a full code scan."""
    vulnerabilities: list[VulnerabilityFinding] = field(default_factory=list)
    security_score: int = 100
    total_lines: int = 0
    language_hint: str = ""
    summary: dict = field(default_factory=dict)  # severity → count


# ──────────────────── Language Detection (best-effort) ────────────────────

def _detect_language(code: str, filename: str = "") -> str:
    """
    Simple heuristic language detection from file extension or code patterns.
    Returns: 'python', 'javascript', 'java', or 'unknown'.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    ext_map = {
        "py": "python",
        "js": "javascript", "mjs": "javascript", "cjs": "javascript",
        "ts": "javascript", "tsx": "javascript", "jsx": "javascript",
        "java": "java",
    }
    if ext in ext_map:
        return ext_map[ext]

    # Fallback: look for language-specific keywords
    if re.search(r"\bdef\s+\w+\s*\(|import\s+\w+|from\s+\w+\s+import", code):
        return "python"
    if re.search(r"\bfunction\s+\w+|const\s+\w+\s*=|require\s*\(|=>\s*\{", code):
        return "javascript"
    if re.search(r"\bpublic\s+(?:static\s+)?(?:void|class|int|String)", code):
        return "java"

    return "unknown"


# ──────────────────── Core Scanner ────────────────────

def scan_code(code: str, filename: str = "") -> CodeScanResult:
    """
    Scan source code for security vulnerabilities.

    Pipeline:
      1. Split code into lines
      2. Run each vulnerability regex against each line
      3. Collect findings with line numbers and snippets
      4. Compute security score (100 minus penalties)
      5. Generate severity summary

    Args:
        code: Raw source code string.
        filename: Optional filename for language detection.

    Returns:
        CodeScanResult with findings, score, and metadata.
    """
    lines = code.splitlines()
    result = CodeScanResult(
        total_lines=len(lines),
        language_hint=_detect_language(code, filename),
    )

    # Track already-reported (line, category) pairs to avoid duplicate findings
    # when multiple patterns for the same category match the same line
    seen: set[tuple[int, str]] = set()

    for line_num, line_text in enumerate(lines, start=1):
        # Skip empty lines and pure comments
        stripped = line_text.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        for category, severity, pattern, description in VULN_PATTERNS:
            if pattern.search(line_text):
                key = (line_num, category)
                if key in seen:
                    continue
                seen.add(key)

                # Truncate long lines for display
                snippet = line_text.strip()[:120]

                result.vulnerabilities.append(
                    VulnerabilityFinding(
                        type=category,
                        severity=severity,
                        line=line_num,
                        code_snippet=snippet,
                        description=description,
                    )
                )

                # Deduct from security score
                penalty = SEVERITY_PENALTY.get(severity, 5)
                result.security_score = max(0, result.security_score - penalty)

    # Build severity summary
    summary: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for vuln in result.vulnerabilities:
        summary[vuln.severity] = summary.get(vuln.severity, 0) + 1
    result.summary = summary

    return result