"""
Guardion OWASP Top 10 Mapping Service
Maps discovered vulnerabilities to OWASP Top 10 (2021) categories
based on CWE IDs, CVE descriptions, package context, and attack vectors.
"""

import logging
import re

logger = logging.getLogger("guardion.owasp")


# ──────────────────── OWASP Top 10 (2021) ────────────────────

OWASP_TOP_10 = {
    "A01": {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "description": "Failures in enforcing access restrictions, allowing unauthorized users to access data or perform actions beyond their permissions.",
        "color": "#e53e3e",
        "cwes": [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275],
    },
    "A02": {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "description": "Weaknesses related to cryptography, including use of broken algorithms, weak keys, improper certificate validation, or transmitting data in cleartext.",
        "color": "#dd6b20",
        "cwes": [261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916],
    },
    "A03": {
        "id": "A03:2021",
        "name": "Injection",
        "description": "Injection flaws such as SQL, NoSQL, OS command, LDAP, and XSS injection occur when untrusted data is sent to an interpreter as part of a command or query.",
        "color": "#d69e2e",
        "cwes": [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917],
    },
    "A04": {
        "id": "A04:2021",
        "name": "Insecure Design",
        "description": "Flaws in design and architecture that represent missing or ineffective control design. Distinct from implementation bugs.",
        "color": "#38a169",
        "cwes": [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173],
    },
    "A05": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": "Missing or incorrect security hardening, open cloud storage, unnecessary features enabled, default accounts, or overly verbose error messages.",
        "color": "#3182ce",
        "cwes": [2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174],
    },
    "A06": {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "description": "Using components with known vulnerabilities, unsupported or out-of-date software including OS, web/application server, DBMS, APIs, and libraries.",
        "color": "#805ad5",
        "cwes": [829, 1035, 1104],
    },
    "A07": {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "description": "Weaknesses in authentication mechanisms including credential stuffing, brute force, weak passwords, or improper session management.",
        "color": "#d53f8c",
        "cwes": [255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216],
    },
    "A08": {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "description": "Code and infrastructure that does not protect against integrity violations — insecure CI/CD pipelines, auto-update without verification, or deserialization of untrusted data.",
        "color": "#319795",
        "cwes": [345, 353, 426, 494, 502, 565, 784, 829, 830, 913],
    },
    "A09": {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging, detection, monitoring, and active response. Without these, breaches cannot be detected or responded to in time.",
        "color": "#718096",
        "cwes": [117, 223, 532, 778],
    },
    "A10": {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL, allowing attackers to coerce the application to send crafted requests.",
        "color": "#e53e3e",
        "cwes": [918],
    },
}

# Build reverse CWE → OWASP lookup
_CWE_TO_OWASP: dict[int, str] = {}
for _code, _info in OWASP_TOP_10.items():
    for _cwe in _info["cwes"]:
        if _cwe not in _CWE_TO_OWASP:
            _CWE_TO_OWASP[_cwe] = _code


# ──────────────────── Keyword-Based Mapping ────────────────────
# When no CWE is available, use keyword matching on descriptions.

_KEYWORD_PATTERNS: list[tuple[str, str]] = [
    # A01 — Broken Access Control
    (r"(?:path|directory)\s*traversal|unauthorized\s*access|access\s*control|privilege\s*escalat|permission|bypass\s*auth|insecure\s*direct\s*object|IDOR|CSRF|cross.site\s*request\s*forgery", "A01"),
    # A02 — Cryptographic Failures
    (r"crypt|ssl|tls|certificate|weak\s*(?:hash|cipher|key|algorithm)|cleartext|plaintext|sensitive\s*data\s*exposure|RSA|AES|SHA\-?1\b|MD5|HMAC", "A02"),
    # A03 — Injection
    (r"inject|SQL\s*inject|XSS|cross.site\s*script|command\s*inject|code\s*inject|LDAP\s*inject|CRLF|template\s*inject|expression\s*language|eval\(|exec\(|OS\s*command|NoSQL\s*inject|SSTI", "A03"),
    # A04 — Insecure Design
    (r"insecure\s*design|race\s*condition|business\s*logic|improper\s*validation|missing\s*(?:input|validation|sanitiz)|unvalidated\s*redirect|open\s*redirect", "A04"),
    # A05 — Security Misconfiguration
    (r"misconfig|default\s*(?:password|credential|setting)|exposed\s*(?:port|endpoint|config|debug)|unnecessary\s*(?:feature|service)|verbose\s*error|stack\s*trace\s*expos|XML\s*external\s*entity|XXE", "A05"),
    # A06 — Vulnerable Components
    (r"(?:known|outdated|vulnerable)\s*(?:component|dependency|library|package|version)|prototype\s*pollut|(?:regular\s*expression\s*)?(?:ReDoS|denial.of.service)|buffer\s*overflow|heap\s*overflow|out.of.bounds|integer\s*overflow|use.after.free|memory\s*corrupt|arbitrary\s*code\s*execut|remote\s*code\s*execut|RCE", "A06"),
    # A07 — Auth Failures
    (r"authenticat|brute\s*force|credential\s*stuff|session\s*(?:fixation|hijack)|weak\s*password|password\s*(?:hash|storage|leak)|token\s*(?:leak|expos)|JWT\s*(?:bypass|forg)", "A07"),
    # A08 — Integrity Failures
    (r"deserializ|integrity|(?:insecure\s*)?(?:CI.?CD|pipeline|auto.update)|untrusted\s*(?:data|input)\s*deserializ|pickle|yaml\.(?:load|unsafe_load)", "A08"),
    # A09 — Logging Failures
    (r"(?:insufficient|missing)\s*(?:log|monitor)|log\s*(?:inject|forg|tamper)|security\s*(?:log|audit|event)|SIEM", "A09"),
    # A10 — SSRF
    (r"SSRF|server.side\s*request\s*forgery|URL\s*(?:redirect|fetch|request)\s*(?:from\s*server|without\s*valid)", "A10"),
]

_COMPILED_PATTERNS = [(re.compile(pat, re.IGNORECASE), code) for pat, code in _KEYWORD_PATTERNS]


# ──────────────────── Public API ────────────────────

def classify_owasp(vuln: dict) -> dict:
    """
    Classify a single vulnerability into an OWASP Top 10 category.

    Looks at:
      1. CWE IDs in NVD data (`cwe_ids` list)
      2. Description keywords (fallback)
      3. Attack vector / package name heuristics (final fallback)

    Returns:
      {"owasp_id": "A06:2021", "owasp_category": "Vulnerable and Outdated Components"}
      or empty strings if no match.
    """
    # 1. Try CWE-based mapping first (most accurate)
    cwe_ids = vuln.get("cwe_ids", [])
    for cwe_id in cwe_ids:
        try:
            cwe_num = int(str(cwe_id).replace("CWE-", ""))
            if cwe_num in _CWE_TO_OWASP:
                code = _CWE_TO_OWASP[cwe_num]
                info = OWASP_TOP_10[code]
                return {"owasp_id": info["id"], "owasp_category": info["name"]}
        except (ValueError, TypeError):
            continue

    # 2. Keyword-based mapping on description
    text = " ".join([
        vuln.get("description", ""),
        vuln.get("nvd_description", ""),
        vuln.get("cve_id", ""),
    ])

    for compiled_re, code in _COMPILED_PATTERNS:
        if compiled_re.search(text):
            info = OWASP_TOP_10[code]
            return {"owasp_id": info["id"], "owasp_category": info["name"]}

    # 3. Default: dependency vulnerabilities are A06
    if vuln.get("cve_id", "N/A") != "N/A" or vuln.get("cvss_score", 0) > 0:
        info = OWASP_TOP_10["A06"]
        return {"owasp_id": info["id"], "owasp_category": info["name"]}

    return {"owasp_id": "", "owasp_category": ""}


def tag_vulnerabilities_owasp(vulns: list[dict]) -> list[dict]:
    """
    Tag a list of vulnerability dicts with their OWASP Top 10 category.
    Adds `owasp_id` and `owasp_category` keys to each dict in-place.

    Returns the same list with OWASP fields added.
    """
    for vuln in vulns:
        owasp = classify_owasp(vuln)
        vuln["owasp_id"] = owasp["owasp_id"]
        vuln["owasp_category"] = owasp["owasp_category"]
    return vulns


def get_owasp_top10_reference() -> list[dict]:
    """Return the full OWASP Top 10 reference list for the frontend."""
    return [
        {
            "id": info["id"],
            "code": code,
            "name": info["name"],
            "description": info["description"],
            "color": info["color"],
        }
        for code, info in OWASP_TOP_10.items()
    ]