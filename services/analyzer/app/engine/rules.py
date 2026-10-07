"""
SAST Analyzer Service - Security Rules Engine

Implements 15+ security detection rules using a combination of:
  - Regex pattern matching on raw source code
  - AST node inspection on parsed code structure

Each rule is self-contained and produces a list of Finding objects
when triggered. The RulesEngine orchestrates all rules in a single pass.
"""

from __future__ import annotations

import ast
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.models import CodeLocation, Finding, SeverityLevel

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rule Metadata
# ---------------------------------------------------------------------------


@dataclass
class SecurityRule:
    """Metadata descriptor for a single security rule."""

    id: str
    name: str
    description: str
    severity: SeverityLevel
    cwe_id: str
    languages: List[str]
    remediation: str = ""
    references: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    rule: SecurityRule,
    language: str,
    filename: str,
    line_start: int,
    line_end: int,
    snippet: str,
    col_start: int = 0,
    confidence: float = 0.85,
    metadata: Optional[Dict[str, Any]] = None,
) -> Finding:
    """Construct a Finding object from a rule match."""
    return Finding(
        rule_id=rule.id,
        rule_name=rule.name,
        description=rule.description,
        severity=rule.severity,
        cwe_id=rule.cwe_id,
        language=language,
        location=CodeLocation(
            filename=filename,
            line_start=line_start,
            line_end=line_end,
            col_start=col_start,
            snippet=snippet[:300],  # Truncate long snippets
        ),
        remediation=rule.remediation,
        references=rule.references,
        confidence=confidence,
        metadata=metadata or {},
    )


def _source_lines(source_code: str) -> List[str]:
    return source_code.splitlines()


def _nodes_of_type(ast_data: Dict[str, Any], *types: str) -> List[Dict[str, Any]]:
    """Filter AST nodes by one or more type labels."""
    return [n for n in ast_data.get("nodes", []) if n.get("type") in types]


# ---------------------------------------------------------------------------
# Rule Definitions
# ---------------------------------------------------------------------------

RULE_SAST001 = SecurityRule(
    id="SAST-001",
    name="Hardcoded Password / Secret",
    description=(
        "A sensitive credential (password, secret, API key, or token) appears to be "
        "hardcoded directly in the source code. Hardcoded secrets can be extracted from "
        "source control and used by attackers."
    ),
    severity=SeverityLevel.CRITICAL,
    cwe_id="CWE-798",
    languages=["python", "javascript", "java"],
    remediation=(
        "Store secrets in environment variables or a dedicated secrets manager "
        "(e.g., AWS Secrets Manager, HashiCorp Vault). "
        "Never commit credentials to source control."
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
    ],
)

RULE_SAST002 = SecurityRule(
    id="SAST-002",
    name="SQL Injection",
    description=(
        "User-controlled input is concatenated directly into an SQL query. "
        "This allows an attacker to manipulate the query structure, bypass "
        "authentication, extract or modify data, or execute administrative operations."
    ),
    severity=SeverityLevel.CRITICAL,
    cwe_id="CWE-89",
    languages=["python", "javascript", "java"],
    remediation=(
        "Use parameterised queries / prepared statements exclusively. "
        "Never build SQL strings via string formatting with untrusted input."
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://owasp.org/www-community/attacks/SQL_Injection",
    ],
)

RULE_SAST003 = SecurityRule(
    id="SAST-003",
    name="Command Injection",
    description=(
        "User-controlled input is passed to a shell command execution function "
        "(os.system, subprocess with shell=True, eval, exec). An attacker can inject "
        "arbitrary commands that execute with the application's privileges."
    ),
    severity=SeverityLevel.CRITICAL,
    cwe_id="CWE-78",
    languages=["python", "javascript", "java"],
    remediation=(
        "Avoid shell=True in subprocess calls. Use subprocess with a list of arguments "
        "instead of a shell string. Validate and sanitize all inputs."
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/78.html",
        "https://owasp.org/www-community/attacks/Command_Injection",
    ],
)

RULE_SAST004 = SecurityRule(
    id="SAST-004",
    name="Path Traversal",
    description=(
        "User-controlled input is used to construct a file path without proper "
        "validation. An attacker can supply '../' sequences to access files outside "
        "the intended directory."
    ),
    severity=SeverityLevel.HIGH,
    cwe_id="CWE-22",
    languages=["python", "javascript", "java"],
    remediation=(
        "Resolve and validate that the canonical path starts with the expected base "
        "directory. Use os.path.abspath() and verify the prefix before opening files."
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/22.html",
        "https://owasp.org/www-community/attacks/Path_Traversal",
    ],
)

RULE_SAST005 = SecurityRule(
    id="SAST-005",
    name="Hardcoded IP Address or Internal URL",
    description=(
        "A hardcoded IP address or internal URL was found in the source code. "
        "This can expose internal network topology and complicate deployments."
    ),
    severity=SeverityLevel.LOW,
    cwe_id="CWE-1041",
    languages=["python", "javascript", "java"],
    remediation=(
        "Externalise host/URL configuration to environment variables or config files. "
        "Avoid embedding infrastructure details in code."
    ),
    references=["https://cwe.mitre.org/data/definitions/1041.html"],
)

RULE_SAST006 = SecurityRule(
    id="SAST-006",
    name="Use of eval() / exec()",
    description=(
        "Dynamic code execution via eval() or exec() is present. If any part of the "
        "evaluated string originates from user input, this is a critical code injection "
        "vulnerability."
    ),
    severity=SeverityLevel.HIGH,
    cwe_id="CWE-95",
    languages=["python", "javascript"],
    remediation=(
        "Avoid eval/exec entirely. Use safer alternatives such as ast.literal_eval() "
        "for data parsing, or refactor logic to eliminate dynamic execution."
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/95.html",
        "https://owasp.org/www-community/attacks/Code_Injection",
    ],
)

RULE_SAST007 = SecurityRule(
    id="SAST-007",
    name="Weak Cryptographic Algorithm",
    description=(
        "A weak or broken cryptographic algorithm (MD5, SHA-1, DES) is used. "
        "These algorithms are susceptible to collision and brute-force attacks "
        "and should not be used for security-sensitive operations."
    ),
    severity=SeverityLevel.MEDIUM,
    cwe_id="CWE-327",
    languages=["python", "javascript", "java"],
    remediation=(
        "Replace MD5/SHA-1 with SHA-256 or SHA-3 for hashing. "
        "Replace DES/3DES with AES-256. For password hashing use bcrypt, Argon2, or scrypt."
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/327.html",
        "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
    ],
)

RULE_SAST008 = SecurityRule(
    id="SAST-008",
    name="Insecure Random Number Generator",
    description=(
        "The standard random module (random.random, random.randint, etc.) is used "
        "in a context that appears security-sensitive. The standard PRNG is not "
        "cryptographically secure."
    ),
    severity=SeverityLevel.MEDIUM,
    cwe_id="CWE-338",
    languages=["python"],
    remediation=(
        "Use the secrets module (Python 3.6+) or os.urandom() for security-sensitive "
        "random number generation such as tokens, passwords, and nonces."
    ),
    references=["https://cwe.mitre.org/data/definitions/338.html"],
)

RULE_SAST009 = SecurityRule(
    id="SAST-009",
    name="Debug Mode Enabled",
    description=(
        "The application is configured with debug mode enabled. In production, "
        "debug mode can expose stack traces, internal state, and may enable "
        "remote code execution in some frameworks (e.g., Flask/Werkzeug debugger)."
    ),
    severity=SeverityLevel.HIGH,
    cwe_id="CWE-94",
    languages=["python", "javascript"],
    remediation=(
        "Disable debug mode in production. Use environment variables to control "
        "debug settings and ensure DEBUG=False before deployment."
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/94.html",
        "https://flask.palletsprojects.com/en/2.3.x/config/#DEBUG",
    ],
)

RULE_SAST010 = SecurityRule(
    id="SAST-010",
    name="Missing HTTPS – Insecure HTTP URL",
    description=(
        "An HTTP (non-encrypted) URL is used for an external API call or resource. "
        "Data in transit is not encrypted and is vulnerable to interception and "
        "man-in-the-middle attacks."
    ),
    severity=SeverityLevel.MEDIUM,
    cwe_id="CWE-319",
    languages=["python", "javascript", "java"],
    remediation=(
        "Replace all http:// URLs with https://. Enforce HSTS headers on server responses."
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/319.html",
        "https://owasp.org/www-community/vulnerabilities/Cleartext_Transmission_of_Sensitive_Information",
    ],
)

RULE_SAST011 = SecurityRule(
    id="SAST-011",
    name="Cross-Site Scripting (XSS) – Unsafe Template Rendering",
    description=(
        "Output is marked as safe for HTML rendering (mark_safe, | safe filter, "
        "Markup()) without proper sanitization. If the value contains user input, "
        "this enables stored or reflected XSS attacks."
    ),
    severity=SeverityLevel.HIGH,
    cwe_id="CWE-79",
    languages=["python", "javascript"],
    remediation=(
        "Never mark user-supplied data as safe. Sanitize all output with a library "
        "such as bleach before passing to mark_safe/Markup. "
        "Prefer auto-escaping templates."
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/79.html",
        "https://owasp.org/www-community/attacks/xss/",
    ],
)

RULE_SAST012 = SecurityRule(
    id="SAST-012",
    name="Server-Side Request Forgery (SSRF)",
    description=(
        "An HTTP request is made to a URL that appears to be user-controlled. "
        "An attacker can direct the server to make requests to internal services, "
        "cloud metadata endpoints, or other sensitive targets."
    ),
    severity=SeverityLevel.HIGH,
    cwe_id="CWE-918",
    languages=["python", "javascript"],
    remediation=(
        "Validate and whitelist allowed URL schemes and hostnames before making "
        "outbound requests. Use an allowlist rather than a blocklist."
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/918.html",
        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
    ],
)

RULE_SAST013 = SecurityRule(
    id="SAST-013",
    name="Insecure Deserialization",
    description=(
        "Unsafe deserialization is performed using pickle.loads or yaml.load without "
        "a safe Loader. Deserializing untrusted data can lead to arbitrary code "
        "execution or denial of service."
    ),
    severity=SeverityLevel.CRITICAL,
    cwe_id="CWE-502",
    languages=["python"],
    remediation=(
        "Avoid pickle for untrusted data. Use json, msgpack, or protobuf instead. "
        "For YAML, always specify Loader=yaml.SafeLoader."
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/502.html",
        "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
    ],
)

RULE_SAST014 = SecurityRule(
    id="SAST-014",
    name="Missing Authentication Decorator",
    description=(
        "A route handler or view function lacks an authentication/authorization "
        "decorator (e.g., @login_required, @jwt_required, @requires_auth). "
        "This may expose the endpoint to unauthenticated access."
    ),
    severity=SeverityLevel.MEDIUM,
    cwe_id="CWE-306",
    languages=["python"],
    remediation=(
        "Apply the appropriate authentication decorator to all protected routes. "
        "Implement default-deny access control policies."
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/306.html",
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    ],
)

RULE_SAST015 = SecurityRule(
    id="SAST-015",
    name="Sensitive Data Exposure in Logs",
    description=(
        "A logging call passes a variable or string that appears to contain sensitive "
        "data (password, token, secret, key). Logging credentials can expose them in "
        "log aggregation systems, audit trails, and observability tooling."
    ),
    severity=SeverityLevel.HIGH,
    cwe_id="CWE-532",
    languages=["python", "javascript"],
    remediation=(
        "Never log credentials, tokens, or other sensitive values. "
        "Redact or mask sensitive fields before logging. "
        "Use structured logging and log only non-sensitive identifiers."
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/532.html",
        "https://owasp.org/www-community/vulnerabilities/Sensitive_Data_Exposure",
    ],
)

ALL_RULES: List[SecurityRule] = [
    RULE_SAST001, RULE_SAST002, RULE_SAST003, RULE_SAST004,
    RULE_SAST005, RULE_SAST006, RULE_SAST007, RULE_SAST008,
    RULE_SAST009, RULE_SAST010, RULE_SAST011, RULE_SAST012,
    RULE_SAST013, RULE_SAST014, RULE_SAST015,
]


# ---------------------------------------------------------------------------
# Detection Logic
# ---------------------------------------------------------------------------

class RulesEngine:
    """
    Orchestrates all security rules against parsed AST data and raw source.

    Usage::

        engine = RulesEngine()
        findings = engine.check_all(ast_data, source_code, "python", "app.py")
    """

    # SAST-001: Patterns for hardcoded credentials
    _SECRET_ASSIGN_PATTERN = re.compile(
        r"""(?ix)
        (?:password|passwd|pwd|secret|api_key|apikey|access_key|auth_token|
           token|private_key|encryption_key|db_pass|database_password)\s*=\s*
        (?P<quote>['"]{1,3})(?P<value>[^'"]{4,})(?P=quote)
        """,
        re.IGNORECASE,
    )

    # SAST-002: SQL injection patterns
    _SQL_INJECT_EXECUTE_PATTERN = re.compile(
        r"""(?x)
        \.execute\s*\(\s*
        (?:
            f['"].*?['"]       |   # f-string
            ['"].*?['"]\.format\s*\(  |  # .format()
            ['"].*?%.*?['"]    |   # % formatting
            \w+\s*\+           |   # concatenation on left
            .*?\+\s*\w+        |   # concatenation on right
            ['"].*?\{.*?\}.*?['"]   # any brace interpolation
        )
        """,
        re.IGNORECASE | re.DOTALL,
    )

    # Also catch cursor.execute with variable (potential injection)
    _SQL_EXECUTE_VAR_PATTERN = re.compile(
        r"""(?x)
        cursor\.execute\s*\(\s*
        (?!['"]SELECT\s+\*\s+FROM\s+\w+\s*['"]\s*\))  # not a simple safe literal
        (?:[^,)]+)
        """,
        re.IGNORECASE,
    )

    # SAST-003: Command injection patterns
    _CMD_INJECT_PATTERNS = [
        re.compile(r"""os\.system\s*\(""", re.IGNORECASE),
        re.compile(r"""subprocess\.(run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True""", re.IGNORECASE | re.DOTALL),
        re.compile(r"""\beval\s*\(""", re.IGNORECASE),
        re.compile(r"""\bexec\s*\(""", re.IGNORECASE),
    ]

    # SAST-004: Path traversal patterns
    _PATH_TRAVERSAL_PATTERNS = [
        re.compile(r"""open\s*\([^)]*(?:request\.|argv|input\(|environ)""", re.IGNORECASE),
        re.compile(r"""os\.path\.join\s*\([^)]*(?:request\.|argv|input\(|environ)""", re.IGNORECASE),
        re.compile(r"""open\s*\([^)]*\+[^)]*\)""", re.IGNORECASE),
    ]

    # SAST-005: Hardcoded IPs and internal URLs
    _IP_PATTERN = re.compile(
        r"""(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])""",
        re.IGNORECASE,
    )

    # SAST-006: eval / exec usage
    _EVAL_EXEC_PATTERN = re.compile(r"""\b(eval|exec)\s*\(""")

    # SAST-007: Weak crypto
    _WEAK_CRYPTO_PATTERNS = [
        re.compile(r"""hashlib\.(md5|sha1)\s*\(""", re.IGNORECASE),
        re.compile(r"""(?:Crypto|cryptography)[.\w]*\.(DES|DES3|Blowfish|RC4)\b""", re.IGNORECASE),
        re.compile(r"""import\s+(?:Crypto\.Cipher\.DES|pyDes)\b""", re.IGNORECASE),
        re.compile(r"""MD5\(\)|SHA1\(\)|SHA-1|MD5Hash""", re.IGNORECASE),
        re.compile(r"""new\s+MessageDigest.*MD5|MessageDigest\.getInstance\s*\(\s*["']MD5["']\)""", re.IGNORECASE),
        re.compile(r"""MessageDigest\.getInstance\s*\(\s*["']SHA-1["']\)""", re.IGNORECASE),
    ]

    # SAST-008: Insecure random
    _INSECURE_RANDOM_PATTERNS = [
        re.compile(r"""random\.random\s*\(\)"""),
        re.compile(r"""random\.randint\s*\("""),
        re.compile(r"""random\.choice\s*\("""),
        re.compile(r"""random\.uniform\s*\("""),
        re.compile(r"""import\s+random\b"""),
    ]
    # Context keywords that indicate security-sensitive usage near random calls
    _RANDOM_SENSITIVE_CONTEXT = re.compile(
        r"""(?:token|password|secret|nonce|salt|key|otp|csrf|session)""",
        re.IGNORECASE,
    )

    # SAST-009: Debug mode
    _DEBUG_MODE_PATTERNS = [
        re.compile(r"""DEBUG\s*=\s*True""", re.IGNORECASE),
        re.compile(r"""app\.run\s*\([^)]*debug\s*=\s*True""", re.IGNORECASE | re.DOTALL),
        re.compile(r"""app\.debug\s*=\s*True""", re.IGNORECASE),
        re.compile(r"""DEBUG\s*=\s*True"""),
    ]

    # SAST-010: HTTP (not HTTPS)
    _HTTP_URL_PATTERN = re.compile(
        r"""(?:requests\.|httpx\.|urllib|fetch\(|axios\.)\s*(?:get|post|put|delete|patch|request)?\s*\([^)]*http://(?!localhost)""",
        re.IGNORECASE,
    )
    _BARE_HTTP_PATTERN = re.compile(
        r"""['"](http://(?!localhost|127\.)[^'"]{4,})['"]""",
        re.IGNORECASE,
    )

    # SAST-011: XSS - unsafe template rendering
    _XSS_PATTERNS = [
        re.compile(r"""mark_safe\s*\(""", re.IGNORECASE),
        re.compile(r"""Markup\s*\("""),
        re.compile(r"""\|\s*safe\b"""),
        re.compile(r"""\.html_safe\b"""),
        re.compile(r"""dangerouslySetInnerHTML"""),
        re.compile(r"""innerHTML\s*="""),
    ]

    # SAST-012: SSRF - requests to user-controlled URLs
    _SSRF_PATTERNS = [
        re.compile(r"""requests\.\w+\s*\(\s*(?:url|request\.|args\.|form\.|json\()""", re.IGNORECASE),
        re.compile(r"""httpx\.\w+\s*\(\s*(?:url|request\.|args\.|form\.)""", re.IGNORECASE),
        re.compile(r"""urllib\.request\.urlopen\s*\(\s*(?:url|request\.|args\.)""", re.IGNORECASE),
        # Variables commonly used for untrusted URLs; validated/configured URLs are not enough evidence.
        re.compile(r"""requests\.\w+\s*\(\s*(?:user|request|input|target|redirect|callback)_url\s*[,)]""", re.IGNORECASE),
        re.compile(r"""requests\.\w+\s*\(\s*target\s*[,)]""", re.IGNORECASE),
    ]

    # SAST-013: Insecure deserialization
    _DESERIAL_PATTERNS = [
        re.compile(r"""pickle\.loads?\s*\(""", re.IGNORECASE),
        re.compile(r"""cPickle\.loads?\s*\(""", re.IGNORECASE),
        re.compile(r"""yaml\.load\s*\([^)]*(?!\bLoader\s*=\s*yaml\.SafeLoader)""", re.IGNORECASE),
        re.compile(r"""yaml\.load\s*\(\s*\w+\s*\)"""),  # yaml.load(data) - no loader
        re.compile(r"""marshal\.loads?\s*\("""),
        re.compile(r"""shelve\.open\s*\("""),
    ]

    # SAST-014: Route decorators indicating web endpoints
    _ROUTE_DECORATORS = re.compile(
        r"""@(?:app|router|blueprint)\.(route|get|post|put|delete|patch)\s*\(""",
        re.IGNORECASE,
    )
    # Auth decorators - if present, route IS protected
    _AUTH_DECORATORS = re.compile(
        r"""@(?:login_required|jwt_required|requires_auth|authenticate|token_required|permission_required|staff_member_required|superuser_required)\b""",
        re.IGNORECASE,
    )
    _SENSITIVE_ROUTE_NAMES = re.compile(
        r"(?:^|_)(?:admin|manage_users|manage_accounts|delete_user|delete_account|"
        r"remove_user|remove_account|grant|revoke|transfer)(?:_|$)",
        re.IGNORECASE,
    )

    # SAST-015: Sensitive data in logs
    _LOG_SENSITIVE_PATTERNS = [
        re.compile(
            r"""(?:logging|logger)\.\w+\s*\([^)]*(?:password|passwd|secret|token|api_key|auth|credential)[^)]*\)""",
            re.IGNORECASE | re.DOTALL,
        ),
        re.compile(
            r"""print\s*\([^)]*(?:password|passwd|secret|token|api_key)[^)]*\)""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""log\.(info|debug|warning|error|critical)\s*\([^)]*(?:password|secret|token)[^)]*\)""",
            re.IGNORECASE,
        ),
    ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_all(
        self,
        ast_data: Dict[str, Any],
        source_code: str,
        language: str,
        filename: str = "unknown",
    ) -> List[Finding]:
        """
        Run all applicable security rules against the provided code.

        Args:
            ast_data:    Parsed AST dict (from ASTParser).
            source_code: Raw source code string.
            language:    Programming language ("python", "javascript", "java").
            filename:    Source file path for location reporting.

        Returns:
            List of Finding objects for all matched rules.
        """
        findings: List[Finding] = []
        lines = _source_lines(source_code)

        check_methods = [
            self._check_sast001,
            self._check_sast002,
            self._check_sast003,
            self._check_sast004,
            self._check_sast005,
            self._check_sast006,
            self._check_sast007,
            self._check_sast008,
            self._check_sast009,
            self._check_sast010,
            self._check_sast011,
            self._check_sast012,
            self._check_sast013,
            self._check_sast014,
            self._check_sast015,
        ]

        for check_fn in check_methods:
            try:
                results = check_fn(ast_data, source_code, language, filename, lines)
                findings.extend(results)
            except Exception as exc:
                logger.warning("Rule check %s failed: %s", check_fn.__name__, exc)

        return findings

    # ------------------------------------------------------------------
    # SAST-001: Hardcoded Passwords / Secrets
    # ------------------------------------------------------------------

    def _check_sast001(self, ast_data, source_code, language, filename, lines):
        findings = []

        # Method 1: Regex on raw source
        for match in self._SECRET_ASSIGN_PATTERN.finditer(source_code):
            value = match.group("value")
            # Filter out obvious non-secrets: empty, env-var references, placeholders
            if not value or value.startswith("${") or value in ("", "None", "null", "undefined"):
                continue
            if re.match(r"^[<\[\(].*[>\]\)]$", value):  # Placeholder like <YOUR_KEY>
                continue

            start_pos = match.start()
            lineno = source_code[:start_pos].count("\n") + 1
            snippet = lines[lineno - 1] if lineno <= len(lines) else match.group()

            findings.append(_make_finding(
                RULE_SAST001, language, filename, lineno, lineno,
                snippet, confidence=0.80,
                metadata={"matched_value_length": len(value)},
            ))

        # Method 2: AST-based (Python only) - look for string assignments to sensitive names
        if language == "python":
            for node in _nodes_of_type(ast_data, "Assign", "AnnAssign"):
                targets = node.get("targets", [node.get("target", "")])
                raw_val = node.get("raw_value")
                if not raw_val or len(raw_val) < 4:
                    continue
                for target in targets:
                    if isinstance(target, str) and re.search(
                        r"(?:password|passwd|secret|api_key|token|private_key)", target, re.I
                    ):
                        # Avoid duplicate with regex match
                        lineno = node.get("lineno", 0)
                        snippet = node.get("snippet", "")
                        findings.append(_make_finding(
                            RULE_SAST001, language, filename, lineno, lineno,
                            snippet, confidence=0.90,
                            metadata={"variable": target},
                        ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # SAST-002: SQL Injection
    # ------------------------------------------------------------------

    def _check_sast002(self, ast_data, source_code, language, filename, lines):
        findings = []

        if language == "python":
            try:
                parsed = ast.parse(source_code)
            except SyntaxError:
                return findings

            for node in ast.walk(parsed):
                if not isinstance(node, ast.Call):
                    continue
                if not isinstance(node.func, ast.Attribute) or node.func.attr != "execute":
                    continue
                if not node.args:
                    continue

                query = node.args[0]
                query_text = ast.get_source_segment(source_code, query) or ""
                if not re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE|REPLACE)\b", query_text, re.I):
                    continue

                dynamic_query = (
                    isinstance(query, ast.JoinedStr)
                    or (
                        isinstance(query, ast.BinOp)
                        and isinstance(query.op, (ast.Add, ast.Mod))
                    )
                    or (
                        isinstance(query, ast.Call)
                        and isinstance(query.func, ast.Attribute)
                        and query.func.attr == "format"
                    )
                )
                if dynamic_query:
                    lineno = node.lineno
                    snippet = lines[lineno - 1] if lineno <= len(lines) else query_text
                    findings.append(_make_finding(
                        RULE_SAST002, language, filename, lineno, lineno,
                        snippet, confidence=0.92,
                        metadata={"func": "execute", "arg": query_text},
                    ))
        else:
            for match in self._SQL_INJECT_EXECUTE_PATTERN.finditer(source_code):
                lineno = source_code[:match.start()].count("\n") + 1
                snippet = lines[lineno - 1] if lineno <= len(lines) else match.group()
                findings.append(_make_finding(
                    RULE_SAST002, language, filename, lineno, lineno, snippet,
                    confidence=0.85,
                ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # SAST-003: Command Injection
    # ------------------------------------------------------------------

    def _check_sast003(self, ast_data, source_code, language, filename, lines):
        findings = []

        if language == "python":
            try:
                parsed = ast.parse(source_code)
            except SyntaxError:
                return findings

            for node in ast.walk(parsed):
                if not isinstance(node, ast.Call):
                    continue
                func_name = ast.unparse(node.func)
                is_os_system = func_name == "os.system"
                is_dynamic_eval = isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec")
                is_shell_subprocess = (
                    func_name in {
                        "subprocess.run",
                        "subprocess.Popen",
                        "subprocess.call",
                        "subprocess.check_output",
                    }
                    and any(
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                        for keyword in node.keywords
                    )
                )
                if not (is_os_system or is_dynamic_eval or is_shell_subprocess):
                    continue

                lineno = node.lineno
                snippet = lines[lineno - 1] if lineno <= len(lines) else func_name
                findings.append(_make_finding(
                    RULE_SAST003, language, filename, lineno, lineno, snippet,
                    confidence=0.90 if is_os_system or is_shell_subprocess else 0.75,
                    metadata={"matched": func_name, "shell": is_shell_subprocess},
                ))
        else:
            for pattern in self._CMD_INJECT_PATTERNS:
                for match in pattern.finditer(source_code):
                    lineno = source_code[:match.start()].count("\n") + 1
                    snippet = lines[lineno - 1] if lineno <= len(lines) else match.group()
                    matched_text = match.group().strip()
                    findings.append(_make_finding(
                        RULE_SAST003, language, filename, lineno, lineno, snippet,
                        confidence=0.75 if matched_text.startswith(("eval", "exec")) else 0.90,
                        metadata={"matched": matched_text},
                    ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # SAST-004: Path Traversal
    # ------------------------------------------------------------------

    def _check_sast004(self, ast_data, source_code, language, filename, lines):
        findings = []

        for pattern in self._PATH_TRAVERSAL_PATTERNS:
            for match in pattern.finditer(source_code):
                lineno = source_code[:match.start()].count("\n") + 1
                snippet = lines[lineno - 1] if lineno <= len(lines) else match.group()
                findings.append(_make_finding(
                    RULE_SAST004, language, filename, lineno, lineno, snippet,
                    confidence=0.80,
                    metadata={"matched": match.group()[:80]},
                ))

        # AST: open() or os.path.join() calls with non-constant first arg
        if language == "python":
            for node in _nodes_of_type(ast_data, "Call"):
                func = node.get("func", "")
                if func not in ("open", "os.path.join", "pathlib.Path"):
                    continue
                args = node.get("args", [])
                if not args:
                    continue
                first_arg = str(args[0])
                # If the arg is a variable (not a string literal starting with quote)
                if first_arg and not first_arg.startswith(("'", '"')):
                    lineno = node.get("lineno", 0)
                    snippet = node.get("snippet", "")
                    findings.append(_make_finding(
                        RULE_SAST004, language, filename, lineno, lineno,
                        snippet, confidence=0.70,
                        metadata={"func": func, "path_arg": first_arg},
                    ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # SAST-005: Hardcoded IPs / Internal URLs
    # ------------------------------------------------------------------

    def _check_sast005(self, ast_data, source_code, language, filename, lines):
        findings = []

        if language == "python":
            try:
                parsed = ast.parse(source_code)
            except SyntaxError:
                return findings

            for node in ast.walk(parsed):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                for match in self._IP_PATTERN.finditer(node.value):
                    try:
                        address = ipaddress.ip_address(match.group())
                    except ValueError:
                        continue
                    if not address.is_global:
                        continue
                    lineno = node.lineno
                    snippet = lines[lineno - 1] if lineno <= len(lines) else match.group()
                    findings.append(_make_finding(
                        RULE_SAST005, language, filename, lineno, lineno, snippet,
                        confidence=0.75,
                        metadata={"ip": str(address)},
                    ))
        else:
            for match in self._IP_PATTERN.finditer(source_code):
                try:
                    address = ipaddress.ip_address(match.group())
                except ValueError:
                    continue
                if not address.is_global:
                    continue
                lineno = source_code[:match.start()].count("\n") + 1
                snippet = lines[lineno - 1] if lineno <= len(lines) else match.group()
                if snippet.strip().startswith(("#", "//")):
                    continue
                findings.append(_make_finding(
                    RULE_SAST005, language, filename, lineno, lineno, snippet,
                    confidence=0.75,
                    metadata={"ip": str(address)},
                ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # SAST-006: eval() / exec()
    # ------------------------------------------------------------------

    def _check_sast006(self, ast_data, source_code, language, filename, lines):
        findings = []

        if language == "python":
            try:
                parsed = ast.parse(source_code)
            except SyntaxError:
                return findings
            for node in ast.walk(parsed):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in ("eval", "exec")
                ):
                    continue
                lineno = node.lineno
                snippet = lines[lineno - 1] if lineno <= len(lines) else node.func.id
                findings.append(_make_finding(
                    RULE_SAST006, language, filename, lineno, lineno, snippet,
                    confidence=0.85,
                    metadata={"call": node.func.id},
                ))
        else:
            for match in self._EVAL_EXEC_PATTERN.finditer(source_code):
                lineno = source_code[:match.start()].count("\n") + 1
                snippet = lines[lineno - 1] if lineno <= len(lines) else match.group()
                if snippet.strip().startswith(("#", "//")):
                    continue
                findings.append(_make_finding(
                    RULE_SAST006, language, filename, lineno, lineno, snippet,
                    confidence=0.85,
                    metadata={"call": match.group()},
                ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # SAST-007: Weak Cryptography
    # ------------------------------------------------------------------

    def _check_sast007(self, ast_data, source_code, language, filename, lines):
        findings = []

        for pattern in self._WEAK_CRYPTO_PATTERNS:
            for match in pattern.finditer(source_code):
                lineno = source_code[:match.start()].count("\n") + 1
                snippet = lines[lineno - 1] if lineno <= len(lines) else match.group()
                findings.append(_make_finding(
                    RULE_SAST007, language, filename, lineno, lineno, snippet,
                    confidence=0.90,
                    metadata={"matched": match.group()},
                ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # SAST-008: Insecure Random
    # ------------------------------------------------------------------

    def _check_sast008(self, ast_data, source_code, language, filename, lines):
        findings = []

        # Strategy: find random usage AND check if nearby context is security-sensitive
        for pattern in self._INSECURE_RANDOM_PATTERNS:
            for match in pattern.finditer(source_code):
                lineno = source_code[:match.start()].count("\n") + 1
                snippet = lines[lineno - 1] if lineno <= len(lines) else match.group()

                # Check surrounding 5 lines for security-sensitive keywords
                ctx_start = max(0, lineno - 5)
                ctx_end = min(len(lines), lineno + 5)
                context = "\n".join(lines[ctx_start:ctx_end])

                if self._RANDOM_SENSITIVE_CONTEXT.search(context):
                    findings.append(_make_finding(
                        RULE_SAST008, language, filename, lineno, lineno, snippet,
                        confidence=0.80,
                        metadata={"matched": match.group()},
                    ))
                elif "import random" in match.group():
                    # Flag the import with lower confidence
                    findings.append(_make_finding(
                        RULE_SAST008, language, filename, lineno, lineno, snippet,
                        confidence=0.50,
                        metadata={"matched": match.group(), "note": "import only - verify usage"},
                    ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # SAST-009: Debug Mode Enabled
    # ------------------------------------------------------------------

    def _check_sast009(self, ast_data, source_code, language, filename, lines):
        findings = []

        for pattern in self._DEBUG_MODE_PATTERNS:
            for match in pattern.finditer(source_code):
                lineno = source_code[:match.start()].count("\n") + 1
                snippet = lines[lineno - 1] if lineno <= len(lines) else match.group()
                # Skip comment lines
                if snippet.strip().startswith("#"):
                    continue
                findings.append(_make_finding(
                    RULE_SAST009, language, filename, lineno, lineno, snippet,
                    confidence=0.95,
                    metadata={"matched": match.group()},
                ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # SAST-010: Missing HTTPS
    # ------------------------------------------------------------------

    def _check_sast010(self, ast_data, source_code, language, filename, lines):
        findings = []

        for match in self._BARE_HTTP_PATTERN.finditer(source_code):
            lineno = source_code[:match.start()].count("\n") + 1
            snippet = lines[lineno - 1] if lineno <= len(lines) else match.group()
            # Skip comment lines
            if snippet.strip().startswith(("#", "//")):
                continue
            # Skip test fixtures / docs
            if re.search(r"(?:test|example|docs|README)", filename, re.I):
                continue
            findings.append(_make_finding(
                RULE_SAST010, language, filename, lineno, lineno, snippet,
                confidence=0.75,
                metadata={"url": match.group(1)[:100]},
            ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # SAST-011: XSS
    # ------------------------------------------------------------------

    def _check_sast011(self, ast_data, source_code, language, filename, lines):
        findings = []

        for pattern in self._XSS_PATTERNS:
            for match in pattern.finditer(source_code):
                lineno = source_code[:match.start()].count("\n") + 1
                snippet = lines[lineno - 1] if lineno <= len(lines) else match.group()
                findings.append(_make_finding(
                    RULE_SAST011, language, filename, lineno, lineno, snippet,
                    confidence=0.80,
                    metadata={"matched": match.group()},
                ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # SAST-012: SSRF
    # ------------------------------------------------------------------

    def _check_sast012(self, ast_data, source_code, language, filename, lines):
        findings = []

        for pattern in self._SSRF_PATTERNS:
            for match in pattern.finditer(source_code):
                lineno = source_code[:match.start()].count("\n") + 1
                snippet = lines[lineno - 1] if lineno <= len(lines) else match.group()
                findings.append(_make_finding(
                    RULE_SAST012, language, filename, lineno, lineno, snippet,
                    confidence=0.75,
                    metadata={"matched": match.group()[:80]},
                ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # SAST-013: Insecure Deserialization
    # ------------------------------------------------------------------

    def _check_sast013(self, ast_data, source_code, language, filename, lines):
        findings = []

        for pattern in self._DESERIAL_PATTERNS:
            for match in pattern.finditer(source_code):
                lineno = source_code[:match.start()].count("\n") + 1
                snippet = lines[lineno - 1] if lineno <= len(lines) else match.group()
                # Skip comment lines
                if snippet.strip().startswith("#"):
                    continue
                findings.append(_make_finding(
                    RULE_SAST013, language, filename, lineno, lineno, snippet,
                    confidence=0.90,
                    metadata={"matched": match.group()},
                ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # SAST-014: Missing Authentication Decorator
    # ------------------------------------------------------------------

    def _check_sast014(self, ast_data, source_code, language, filename, lines):
        """
        Flag only clearly privileged route handlers that lack an auth decorator.

        Whether a public route needs authentication depends on the application's
        authorization model, so route presence alone is not sufficient evidence.
        """
        findings = []

        if language != "python":
            return findings

        for node in _nodes_of_type(ast_data, "FunctionDef"):
            decorators = node.get("decorators", [])
            lineno = node.get("lineno", 0)
            func_name = node.get("name", "")

            has_route = any(
                re.search(r"(?:app|router|blueprint)\.(route|get|post|put|delete|patch)", d, re.I)
                for d in decorators
            )
            has_auth = any(
                re.search(r"(?:login_required|jwt_required|requires_auth|authenticate|"
                          r"token_required|permission_required|staff_member_required|"
                          r"superuser_required|current_user)", d, re.I)
                for d in decorators
            )

            if has_route and not has_auth and self._SENSITIVE_ROUTE_NAMES.search(func_name):
                snippet = node.get("snippet", lines[lineno - 1] if lineno <= len(lines) else "")
                findings.append(_make_finding(
                    RULE_SAST014, language, filename, lineno, lineno,
                    snippet, confidence=0.85,
                    metadata={"function": func_name, "decorators": decorators},
                ))

        return findings

    # ------------------------------------------------------------------
    # SAST-015: Sensitive Data in Logs
    # ------------------------------------------------------------------

    def _check_sast015(self, ast_data, source_code, language, filename, lines):
        findings = []

        if language == "python":
            try:
                parsed = ast.parse(source_code)
            except SyntaxError:
                return findings

            sensitive_name = re.compile(
                r"(?:password|passwd|secret|token|api_key|auth|credential)",
                re.IGNORECASE,
            )
            for node in ast.walk(parsed):
                if not isinstance(node, ast.Call):
                    continue
                func_name = ast.unparse(node.func).lower()
                is_log_call = func_name == "print" or (
                    func_name.rsplit(".", 1)[-1]
                    in {"debug", "info", "warning", "error", "exception", "critical"}
                    and func_name.startswith(("logger.", "logging.", "log."))
                )
                if not is_log_call:
                    continue

                exposed_names = set()
                for argument in [*node.args, *(keyword.value for keyword in node.keywords)]:
                    for value in ast.walk(argument):
                        if isinstance(value, ast.Name):
                            exposed_names.add(value.id)
                        elif isinstance(value, ast.Attribute):
                            exposed_names.add(value.attr)
                sensitive_names = [
                    name for name in exposed_names
                    if sensitive_name.search(name)
                    and not re.search(r"_(?:hash|digest)$", name, re.IGNORECASE)
                ]
                if sensitive_names:
                    lineno = node.lineno
                    snippet = lines[lineno - 1] if lineno <= len(lines) else func_name
                    findings.append(_make_finding(
                        RULE_SAST015, language, filename, lineno, lineno, snippet,
                        confidence=0.85,
                        metadata={"sensitive_variables": sorted(sensitive_names)},
                    ))
        else:
            for pattern in self._LOG_SENSITIVE_PATTERNS:
                for match in pattern.finditer(source_code):
                    lineno = source_code[:match.start()].count("\n") + 1
                    snippet = lines[lineno - 1] if lineno <= len(lines) else match.group()
                    findings.append(_make_finding(
                        RULE_SAST015, language, filename, lineno, lineno, snippet,
                        confidence=0.80,
                        metadata={"matched": match.group()[:120]},
                    ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate(findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings by (rule_id, line_start) key."""
        seen: set = set()
        unique: List[Finding] = []
        for f in findings:
            key = (f.rule_id, f.location.line_start)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def get_all_rules(self) -> List[SecurityRule]:
        """Return the full list of registered security rules."""
        return ALL_RULES
