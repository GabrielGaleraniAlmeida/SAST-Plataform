"""
sample_targets/secure_app.py
==============================
✅  Secure implementation of the same application as vulnerable_app.py.
====================================================================
This module demonstrates the correct, security-hardened approach to
implementing the same features shown in vulnerable_app.py.

Each section references the corresponding vulnerability (VUL-xx) from the
vulnerable version and explains the mitigation applied.

Security controls implemented:
  VUL-01  → Parameterized queries (prepared statements)
  VUL-02  → Passwords from environment variables
  VUL-03  → API keys from environment variables / secrets manager
  VUL-04  → eval() replaced with ast.literal_eval() / safe math parser
  VUL-05  → subprocess with list args and shell=False
  VUL-06  → JSON serialization instead of pickle
  VUL-07  → Argon2 / bcrypt for password hashing
  VUL-08  → Debug mode controlled by environment variable
  VUL-09  → HTTPS enforced; SSL verification enabled
  VUL-10  → Path validation with pathlib.resolve()
  VUL-11  → Jinja2 auto-escaping; no f-string templates
  VUL-12  → URL allowlisting + private IP blocking
  VUL-13  → secrets module for cryptographic tokens
  VUL-14  → yaml.safe_load()
  VUL-15  → subprocess list args, shell=False
"""

# =============================================================================
# Imports
# =============================================================================
import ast
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import urllib.parse
from pathlib import Path
from typing import Any, Optional

import bcrypt
import requests
import yaml
from flask import Flask, abort, jsonify, render_template, request, send_from_directory

# =============================================================================
# Logging
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

# =============================================================================
# Application bootstrap
# =============================================================================
app = Flask(__name__)

# VUL-02 FIX – Read credentials from environment; raise immediately if absent
DB_PASSWORD: str = os.environ["DB_PASSWORD"]          # Fails fast if not set
SECRET_KEY: str  = os.environ["FLASK_SECRET_KEY"]     # Used for session signing
app.secret_key   = SECRET_KEY

# VUL-03 FIX – API key from environment; never hardcoded
EXTERNAL_API_KEY: str = os.environ["EXTERNAL_API_KEY"]

# VUL-08 FIX – Debug flag from environment; default is OFF
FLASK_DEBUG: bool = os.getenv("FLASK_DEBUG", "false").lower() == "true"

# Static directory for safe file downloads (VUL-10 fix)
REPORTS_DIR: Path = Path(os.getenv("REPORTS_DIR", "/var/app/reports")).resolve()

# Allowed external domains for webhook / outbound requests (VUL-12 fix)
ALLOWED_DOMAINS: set[str] = {
    "external-service.example.com",
    "api.partner.example.com",
}

# =============================================================================
# Private / reserved IP ranges — used to block SSRF (VUL-12)
# =============================================================================
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local (AWS metadata)
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
]


def _is_private_ip(host: str) -> bool:
    """Return True if the resolved IP belongs to a private/reserved range."""
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return any(ip in net for net in _PRIVATE_NETWORKS)
    except (socket.gaierror, ValueError):
        return True  # treat unresolvable hosts as unsafe


def _validate_url(url: str) -> str:
    """
    Validate that a URL uses HTTPS, belongs to an allowed domain,
    and does not resolve to a private IP (SSRF protection).
    Raises ValueError on invalid input.
    """
    parsed = urllib.parse.urlparse(url)

    if parsed.scheme != "https":
        raise ValueError("Only HTTPS URLs are permitted")

    if parsed.netloc not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain '{parsed.netloc}' is not in the allowlist")

    if _is_private_ip(parsed.hostname or ""):
        raise ValueError("URL resolves to a private/internal IP address (SSRF blocked)")

    return url


# =============================================================================
# Database helpers
# =============================================================================

def get_db_connection() -> sqlite3.Connection:
    """Open a SQLite connection with row_factory for dict-like access."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT UNIQUE, "
        " password_hash TEXT NOT NULL, email TEXT)"
    )
    conn.commit()
    return conn


# =============================================================================
# Routes
# =============================================================================

# -----------------------------------------------------------------------------
# VUL-01 FIX – Parameterized Queries
# -----------------------------------------------------------------------------
@app.route("/user")
def get_user():
    """
    VUL-01 FIX: Parameterized query — user input is passed as a bound
    parameter, never interpolated into the SQL string.
    """
    username: str = request.args.get("username", "")
    if not username:
        abort(400, description="username is required")

    conn = get_db_connection()
    # ✅ SECURE: placeholder '?' with tuple parameter
    cursor = conn.execute(
        "SELECT id, username, email FROM users WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()
    if row is None:
        abort(404, description="User not found")

    return jsonify(dict(row))


@app.route("/search")
def search_users():
    """
    VUL-01b FIX: LIKE query uses parameterized LIKE with '%?%' pattern.
    """
    term: str = request.args.get("term", "")
    conn = get_db_connection()
    # ✅ SECURE: bind parameter for LIKE search
    cursor = conn.execute(
        "SELECT id, username, email FROM users WHERE email LIKE ?",
        (f"%{term}%",),
    )
    results = [dict(row) for row in cursor.fetchall()]
    return jsonify({"results": results})


# -----------------------------------------------------------------------------
# VUL-04 FIX – Safe expression evaluation
# -----------------------------------------------------------------------------
@app.route("/calculate")
def calculate():
    """
    VUL-04 FIX: ast.literal_eval() only handles literals (numbers, strings,
    lists, dicts) — it cannot execute arbitrary code.
    For math expressions, use a dedicated safe evaluator.
    """
    expr: str = request.args.get("expr", "0")

    # Allowlist: only digits, operators, parentheses, and whitespace
    if not re.fullmatch(r"[\d\s\+\-\*/\(\)\.]+", expr):
        abort(400, description="Invalid expression. Only numeric operators are allowed.")

    try:
        # ✅ SECURE: ast.literal_eval for safe evaluation of simple expressions
        # For math, parse the AST manually or use a library like simpleeval
        result = ast.literal_eval(expr)
    except (ValueError, SyntaxError):
        abort(400, description="Could not evaluate expression")

    return jsonify({"result": result})


# -----------------------------------------------------------------------------
# VUL-05 FIX – subprocess with list args, shell=False
# -----------------------------------------------------------------------------
@app.route("/ping")
def ping_host():
    """
    VUL-05 FIX: subprocess.run() with list args and shell=False.
    Input is validated against an allowlist regex before use.
    """
    host: str = request.args.get("host", "")

    # Validate: only hostnames/IPs (no shell metacharacters)
    if not re.fullmatch(r"[a-zA-Z0-9.\-]{1,253}", host):
        abort(400, description="Invalid hostname")

    try:
        # ✅ SECURE: list args, shell=False, timeout, no user data in command string
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            capture_output=True,
            text=True,
            timeout=5,
            shell=False,    # ← critical
            check=False,
        )
        return jsonify({"host": host, "returncode": result.returncode, "output": result.stdout})
    except subprocess.TimeoutExpired:
        abort(504, description="Ping timed out")


# -----------------------------------------------------------------------------
# VUL-15 FIX – subprocess list args
# -----------------------------------------------------------------------------
@app.route("/traceroute")
def traceroute():
    """
    VUL-15 FIX: shell=False + list args — user input cannot inject shell commands.
    """
    host: str = request.args.get("host", "")

    if not re.fullmatch(r"[a-zA-Z0-9.\-]{1,253}", host):
        abort(400, description="Invalid hostname")

    try:
        # ✅ SECURE: list args, no shell
        result = subprocess.run(
            ["traceroute", "-m", "10", host],
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
            check=False,
        )
        return jsonify({"output": result.stdout})
    except subprocess.TimeoutExpired:
        abort(504, description="Traceroute timed out")


# -----------------------------------------------------------------------------
# VUL-06 FIX – JSON instead of pickle
# -----------------------------------------------------------------------------
@app.route("/load-profile", methods=["POST"])
def load_profile():
    """
    VUL-06 FIX: JSON deserialization — cannot execute arbitrary code.
    Validate the schema after loading.
    """
    try:
        raw = request.get_data(as_text=True)
        # ✅ SECURE: JSON is safe to deserialize from untrusted input
        profile: dict[str, Any] = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        abort(400, description=f"Invalid JSON: {exc}")

    # Schema validation (basic example)
    allowed_keys = {"name", "email", "preferences"}
    if not isinstance(profile, dict) or not profile.keys() <= allowed_keys:
        abort(400, description="Invalid profile structure")

    return jsonify({"profile": profile})


# -----------------------------------------------------------------------------
# VUL-07 FIX – bcrypt for password hashing
# -----------------------------------------------------------------------------
@app.route("/register", methods=["POST"])
def register():
    """
    VUL-07 FIX: bcrypt with auto-generated salt — resistant to brute force
    and rainbow table attacks.
    """
    data: dict[str, Any] = request.get_json() or {}
    username: str = data.get("username", "").strip()
    password: str = data.get("password", "")

    if not username or not password:
        abort(400, description="username and password are required")

    if len(password) < 12:
        abort(400, description="Password must be at least 12 characters")

    # ✅ SECURE: bcrypt with cost factor 12
    hashed: bytes = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))

    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hashed.decode("utf-8")),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        abort(409, description="Username already exists")

    return jsonify({"status": "registered"}), 201


# -----------------------------------------------------------------------------
# VUL-09 FIX – HTTPS enforced, SSL verification enabled
# -----------------------------------------------------------------------------
@app.route("/webhook")
def send_webhook():
    """
    VUL-09 FIX: HTTPS URL, verify=True (default), no secrets in payload body.
    API key sent via Authorization header.
    """
    # ✅ SECURE: HTTPS; API key in Authorization header, not request body
    headers = {
        "Authorization": f"Bearer {EXTERNAL_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {"event": "scan_complete"}

    try:
        response = requests.post(
            "https://external-service.example.com/webhook",
            json=payload,
            headers=headers,
            verify=True,    # ← SSL certificate verified (default)
            timeout=10,
        )
        response.raise_for_status()
        return jsonify({"status": response.status_code})
    except requests.exceptions.RequestException as exc:
        logger.error("Webhook delivery failed: %s", exc)
        abort(502, description="Webhook delivery failed")


# -----------------------------------------------------------------------------
# VUL-10 FIX – Path validation with pathlib.resolve()
# -----------------------------------------------------------------------------
@app.route("/download")
def download_file():
    """
    VUL-10 FIX: Resolve the full path and verify it stays inside REPORTS_DIR.
    Any '..' traversal will cause the resolved path to escape the base dir,
    which is caught and rejected.
    """
    filename: str = request.args.get("filename", "")

    if not filename:
        abort(400, description="filename is required")

    # ✅ SECURE: resolve absolute path and check prefix
    requested = (REPORTS_DIR / filename).resolve()

    if not str(requested).startswith(str(REPORTS_DIR)):
        abort(403, description="Access denied: path traversal detected")

    if not requested.is_file():
        abort(404, description="File not found")

    # send_from_directory is inherently safe — serves only within the given dir
    return send_from_directory(str(REPORTS_DIR), requested.name)


# -----------------------------------------------------------------------------
# VUL-11 FIX – Jinja2 auto-escaping; render from template file
# -----------------------------------------------------------------------------
@app.route("/greet")
def greet():
    """
    VUL-11 FIX: Use render_template() with a real template file and
    Jinja2 auto-escaping (enabled by default for .html files).
    User input is passed as a context variable — Jinja2 escapes it.
    """
    name: str = request.args.get("name", "World")

    # Length limit to prevent abuse
    name = name[:100]

    # ✅ SECURE: render_template with auto-escaping; 'name' is escaped by Jinja2
    # Template file: templates/greet.html  →  <h1>Hello, {{ name }}!</h1>
    # For demo (no template file available), we escape manually:
    from markupsafe import escape
    safe_name = escape(name)
    return f"<h1>Hello, {safe_name}!</h1>", 200, {"Content-Type": "text/html"}


# -----------------------------------------------------------------------------
# VUL-12 FIX – URL allowlisting + SSRF protection
# -----------------------------------------------------------------------------
@app.route("/fetch")
def fetch_url():
    """
    VUL-12 FIX: URL is validated against an allowlist of domains,
    must use HTTPS, and resolved IPs are checked against private ranges.
    """
    url: str = request.args.get("url", "")

    if not url:
        abort(400, description="url is required")

    try:
        safe_url = _validate_url(url)
    except ValueError as exc:
        abort(403, description=str(exc))

    try:
        # ✅ SECURE: allowlisted HTTPS URL; SSL verification on; timeout set
        response = requests.get(safe_url, timeout=5, verify=True)
        return jsonify({"content": response.text[:1000]})
    except requests.exceptions.RequestException as exc:
        logger.warning("Outbound fetch failed: %s", exc)
        abort(502, description="Failed to fetch URL")


# -----------------------------------------------------------------------------
# VUL-13 FIX – secrets module for cryptographic token
# -----------------------------------------------------------------------------
@app.route("/reset-password")
def reset_password():
    """
    VUL-13 FIX: secrets.token_urlsafe() generates a cryptographically
    secure, URL-safe token using the OS CSPRNG.
    """
    # ✅ SECURE: 32 bytes → 256-bit entropy, URL-safe base64 encoded
    token: str = secrets.token_urlsafe(32)

    # In production: store a hash of the token, not the token itself
    token_hash: str = hashlib.sha256(token.encode()).hexdigest()
    logger.info("Password reset token hash stored: %s", token_hash)

    # Only return token once; store hashed version in DB
    return jsonify({"reset_token": token, "expires_in": 900})


# -----------------------------------------------------------------------------
# VUL-14 FIX – yaml.safe_load()
# -----------------------------------------------------------------------------
@app.route("/load-config", methods=["POST"])
def load_config():
    """
    VUL-14 FIX: yaml.safe_load() only supports scalar types — it cannot
    instantiate arbitrary Python objects.
    """
    raw: str = request.get_data(as_text=True)

    try:
        # ✅ SECURE: safe_load() — no arbitrary object construction
        config: Any = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        abort(400, description=f"Invalid YAML: {exc}")

    if not isinstance(config, dict):
        abort(400, description="Config must be a YAML mapping")

    return jsonify({"config": config})


# =============================================================================
# Error handlers
# =============================================================================

@app.errorhandler(400)
def bad_request(exc: Exception):
    return jsonify({"error": "Bad Request", "message": str(exc)}), 400


@app.errorhandler(403)
def forbidden(exc: Exception):
    return jsonify({"error": "Forbidden", "message": str(exc)}), 403


@app.errorhandler(404)
def not_found(exc: Exception):
    return jsonify({"error": "Not Found", "message": str(exc)}), 404


@app.errorhandler(500)
def internal_error(exc: Exception):
    logger.exception("Unhandled exception")
    return jsonify({"error": "Internal Server Error"}), 500


# =============================================================================
# Entry point
# =============================================================================
if __name__ == "__main__":
    # ✅ SECURE: debug controlled by env var; host binding configurable
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "5000")),
        debug=FLASK_DEBUG,
    )
