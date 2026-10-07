"""
sample_targets/vulnerable_app.py
=================================
⚠️  WARNING: THIS FILE CONTAINS INTENTIONAL SECURITY VULNERABILITIES ⚠️
====================================================================
This file is used EXCLUSIVELY for testing SAST (Static Application
Security Testing) tools and training purposes.

DO NOT deploy, run, or adapt this code in any production environment.
All vulnerabilities are deliberate and documented below.

Vulnerability index:
  VUL-01  SQL Injection (string formatting)
  VUL-02  Hardcoded password
  VUL-03  Hardcoded API key
  VUL-04  Use of eval()
  VUL-05  Command injection (os.system with user input)
  VUL-06  Insecure deserialization (pickle.loads)
  VUL-07  MD5 used for password hashing
  VUL-08  Debug mode enabled
  VUL-09  Missing HTTPS (plain HTTP endpoint)
  VUL-10  Path traversal (unvalidated file path)
  VUL-11  XSS in template rendering (Markup / Jinja2)
  VUL-12  SSRF (user-controlled URL fetch)
  VUL-13  Insecure random (secrets/tokens)
  VUL-14  yaml.load without SafeLoader
  VUL-15  Shell injection via subprocess(shell=True)
"""

# =============================================================================
# Imports
# =============================================================================
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import urllib.request
from typing import Any

import requests
import yaml
from flask import Flask, request, render_template_string, send_file

# =============================================================================
# Application bootstrap
# =============================================================================
app = Flask(__name__)

# VUL-02 – Hardcoded password
# Fix: Read from environment variable: os.environ["DB_PASSWORD"]
DB_PASSWORD = "supersecret123"  # noqa: S105

# VUL-03 – Hardcoded API key
# Fix: Use os.environ["EXTERNAL_API_KEY"] or a secrets manager
EXTERNAL_API_KEY = "sk-abc123def456ghi789jkl012mno345pqr678stu"  # noqa: S105

# VUL-08 – Debug mode enabled
# Fix: app.run(debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
DEBUG_MODE = True


def get_db_connection() -> sqlite3.Connection:
    """Open a SQLite connection (in-memory for demo)."""
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)"
    )
    conn.execute(
        "INSERT INTO users (username, password, email) VALUES "
        "('admin', 'admin123', 'admin@example.com')"
    )
    conn.commit()
    return conn


# =============================================================================
# Routes
# =============================================================================

# -----------------------------------------------------------------------------
# VUL-01 – SQL Injection
# -----------------------------------------------------------------------------
@app.route("/user")
def get_user():
    """
    VUL-01: SQL query built via string formatting with unsanitized user input.
    Attack: GET /user?username=' OR '1'='1
    """
    username = request.args.get("username", "")
    conn = get_db_connection()

    # ❌ VULNERABLE: direct string interpolation
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cursor = conn.execute(query)
    user = cursor.fetchone()

    return {"user": user}


@app.route("/search")
def search_users():
    """
    VUL-01b: SQL injection via f-string.
    Attack: GET /search?term='; DROP TABLE users; --
    """
    term = request.args.get("term", "")
    conn = get_db_connection()

    # ❌ VULNERABLE: f-string in SQL
    cursor = conn.execute(f"SELECT * FROM users WHERE email LIKE '%{term}%'")
    results = cursor.fetchall()
    return {"results": results}


# -----------------------------------------------------------------------------
# VUL-04 – Use of eval()
# -----------------------------------------------------------------------------
@app.route("/calculate")
def calculate():
    """
    VUL-04: Arbitrary Python expression evaluated via eval().
    Attack: GET /calculate?expr=__import__('os').system('id')
    """
    expr = request.args.get("expr", "1+1")
    # ❌ VULNERABLE: eval() with user-controlled input
    result = eval(expr)  # noqa: S307
    return {"result": result}


# -----------------------------------------------------------------------------
# VUL-05 – Command Injection (os.system)
# -----------------------------------------------------------------------------
@app.route("/ping")
def ping_host():
    """
    VUL-05: User input passed directly to os.system — command injection.
    Attack: GET /ping?host=localhost; cat /etc/passwd
    """
    host = request.args.get("host", "localhost")
    # ❌ VULNERABLE: os.system with unsanitized input
    os.system(f"ping -c 1 {host}")  # noqa: S605
    return {"status": "ping sent", "host": host}


# -----------------------------------------------------------------------------
# VUL-15 – Shell Injection via subprocess(shell=True)
# -----------------------------------------------------------------------------
@app.route("/traceroute")
def traceroute():
    """
    VUL-15: subprocess.check_output with shell=True and user-controlled command.
    Attack: GET /traceroute?host=localhost && rm -rf /tmp/test
    """
    host = request.args.get("host", "localhost")
    # ❌ VULNERABLE: shell=True + user input
    output = subprocess.check_output(  # noqa: S602
        f"traceroute {host}", shell=True, text=True
    )
    return {"output": output}


# -----------------------------------------------------------------------------
# VUL-06 – Insecure Deserialization (pickle)
# -----------------------------------------------------------------------------
@app.route("/load-profile", methods=["POST"])
def load_profile():
    """
    VUL-06: pickle.loads() on user-submitted data — arbitrary code execution.
    Attack: Submit a crafted pickle payload that executes os.system().
    """
    raw = request.get_data()
    # ❌ VULNERABLE: deserializing untrusted bytes
    profile = pickle.loads(raw)  # noqa: S301
    return {"profile": str(profile)}


# -----------------------------------------------------------------------------
# VUL-07 – MD5 for Password Hashing
# -----------------------------------------------------------------------------
@app.route("/register", methods=["POST"])
def register():
    """
    VUL-07: MD5 used as a password hash — easily brute-forced.
    Fix: Use bcrypt / argon2 via passlib.
    """
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # ❌ VULNERABLE: MD5 for passwords
    password_hash = hashlib.md5(password.encode()).hexdigest()  # noqa: S324

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, password_hash),
    )
    conn.commit()
    return {"status": "registered", "hash": password_hash}


# -----------------------------------------------------------------------------
# VUL-09 – Missing HTTPS / Insecure HTTP
# -----------------------------------------------------------------------------
@app.route("/webhook")
def send_webhook():
    """
    VUL-09: Sensitive data transmitted over plain HTTP (no TLS).
    Fix: Enforce HTTPS; validate SSL certificates.
    """
    payload = {"api_key": EXTERNAL_API_KEY, "event": "scan_complete"}
    # ❌ VULNERABLE: plain http:// URL, and hardcoded key in payload
    response = requests.post(  # noqa: S113
        "http://external-service.example.com/webhook",
        json=payload,
        verify=False,  # noqa: S501  ← also: SSL verification disabled
    )
    return {"status": response.status_code}


# -----------------------------------------------------------------------------
# VUL-10 – Path Traversal
# -----------------------------------------------------------------------------
@app.route("/download")
def download_file():
    """
    VUL-10: File path constructed from user input without sanitization.
    Attack: GET /download?filename=../../etc/passwd
    """
    filename = request.args.get("filename", "report.pdf")
    # ❌ VULNERABLE: no path validation
    file_path = os.path.join("/var/app/reports", filename)
    return send_file(file_path)  # noqa: S108


# -----------------------------------------------------------------------------
# VUL-11 – XSS in Template Rendering
# -----------------------------------------------------------------------------
@app.route("/greet")
def greet():
    """
    VUL-11: User input injected directly into an HTML template — reflected XSS.
    Attack: GET /greet?name=<script>alert('XSS')</script>
    """
    name = request.args.get("name", "World")
    # ❌ VULNERABLE: render_template_string with unsanitized user data
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


# -----------------------------------------------------------------------------
# VUL-12 – SSRF (Server-Side Request Forgery)
# -----------------------------------------------------------------------------
@app.route("/fetch")
def fetch_url():
    """
    VUL-12: User-controlled URL fetched by the server — SSRF.
    Attack: GET /fetch?url=http://169.254.169.254/latest/meta-data/ (AWS metadata)
    Attack: GET /fetch?url=file:///etc/passwd
    """
    url = request.args.get("url", "https://example.com")
    # ❌ VULNERABLE: no URL validation or allowlisting
    content = urllib.request.urlopen(url).read()  # noqa: S310
    return {"content": content.decode("utf-8", errors="replace")[:1000]}


# -----------------------------------------------------------------------------
# VUL-13 – Insecure Random (for token generation)
# -----------------------------------------------------------------------------
@app.route("/reset-password")
def reset_password():
    """
    VUL-13: Password reset token generated with non-cryptographic random.
    Fix: Use secrets.token_urlsafe(32) instead.
    """
    # ❌ VULNERABLE: random is not cryptographically secure
    token = "".join([str(random.randint(0, 9)) for _ in range(6)])  # noqa: S311
    return {"reset_token": token}


# -----------------------------------------------------------------------------
# VUL-14 – yaml.load without SafeLoader
# -----------------------------------------------------------------------------
@app.route("/load-config", methods=["POST"])
def load_config():
    """
    VUL-14: yaml.load() without a safe Loader — can execute arbitrary Python.
    Attack: POST body: !!python/object/apply:os.system ['id']
    Fix: yaml.safe_load(data) or yaml.load(data, Loader=yaml.SafeLoader)
    """
    raw = request.get_data(as_text=True)
    # ❌ VULNERABLE: unsafe yaml.load
    config = yaml.load(raw)  # noqa: S506
    return {"config": str(config)}


# =============================================================================
# Entry point
# =============================================================================
if __name__ == "__main__":
    # VUL-08 – Debug mode enabled in production code
    app.run(host="0.0.0.0", port=5000, debug=DEBUG_MODE)  # noqa: S104
