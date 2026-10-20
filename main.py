import hmac
import ipaddress
import os
import re
import secrets
import socket
import time
from datetime import timedelta
from html import unescape
from urllib.parse import urljoin, urlsplit

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(hours=6)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
    MAX_CONTENT_LENGTH=512 * 1024,
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

MASTER_PASSWORD = os.environ.get("MASTER_PASSWORD", "")
SESSION_SECONDS = 6 * 60 * 60
MAX_FETCH_BYTES = 160_000
MAX_FETCH_URLS = 2
MAX_FETCH_ATTEMPTS = 2
TIMESTAMP_PATTERN = re.compile(
    r"(?:^|[?&~|;=\s])(?:Expires|exp|expiry|expires_at|expiresat|expire|exp_time|expiration|e)\s*=\s*['\"]?(\d{10,13})",
    re.IGNORECASE,
)
START_PATTERN = re.compile(
    r"(?:^|[?&~|;=\s])(?:st|start|start_time|starttime|issued|issued_at|issuedat|iat|created|created_at|createdat|generated|generated_at|generation_time|generationtime|gen_time|gen)\s*=\s*['\"]?(\d{10,13})",
    re.IGNORECASE,
)
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def epoch_seconds(value):
    number = int(value)
    if number > 10_000_000_000:
        number //= 1000
    if 946684800 <= number <= 4102444800:
        return number
    return None


def first_timestamp(pattern, text):
    for match in pattern.finditer(text):
        value = epoch_seconds(match.group(1))
        if value is not None:
            return value
    return None


def timestamp_record(text):
    return {
        "generated": first_timestamp(START_PATTERN, text),
        "expires": first_timestamp(TIMESTAMP_PATTERN, text),
    }


def extract_urls(text):
    found = []
    seen = set()
    for match in URL_PATTERN.findall(text):
        candidate = match.rstrip(".,;!?)\\]}>")
        if candidate not in seen:
            seen.add(candidate)
            found.append(candidate)
    return found[:20]


def public_http_url(value):
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        if parsed.username or parsed.password:
            return False
        if parsed.port and parsed.port not in {80, 443}:
            return False
        host = parsed.hostname.rstrip(".").lower()
        if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local", ".internal")):
            return False
        addresses = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        return bool(addresses) and all(ipaddress.ip_address(item[4][0]).is_global for item in addresses)
    except (ValueError, OSError, socket.gaierror):
        return False


def fetch_text(url):
    current = url
    headers_seen = {}
    body = ""
    error = None
    for attempt in range(MAX_FETCH_ATTEMPTS):
        if not public_http_url(current):
            error = "Remote inspection was blocked because the URL is not a public HTTP(S) address."
            break
        try:
            response = requests.get(
                current,
                timeout=(2, 4),
                stream=True,
                allow_redirects=False,
                headers={"User-Agent": "ChronoGlass/1.0 manifest-inspector", "Accept": "*/*"},
            )
            headers_seen = {key.lower(): value for key, value in response.headers.items()}
            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                response.close()
                if not location:
                    break
                if attempt + 1 >= MAX_FETCH_ATTEMPTS:
                    error = "Remote inspection stopped after the redirect safety limit."
                    break
                current = urljoin(current, location)
                continue
            if response.status_code >= 400:
                error = f"Remote server returned HTTP {response.status_code}."
                response.close()
                break
            chunks = []
            size = 0
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                size += len(chunk)
                if size > MAX_FETCH_BYTES:
                    error = "Remote manifest exceeded the 160 KB inspection limit."
                    break
                chunks.append(chunk)
            response.close()
            body = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
            break
        except requests.RequestException:
            error = "Could not reach the remote URL. It may be unavailable or reject server-side requests."
            break
    return {"url": current, "headers": headers_seen, "body": body, "error": error}


def analyze_text(text, inspect_remote):
    fetch_budget = [MAX_FETCH_URLS]
    cleaned = unescape(text).replace("\\u0026", "&")
    urls = extract_urls(cleaned)
    sources = urls or [cleaned.strip()]
    results = []
    for source in sources:
        direct = timestamp_record(source)
        inspected = []
        remote_error = None
        discovered = []
        if inspect_remote and source.startswith(("http://", "https://")) and (direct["expires"] is None or direct["generated"] is None):
            queue = [source]
            visited = set()
            while queue and len(visited) < MAX_FETCH_URLS and fetch_budget[0] > 0:
                target = queue.pop(0)
                if target in visited:
                    continue
                visited.add(target)
                fetch_budget[0] -= 1
                fetched = fetch_text(target)
                body = fetched["body"]
                headers = fetched["headers"]
                if fetched["error"] and not body:
                    remote_error = fetched["error"]
                    continue
                inspected.append({"url": fetched["url"], "status": "Fetched", "bytes": len(body.encode("utf-8"))})
                combined = "\n".join([fetched["url"], body])
                discovered.append(combined)
                if headers.get("last-modified"):
                    inspected[-1]["lastModified"] = headers["last-modified"]
                if headers.get("content-type"):
                    inspected[-1]["contentType"] = headers["content-type"]
                for line in body.splitlines():
                    candidate = line.strip()
                    if not candidate or candidate.startswith("#"):
                        continue
                    if TIMESTAMP_PATTERN.search(candidate) or START_PATTERN.search(candidate):
                        absolute = urljoin(fetched["url"], candidate)
                        if absolute not in visited and absolute not in queue:
                            queue.append(absolute)
                for candidate in extract_urls(body):
                    if TIMESTAMP_PATTERN.search(candidate) or START_PATTERN.search(candidate):
                        if candidate not in visited and candidate not in queue:
                            queue.append(candidate)
            if queue and (len(visited) >= MAX_FETCH_URLS or fetch_budget[0] == 0):
                remote_error = remote_error or "Remote inspection stopped at the two-URL safety limit."
        combined_sources = "\n".join([source, *discovered])
        timestamps = timestamp_record(combined_sources)
        result = {
            "input": source,
            "generated": timestamps["generated"],
            "expires": timestamps["expires"],
            "inspected": inspected,
            "remoteError": remote_error,
        }
        result["raw"] = "\n\n".join(discovered)[:8000]
        results.append(result)
    if not results:
        results = [{"input": cleaned.strip(), "generated": None, "expires": None, "inspected": [], "remoteError": None, "raw": ""}]
    return results


def is_authenticated():
    auth_at = session.get("auth_at")
    if not auth_at or time.time() - auth_at >= SESSION_SECONDS:
        session.clear()
        return False
    return True


def auth_required():
    if not is_authenticated():
        return jsonify({"error": "Authentication required."}), 401
    return None


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/manifest.webmanifest")
def manifest():
    return app.send_static_file("manifest.webmanifest")


@app.get("/sw.js")
def service_worker():
    return app.send_static_file("sw.js")


@app.get("/api/session")
def session_status():
    authenticated = is_authenticated()
    remaining = max(0, int(SESSION_SECONDS - (time.time() - session.get("auth_at", 0)))) if authenticated else 0
    return jsonify({"authenticated": authenticated, "remaining": remaining, "configured": bool(MASTER_PASSWORD)})


@app.post("/api/login")
def login():
    if not MASTER_PASSWORD:
        return jsonify({"error": "Access is not configured. Set MASTER_PASSWORD in the server environment."}), 503
    payload = request.get_json(silent=True) or {}
    supplied = str(payload.get("password", ""))
    if not hmac.compare_digest(supplied.encode("utf-8"), MASTER_PASSWORD.encode("utf-8")):
        return jsonify({"error": "That passphrase is not correct."}), 401
    session.clear()
    session.permanent = True
    session["auth_at"] = time.time()
    return jsonify({"authenticated": True, "remaining": SESSION_SECONDS})


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.post("/api/analyze")
def analyze():
    denied = auth_required()
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    text = str(payload.get("text", ""))
    if not text.strip():
        return jsonify({"error": "Paste a URL, cookie string, or manifest source to inspect."}), 400
    if len(text) > 300_000:
        return jsonify({"error": "Input is too large. Keep it under 300 KB."}), 413
    return jsonify({"results": analyze_text(text, bool(payload.get("inspectRemote", True)))})


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
    if request.path == "/sw.js":
        response.headers["Service-Worker-Allowed"] = "/"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
