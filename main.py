import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import time
from calendar import timegm
from datetime import timedelta
from html import unescape
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

MASTER_PASSWORD = os.environ.get("MASTER_PASSWORD", "")


def stable_secret_key():
    """One signing key for every gunicorn worker.

    With a random per-process key each worker rejects the others' session
    cookies, which is why a correct passphrase could still be asked for again
    on the next request. SECRET_KEY wins when configured; otherwise derive a
    deterministic key so sessions stay valid across workers and restarts.
    """
    configured = os.environ.get("SECRET_KEY")
    if configured:
        return configured
    if MASTER_PASSWORD:
        return hashlib.sha256(f"token-inspector|{MASTER_PASSWORD}".encode("utf-8")).hexdigest()
    return secrets.token_hex(32)


app = Flask(__name__)
app.secret_key = stable_secret_key()
app.permanent_session_lifetime = timedelta(minutes=30)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
    MAX_CONTENT_LENGTH=512 * 1024,
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

SESSION_SECONDS = 30 * 60          # passkey session: 30 minutes
SESSION_TOUCH_INTERVAL = 45        # sliding renewal, so active use never expires

# ---- inspection limits -------------------------------------------------------
MAX_INPUT_CHARS = 300_000
MAX_RESULTS = 20
MAX_FETCHES = 7              # total outbound manifest requests per analysis
MAX_DEPTH = 3                # master -> variant -> sub-variant
MAX_FETCH_BYTES = 240_000
REDIRECT_LIMIT = 3
CONNECT_TIMEOUT = 3
READ_TIMEOUT = 5

# ---- token vocabulary --------------------------------------------------------
EXPIRY_KEYS = {
    "exp", "expires", "expire", "expiry", "expiration", "expires_at", "expiresat",
    "exp_time", "exptime", "expiration_time", "end", "ends", "end_time", "endtime",
    "until", "valid_until", "validuntil", "valid_to", "deadline", "e", "se",
    "hdnts_exp", "expiry_time", "expirytime", "token_expiry", "not_after",
}
START_KEYS = {
    "st", "start", "starts", "start_time", "starttime", "started", "started_at",
    "iat", "issued", "issued_at", "issuedat", "issue_time", "issuetime", "created",
    "created_at", "createdat", "created_time", "createdtime", "generated",
    "generated_at", "generatedat", "generation_time", "generationtime", "gen_time",
    "gen", "not_before", "nbf", "birth", "ts", "timestamp", "issued_on",
    "creation_time",
}
TTL_KEYS = {
    "ttl", "lifetime", "hdntl", "valid_for", "validfor", "duration", "max_age",
    "maxage", "expires_in", "expiresin", "timeout", "window", "age", "validity",
}
SIGNATURE_KEYS = {
    "hmac", "signature", "sig", "hash", "key", "sign", "auth", "auth_key",
    "authkey", "api_key", "apikey", "access_key", "accesskey", "secret", "tk",
    "token", "session", "sessionid", "sid", "jwt", "credential", "x-amz-signature",
    "x-amz-credential", "x-amz-security-token", "policy", "cs",
}

KEY_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]{0,34}$")
VALUE_STOP = set("&~|;,\"'<>()[]{}=" + " \r\n\t")
JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{0,}")
URL_PATTERN = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)
HEXISH_PATTERN = re.compile(r"^[0-9a-f]{24,}$", re.IGNORECASE)
BASE64ISH_PATTERN = re.compile(r"^[A-Za-z0-9+/_\-]{16,}={0,2}$")
ISO_PATTERN = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?"
)
URI_ATTR_PATTERN = re.compile(r'URI\s*=\s*"([^"]+)"', re.IGNORECASE)
RESOLUTION_PATTERN = re.compile(r"RESOLUTION\s*=\s*(\d+)x(\d+)", re.IGNORECASE)
BANDWIDTH_PATTERN = re.compile(r"(?:AVERAGE-)?BANDWIDTH\s*=\s*(\d+)", re.IGNORECASE)
CODECS_PATTERN = re.compile(r'CODECS\s*=\s*"([^"]+)"', re.IGNORECASE)
TARGETDURATION_PATTERN = re.compile(r"#EXT-X-TARGETDURATION:\s*([\d.]+)", re.IGNORECASE)
EXTINF_PATTERN = re.compile(r"#EXTINF:\s*([\d.]+)", re.IGNORECASE)
MANIFEST_EXTENSIONS = (".m3u8", ".m3u", ".mpd")
SENSITIVE_VALUE_RE = re.compile(
    r"(?i)((?:^|[?&~|;])(?:hmac|signature|sig|hash|token|policy|key|auth|sessionid|session|cs|x-amz-signature|x-amz-security-token)=)([^&~\s\"'<>]+)"
)


# =============================================================================
# time helpers
# =============================================================================
def epoch_seconds(value):
    """Normalise 10s / 13s / 16s integer epochs into a plausible Unix second."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    while number > 10_000_000_000_000:
        number //= 1000
    if number > 10_000_000_000:
        number //= 1000
    if 946684800 <= number <= 4102444800:
        return number
    return None


def iso_seconds(value):
    match = ISO_PATTERN.search(value or "")
    if not match:
        return None
    year, month, day, hour, minute, second, zone = match.groups()
    try:
        stamp = timegm(
            (int(year), int(month), int(day), int(hour), int(minute), int(second), 0, 0, 0)
        )
    except (ValueError, OverflowError):
        return None
    if zone and zone.upper() != "Z":
        sign = 1 if zone[0] == "+" else -1
        digits = zone[1:].replace(":", "")
        try:
            stamp -= sign * (int(digits[:2]) * 3600 + int(digits[2:4]) * 60)
        except (ValueError, IndexError):
            pass
    return stamp if 946684800 <= stamp <= 4102444800 else None


def relative_seconds(value):
    """Parse '3600', '3600s', '2h', '30m', '1d' into seconds (lifetime fields)."""
    match = re.match(r"^(\d{1,8})\s*([smhd]?)$", str(value).strip(), re.IGNORECASE)
    if not match:
        return None
    amount = int(match.group(1))
    unit = (match.group(2) or "s").lower()
    factor = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    total = amount * factor
    return total if 1 <= total <= 86400 * 90 else None


def b64_json(blob):
    """Decode a base64url/base64 segment into JSON if possible."""
    text = str(blob).strip()
    if not BASE64ISH_PATTERN.match(text):
        return None
    padded = text.replace("-", "+").replace("_", "/")
    padded += "=" * (-len(padded) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return None
    for candidate in (raw, unquote(raw.decode("utf-8", "ignore")).encode("utf-8")):
        try:
            loaded = json.loads(candidate.decode("utf-8", "ignore"))
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(loaded, dict):
            return loaded
    return None


def compact_iso_seconds(value):
    """Parse AWS/Google style timestamps: 20240101T000000Z."""
    match = re.match(r"^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z?$", str(value).strip())
    if not match:
        return None
    try:
        stamp = timegm(tuple(int(part) for part in match.groups()) + (0, 0, 0))
    except (ValueError, OverflowError):
        return None
    return stamp if 946684800 <= stamp <= 4102444800 else None


def classify_key(key):
    cleaned = key.strip().lower().lstrip("._-")
    if cleaned in EXPIRY_KEYS:
        return "expires"
    if cleaned in START_KEYS:
        return "generated"
    if cleaned in {"x-amz-date", "x-goog-date", "x-amz-created"}:
        return "generated"
    if cleaned in TTL_KEYS or cleaned in {"x-amz-expires", "x-goog-expires"}:
        return "lifetime"
    if cleaned in SIGNATURE_KEYS or cleaned.startswith("x-amz-"):
        return "signature"
    return None


# =============================================================================
# token extraction
# =============================================================================
def add_token(store, seen, kind, field, value, origin, note=None, human=None):
    signature = (kind, field.lower(), str(value))
    if signature in seen:
        return
    seen.add(signature)
    store.append({
        "kind": kind,
        "field": field,
        "value": value,
        "epoch": human,
        "origin": origin,
        "note": note,
    })


def scan_jwt(text, store, seen, origin):
    for match in JWT_PATTERN.finditer(text):
        payload = b64_json(match.group(0).split(".")[1])
        if not payload:
            continue
        for claim, kind in (
            ("exp", "expires"), ("iat", "generated"), ("nbf", "generated"),
            ("start", "generated"), ("start_time", "generated"),
            ("expiry", "expires"), ("expires", "expires"),
        ):
            epoch = epoch_seconds(payload.get(claim))
            if epoch:
                add_token(
                    store, seen, kind, f"jwt.{claim}", epoch, origin,
                    note="Decoded from a JWT payload", human=epoch,
                )


def iter_pairs(text):
    """Yield key/value pairs from free text, allowing nested tokens.

    `hdnts=exp=1893456000~acl=/*~hmac=abc` yields ('hdnts','exp'),
    ('exp','1893456000'), ('acl','/*') and ('hmac','abc') so the timestamp is
    never hidden behind a CDN token wrapper.
    """
    for marker in re.finditer("=", text):
        index = marker.start()
        start = index
        while start > 0 and (text[start - 1].isalnum() or text[start - 1] in "_-."):
            start -= 1
        key = text[start:index]
        if not KEY_PATTERN.match(key):
            continue
        end = index + 1
        while end < len(text) and text[end] not in VALUE_STOP:
            end += 1
        value = text[index + 1:end]
        if value:
            yield key, value


def scan_text_tokens(raw, store, seen, origin):
    """Pull every timestamp-ish key=value pair out of arbitrary text.

    This is what makes wrapper links work: the manifest body itself (key URIs,
    segment URIs, hdnts/hdnea tokens) is scanned, not just the pasted URL.
    """
    if not raw:
        return
    cleaned = unescape(raw).replace("\\u0026", "&").replace("\\u003d", "=")
    cleaned = unquote(cleaned)
    scan_jwt(cleaned, store, seen, origin)
    for field, value in iter_pairs(cleaned):
        value = value.strip("'\".,;:")
        if not value or value.lower() in {"true", "false", "null", "none"}:
            continue
        lowered = field.lower()
        if lowered in {"x-amz-date", "x-goog-date", "x-amz-created"}:
            stamp = compact_iso_seconds(value) or iso_seconds(value)
            if stamp:
                add_token(store, seen, "generated", field, stamp, origin,
                          note="Signed request start time", human=stamp)
            continue
        if lowered in {"x-amz-expires", "x-goog-expires"}:
            seconds = relative_seconds(value)
            if seconds:
                add_token(store, seen, "lifetime", field, seconds, origin,
                          note=f"Signed lifetime: {seconds}s")
            continue
        key_kind = classify_key(field)
        if key_kind == "lifetime":
            seconds = relative_seconds(value)
            if seconds:
                add_token(store, seen, "lifetime", field, seconds, origin,
                          note=f"{field} = {value} (lifetime in seconds)")
            continue
        if key_kind not in {"expires", "generated"}:
            continue
        stamp = epoch_seconds(value) or iso_seconds(value)
        if stamp is None:
            continue
        add_token(store, seen, key_kind, field, stamp, origin, human=stamp)
    # explicit ISO-8601 values such as expires=2024-05-01T10:00:00Z
    for field, rest in re.findall(
        r"([A-Za-z][A-Za-z0-9_.\-]{0,34})\s*=\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^&~\s\"']*)",
        cleaned,
    ):
        key_kind = classify_key(field)
        stamp = iso_seconds(rest)
        if key_kind in {"expires", "generated"} and stamp:
            add_token(store, seen, key_kind, field, stamp, origin, human=stamp)
    # bare epoch values such as /exp/1712345678/ or exp:1712345678
    for bare in re.findall(r"(?:exp|expires)[/:](\d{10,13})", cleaned, re.IGNORECASE):
        stamp = epoch_seconds(bare)
        if stamp:
            add_token(store, seen, "expires", "exp", stamp, origin, human=stamp)


def scan_headers(headers, store, seen, origin, fetched_at):
    if not headers:
        return
    amz_date = headers.get("x-amz-date") or headers.get("date")
    amz_expires = headers.get("x-amz-expires")
    if amz_expires:
        try:
            start = iso_seconds(amz_date) or fetched_at
            add_token(store, seen, "expires", "x-amz-expires", int(amz_expires),
                      origin, note="Signed lifetime in seconds from X-Amz-Expires",
                      human=start + int(amz_expires))
            add_token(store, seen, "generated", "x-amz-date", int(start), origin,
                      note="Signed request start from X-Amz-Date", human=int(start))
        except ValueError:
            pass
    expires_header = headers.get("expires")
    if expires_header and "x-amz-expires" not in headers:
        stamp = iso_seconds(expires_header)
        if stamp:
            add_token(store, seen, "expires", "http.expires", stamp, origin,
                      note="HTTP Expires response header (cache lifetime, not a token claim)",
                      human=stamp)


def collect_tokens(parts, origin, now):
    """Tag a group of scan sources into one token bucket."""
    store, seen = parts
    expires = [t["value"] for t in store if t["kind"] == "expires"]
    generated = [t["value"] for t in store if t["kind"] == "generated"]
    lifetimes = [t["value"] for t in store if t["kind"] == "lifetime"]
    start = max(generated) if generated else None
    if expires:
        expiry = min(expires)
    elif lifetimes:
        # a lifetime only means something relative to its start time
        expiry = (start if start else now) + min(lifetimes)
    else:
        expiry = None
    if expiry and not start and lifetimes:
        start = expiry - min(lifetimes)
    if expiry and start and expiry <= start:
        start = None
    return start, expiry


# =============================================================================
# URL anatomy
# =============================================================================
def segment_kind(value):
    lowered = value.lower()
    if lowered.split("?")[0].endswith(MANIFEST_EXTENSIONS):
        return "manifest"
    if lowered.endswith((".ts", ".m4s", ".mp4", ".aac", ".key", ".cmfv", ".cmfa")):
        return "media"
    if HEXISH_PATTERN.match(value):
        return "hash"
    if re.fullmatch(r"\d{10,13}", value):
        return "timestamp"
    if re.fullmatch(r"\d+", value):
        return "number"
    if re.search(r"exp=|expires=|st=|hdnts=|hdnea=", lowered):
        return "token"
    return "path"


def query_rows(query):
    rows = []
    for key, value in parse_qsl(query, keep_blank_values=True):
        kind = classify_key(key)
        if kind == "signature":
            rows.append({
                "key": key,
                "value": f"[{len(value)} chars, hidden]",
                "kind": "signature",
                "masked": True,
            })
            continue
        if kind == "lifetime":
            rows.append({
                "key": key,
                "value": value,
                "kind": "lifetime",
                "note": f"{relative_seconds(value) or '-'}s lifetime",
            })
            continue
        if kind in {"expires", "generated"}:
            rows.append({
                "key": key,
                "value": value,
                "kind": kind,
                "epoch": epoch_seconds(value) or iso_seconds(value),
            })
            continue
        # nested token blobs: hdnts=exp=...~acl=...~hmac=...
        if "=" in value or "~" in value:
            for inner_key, inner_value in re.findall(
                r"([A-Za-z][A-Za-z0-9_.\-]{0,30})=([^~&]+)", value
            ):
                inner_kind = classify_key(inner_key) or "other"
                masked = inner_kind == "signature" or len(inner_value) > 48
                rows.append({
                    "key": f"{key}.{inner_key}",
                    "value": f"[{len(inner_value)} chars, hidden]" if masked
                             else inner_value,
                    "kind": inner_kind,
                    "masked": masked,
                    "epoch": (epoch_seconds(inner_value) or iso_seconds(inner_value))
                             if inner_kind in {"expires", "generated"} else None,
                })
            continue
        rows.append({
            "key": key,
            "value": value if len(value) <= 120 else value[:117] + "...",
            "kind": "other",
        })
    return rows


def url_anatomy(url):
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.scheme or not parts.hostname:
        return None
    path = parts.path or "/"
    segments = []
    for item in [chunk for chunk in path.split("/") if chunk]:
        segments.append({"value": item, "kind": segment_kind(item)})
    filename = segments[-1]["value"] if segments else ""
    extension = ""
    if "." in filename:
        extension = filename.rsplit(".", 1)[1].lower()
    return {
        "raw": url,
        "scheme": parts.scheme,
        "host": parts.hostname,
        "port": parts.port,
        "path": unquote(path),
        "filename": unquote(filename),
        "extension": extension,
        "segments": segments,
        "queryCount": len(parse_qsl(parts.query, keep_blank_values=True)) if parts.query else 0,
        "query": query_rows(parts.query),
        "hasQuery": bool(parts.query),
        "hasFragment": bool(parts.fragment),
        "signed": bool(
            re.search(r"(?i)[?&~](exp|expires|st|hdnts|hdnea|token|signature|sig)=", url)
        ),
    }


def mask_source_line(line):
    return SENSITIVE_VALUE_RE.sub(
        lambda match: f"{match.group(1)}[{len(match.group(2))} chars hidden]", line
    )


def masked_url(url):
    """Readable URL with signature values masked but structure intact."""
    try:
        parts = urlsplit(url)
        if not parts.hostname:
            return SENSITIVE_VALUE_RE.sub(r"\1[redacted]", url)
        path = unquote(parts.path or "/")
        if len(path) > 150:
            path = path[:147] + "..."
        query = ""
        if parts.query:
            pairs = parse_qsl(parts.query, keep_blank_values=True)
            shown = []
            for key, value in pairs:
                if classify_key(key) == "signature":
                    shown.append(f"{key}=[hidden]")
                else:
                    cleaned = SENSITIVE_VALUE_RE.sub(r"\1[hidden]", value)
                    if len(cleaned) > 90:
                        cleaned = cleaned[:87] + "..."
                    shown.append(f"{key}={cleaned}")
            query = "?" + "&".join(shown)
        return f"{parts.hostname}{path}{query}"
    except ValueError:
        return SENSITIVE_VALUE_RE.sub(r"\1[redacted]", url)


# =============================================================================
# network
# =============================================================================
def public_http_url(value):
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        if parsed.username or parsed.password:
            return False
        if parsed.port and parsed.port not in {80, 443, 8080, 8443}:
            return False
        host = parsed.hostname.rstrip(".").lower()
        if host in {"localhost", "localhost.localdomain"} or host.endswith(
            (".localhost", ".local", ".internal", ".home.arpa")
        ):
            return False
        addresses = socket.getaddrinfo(
            host, parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
        if not addresses:
            return False
        for item in addresses:
            address = ipaddress.ip_address(item[4][0])
            if (
                address.is_private or address.is_loopback or address.is_link_local
                or address.is_reserved or address.is_multicast or not address.is_global
            ):
                return False
        return True
    except (ValueError, OSError, socket.gaierror):
        return False


def fetch_manifest(url):
    """Fetch a manifest with redirect + SSRF re-validation on every hop."""
    result = {
        "url": url, "finalUrl": url, "status": None, "bytes": 0,
        "contentType": "", "headers": {}, "body": "", "error": None,
        "redirects": 0, "fetchedAt": int(time.time()),
    }
    current = url
    for hop in range(REDIRECT_LIMIT + 1):
        if not public_http_url(current):
            result["error"] = "Blocked: not a public HTTP(S) address."
            break
        try:
            response = requests.get(
                current,
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                stream=True,
                allow_redirects=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; TokenInspector/3.0)",
                    "Accept": "application/vnd.apple.mpegurl, application/dash+xml, "
                              "application/json, text/plain, */*",
                },
            )
        except requests.RequestException:
            result["error"] = "Request failed (timeout or connection refused)."
            break
        result["status"] = response.status_code
        result["headers"] = {k.lower(): v for k, v in response.headers.items()}
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                result["error"] = "Redirect without a Location header."
                break
            if hop >= REDIRECT_LIMIT:
                result["error"] = "Stopped after 3 redirects."
                break
            current = urljoin(current, location)
            result["redirects"] += 1
            continue
        if response.status_code >= 400:
            result["error"] = f"Remote server returned HTTP {response.status_code}."
            response.close()
            break
        chunks, size = [], 0
        for chunk in response.iter_content(chunk_size=16384):
            if not chunk:
                continue
            size += len(chunk)
            if size > MAX_FETCH_BYTES:
                result["error"] = "Response exceeded the 240 KB inspection limit."
                break
            chunks.append(chunk)
        response.close()
        result["body"] = b"".join(chunks).decode("utf-8", errors="replace")
        result["bytes"] = len(result["body"].encode("utf-8"))
        result["contentType"] = result["headers"].get("content-type", "unknown").split(";")[0]
        break
    result["finalUrl"] = current
    result["url"] = masked_url(current)
    return result


# =============================================================================
# manifest parsing
# =============================================================================
def parse_manifest(body, base_url):
    text = unescape(body or "")
    info = {
        "type": None,
        "targetDuration": None,
        "segmentCount": 0,
        "duration": None,
        "encrypted": False,
        "variants": [],
        "children": [],
        "keyUris": [],
        "segmentUris": [],
    }
    if not text.strip():
        return info
    upper = text.upper()
    if "<MPD" in upper:
        info["type"] = "dash"
        for match in re.finditer(r'<BaseURL[^>]*>([^<]+)</BaseURL>', text, re.IGNORECASE):
            info["children"].append(match.group(1).strip())
        info["segmentCount"] = len(re.findall(r"<S\b", text))
        return info
    if "#EXTM3U" not in upper:
        return info
    pending = None
    durations = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.upper().startswith("#EXT-X-STREAM-INF"):
            resolution = RESOLUTION_PATTERN.search(stripped)
            bandwidth = BANDWIDTH_PATTERN.search(stripped)
            codecs = CODECS_PATTERN.search(stripped)
            pending = {
                "resolution": f"{resolution.group(1)}x{resolution.group(2)}" if resolution else None,
                "height": int(resolution.group(2)) if resolution else None,
                "bandwidth": int(bandwidth.group(1)) if bandwidth else None,
                "codecs": codecs.group(1) if codecs else None,
            }
            continue
        if stripped.upper().startswith("#EXT-X-TARGETDURATION:"):
            match = TARGETDURATION_PATTERN.search(stripped)
            if match:
                info["targetDuration"] = float(match.group(1))
            continue
        if stripped.upper().startswith("#EXT-X-KEY:"):
            if "METHOD=NONE" not in stripped.upper():
                info["encrypted"] = True
            for uri in URI_ATTR_PATTERN.findall(stripped):
                info["keyUris"].append(urljoin(base_url, uri) if base_url else uri)
            continue
        if stripped.upper().startswith("#EXT-X-MAP:"):
            for uri in URI_ATTR_PATTERN.findall(stripped):
                info["segmentUris"].append(urljoin(base_url, uri) if base_url else uri)
            continue
        if stripped.startswith("#EXTINF:"):
            match = EXTINF_PATTERN.search(stripped)
            if match:
                durations.append(float(match.group(1)))
            continue
        if stripped.startswith("#"):
            continue
        absolute = urljoin(base_url, stripped) if base_url else stripped
        if pending is not None:
            pending["uri"] = absolute
            pending["raw"] = stripped
            info["variants"].append(pending)
            pending = None
            info["children"].append(absolute)
        elif absolute.split("?")[0].lower().endswith(MANIFEST_EXTENSIONS):
            info["children"].append(absolute)
        else:
            info["segmentUris"].append(absolute)
    if info["variants"]:
        info["type"] = "master"
    elif durations or info["segmentUris"]:
        info["type"] = "media"
        info["segmentCount"] = len(durations) or len(info["segmentUris"])
        info["duration"] = round(sum(durations), 1) if durations else None
    return info


# =============================================================================
# analysis pipeline
# =============================================================================
def analyse_url(url, allow_remote, budget, now):
    token_parts = ([], set())
    tokens, seen = token_parts
    result = {
        "kind": "url",
        "input": url,
        "displayInput": masked_url(url),
        "url": url_anatomy(url),
        "generated": None,
        "expires": None,
        "tokens": tokens,
        "requests": [],
        "manifest": None,
        "variants": [],
        "excerpts": [],
        "notes": [],
    }

    scan_text_tokens(url, tokens, seen, "URL")
    if not allow_remote:
        start, expiry = collect_tokens(token_parts, "URL", now)
        result["generated"], result["expires"] = start, expiry
        result["notes"].append(
            "Remote inspection is off, so only the pasted link itself was parsed."
        )
        return result

    queue = [(url, 0, "Entry manifest")]
    visited = set()
    manifest_summary = None
    while queue and budget[0] > 0 and len(visited) < MAX_FETCHES:
        target, depth, label = queue.pop(0)
        if target in visited:
            continue
        visited.add(target)
        budget[0] -= 1
        fetched = fetch_manifest(target)
        result["requests"].append({
            "url": fetched["url"],
            "status": fetched["status"],
            "bytes": fetched["bytes"],
            "contentType": fetched["contentType"],
            "depth": depth,
            "redirects": fetched["redirects"],
            "error": fetched["error"],
            "label": label,
        })
        scan_text_tokens(fetched["finalUrl"], tokens, seen, f"Fetched URL (depth {depth})")
        scan_headers(fetched["headers"], tokens, seen,
                     f"Response headers (depth {depth})", fetched["fetchedAt"])
        if not fetched["body"]:
            if fetched["error"]:
                result["notes"].append(f"Depth {depth}: {fetched['error']}")
            continue
        # Body scan is the important one for wrapper links with no query token.
        scan_text_tokens(fetched["body"], tokens, seen,
                         f"Manifest body (depth {depth})")
        if len(result["excerpts"]) < 3:
            result["excerpts"].append({
                "url": fetched["url"],
                "text": mask_source_line(fetched["body"][:4000]),
            })
        info = parse_manifest(fetched["body"], fetched["finalUrl"])
        if info["type"] and (manifest_summary is None or depth == 0):
            manifest_summary = {
                "type": info["type"],
                "targetDuration": info["targetDuration"],
                "segmentCount": info["segmentCount"],
                "duration": info["duration"],
                "encrypted": info["encrypted"],
                "depth": depth,
                "url": fetched["url"],
            }
        elif manifest_summary and info["type"] == "media":
            # enrich a master summary with what the media playlist knows
            for field in ("targetDuration", "segmentCount", "duration"):
                if not manifest_summary.get(field) and info.get(field):
                    manifest_summary[field] = info[field]
            if info["encrypted"]:
                manifest_summary["encrypted"] = True
        if info["encrypted"] and not any("encrypted" in note for note in result["notes"]):
            result["notes"].append(
                "This manifest is encrypted: an EXT-X-KEY / DRM key URI was found "
                "and its signature is hidden in this report."
            )
        # Pull token-bearing URIs (segments / keys) as variants.
        for uri in info["keyUris"] + info["segmentUris"]:
            variant_tokens = ([], set())
            scan_text_tokens(uri, variant_tokens[0], variant_tokens[1], "Segment URI")
            has_timestamp = any(t["kind"] in {"expires", "generated", "lifetime"}
                                for t in variant_tokens[0])
            if has_timestamp:
                start, expiry = collect_tokens(variant_tokens, "Segment URI", now)
                result["variants"].append({
                    "label": "Key" if uri in info["keyUris"] else "Segment",
                    "url": masked_url(uri),
                    "generated": start,
                    "expires": expiry,
                    "path": urlsplit(uri).path.rsplit("/", 1)[-1][:48],
                    "depth": depth + 1,
                })
        for variant in info["variants"]:
            variant_tokens = ([], set())
            scan_text_tokens(variant["uri"], variant_tokens[0], variant_tokens[1], "Variant URI")
            start, expiry = collect_tokens(variant_tokens, "Variant URI", now)
            result["variants"].append({
                "label": f"{variant['height']}p" if variant.get("height")
                         else (f"{int(variant['bandwidth']) // 1000} kbps"
                               if variant.get("bandwidth") else "Variant"),
                "url": masked_url(variant["uri"]),
                "generated": start,
                "expires": expiry,
                "resolution": variant.get("resolution"),
                "bandwidth": variant.get("bandwidth"),
                "codecs": variant.get("codecs"),
                "depth": depth + 1,
            })
        if depth < MAX_DEPTH:
            for child in info["children"]:
                if child not in visited and all(child != item[0] for item in queue):
                    queue.append((child, depth + 1,
                                  f"{info['type'] or 'manifest'} child (depth {depth + 1})"))

    if manifest_summary:
        result["manifest"] = manifest_summary
    # one row per unique URI, keeping the richest metadata
    unique_variants = {}
    for variant in result["variants"]:
        key = variant["url"]
        if key not in unique_variants or not unique_variants[key].get("resolution"):
            unique_variants[key] = variant
    result["variants"] = list(unique_variants.values())[:40]
    if not result["variants"]:
        result["notes"].append(
            "No timestamped variant or segment URI was found in the fetched manifests."
        )
    if queue and (budget[0] <= 0 or len(visited) >= MAX_FETCHES):
        result["notes"].append(
            f"Stopped after {len(visited)} manifest request(s); deeper levels were not fetched."
        )
    start, expiry = collect_tokens(token_parts, "all", now)
    if start is None or (expiry is not None and start < expiry):
        variant_starts = [v["generated"] for v in result["variants"] if v["generated"]]
        if start is None and variant_starts:
            start = min(variant_starts)
    if expiry is None:
        variant_expiries = [v["expires"] for v in result["variants"] if v["expires"]]
        if variant_expiries:
            expiry = min(variant_expiries)
    result["generated"], result["expires"] = start, expiry
    return result


def analyse_text_input(raw, allow_remote, budget, now):  # noqa: ARG001 - shared signature
    cleaned = unescape(raw).replace("\\u0026", "&").replace("\\/", "/")
    manifest_like = any(tag in cleaned.upper() for tag in ("#EXTM3U", "<MPD", "#EXT-X-"))
    if manifest_like:
        tokens, seen = [], set()
        scan_text_tokens(cleaned, tokens, seen, "Pasted manifest")
        info = parse_manifest(cleaned, None)
        start, expiry = collect_tokens((tokens, seen), "Pasted manifest", now)
        variants = []
        for variant in info["variants"]:
            variant_tokens = ([], set())
            scan_text_tokens(variant["uri"], variant_tokens[0], variant_tokens[1], "Variant URI")
            v_start, v_expiry = collect_tokens(variant_tokens, "Variant URI", now)
            variants.append({
                "label": f"{variant['height']}p" if variant.get("height") else "Variant",
                "url": masked_url(variant["uri"]),
                "generated": v_start,
                "expires": v_expiry,
                "resolution": variant.get("resolution"),
                "bandwidth": variant.get("bandwidth"),
                "codecs": variant.get("codecs"),
                "depth": 1,
            })
        return [{
            "kind": "manifest",
            "input": "Pasted manifest source",
            "displayInput": "Pasted manifest source",
            "url": None,
            "generated": start,
            "expires": expiry,
            "tokens": tokens,
            "requests": [],
            "manifest": {
                "type": info["type"], "targetDuration": info["targetDuration"],
                "segmentCount": info["segmentCount"], "duration": info["duration"],
                "encrypted": info["encrypted"], "depth": 0, "url": None,
            },
            "variants": variants,
            "excerpts": [{"url": "Pasted source", "text": mask_source_line(cleaned[:4000])}],
            "notes": [],
        }]
    tokens, seen = [], set()
    scan_text_tokens(cleaned, tokens, seen, "Pasted text")
    start, expiry = collect_tokens((tokens, seen), "Pasted text", now)
    return [{
        "kind": "text",
        "input": "Pasted text",
        "displayInput": "Pasted text / cookie string",
        "url": None,
        "generated": start,
        "expires": expiry,
        "tokens": tokens,
        "requests": [],
        "manifest": None,
        "variants": [],
        "excerpts": [],
        "notes": [] if tokens else [
            "No numeric expiry, start time or lifetime field was found in this text."
        ],
    }]


def analyse(raw, allow_remote):
    now = int(time.time())
    budget = [MAX_FETCHES]
    cleaned = unescape(raw).replace("\\u0026", "&").replace("\\/", "/")
    urls = []
    seen_urls = set()
    for match in URL_PATTERN.findall(cleaned):
        candidate = match.rstrip(".,;!?)]}>\"'`")
        if candidate and candidate not in seen_urls:
            seen_urls.add(candidate)
            urls.append(candidate)
    if not urls:
        return analyse_text_input(cleaned, allow_remote, budget, now)
    results = []
    for url in urls[:MAX_RESULTS]:
        results.append(analyse_url(url, allow_remote, budget, now))
    if len(urls) > MAX_RESULTS:
        results.append({
            "kind": "note",
            "displayInput": f"{len(urls) - MAX_RESULTS} more link(s) skipped",
            "notes": [f"Only the first {MAX_RESULTS} links are inspected per run."],
            "tokens": [], "requests": [], "variants": [], "url": None,
            "generated": None, "expires": None, "manifest": None,
            "excerpts": [],
        })
    return results


# =============================================================================
# auth + routes
# =============================================================================
def is_authenticated(touch=True):
    """Valid for 30 minutes, renewed while the console is actually used."""
    auth_at = session.get("auth_at")
    if not auth_at or time.time() - auth_at >= SESSION_SECONDS:
        session.pop("auth_at", None)
        return False
    if touch and time.time() - auth_at > SESSION_TOUCH_INTERVAL:
        session["auth_at"] = time.time()
        session.modified = True
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
    remaining = max(
        0, int(SESSION_SECONDS - (time.time() - session.get("auth_at", 0)))
    ) if authenticated else 0
    return jsonify({
        "authenticated": authenticated,
        "remaining": remaining,
        "sessionSeconds": SESSION_SECONDS,
        "configured": bool(MASTER_PASSWORD),
    })


@app.post("/api/login")
def login():
    if not MASTER_PASSWORD:
        return jsonify({
            "error": "Access is not configured. Set MASTER_PASSWORD in the server environment."
        }), 503
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
        return jsonify({"error": "Paste a link, cookie string or manifest source first."}), 400
    if len(text) > MAX_INPUT_CHARS:
        return jsonify({"error": "Input is too large. Keep it under 300 KB."}), 413
    results = analyse(text, bool(payload.get("inspectRemote", True)))
    return jsonify({
        "results": results,
        "serverTime": int(time.time()),
        "limits": {
            "maxFetches": MAX_FETCHES,
            "maxDepth": MAX_DEPTH,
            "maxResults": MAX_RESULTS,
        },
    })


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    )
    if request.path == "/sw.js":
        response.headers["Service-Worker-Allowed"] = "/"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    if request.is_secure:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
