"""
slprov2 Auth Site — hardened license + admin web panel (stdlib only).
Deploy from GitHub to Render / Railway / Fly / VPS.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DB_PATH = Path(os.environ.get("SLPROV2_DB", str(ROOT / "slprov2_auth.db")))
SECRET_PATH = ROOT / "secret.key"
CONFIG_PATH = ROOT / "config.json"

DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": int(os.environ.get("PORT", "8787")),
    "token_ttl_seconds": 3600,
    "admin_ttl_seconds": 28800,
    "max_fails_per_ip": 8,
    "max_fails_per_user": 6,
    "fail_window_seconds": 600,
    "lockout_seconds": 900,
    "challenge_ttl_seconds": 90,
    "request_skew_seconds": 45,
    "product": "slprov2",
    "pbkdf2_iterations": 310000,
    "require_request_sign": False,
    "site_name": "slprov2 Auth",
}


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
    # env overrides
    if os.environ.get("PORT"):
        cfg["port"] = int(os.environ["PORT"])
    if os.environ.get("SLPROV2_REQUIRE_SIGN") == "1":
        cfg["require_request_sign"] = True
    if os.environ.get("SLPROV2_APP_SECRET"):
        cfg["app_secret"] = os.environ["SLPROV2_APP_SECRET"]
    return cfg


def get_master_secret() -> bytes:
    env = os.environ.get("SLPROV2_MASTER_SECRET")
    if env:
        return hashlib.sha256(env.encode()).digest()
    if SECRET_PATH.exists():
        return SECRET_PATH.read_bytes().strip()
    secret = secrets.token_bytes(48)
    SECRET_PATH.write_bytes(secret)
    return secret


CFG = load_config()
SECRET = get_master_secret()
APP_SECRET = (
    os.environ.get("SLPROV2_APP_SECRET")
    or CFG.get("app_secret")
    or base64.urlsafe_b64encode(hmac.new(SECRET, b"app", hashlib.sha256).digest()).decode()
)

_lock = threading.RLock()
_fails_ip: dict[str, list[float]] = {}
_fails_user: dict[str, list[float]] = {}
_lockout_until: dict[str, float] = {}
_challenges: dict[str, dict] = {}
_used_nonces: dict[str, float] = {}
_admin_sessions: dict[str, dict] = {}
_csrf: dict[str, str] = {}


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                license_key TEXT NOT NULL UNIQUE,
                hwid TEXT,
                expires_at INTEGER,
                banned INTEGER NOT NULL DEFAULT 0,
                note TEXT DEFAULT '',
                created_at INTEGER NOT NULL,
                last_login_at INTEGER,
                fail_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_jti TEXT NOT NULL UNIQUE,
                hwid TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                last_seen INTEGER
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                ip TEXT,
                username TEXT,
                action TEXT,
                ok INTEGER,
                detail TEXT
            );
            """
        )


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, int(CFG["pbkdf2_iterations"])
    )
    return "pbkdf2$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_b64, hash_b64 = stored.split("$", 2)
        if algo != "pbkdf2":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(CFG["pbkdf2_iterations"])
        )
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def make_token(user_id: int, username: str, hwid: str, jti: str) -> str:
    now = int(time.time())
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64url(
        json.dumps(
            {
                "sub": username,
                "uid": user_id,
                "hwid": hwid,
                "jti": jti,
                "iat": now,
                "exp": now + int(CFG["token_ttl_seconds"]),
                "prd": CFG["product"],
            },
            separators=(",", ":"),
        ).encode()
    )
    sig = b64url(hmac.new(SECRET, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def verify_token(token: str) -> dict:
    header_b64, payload_b64, sig_b64 = token.split(".")
    expect = b64url(hmac.new(SECRET, f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expect, sig_b64):
        raise ValueError("bad signature")
    payload = json.loads(b64url_decode(payload_b64))
    if int(payload.get("exp", 0)) < int(time.time()):
        raise ValueError("expired")
    if payload.get("prd") != CFG["product"]:
        raise ValueError("wrong product")
    return payload


def audit(ip: str, username: str, action: str, ok: bool, detail: str = "") -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO audit(ts, ip, username, action, ok, detail) VALUES (?,?,?,?,?,?)",
            (int(time.time()), ip, username, action, 1 if ok else 0, detail[:400]),
        )


def gc_maps() -> None:
    now = time.time()
    with _lock:
        for d in (_challenges,):
            dead = [k for k, v in _challenges.items() if v["exp"] < now]
            for k in dead:
                _challenges.pop(k, None)
        dead_n = [k for k, exp in _used_nonces.items() if exp < now]
        for k in dead_n:
            _used_nonces.pop(k, None)
        dead_a = [k for k, v in _admin_sessions.items() if v["exp"] < now]
        for k in dead_a:
            _admin_sessions.pop(k, None)
            _csrf.pop(k, None)


def is_locked(key: str) -> bool:
    with _lock:
        until = _lockout_until.get(key, 0)
        return until > time.time()


def set_lock(key: str) -> None:
    with _lock:
        _lockout_until[key] = time.time() + float(CFG["lockout_seconds"])


def record_fail(ip: str, username: str = "") -> None:
    now = time.time()
    window = float(CFG["fail_window_seconds"])
    with _lock:
        ipb = [t for t in _fails_ip.get(ip, []) if now - t < window]
        ipb.append(now)
        _fails_ip[ip] = ipb
        if len(ipb) >= int(CFG["max_fails_per_ip"]):
            set_lock("ip:" + ip)
        if username:
            ub = [t for t in _fails_user.get(username.lower(), []) if now - t < window]
            ub.append(now)
            _fails_user[username.lower()] = ub
            if len(ub) >= int(CFG["max_fails_per_user"]):
                set_lock("user:" + username.lower())


def create_challenge(ip: str) -> dict:
    gc_maps()
    nonce = secrets.token_urlsafe(24)
    exp = time.time() + float(CFG["challenge_ttl_seconds"])
    with _lock:
        _challenges[nonce] = {"exp": exp, "ip": ip, "used": False}
    return {
        "nonce": nonce,
        "expires_in": int(CFG["challenge_ttl_seconds"]),
        "server_time": int(time.time()),
        "sign_required": bool(CFG.get("require_request_sign")),
    }


def consume_challenge(nonce: str, ip: str) -> bool:
    with _lock:
        ch = _challenges.get(nonce)
        if not ch or ch["used"] or ch["exp"] < time.time():
            return False
        # soft IP bind (proxies may differ — allow if same /24 not enforced; just mark used)
        ch["used"] = True
        _used_nonces[nonce] = ch["exp"]
        _challenges.pop(nonce, None)
        return True


def verify_request_sign(handler: BaseHTTPRequestHandler, raw_body: bytes) -> bool:
    if not CFG.get("require_request_sign"):
        return True
    ts = handler.headers.get("X-SLPro-Timestamp", "")
    sig = handler.headers.get("X-SLPro-Sign", "")
    if not ts or not sig:
        return False
    try:
        tsi = int(ts)
    except ValueError:
        return False
    if abs(int(time.time()) - tsi) > int(CFG["request_skew_seconds"]):
        return False
    expect = hmac.new(
        APP_SECRET.encode() if isinstance(APP_SECRET, str) else APP_SECRET,
        f"{ts}.".encode() + raw_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expect, sig.lower())


def ensure_bootstrap_admin() -> None:
    user = os.environ.get("SLPROV2_ADMIN_USER", "admin")
    password = os.environ.get("SLPROV2_ADMIN_PASSWORD", "")
    with db() as conn:
        row = conn.execute("SELECT id FROM admins LIMIT 1").fetchone()
        if row:
            return
        if not password:
            password = secrets.token_urlsafe(12)
            print(f"[BOOTSTRAP] admin created: user={user} pass={password}")
            print("[BOOTSTRAP] set SLPROV2_ADMIN_PASSWORD env to override next deploys")
        conn.execute(
            "INSERT INTO admins(username, password_hash, created_at) VALUES (?,?,?)",
            (user, hash_password(password), int(time.time())),
        )


def mime(path: Path) -> str:
    return {
        ".html": "text/html; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".js": "application/javascript; charset=utf-8",
        ".svg": "image/svg+xml",
        ".png": "image/png",
        ".ico": "image/x-icon",
        ".json": "application/json",
    }.get(path.suffix.lower(), "application/octet-stream")


def send_json(handler: BaseHTTPRequestHandler, code: int, obj: Any, extra_headers: Optional[dict] = None) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    if extra_headers:
        for k, v in extra_headers.items():
            handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(body)


def send_bytes(handler: BaseHTTPRequestHandler, code: int, data: bytes, content_type: str, extra: Optional[dict] = None) -> None:
    handler.send_response(code)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
    )
    if extra:
        for k, v in extra.items():
            handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(data)


def read_body(handler: BaseHTTPRequestHandler) -> bytes:
    length = int(handler.headers.get("Content-Length", "0") or 0)
    if length < 0 or length > 64_000:
        raise ValueError("body too large")
    return handler.rfile.read(length) if length else b""


def get_cookie(handler: BaseHTTPRequestHandler, name: str) -> str:
    raw = handler.headers.get("Cookie", "")
    c = SimpleCookie()
    try:
        c.load(raw)
    except Exception:
        return ""
    if name in c:
        return c[name].value
    return ""


def admin_from_request(handler: BaseHTTPRequestHandler) -> Optional[dict]:
    sid = get_cookie(handler, "slpro_admin")
    if not sid:
        auth = handler.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            sid = auth[7:].strip()
    with _lock:
        sess = _admin_sessions.get(sid)
        if not sess or sess["exp"] < time.time():
            return None
        return {"sid": sid, **sess}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[auth] {self.address_string()} {fmt % args}")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "*"))
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-SLPro-Timestamp, X-SLPro-Sign, X-CSRF")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            send_json(self, 200, {"ok": True, "product": CFG["product"], "ts": int(time.time())})
            return
        if path == "/v1/challenge":
            if is_locked("ip:" + self.client_address[0]):
                send_json(self, 429, {"detail": "temporarily locked"})
                return
            send_json(self, 200, create_challenge(self.client_address[0]))
            return
        if path.startswith("/api/admin/"):
            self._admin_api_get(path)
            return
        self._static(path)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        ip = self.client_address[0]
        try:
            raw = read_body(self)
        except Exception:
            send_json(self, 400, {"detail": "bad request"})
            return
        if not verify_request_sign(self, raw):
            send_json(self, 401, {"detail": "invalid signature"})
            return
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            send_json(self, 400, {"detail": "invalid json"})
            return

        if path == "/v1/login":
            self._login(ip, body)
        elif path == "/v1/heartbeat":
            self._heartbeat(ip, body)
        elif path == "/v1/logout":
            self._logout(ip, body)
        elif path.startswith("/api/admin/"):
            self._admin_api_post(path, ip, body)
        else:
            send_json(self, 404, {"detail": "not found"})

    def _static(self, path: str) -> None:
        if path in ("/", ""):
            path = "/index.html"
        # block path traversal
        rel = path.lstrip("/").replace("\\", "/")
        if ".." in rel or rel.startswith("/"):
            send_json(self, 404, {"detail": "not found"})
            return
        file_path = (STATIC / rel).resolve()
        if not str(file_path).startswith(str(STATIC.resolve())) or not file_path.is_file():
            send_json(self, 404, {"detail": "not found"})
            return
        data = file_path.read_bytes()
        send_bytes(self, 200, data, mime(file_path))

    def _login(self, ip: str, body: dict) -> None:
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))
        hwid = str(body.get("hwid", "")).strip().lower()
        nonce = str(body.get("nonce", "")).strip()

        # generic fail message — no user enumeration
        fail_msg = "invalid credentials"

        if is_locked("ip:" + ip) or (username and is_locked("user:" + username.lower())):
            audit(ip, username, "login", False, "locked")
            send_json(self, 429, {"detail": "temporarily locked"})
            return

        if len(username) < 2 or len(password) < 4 or len(hwid) < 16 or not nonce:
            record_fail(ip, username)
            audit(ip, username, "login", False, "bad_fields")
            send_json(self, 401, {"detail": fail_msg})
            return

        if not consume_challenge(nonce, ip):
            record_fail(ip, username)
            audit(ip, username, "login", False, "bad_nonce")
            send_json(self, 401, {"detail": fail_msg})
            return

        with db() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
            ).fetchone()

        # always burn similar CPU even if missing user
        dummy = hash_password("timing-padding")
        if not row:
            verify_password(password, dummy)
            record_fail(ip, username)
            audit(ip, username, "login", False, "user_not_found")
            send_json(self, 401, {"detail": fail_msg})
            return

        if row["banned"] or (
            row["expires_at"] is not None and int(row["expires_at"]) < int(time.time())
        ):
            record_fail(ip, username)
            audit(ip, username, "login", False, "banned_or_expired")
            send_json(self, 401, {"detail": fail_msg})
            return

        if not verify_password(password, row["password_hash"]):
            record_fail(ip, username)
            audit(ip, username, "login", False, "bad_password")
            send_json(self, 401, {"detail": fail_msg})
            return

        stored_hwid = (row["hwid"] or "").lower()
        if stored_hwid and stored_hwid != hwid:
            record_fail(ip, username)
            audit(ip, username, "login", False, "hwid_mismatch")
            send_json(self, 403, {"detail": "hwid mismatch"})
            return

        jti = secrets.token_hex(16)
        token = make_token(int(row["id"]), row["username"], hwid, jti)
        now = int(time.time())
        exp = now + int(CFG["token_ttl_seconds"])

        with db() as conn:
            if not stored_hwid:
                conn.execute("UPDATE users SET hwid = ? WHERE id = ?", (hwid, row["id"]))
            conn.execute(
                "UPDATE users SET last_login_at = ?, fail_count = 0 WHERE id = ?",
                (now, row["id"]),
            )
            conn.execute(
                "INSERT INTO sessions(user_id, token_jti, hwid, created_at, expires_at, last_seen) VALUES (?,?,?,?,?,?)",
                (row["id"], jti, hwid, now, exp, now),
            )

        audit(ip, username, "login", True, "ok")
        send_json(
            self,
            200,
            {
                "ok": True,
                "token": token,
                "expires_at": exp,
                "username": row["username"],
                "product": CFG["product"],
                "session_id": jti,
            },
        )

    def _heartbeat(self, ip: str, body: dict) -> None:
        token = str(body.get("token", ""))
        hwid = str(body.get("hwid", "")).strip().lower()
        try:
            claims = verify_token(token)
        except Exception:
            send_json(self, 401, {"detail": "invalid token"})
            return
        if claims.get("hwid") != hwid:
            send_json(self, 403, {"detail": "hwid mismatch"})
            return
        with db() as conn:
            sess = conn.execute(
                "SELECT * FROM sessions WHERE token_jti = ?", (claims["jti"],)
            ).fetchone()
            user = conn.execute("SELECT * FROM users WHERE id = ?", (claims["uid"],)).fetchone()
            if sess and not sess["revoked"]:
                conn.execute(
                    "UPDATE sessions SET last_seen = ? WHERE token_jti = ?",
                    (int(time.time()), claims["jti"]),
                )
        if not sess or sess["revoked"] or not user or user["banned"]:
            send_json(self, 401, {"detail": "session revoked"})
            return
        if user["expires_at"] is not None and int(user["expires_at"]) < int(time.time()):
            send_json(self, 403, {"detail": "license expired"})
            return
        send_json(self, 200, {"ok": True, "server_time": int(time.time())})

    def _logout(self, ip: str, body: dict) -> None:
        token = str(body.get("token", ""))
        try:
            claims = verify_token(token)
            with db() as conn:
                conn.execute(
                    "UPDATE sessions SET revoked = 1 WHERE token_jti = ?", (claims["jti"],)
                )
            audit(ip, claims.get("sub", ""), "logout", True, "ok")
        except Exception:
            pass
        send_json(self, 200, {"ok": True})

    # ---------- Admin API ----------
    def _admin_api_get(self, path: str) -> None:
        adm = admin_from_request(self)
        if path == "/api/admin/me":
            if not adm:
                send_json(self, 401, {"detail": "unauthorized"})
                return
            send_json(self, 200, {"ok": True, "username": adm["username"], "csrf": _csrf.get(adm["sid"], "")})
            return
        if not adm:
            send_json(self, 401, {"detail": "unauthorized"})
            return
        if path == "/api/admin/users":
            with db() as conn:
                rows = conn.execute(
                    "SELECT id, username, license_key, hwid, expires_at, banned, note, created_at, last_login_at FROM users ORDER BY id DESC"
                ).fetchall()
            users = [dict(r) for r in rows]
            send_json(self, 200, {"ok": True, "users": users})
            return
        if path == "/api/admin/audit":
            with db() as conn:
                rows = conn.execute(
                    "SELECT ts, ip, username, action, ok, detail FROM audit ORDER BY id DESC LIMIT 200"
                ).fetchall()
            send_json(self, 200, {"ok": True, "items": [dict(r) for r in rows]})
            return
        if path == "/api/admin/stats":
            with db() as conn:
                total = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
                banned = conn.execute("SELECT COUNT(*) c FROM users WHERE banned=1").fetchone()["c"]
                active = conn.execute(
                    "SELECT COUNT(*) c FROM sessions WHERE revoked=0 AND expires_at > ?",
                    (int(time.time()),),
                ).fetchone()["c"]
            send_json(self, 200, {"ok": True, "users": total, "banned": banned, "sessions": active})
            return
        send_json(self, 404, {"detail": "not found"})

    def _admin_api_post(self, path: str, ip: str, body: dict) -> None:
        if path == "/api/admin/login":
            self._admin_login(ip, body)
            return
        if path == "/api/admin/logout":
            sid = get_cookie(self, "slpro_admin")
            with _lock:
                _admin_sessions.pop(sid, None)
                _csrf.pop(sid, None)
            send_json(
                self,
                200,
                {"ok": True},
                {"Set-Cookie": "slpro_admin=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"},
            )
            return

        adm = admin_from_request(self)
        if not adm:
            send_json(self, 401, {"detail": "unauthorized"})
            return
        csrf = self.headers.get("X-CSRF", "")
        if not csrf or not hmac.compare_digest(csrf, _csrf.get(adm["sid"], "")):
            send_json(self, 403, {"detail": "csrf"})
            return

        if path == "/api/admin/users/create":
            username = str(body.get("username", "")).strip()
            password = str(body.get("password", ""))
            days = int(body.get("days", 30))
            note = str(body.get("note", ""))[:200]
            if len(username) < 2 or len(password) < 6:
                send_json(self, 400, {"detail": "weak credentials"})
                return
            license_key = "SLPRO-" + secrets.token_hex(8).upper()
            expires = None if days <= 0 else int(time.time()) + days * 86400
            try:
                with db() as conn:
                    conn.execute(
                        "INSERT INTO users(username, password_hash, license_key, hwid, expires_at, banned, note, created_at) VALUES (?,?,?,?,?,?,?,?)",
                        (username, hash_password(password), license_key, None, expires, 0, note, int(time.time())),
                    )
            except sqlite3.IntegrityError:
                send_json(self, 409, {"detail": "username exists"})
                return
            audit(ip, adm["username"], "admin_create", True, username)
            send_json(self, 200, {"ok": True, "license_key": license_key, "expires_at": expires})
            return

        if path == "/api/admin/users/ban":
            username = str(body.get("username", "")).strip()
            banned = 1 if body.get("banned", True) else 0
            with db() as conn:
                conn.execute(
                    "UPDATE users SET banned = ? WHERE username = ? COLLATE NOCASE",
                    (banned, username),
                )
                if banned:
                    conn.execute(
                        "UPDATE sessions SET revoked = 1 WHERE user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE)",
                        (username,),
                    )
            audit(ip, adm["username"], "admin_ban", True, f"{username}:{banned}")
            send_json(self, 200, {"ok": True})
            return

        if path == "/api/admin/users/reset-hwid":
            username = str(body.get("username", "")).strip()
            with db() as conn:
                conn.execute(
                    "UPDATE users SET hwid = NULL WHERE username = ? COLLATE NOCASE", (username,)
                )
                conn.execute(
                    "UPDATE sessions SET revoked = 1 WHERE user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE)",
                    (username,),
                )
            audit(ip, adm["username"], "admin_reset_hwid", True, username)
            send_json(self, 200, {"ok": True})
            return

        if path == "/api/admin/users/extend":
            username = str(body.get("username", "")).strip()
            days = int(body.get("days", 30))
            with db() as conn:
                row = conn.execute(
                    "SELECT expires_at FROM users WHERE username = ? COLLATE NOCASE", (username,)
                ).fetchone()
                if not row:
                    send_json(self, 404, {"detail": "not found"})
                    return
                base = int(time.time())
                if row["expires_at"] and int(row["expires_at"]) > base:
                    base = int(row["expires_at"])
                new_exp = base + days * 86400
                conn.execute(
                    "UPDATE users SET expires_at = ? WHERE username = ? COLLATE NOCASE",
                    (new_exp, username),
                )
            audit(ip, adm["username"], "admin_extend", True, f"{username}:{days}")
            send_json(self, 200, {"ok": True, "expires_at": new_exp})
            return

        if path == "/api/admin/users/delete":
            username = str(body.get("username", "")).strip()
            with db() as conn:
                conn.execute(
                    "DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE)",
                    (username,),
                )
                conn.execute("DELETE FROM users WHERE username = ? COLLATE NOCASE", (username,))
            audit(ip, adm["username"], "admin_delete", True, username)
            send_json(self, 200, {"ok": True})
            return

        send_json(self, 404, {"detail": "not found"})

    def _admin_login(self, ip: str, body: dict) -> None:
        if is_locked("ip:" + ip):
            send_json(self, 429, {"detail": "temporarily locked"})
            return
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))
        with db() as conn:
            row = conn.execute(
                "SELECT * FROM admins WHERE username = ? COLLATE NOCASE", (username,)
            ).fetchone()
        dummy = hash_password("timing-padding")
        if not row or not verify_password(password, row["password_hash"] if row else dummy):
            if row:
                verify_password(password, row["password_hash"])
            else:
                verify_password(password, dummy)
            record_fail(ip, "admin:" + username)
            audit(ip, username, "admin_login", False, "fail")
            send_json(self, 401, {"detail": "invalid credentials"})
            return

        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        exp = time.time() + float(CFG["admin_ttl_seconds"])
        with _lock:
            _admin_sessions[sid] = {"username": row["username"], "exp": exp}
            _csrf[sid] = csrf
        secure = " Secure;" if self.headers.get("X-Forwarded-Proto") == "https" else ""
        cookie = f"slpro_admin={sid}; Path=/; Max-Age={int(CFG['admin_ttl_seconds'])}; HttpOnly; SameSite=Strict;{secure}"
        audit(ip, username, "admin_login", True, "ok")
        send_json(self, 200, {"ok": True, "username": row["username"], "csrf": csrf}, {"Set-Cookie": cookie})


def main() -> None:
    STATIC.mkdir(exist_ok=True)
    init_db()
    ensure_bootstrap_admin()
    host = CFG.get("host", "0.0.0.0")
    port = int(CFG.get("port", 8787))
    # persist generated app secret hint for loader signing (optional)
    if not CONFIG_PATH.exists():
        out = dict(DEFAULT_CONFIG)
        out["port"] = port
        out["app_secret"] = APP_SECRET if isinstance(APP_SECRET, str) else base64.urlsafe_b64encode(APP_SECRET).decode()
        CONFIG_PATH.write_text(json.dumps(out, indent=2), encoding="utf-8")
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"[slprov2-auth] site http://{host}:{port}")
    print(f"[slprov2-auth] admin panel → /   | API → /v1/*")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
