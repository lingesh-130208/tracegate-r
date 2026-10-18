"""TraceGate-R API, decision gate, and SQLite audit trail."""
import json
import math
import os
import sqlite3
import hashlib
import hmac
import secrets
import time
from contextlib import contextmanager
from dataclasses import dataclass
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, SecretStr, field_validator
from starlette.middleware.cors import CORSMiddleware
from starlette.staticfiles import StaticFiles

from backend.app.evidence_gate import evaluate_evidence
from backend.app.auth import hash_password, hash_token, new_token, normalize_username, validate_password, verify_password
from backend.app.model_service import (
    ModelsUnavailableError,
    model_info,
    predict_models,
    release_feature_names,
    release_schema_sha256,
)
from backend.app.sqlite_security import prepare_sqlite_path, secure_new_sqlite_sidecars

ROOT = Path(__file__).resolve().parents[2]
FRONTEND_ROOT = ROOT / "frontend"
FRONTEND_DIST = FRONTEND_ROOT / "dist"
FRONTEND_INDEX = FRONTEND_DIST / "index.html"
FRONTEND_ASSETS = FRONTEND_DIST / "assets"
FRONTEND_BUILD_REQUIRED = FRONTEND_ROOT / "build-required.html"
DB_PATH = Path(os.environ.get(
    "TRACEGATE_DB_PATH",
    str(Path.home() / ".tracegate-r" / "audit.sqlite3"),
))
SESSION_COOKIE = "tracegate_session"
SESSION_TTL_SECONDS = max(300, min(86400, int(os.environ.get("TRACEGATE_SESSION_TTL_SECONDS", "28800"))))
COOKIE_SECURE = os.environ.get("TRACEGATE_COOKIE_SECURE", "true").strip().lower() not in {"0", "false", "no"}
COOKIE_SAMESITE = os.environ.get("TRACEGATE_COOKIE_SAMESITE", "strict").strip().lower()
if COOKIE_SAMESITE not in {"strict", "lax", "none"}:
    COOKIE_SAMESITE = "strict"
if COOKIE_SAMESITE == "none" and not COOKIE_SECURE:
    raise RuntimeError("TRACEGATE_COOKIE_SAMESITE=none requires TRACEGATE_COOKIE_SECURE=true")
ALLOWED_ORIGINS = tuple(
    origin.strip().rstrip("/") for origin in os.environ.get("TRACEGATE_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
)
MAX_REQUEST_BYTES = 1024 * 1024
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_MAX_PER_USERNAME = 5
LOGIN_MAX_PER_IP = 20
WRITE_WINDOW_SECONDS = 60
WRITE_MAX_PER_PRINCIPAL = 30
_SCHEMA_READY_PATHS: set[str] = set()

app = FastAPI(
    title="TraceGate-R",
    version="0.2.0",
    description="Evidence reliability and model-disagreement checks for software security.",
)


class _RequestBodyTooLarge(Exception):
    pass


class RequestSizeLimitMiddleware:
    """Bound API request bodies even when Content-Length is absent or false."""

    def __init__(self, app, maximum: int = MAX_REQUEST_BYTES):
        self.app = app
        self.maximum = maximum

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length:
            try:
                if int(raw_length) > self.maximum:
                    await JSONResponse(status_code=413, content={"detail": "Request body exceeds the 1 MiB limit."})(scope, receive, send)
                    return
            except ValueError:
                await JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header."})(scope, receive, send)
                return
        total = 0
        response_started = False

        async def bounded_receive():
            nonlocal total
            message = await receive()
            if message.get("type") == "http.request":
                total += len(message.get("body", b""))
                if total > self.maximum:
                    raise _RequestBodyTooLarge()
            return message

        async def track_send(message):
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, bounded_receive, track_send)
        except _RequestBodyTooLarge:
            if not response_started:
                await JSONResponse(status_code=413, content={"detail": "Request body exceeds the 1 MiB limit."})(scope, receive, send)


app.add_middleware(RequestSizeLimitMiddleware)
if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(ALLOWED_ORIGINS),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Content-Type", "Authorization", "X-TraceGate-CSRF"],
        max_age=600,
    )


@dataclass(frozen=True)
class Principal:
    user_id: str | None
    username: str
    role: str
    tenant_id: str
    service: bool = False


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_now() -> str:
    return _utc_now().isoformat()


def _same_origin_request(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return True
    normalized = origin.rstrip("/")
    if normalized in ALLOWED_ORIGINS:
        return True
    request_origin = f"{request.url.scheme}://{request.url.netloc}".rstrip("/")
    return normalized == request_origin


def _security_event(db, action: str, actor_id: str | None = None,
                    target: str | None = None, details: dict | None = None) -> None:
    db.execute(
        "INSERT INTO security_events (event_id, created_at, actor_user_id, action, target, details_json) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), _iso_now(), actor_id, action, target,
         json.dumps(details or {}, sort_keys=True, separators=(",", ":"))),
    )

if FRONTEND_ASSETS.is_dir():
    app.mount("/assets", StaticFiles(directory=FRONTEND_ASSETS), name="dashboard-assets")


@app.exception_handler(RequestValidationError)
async def request_validation_error_handler(_request, exc):
    """Return bounded validation details without echoing unsafe request values."""
    details = []
    for error in exc.errors():
        location = error.get("loc", ())
        details.append({
            "loc": [part if isinstance(part, (str, int)) else str(part) for part in location],
            "msg": str(error.get("msg", "Invalid request.")),
            "type": str(error.get("type", "validation_error")),
        })
    return JSONResponse(status_code=422, content={"detail": details})


@contextmanager
def db_connect():
    existing_sidecars = prepare_sqlite_path(DB_PATH)
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    try:
        schema_key = str(DB_PATH.resolve())
        if schema_key not in _SCHEMA_READY_PATHS:
            _ensure_schema(conn)
            conn.commit()
            conn.execute("PRAGMA foreign_keys = OFF")
            try:
                conn.execute("BEGIN IMMEDIATE")
                _migrate_human_roles(conn)
                violations = conn.execute("PRAGMA foreign_key_check").fetchall()
                if violations:
                    raise sqlite3.IntegrityError("Role migration left foreign-key violations.")
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.execute("PRAGMA foreign_keys = ON")
            _SCHEMA_READY_PATHS.add(schema_key)
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        try:
            secure_new_sqlite_sidecars(DB_PATH, existing_sidecars)
        finally:
            conn.close()


def _ensure_schema(db):
    db.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                package_ref TEXT,
                model_verdict TEXT NOT NULL,
                decision TEXT NOT NULL,
                logistic_probability REAL,
                random_forest_probability REAL,
                ensemble_probability REAL,
                probability_gap REAL,
                coverage_percent REAL,
                reasons_json TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                alerts_json TEXT NOT NULL
            )
        """)
    # Additive migrations preserve existing audit records and allow the API to
    # retain the exact observation even when trained artifacts are unavailable.
    columns = {
        row["name"] for row in db.execute("PRAGMA table_info(audit_events)")
    }
    migrations = {
        "features_json": "TEXT NOT NULL DEFAULT '{}'",
        "missing_features_json": "TEXT NOT NULL DEFAULT '[]'",
        "model_labels_json": "TEXT NOT NULL DEFAULT '{}'",
        "model_disagreement": "INTEGER NOT NULL DEFAULT 0",
        "score_available": "INTEGER NOT NULL DEFAULT 0",
        "prediction_unavailable_reason": "TEXT",
        "provided_feature_count": "INTEGER NOT NULL DEFAULT 0",
        "expected_feature_count": "INTEGER NOT NULL DEFAULT 0",
        "missing_feature_count": "INTEGER NOT NULL DEFAULT 0",
        "schema_sha256": "TEXT",
    }
    for name, column_type in migrations.items():
        if name not in columns:
            db.execute(f"ALTER TABLE audit_events ADD COLUMN {name} {column_type}")

    db.executescript("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tenants (
            tenant_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT,
            role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
            tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
            active INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1)),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS users_tenant_idx ON users(tenant_id, active);
        CREATE TABLE IF NOT EXISTS auth_sessions (
            session_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            csrf_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT
        );
        CREATE INDEX IF NOT EXISTS auth_sessions_user_idx ON auth_sessions(user_id, expires_at);
        CREATE TABLE IF NOT EXISTS enrollment_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            purpose TEXT NOT NULL CHECK (purpose IN ('enroll', 'reset')),
            created_by_user_id TEXT REFERENCES users(user_id) ON DELETE SET NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            bucket_hash TEXT NOT NULL,
            attempted_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS login_attempts_bucket_idx ON login_attempts(bucket_hash, attempted_at);
        CREATE TABLE IF NOT EXISTS write_rate_limits (
            bucket_hash TEXT NOT NULL,
            attempted_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS write_rate_limits_bucket_idx ON write_rate_limits(bucket_hash, attempted_at);
        CREATE TABLE IF NOT EXISTS security_events (
            event_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            actor_user_id TEXT REFERENCES users(user_id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            target TEXT,
            details_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS security_events_created_idx ON security_events(created_at DESC);
        CREATE TABLE IF NOT EXISTS audit_ownership (
            event_id TEXT PRIMARY KEY REFERENCES audit_events(event_id) ON DELETE CASCADE,
            user_id TEXT REFERENCES users(user_id) ON DELETE SET NULL,
            tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS audit_ownership_tenant_idx ON audit_ownership(tenant_id, created_at DESC);
    """)
    db.execute(
        "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (1, ?)",
        (_iso_now(),),
    )
    if db.execute("SELECT 1 FROM schema_migrations WHERE version = 2").fetchone() is None:
        db.execute("INSERT INTO schema_migrations(version, applied_at) VALUES (2, ?)", (_iso_now(),))


def _migrate_human_roles(db: sqlite3.Connection) -> None:
    """Map legacy human roles and replace the SQLite role constraint atomically."""
    if db.execute("SELECT 1 FROM schema_migrations WHERE version = 3").fetchone():
        return
    db.execute("""
        CREATE TABLE users_role_migration (
            user_id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT,
            role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
            tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
            active INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1)),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    db.execute("""
        INSERT INTO users_role_migration(
            user_id, username, password_hash, role, tenant_id, active, created_at, updated_at
        )
        SELECT user_id, username, password_hash,
               CASE WHEN role IN ('analyst', 'viewer') THEN 'user' ELSE role END,
               tenant_id, active, created_at, updated_at
        FROM users
    """)
    db.execute("DROP TABLE users")
    db.execute("ALTER TABLE users_role_migration RENAME TO users")
    db.execute("CREATE INDEX users_tenant_idx ON users(tenant_id, active)")
    db.execute(
        "INSERT INTO schema_migrations(version, applied_at) VALUES (3, ?)",
        (_iso_now(),),
    )


def init_db():
    """Initialize or safely migrate the configured SQLite audit database."""
    with db_connect():
        pass


_DUMMY_PASSWORD_HASH = hash_password("This is a timing-only value, not an account credential.")


def authenticate_request(request: Request) -> Principal | None:
    """Authenticate an opaque browser session or configured collector token."""
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer "):
        supplied = authorization[7:].strip()
        expected = os.environ.get("TRACEGATE_COLLECTOR_TOKEN", "")
        tenant_id = os.environ.get("TRACEGATE_COLLECTOR_TENANT_ID", "")
        if expected and tenant_id and hmac.compare_digest(supplied, expected):
            with db_connect() as db:
                tenant_exists = db.execute("SELECT 1 FROM tenants WHERE tenant_id = ?", (tenant_id,)).fetchone()
            if tenant_exists:
                return Principal(None, "collector-service", "collector", tenant_id, True)
        return None

    raw_session = request.cookies.get(SESSION_COOKIE)
    if not raw_session:
        return None
    now = _iso_now()
    with db_connect() as db:
        row = db.execute("""
            SELECT u.user_id, u.username, u.role, u.tenant_id
            FROM auth_sessions s JOIN users u ON u.user_id = s.user_id
            WHERE s.session_hash = ? AND s.revoked_at IS NULL
              AND s.expires_at > ? AND u.active = 1
        """, (hash_token(raw_session), now)).fetchone()
    if row is None:
        return None
    return Principal(row["user_id"], row["username"], row["role"], row["tenant_id"])


def require_authenticated(request: Request) -> Principal:
    principal = authenticate_request(request)
    if principal is None:
        raise HTTPException(status_code=401, detail="Authentication required.", headers={"WWW-Authenticate": "Bearer"})
    return principal


def _check_csrf(request: Request, principal: Principal, csrf_token: str | None) -> None:
    if principal.service:
        return
    if not _same_origin_request(request):
        raise HTTPException(status_code=403, detail="Request origin is not allowed.")
    raw_session = request.cookies.get(SESSION_COOKIE)
    if not raw_session or not csrf_token:
        raise HTTPException(status_code=403, detail="A valid CSRF token is required.")
    with db_connect() as db:
        row = db.execute(
            "SELECT csrf_hash FROM auth_sessions WHERE session_hash = ? AND revoked_at IS NULL AND expires_at > ?",
            (hash_token(raw_session), _iso_now()),
        ).fetchone()
    if row is None or not hmac.compare_digest(row["csrf_hash"], hash_token(csrf_token)):
        raise HTTPException(status_code=403, detail="A valid CSRF token is required.")


def _check_write_rate(principal: Principal, route: str) -> None:
    identity = principal.user_id or f"service:{principal.tenant_id}"
    bucket = hash_token(f"{identity}:{route}")
    cutoff = (_utc_now() - timedelta(seconds=WRITE_WINDOW_SECONDS)).isoformat()
    with db_connect() as db:
        count = db.execute(
            "SELECT COUNT(*) FROM write_rate_limits WHERE bucket_hash = ? AND attempted_at > ?",
            (bucket, cutoff),
        ).fetchone()[0]
        if count >= WRITE_MAX_PER_PRINCIPAL:
            raise HTTPException(status_code=429, detail="Write rate limit exceeded.")
        db.execute("INSERT INTO write_rate_limits(bucket_hash, attempted_at) VALUES (?, ?)", (bucket, _iso_now()))
        db.execute("DELETE FROM write_rate_limits WHERE attempted_at < ?", (cutoff,))


def require_reader(request: Request) -> Principal:
    principal = require_authenticated(request)
    if principal.role not in {"admin", "user", "collector"}:
        raise HTTPException(status_code=403, detail="This account cannot read audit records.")
    return principal


def require_writer(
    request: Request,
    csrf_token: str | None = Header(default=None, alias="X-TraceGate-CSRF"),
) -> Principal:
    principal = require_authenticated(request)
    if principal.role not in {"admin", "user", "collector"}:
        raise HTTPException(status_code=403, detail="This account cannot submit observations.")
    _check_csrf(request, principal, csrf_token)
    _check_write_rate(principal, request.url.path)
    return principal


def require_admin_read(request: Request) -> Principal:
    principal = require_authenticated(request)
    if principal.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required.")
    return principal


def require_admin_write(
    request: Request,
    csrf_token: str | None = Header(default=None, alias="X-TraceGate-CSRF"),
) -> Principal:
    principal = require_admin_read(request)
    _check_csrf(request, principal, csrf_token)
    _check_write_rate(principal, request.url.path)
    return principal


def _issue_session(db, user, response: Response) -> tuple[str, str, str]:
    session_value, csrf_value = new_token(), new_token()
    expires_at = (_utc_now() + timedelta(seconds=SESSION_TTL_SECONDS)).isoformat()
    db.execute(
        "INSERT INTO auth_sessions(session_hash, user_id, csrf_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        (hash_token(session_value), user["user_id"], hash_token(csrf_value), _iso_now(), expires_at),
    )
    response.set_cookie(
        SESSION_COOKIE, session_value, max_age=SESSION_TTL_SECONDS,
        httponly=True, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE, path="/",
    )
    return csrf_value, expires_at, user["user_id"]


def _user_payload(user, csrf_token: str, expires_at: str) -> dict:
    return {
        "authenticated": True,
        "user": {
            "user_id": user["user_id"], "username": user["username"],
            "role": user["role"], "tenant_id": user["tenant_id"],
        },
        "csrf_token": csrf_token,
        "expires_at": expires_at,
    }


def _ip_hash(request: Request) -> str:
    address = request.client.host if request.client else "unknown"
    return hash_token(address)


def _allow_login_attempt(db, username: str, request: Request) -> bool:
    now = _utc_now()
    cutoff = (now - timedelta(seconds=LOGIN_WINDOW_SECONDS)).isoformat()
    buckets = (
        (hash_token("ip:" + _ip_hash(request)), LOGIN_MAX_PER_IP),
        (hash_token("username:" + hash_token(username)), LOGIN_MAX_PER_USERNAME),
    )
    db.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (cutoff,))
    counts = [db.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE bucket_hash = ? AND attempted_at > ?",
        (bucket, cutoff),
    ).fetchone()[0] for bucket, _limit in buckets]
    for bucket, _limit in buckets:
        db.execute("INSERT INTO login_attempts(bucket_hash, attempted_at) VALUES (?, ?)", (bucket, now.isoformat()))
    return all(count < limit for count, (_bucket, limit) in zip(counts, buckets))


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=1024)


class EnrollmentRequest(BaseModel):
    token: str = Field(min_length=32, max_length=128)
    password: SecretStr = Field(min_length=15, max_length=1024)


class PasswordChangeRequest(BaseModel):
    current_password: SecretStr = Field(min_length=1, max_length=1024)
    new_password: SecretStr = Field(min_length=15, max_length=1024)


class CreateTenantRequest(BaseModel):
    tenant_id: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    display_name: str = Field(min_length=1, max_length=120)


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    role: Literal["admin", "user"]
    tenant_id: str = Field(min_length=2, max_length=64)


class UpdateUserRequest(BaseModel):
    role: Literal["admin", "user"] | None = None
    tenant_id: str | None = Field(default=None, min_length=2, max_length=64)
    active: bool | None = None


@app.get("/api/auth/session")
def auth_session(request: Request):
    principal = authenticate_request(request)
    if principal is None or principal.service:
        return {"authenticated": False, "user": None, "csrf_token": None, "expires_at": None}
    raw_session = request.cookies.get(SESSION_COOKIE, "")
    csrf_value = new_token()
    with db_connect() as db:
        row = db.execute("""
            SELECT s.expires_at, u.user_id, u.username, u.role, u.tenant_id
            FROM auth_sessions s JOIN users u ON u.user_id = s.user_id
            WHERE s.session_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND u.active = 1
        """, (hash_token(raw_session), _iso_now())).fetchone()
        if row is None:
            return {"authenticated": False, "user": None, "csrf_token": None, "expires_at": None}
        db.execute("UPDATE auth_sessions SET csrf_hash = ? WHERE session_hash = ?",
                   (hash_token(csrf_value), hash_token(raw_session)))
    return _user_payload(row, csrf_value, row["expires_at"])


@app.post("/api/auth/login")
def auth_login(request_data: LoginRequest, request: Request, response: Response):
    if not _same_origin_request(request):
        raise HTTPException(status_code=403, detail="Request origin is not allowed.")
    try:
        username = normalize_username(request_data.username)
    except ValueError:
        username = request_data.username.strip().casefold()[:64]
    password = request_data.password.get_secret_value()
    blocked = False
    invalid = False
    payload = None
    with db_connect() as db:
        if not _allow_login_attempt(db, username, request):
            _security_event(db, "auth.login_rate_limited", target=hash_token(username)[:16])
            blocked = True
        else:
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            actual_hash = user["password_hash"] if user and user["password_hash"] else _DUMMY_PASSWORD_HASH
            password_ok = verify_password(password, actual_hash)
            if user is None or not user["active"] or not password_ok:
                invalid = True
            else:
                csrf_value, expires_at, _user_id = _issue_session(db, user, response)
                _security_event(db, "auth.login_succeeded", user["user_id"])
                db.execute("DELETE FROM login_attempts WHERE bucket_hash IN (?, ?)", (
                    hash_token("ip:" + _ip_hash(request)),
                    hash_token("username:" + hash_token(username)),
                ))
                payload = _user_payload(user, csrf_value, expires_at)
        if invalid:
            _security_event(db, "auth.login_failed", target=hash_token(username)[:16])
    if blocked:
        raise HTTPException(status_code=429, detail="Too many sign-in attempts. Try again later.")
    if invalid or payload is None:
        raise HTTPException(status_code=401, detail="Username or password is incorrect.")
    return payload


@app.post("/api/auth/logout")
def auth_logout(
    request: Request,
    response: Response,
    principal: Principal = Depends(require_authenticated),
    csrf_token: str | None = Header(default=None, alias="X-TraceGate-CSRF"),
):
    if principal.service:
        raise HTTPException(status_code=403, detail="Collector service credentials cannot create browser sessions.")
    _check_csrf(request, principal, csrf_token)
    raw_session = request.cookies.get(SESSION_COOKIE, "")
    with db_connect() as db:
        db.execute("UPDATE auth_sessions SET revoked_at = ? WHERE session_hash = ? AND revoked_at IS NULL",
                   (_iso_now(), hash_token(raw_session)))
        _security_event(db, "auth.logout", principal.user_id)
    response.delete_cookie(SESSION_COOKIE, path="/", secure=COOKIE_SECURE,
                           httponly=True, samesite=COOKIE_SAMESITE)
    return {"authenticated": False}


@app.post("/api/auth/password")
def auth_change_password(
    request_data: PasswordChangeRequest,
    request: Request,
    response: Response,
    principal: Principal = Depends(require_authenticated),
    csrf_token: str | None = Header(default=None, alias="X-TraceGate-CSRF"),
):
    if principal.service or not principal.user_id:
        raise HTTPException(status_code=403, detail="A user account is required.")
    _check_csrf(request, principal, csrf_token)
    current_password = request_data.current_password.get_secret_value()
    new_password = request_data.new_password.get_secret_value()
    try:
        validate_password(new_password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if hmac.compare_digest(current_password, new_password):
        raise HTTPException(status_code=422, detail="New password must differ from the current password.")
    with db_connect() as db:
        user = db.execute("SELECT * FROM users WHERE user_id = ? AND active = 1", (principal.user_id,)).fetchone()
        if user is None or not verify_password(current_password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Current password is incorrect.")
        now = _iso_now()
        db.execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE user_id = ?",
                   (hash_password(new_password), now, principal.user_id))
        db.execute("UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                   (now, principal.user_id))
        db.execute("UPDATE enrollment_tokens SET consumed_at = ? WHERE user_id = ? AND consumed_at IS NULL",
                   (now, principal.user_id))
        fresh_user = db.execute("SELECT * FROM users WHERE user_id = ?", (principal.user_id,)).fetchone()
        csrf_value, expires_at, _user_id = _issue_session(db, fresh_user, response)
        _security_event(db, "auth.password_changed", principal.user_id)
    return _user_payload(fresh_user, csrf_value, expires_at)


@app.post("/api/auth/enroll")
def auth_enroll(request_data: EnrollmentRequest, request: Request, response: Response):
    if not _same_origin_request(request):
        raise HTTPException(status_code=403, detail="Request origin is not allowed.")
    password = request_data.password.get_secret_value()
    try:
        validate_password(password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    with db_connect() as db:
        token = db.execute("""
            SELECT t.*, u.active FROM enrollment_tokens t JOIN users u ON u.user_id = t.user_id
            WHERE t.token_hash = ? AND t.consumed_at IS NULL AND t.expires_at > ?
              AND (t.purpose = 'enroll' OR u.active = 1)
        """, (hash_token(request_data.token), _iso_now())).fetchone()
        if token is None:
            _security_event(db, "auth.enrollment_rejected", target=_ip_hash(request))
            raise HTTPException(status_code=400, detail="Enrollment or recovery token is invalid or expired.")
        now = _iso_now()
        db.execute("UPDATE users SET password_hash = ?, active = 1, updated_at = ? WHERE user_id = ?",
                   (hash_password(password), now, token["user_id"]))
        db.execute("UPDATE enrollment_tokens SET consumed_at = ? WHERE user_id = ? AND consumed_at IS NULL",
                   (now, token["user_id"]))
        db.execute("UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                   (now, token["user_id"]))
        user = db.execute("SELECT * FROM users WHERE user_id = ?", (token["user_id"],)).fetchone()
        csrf_value, expires_at, _user_id = _issue_session(db, user, response)
        _security_event(db, "auth.account_enrolled" if token["purpose"] == "enroll" else "auth.password_reset", user["user_id"])
    return _user_payload(user, csrf_value, expires_at)


@app.get("/api/admin/tenants")
def list_tenants(principal: Principal = Depends(require_admin_read)):
    with db_connect() as db:
        rows = db.execute("SELECT tenant_id, display_name, created_at FROM tenants ORDER BY tenant_id").fetchall()
    return {"tenants": [dict(row) for row in rows]}


@app.post("/api/admin/tenants")
def create_tenant(
    request_data: CreateTenantRequest,
    principal: Principal = Depends(require_admin_write),
):
    tenant_id = request_data.tenant_id.strip().lower()
    with db_connect() as db:
        try:
            db.execute("INSERT INTO tenants(tenant_id, display_name, created_at) VALUES (?, ?, ?)",
                       (tenant_id, request_data.display_name.strip(), _iso_now()))
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="Tenant identifier already exists.") from exc
        _security_event(db, "admin.tenant_created", principal.user_id, tenant_id)
    return {"tenant_id": tenant_id, "display_name": request_data.display_name.strip()}


@app.get("/api/admin/users")
def list_users(principal: Principal = Depends(require_admin_read)):
    with db_connect() as db:
        rows = db.execute("""
            SELECT user_id, username, role, tenant_id, active, created_at, updated_at
            FROM users ORDER BY username
        """).fetchall()
    return {"users": [dict(row) for row in rows]}


@app.post("/api/admin/users")
def create_user(
    request_data: CreateUserRequest,
    principal: Principal = Depends(require_admin_write),
):
    try:
        username = normalize_username(request_data.username)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    now = _iso_now()
    user_id, enrollment = str(uuid.uuid4()), new_token()
    expiry = (_utc_now() + timedelta(minutes=30)).isoformat()
    with db_connect() as db:
        if not db.execute("SELECT 1 FROM tenants WHERE tenant_id = ?", (request_data.tenant_id,)).fetchone():
            raise HTTPException(status_code=422, detail="Tenant does not exist.")
        try:
            db.execute("""
                INSERT INTO users(user_id, username, password_hash, role, tenant_id, active, created_at, updated_at)
                VALUES (?, ?, NULL, ?, ?, 0, ?, ?)
            """, (user_id, username, request_data.role, request_data.tenant_id, now, now))
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="Username already exists.") from exc
        db.execute("""
            INSERT INTO enrollment_tokens(token_hash, user_id, purpose, created_by_user_id, created_at, expires_at)
            VALUES (?, ?, 'enroll', ?, ?, ?)
        """, (hash_token(enrollment), user_id, principal.user_id, now, expiry))
        _security_event(db, "admin.user_invited", principal.user_id, user_id,
                        {"role": request_data.role, "tenant_id": request_data.tenant_id})
    return {"user_id": user_id, "username": username, "role": request_data.role,
            "tenant_id": request_data.tenant_id, "active": False,
            "enrollment_token": enrollment, "token_expires_at": expiry}


@app.patch("/api/admin/users/{user_id}")
def update_user(
    user_id: str,
    request_data: UpdateUserRequest,
    principal: Principal = Depends(require_admin_write),
):
    updates = request_data.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=422, detail="At least one account field is required.")
    with db_connect() as db:
        user = db.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if user is None:
            raise HTTPException(status_code=404, detail="User not found.")
        role = updates.get("role", user["role"])
        active = updates.get("active", bool(user["active"]))
        tenant_id = updates.get("tenant_id", user["tenant_id"])
        if not db.execute("SELECT 1 FROM tenants WHERE tenant_id = ?", (tenant_id,)).fetchone():
            raise HTTPException(status_code=422, detail="Tenant does not exist.")
        if user["active"] and user["role"] == "admin" and (role != "admin" or not active):
            remaining = db.execute("SELECT COUNT(*) FROM users WHERE active = 1 AND role = 'admin'").fetchone()[0]
            if remaining <= 1:
                raise HTTPException(status_code=409, detail="The last active administrator cannot be disabled or demoted.")
        now = _iso_now()
        db.execute("UPDATE users SET role = ?, tenant_id = ?, active = ?, updated_at = ? WHERE user_id = ?",
                   (role, tenant_id, int(bool(active)), now, user_id))
        if role != user["role"] or tenant_id != user["tenant_id"] or bool(active) != bool(user["active"]):
            db.execute("UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                       (now, user_id))
        if not active:
            db.execute("UPDATE enrollment_tokens SET consumed_at = ? WHERE user_id = ? AND consumed_at IS NULL",
                       (now, user_id))
        _security_event(db, "admin.user_updated", principal.user_id, user_id,
                        {"role": role, "tenant_id": tenant_id, "active": bool(active)})
    return {"user_id": user_id, "username": user["username"], "role": role,
            "tenant_id": tenant_id, "active": bool(active)}


@app.post("/api/admin/users/{user_id}/reset-password")
def reset_user_password(user_id: str, principal: Principal = Depends(require_admin_write)):
    token_value = new_token()
    now = _iso_now()
    expiry = (_utc_now() + timedelta(minutes=30)).isoformat()
    with db_connect() as db:
        user = db.execute("SELECT user_id, active FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if user is None or not user["active"]:
            raise HTTPException(status_code=404, detail="Active user not found.")
        db.execute("UPDATE enrollment_tokens SET consumed_at = ? WHERE user_id = ? AND consumed_at IS NULL",
                   (now, user_id))
        db.execute("UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (now, user_id))
        db.execute("INSERT INTO enrollment_tokens(token_hash, user_id, purpose, created_by_user_id, created_at, expires_at) VALUES (?, ?, 'reset', ?, ?, ?)",
                   (hash_token(token_value), user_id, principal.user_id, now, expiry))
        _security_event(db, "admin.password_reset_issued", principal.user_id, user_id)
    return {"user_id": user_id, "reset_token": token_value, "token_expires_at": expiry}


class EvaluateRequest(BaseModel):
    model_verdict: str
    evidence: dict[str, str] = Field(default_factory=dict, max_length=4)
    integrity_alerts: list[str] = Field(default_factory=list, max_length=64)

    @field_validator("evidence", mode="before")
    @classmethod
    def validate_evidence_shape(cls, value):
        if not isinstance(value, dict):
            raise ValueError("evidence must be an object of category names and states.")
        allowed = {"file_activity", "process_execution", "system_calls", "network_behavior"}
        if any(not isinstance(key, str) or key not in allowed for key in value):
            raise ValueError("evidence contains an unknown category.")
        if any(not isinstance(state, str) for state in value.values()):
            raise ValueError("evidence states must be strings.")
        return value

    @field_validator("integrity_alerts", mode="before")
    @classmethod
    def validate_alert_shape(cls, value):
        if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() or len(item) > 200 for item in value):
            raise ValueError("integrity_alerts must be a list of non-empty strings of at most 200 characters.")
        return value


class PredictRequest(BaseModel):
    event_id: str | None = Field(default=None, max_length=100)
    package_ref: str | None = Field(default=None, max_length=200)
    features: dict[str, float | None] = Field(min_length=1, max_length=48)
    evidence: dict[str, str] = Field(default_factory=dict, max_length=4)
    integrity_alerts: list[str] = Field(default_factory=list, max_length=64)

    @field_validator("features", mode="before")
    @classmethod
    def validate_feature_shape(cls, value):
        if not isinstance(value, dict):
            return value
        if any(not isinstance(name, str) or not name or len(name) > 128 for name in value):
            raise ValueError("Feature names must be non-empty strings of at most 128 characters.")
        return value

    @field_validator("evidence", mode="before")
    @classmethod
    def validate_evidence_shape(cls, value):
        return EvaluateRequest.validate_evidence_shape(value)

    @field_validator("integrity_alerts", mode="before")
    @classmethod
    def validate_alert_shape(cls, value):
        return EvaluateRequest.validate_alert_shape(value)

    @field_validator("features", mode="before")
    @classmethod
    def validate_feature_scalars(cls, value):
        if not isinstance(value, dict):
            return value
        for name, number in value.items():
            if number is None:
                continue
            if isinstance(number, bool) or not isinstance(number, (int, float)):
                raise ValueError(f"Feature {name!r} must be a JSON number or null.")
            try:
                is_finite = math.isfinite(number)
            except OverflowError:
                is_finite = False
            if not is_finite:
                raise ValueError(f"Feature {name!r} must be finite or null.")
        return value


def persist_prediction(event_id, package_ref, features, missing_features, result, evidence, alerts, principal):
    probabilities = result["model_probabilities"]
    with db_connect() as db:
        db.execute("""
            INSERT INTO audit_events (
                event_id, created_at, package_ref, model_verdict, decision,
                logistic_probability, random_forest_probability,
                ensemble_probability, probability_gap, coverage_percent,
                reasons_json, evidence_json, alerts_json, features_json,
                missing_features_json, model_labels_json, model_disagreement,
                score_available, prediction_unavailable_reason,
                provided_feature_count, expected_feature_count,
                missing_feature_count, schema_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_id,
            result["created_at"],
            package_ref,
            result["model_verdict"],
            result["decision"],
            probabilities["logistic_regression"],
            probabilities["random_forest"],
            probabilities["ensemble"],
            result["probability_gap"],
            result["coverage_percent"],
            json.dumps(result["reason_codes"]),
            json.dumps(evidence),
            json.dumps(alerts),
            json.dumps(features, allow_nan=False, sort_keys=True),
            json.dumps(missing_features),
            json.dumps(result["model_labels"]),
            int(result["model_disagreement"]),
            int(result["score_available"]),
            result["prediction_unavailable_reason"],
            result["provided_feature_count"],
            result["expected_feature_count"],
            result["missing_feature_count"],
            result["schema_sha256"],
        ))
        db.execute(
            "INSERT INTO audit_ownership(event_id, user_id, tenant_id, created_at) VALUES (?, ?, ?, ?)",
            (event_id, principal.user_id, principal.tenant_id, result["created_at"]),
        )


@app.get("/")
def dashboard():
    if FRONTEND_INDEX.is_file():
        return FileResponse(FRONTEND_INDEX)
    if FRONTEND_BUILD_REQUIRED.is_file():
        return FileResponse(FRONTEND_BUILD_REQUIRED, status_code=503)
    return HTMLResponse(
        "<h1>TraceGate-R dashboard build required</h1><p>Build the frontend before starting the API.</p>",
        status_code=503,
    )


@app.get("/health")
def health():
    info = model_info()
    return {
        "status": "ok",
        "service": "tracegate-r",
        "model_ready": info["models_available"],
        "feature_count": info["feature_count"],
    }


@app.get("/api/model-info")
def get_model_info():
    return model_info()


def _normalized_model_result(result, feature_names: list[str], missing_features: list[str]) -> dict:
    """Reject malformed model output before it can be persisted as a scored event."""
    expected_count = len(feature_names)
    provided_count = expected_count - len(missing_features)

    def unavailable(reason: str) -> dict:
        return {
            "prediction_available": False,
            "prediction_unavailable_reason": reason,
            "logistic_probability_malicious": None,
            "random_forest_probability_malicious": None,
            "ensemble_probability_malicious": None,
            "logistic_label": None,
            "random_forest_label": None,
            "probability_gap": None,
            "model_disagreement": False,
            "missing_features": missing_features,
            "feature_count": expected_count,
            "provided_feature_count": provided_count,
        }

    if not isinstance(result, dict):
        return unavailable("MODEL_OUTPUT_INVALID")
    if result.get("prediction_available") is not True:
        reason = result.get("prediction_unavailable_reason")
        if not isinstance(reason, str) or not reason:
            reason = "MODEL_OUTPUT_INVALID"
        return unavailable(reason)

    probabilities = (
        result.get("logistic_probability_malicious"),
        result.get("random_forest_probability_malicious"),
        result.get("ensemble_probability_malicious"),
    )
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or value < 0.0
        or value > 1.0
        or not math.isfinite(value)
        for value in probabilities
    ):
        return unavailable("MODEL_OUTPUT_INVALID")
    logistic, forest, ensemble = probabilities
    expected_labels = (int(logistic >= 0.5), int(forest >= 0.5))
    expected_gap = abs(logistic - forest)
    expected_disagreement = expected_labels[0] != expected_labels[1] or expected_gap >= 0.25
    labels = (result.get("logistic_label"), result.get("random_forest_label"))
    gap = result.get("probability_gap")
    if (
        type(labels[0]) is not int
        or type(labels[1]) is not int
        or labels != expected_labels
        or isinstance(gap, bool)
        or not isinstance(gap, (int, float))
        or gap < 0.0
        or gap > 1.0
        or not math.isfinite(gap)
        or not math.isclose(gap, expected_gap, rel_tol=1e-9, abs_tol=1e-12)
        or not math.isclose(ensemble, (logistic + forest) / 2, rel_tol=1e-9, abs_tol=1e-12)
        or result.get("model_disagreement") is not expected_disagreement
        or result.get("missing_features") != missing_features
        or result.get("feature_count") != expected_count
        or result.get("provided_feature_count") != provided_count
        or provided_count == 0
        or result.get("prediction_unavailable_reason") is not None
    ):
        return unavailable("MODEL_OUTPUT_INVALID")
    return result


@app.post("/api/evaluate")
def evaluate(request: EvaluateRequest, _principal: Principal = Depends(require_writer)):
    try:
        return evaluate_evidence(
            evidence=request.evidence,
            model_verdict=request.model_verdict,
            integrity_alerts=request.integrity_alerts,
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/predict")
def predict(request: PredictRequest, principal: Principal = Depends(require_writer)):
    event_id = (request.event_id or str(uuid.uuid4())).strip()
    if not event_id:
        raise HTTPException(status_code=422, detail="event_id cannot be blank")

    package_ref = (request.package_ref or "").strip() or None
    if package_ref and len(package_ref) > 200:
        raise HTTPException(status_code=422, detail="package_ref is too long")

    try:
        feature_names = release_feature_names()
    except ModelsUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    unknown = sorted(set(request.features) - set(feature_names))
    if unknown:
        raise HTTPException(
            status_code=422,
            detail="Unknown feature names: " + ", ".join(unknown[:10]),
        )
    missing_features = [
        name for name in feature_names if request.features.get(name) is None
    ]
    provided_feature_count = len(feature_names) - len(missing_features)

    try:
        model_result = predict_models(request.features)
    except ModelsUnavailableError:
        # Keep the observation and review decision even when this host has no
        # verified trained model artifacts. Never invent probabilities/labels.
        model_result = {
            "prediction_available": False,
            "prediction_unavailable_reason": "MODEL_NOT_READY",
            "logistic_probability_malicious": None,
            "random_forest_probability_malicious": None,
            "ensemble_probability_malicious": None,
            "logistic_label": None,
            "random_forest_label": None,
            "probability_gap": None,
            "model_disagreement": False,
            "missing_features": missing_features,
            "feature_count": len(feature_names),
            "provided_feature_count": provided_feature_count,
        }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    model_result = _normalized_model_result(model_result, feature_names, missing_features)
    alerts = list(request.integrity_alerts)
    if model_result["missing_features"]:
        alerts.append(
            f"FEATURE_VECTOR_INCOMPLETE:{len(model_result['missing_features'])}"
        )
    score_available = model_result["prediction_available"]
    if not score_available:
        alerts.append(model_result["prediction_unavailable_reason"])
        verdict = "unknown"
    elif model_result["model_disagreement"]:
        alerts.append("MODEL_DISAGREEMENT")
    probability = model_result["ensemble_probability_malicious"]
    if score_available:
        verdict = "malicious" if probability >= 0.5 else "benign"

    try:
        gate = evaluate_evidence(request.evidence, verdict, alerts)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    created_at = datetime.now(timezone.utc).isoformat()
    result = {
        **gate,
        "event_id": event_id,
        "package_ref": package_ref,
        "created_at": created_at,
        "model_probabilities": {
            "logistic_regression":
                model_result["logistic_probability_malicious"],
            "random_forest":
                model_result["random_forest_probability_malicious"],
            "ensemble": probability,
        },
        "model_labels": {
            "logistic_regression": model_result["logistic_label"],
            "random_forest": model_result["random_forest_label"],
        },
        "model_disagreement": model_result["model_disagreement"],
        "score_available": score_available,
        "prediction_unavailable_reason": model_result["prediction_unavailable_reason"],
        "probability_gap": model_result["probability_gap"],
        "provided_feature_count": model_result["provided_feature_count"],
        "expected_feature_count": model_result["feature_count"],
        "missing_feature_count": len(model_result["missing_features"]),
        "missing_features": model_result["missing_features"],
        "schema_sha256": release_schema_sha256(),
        "policy_note": (
            "EVIDENCE_SUFFICIENT means the supplied evidence passed this gate; "
            "it does not guarantee the package is safe."
        ),
    }
    try:
        persist_prediction(
            event_id,
            package_ref,
            request.features,
            model_result["missing_features"],
            result,
            request.evidence,
            alerts,
            principal,
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=409,
            detail="event_id already exists; audited events are immutable.",
        ) from exc
    return result


def _serialize_audit_row(row) -> dict:
    item = dict(row)
    item["reason_codes"] = json.loads(item.pop("reasons_json"))
    item["evidence"] = json.loads(item.pop("evidence_json"))
    item["integrity_alerts"] = json.loads(item.pop("alerts_json"))
    item["features"] = json.loads(item.pop("features_json"))
    item["missing_features"] = json.loads(item.pop("missing_features_json"))
    item["model_labels"] = json.loads(item.pop("model_labels_json"))
    item["model_disagreement"] = bool(item["model_disagreement"])
    item["score_available"] = bool(item["score_available"])
    item["created_by_user_id"] = item.pop("owner_user_id", None)
    item["tenant_id"] = item.pop("owner_tenant_id", None)
    return item


def get_visible_audit_event(event_id: str, principal: Principal) -> dict:
    with db_connect() as db:
        row = db.execute("""
            SELECT e.*, o.user_id AS owner_user_id, o.tenant_id AS owner_tenant_id
            FROM audit_events e LEFT JOIN audit_ownership o ON o.event_id = e.event_id
            WHERE e.event_id = ?
        """, (event_id,)).fetchone()
    if row is None or (principal.role != "admin" and row["owner_tenant_id"] != principal.tenant_id):
        raise HTTPException(status_code=404, detail="Event not found.")
    return _serialize_audit_row(row)


@app.get("/api/audit")
def audit(limit: int = Query(default=30, ge=1, le=200), principal: Principal = Depends(require_reader)):
    with db_connect() as db:
        if principal.role == "admin":
            rows = db.execute("""
                SELECT e.*, o.user_id AS owner_user_id, o.tenant_id AS owner_tenant_id
                FROM audit_events e LEFT JOIN audit_ownership o ON o.event_id = e.event_id
                ORDER BY e.created_at DESC LIMIT ?
            """, (limit,)).fetchall()
        else:
            rows = db.execute("""
                SELECT e.*, o.user_id AS owner_user_id, o.tenant_id AS owner_tenant_id
                FROM audit_events e JOIN audit_ownership o ON o.event_id = e.event_id
                WHERE o.tenant_id = ? ORDER BY e.created_at DESC LIMIT ?
            """, (principal.tenant_id, limit)).fetchall()
    results = [_serialize_audit_row(row) for row in rows]
    return {"count": len(results), "events": results}


# Local deterministic evidence explanation route (does not alter decisions).
from .genai_explain import router as tracegate_genai_router
app.include_router(tracegate_genai_router)
