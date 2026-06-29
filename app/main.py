from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .api import admin, auth, collections, config, folders, items, me, users
from .config import settings
from .db import init_db
from .security import SlidingWindowRateLimiter

ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT / "static"
CSRF_COOKIE_NAME = "sv_csrf"
CSRF_HEADER_NAME = "x-csrf-token"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None, lifespan=lifespan)
auth_limiter = SlidingWindowRateLimiter(settings.max_login_attempts_per_minute, 60)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)


def add_security_headers(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers[
        "Content-Security-Policy"
    ] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    if settings.force_https or settings.secure_cookies:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def csrf_required(request: Request) -> bool:
    if request.method not in UNSAFE_METHODS:
        return False
    auth_header = request.headers.get("authorization", "")
    return not auth_header.lower().startswith("bearer ")


def validate_csrf(request: Request) -> bool:
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    header_token = request.headers.get(CSRF_HEADER_NAME)
    if not cookie_token or not header_token:
        return False
    return secrets.compare_digest(cookie_token, header_token)


@app.middleware("http")
async def hardening_middleware(request: Request, call_next):
    if settings.force_https and request.url.scheme != "https":
        https_url = request.url.replace(scheme="https")
        return add_security_headers(RedirectResponse(str(https_url), status_code=status.HTTP_307_TEMPORARY_REDIRECT))

    if request.method in UNSAFE_METHODS:
        origin = request.headers.get("origin")
        if origin:
            origin_host = urlparse(origin).netloc
            if origin_host and origin_host != request.headers.get("host"):
                return add_security_headers(JSONResponse({"detail": "Cross-origin request blocked"}, status_code=403))
        if csrf_required(request) and not validate_csrf(request):
            return add_security_headers(JSONResponse({"detail": "CSRF validation failed"}, status_code=403))

    if request.url.path.startswith("/api/auth/"):
        client = request.client.host if request.client else "unknown"
        result = auth_limiter.check(f"{client}:{request.url.path}")
        if not result.allowed:
            response = Response("Too many attempts", status_code=429)
            response.headers["Retry-After"] = str(result.retry_after_seconds)
            return add_security_headers(response)

    response = await call_next(request)
    add_security_headers(response)
    if not request.cookies.get(CSRF_COOKIE_NAME):
        response.set_cookie(
            CSRF_COOKIE_NAME,
            secrets.token_urlsafe(32),
            max_age=60 * 60 * 12,
            httponly=False,
            secure=settings.secure_cookies,
            samesite="strict",
            path="/",
        )
    return response


app.include_router(config.router)
app.include_router(auth.router)
app.include_router(me.router)
app.include_router(folders.router)
app.include_router(items.router)
app.include_router(collections.router)
app.include_router(users.router)
app.include_router(admin.router)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/{path:path}")
def frontend(path: str) -> FileResponse:
    if path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(STATIC_DIR / "index.html")
