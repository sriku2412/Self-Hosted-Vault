from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from ..config import settings
from ..db import db_session
from ..repositories.settings import get_registration_enabled

router = APIRouter(prefix="/api", tags=["config"])


@router.get("/config")
def api_config() -> dict[str, Any]:
    with db_session() as conn:
        registration_enabled = get_registration_enabled(conn)
    return {
        "appName": settings.app_name,
        "kdfIterations": settings.kdf_iterations,
        "registrationEnabled": registration_enabled,
        "secureCookies": settings.secure_cookies,
    }
