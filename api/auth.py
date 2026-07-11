"""
api/auth.py

Authentication: login, logout, setup-status check.
Session is a signed cookie (itsdangerous), not a JWT — no external
session store needed, verification is just a signature check.
"""

import bcrypt
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Response, Request, HTTPException
from pydantic import BaseModel
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from api.elastic import es_search, get_es_client

log = logging.getLogger("api.auth")

router = APIRouter()
es_client = get_es_client()

# In production this secret should come from an env var. Keeping it
# here as a constant for now since the project has no secrets manager yet.
SESSION_SECRET = "siem-ai-dev-secret-change-in-production"
COOKIE_NAME = "siem_session"
COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 7  # 7 days

serializer = URLSafeTimedSerializer(SESSION_SECRET)


class LoginPayload(BaseModel):
    username: str
    password: str


def _get_admin_user():
    """Returns the single admin user doc, or None if setup hasn't run."""
    res = es_search("siem-users", {"query": {"match_all": {}}}, size=1)
    hits = res.get("hits", [])
    return hits[0] if hits else None


def create_session_cookie(response: Response, username: str) -> None:
    token = serializer.dumps({"username": username})
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=COOKIE_MAX_AGE_SECONDS,
    )


def verify_session(request: Request) -> str:
    """
    Returns the logged-in username if the session cookie is valid.
    Raises HTTPException(401) otherwise. Use as a FastAPI dependency
    on any route that should require login.
    """
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        data = serializer.loads(token, max_age=COOKIE_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        raise HTTPException(status_code=401, detail="Session invalid or expired")
    return data.get("username")


@router.get("/auth/status")
def auth_status():
    """
    No auth required. Tells the frontend whether an admin account
    already exists, so login.html knows whether to push toward the
    setup wizard or just show the normal login form.
    """
    admin = _get_admin_user()
    return {"setup_complete": admin is not None}


@router.post("/auth/login")
def login(payload: LoginPayload, response: Response):
    admin = _get_admin_user()
    if not admin:
        raise HTTPException(status_code=400, detail="No account exists yet. Run setup first.")

    source = admin.get("_source", {})
    stored_username = source.get("username")
    stored_hash = source.get("password_hash", "")

    if payload.username != stored_username:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not bcrypt.checkpw(payload.password.encode("utf-8"), stored_hash.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    create_session_cookie(response, stored_username)
    return {"success": True, "username": stored_username}


@router.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME)
    return {"success": True}


@router.get("/auth/me")
def me(request: Request):
    """Lightweight check used by dashboard pages to confirm session validity."""
    username = verify_session(request)
    return {"username": username}