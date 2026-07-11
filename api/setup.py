"""
api/setup.py

One-time setup wizard endpoint. Creates the admin account and writes
system configuration to Elasticsearch. Refuses to run twice.
"""

import bcrypt
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Response, HTTPException
from pydantic import BaseModel
from typing import Optional

from api.elastic import get_es_client
from api.auth import create_session_cookie, _get_admin_user

log = logging.getLogger("api.setup")

router = APIRouter()
es_client = get_es_client()


class SetupPayload(BaseModel):
    # Admin account
    username: str
    password: str

    # System config
    es_host: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    notification_email: Optional[str] = None
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    ai_provider: Optional[str] = None
    ai_api_key: Optional[str] = None
    correlation_window_seconds: Optional[int] = 7200
    incident_silence_threshold_seconds: Optional[int] = 1800
    auth_log_path: Optional[str] = None
    web_log_path: Optional[str] = None
    network_log_path: Optional[str] = None
    admin_email: Optional[str] = None


@router.post("/setup/complete")
def complete_setup(payload: SetupPayload, response: Response):
    if _get_admin_user():
        raise HTTPException(
            status_code=400,
            detail="Setup has already been completed. An admin account already exists.",
        )

    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    now = datetime.now(timezone.utc).isoformat()
    password_hash = bcrypt.hashpw(payload.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    user_doc = {
        "username": payload.username,
        "password_hash": password_hash,
        "created_at": now,
    }

    config_doc = {
        "es_host": payload.es_host,
        "telegram_bot_token": payload.telegram_bot_token,
        "telegram_chat_id": payload.telegram_chat_id,
        "notification_email": payload.notification_email,
        "smtp_host": payload.smtp_host,
        "smtp_port": payload.smtp_port,
        "smtp_user": payload.smtp_user,
        "smtp_password": payload.smtp_password,
        "ai_provider": payload.ai_provider,
        "ai_api_key": payload.ai_api_key,
        "correlation_window_seconds": payload.correlation_window_seconds,
        "incident_silence_threshold_seconds": payload.incident_silence_threshold_seconds,
        "auth_log_path": payload.auth_log_path,
        "web_log_path": payload.web_log_path,
        "network_log_path": payload.network_log_path,
        "admin_email": payload.admin_email,
        "created_at": now,
        "updated_at": now,
    }

    try:
        es_client.index(index="siem-users", body=user_doc, refresh="wait_for")
        es_client.index(index="siem-config", id="active", body=config_doc, refresh="wait_for")
    except Exception:
        log.exception("Setup failed to write to Elasticsearch")
        raise HTTPException(status_code=500, detail="Failed to save setup. Check Elasticsearch connection.")

    create_session_cookie(response, payload.username)
    log.info("✅ SETUP COMPLETE — admin account created: %s", payload.username)

    return {"success": True, "username": payload.username}