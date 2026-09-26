import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr


APP_VERSION = "1.2.0"
WP_BRIDGE_SECRET = os.getenv("WP_BRIDGE_SECRET", "").strip()
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "3600"))
AI_ENABLED = os.getenv("AI_ENABLED", "false").lower() == "true"


app = FastAPI(
    title="Lex Monk API",
    version=APP_VERSION,
    description="FastAPI backend for Lex Monk. WordPress remains the identity system.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://lexmonk.in",
        "https://www.lexmonk.in",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-WP-Bridge-Signature",
        "X-WP-Bridge-Timestamp",
        "X-Lex-Monk-Session",
    ],
)


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


class WPIdentity(BaseModel):
    user_id: int
    email: EmailStr
    name: str = ""
    premium: bool = False


class IdentityExchangeRequest(WPIdentity):
    timestamp: int
    signature: str


class SessionResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class AIChatRequest(BaseModel):
    message: str


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _sign(value: str) -> str:
    if not WP_BRIDGE_SECRET:
        raise HTTPException(
            status_code=503,
            detail="WP_BRIDGE_SECRET is not configured on the API.",
        )
    digest = hmac.new(
        WP_BRIDGE_SECRET.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64url_encode(digest)


def _canonical_identity(identity: WPIdentity, timestamp: int) -> str:
    # Stable representation used by the WordPress bridge.
    return json.dumps(
        {
            "user_id": identity.user_id,
            "email": str(identity.email),
            "name": identity.name,
            "premium": identity.premium,
            "timestamp": timestamp,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _make_session(identity: WPIdentity) -> str:
    now = int(time.time())
    payload = {
        "sub": identity.user_id,
        "email": str(identity.email),
        "name": identity.name,
        "premium": identity.premium,
        "iat": now,
        "exp": now + SESSION_TTL_SECONDS,
    }
    payload_b64 = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signature = _sign(payload_b64)
    return f"{payload_b64}.{signature}"


def _read_session(token: str) -> dict[str, Any]:
    try:
        payload_b64, supplied_signature = token.split(".", 1)
        expected_signature = _sign(payload_b64)
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise ValueError("invalid signature")

        payload = json.loads(_b64url_decode(payload_b64))
        if int(payload["exp"]) < int(time.time()):
            raise ValueError("expired")

        return payload
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Lex Monk session.",
        ) from exc


def _verify_wp_signature(
    identity: WPIdentity,
    timestamp: int,
    supplied_signature: str,
) -> None:
    # Reject stale assertions.
    if abs(int(time.time()) - int(timestamp)) > 300:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="WordPress identity assertion has expired.",
        )

    canonical = _canonical_identity(identity, timestamp)
    expected = _sign(canonical)

    if not hmac.compare_digest(supplied_signature, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid WordPress bridge signature.",
        )


def _read_wordpress_session(token: str) -> dict[str, Any]:
    """Read the short-lived session token issued by the WordPress plugin."""
    try:
        payload_b64, supplied_signature = token.split(".", 1)
        expected_signature = _sign(payload_b64)
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise ValueError("invalid signature")

        payload = json.loads(_b64url_decode(payload_b64))
        if int(payload["exp"]) < int(time.time()):
            raise ValueError("expired")

        # WordPress plugin v2.x uses user_id instead of sub.
        if not payload.get("user_id") or not payload.get("email"):
            raise ValueError("invalid WordPress session payload")

        return {
            "sub": int(payload["user_id"]),
            "email": payload["email"],
            "name": payload.get("name", ""),
            "premium": bool(payload.get("premium", False)),
            "exp": int(payload["exp"]),
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Lex Monk session.",
        ) from exc


def _current_user(
    authorization: Optional[str] = Header(default=None),
    lex_monk_session: Optional[str] = Header(default=None, alias="X-Lex-Monk-Session"),
) -> dict[str, Any]:
    # The WordPress integration plugin sends the session in this header.
    if lex_monk_session:
        return _read_wordpress_session(lex_monk_session)

    # Also accept standard Bearer authentication for API clients.
    if authorization and authorization.lower().startswith("bearer "):
        return _read_session(authorization.split(" ", 1)[1].strip())

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Lex Monk session required.",
    )


@app.get("/", response_model=HealthResponse)
def root():
    return HealthResponse(
        status="ok",
        service="Lex Monk API",
        version=APP_VERSION,
    )


@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(
        status="ok",
        service="Lex Monk API",
        version=APP_VERSION,
    )


@app.get("/api/services")
def services():
    return [
        {
            "name": "Free Legal Resources",
            "description": "General legal information, guides, checklists and templates.",
            "tier": "free",
        },
        {
            "name": "Premium Legal Services",
            "description": "Account-based premium legal services.",
            "tier": "premium",
        },
        {
            "name": "Lex Monk AI Assistant",
            "description": "Premium general legal-information assistant.",
            "tier": "premium",
        },
    ]


@app.post(
    "/api/v1/identity/exchange",
    response_model=SessionResponse,
    tags=["WordPress Identity"],
)
@app.post(
    "/api/auth/wp",
    response_model=SessionResponse,
    include_in_schema=False,
)
def identity_exchange(payload: IdentityExchangeRequest):
    """
    Exchange a short-lived, HMAC-signed WordPress identity assertion
    for a short-lived FastAPI session.

    WordPress remains the source of truth for the account and Premium flag.
    FastAPI never receives or stores the WordPress password.
    """
    identity = WPIdentity(
        user_id=payload.user_id,
        email=payload.email,
        name=payload.name,
        premium=payload.premium,
    )
    _verify_wp_signature(identity, payload.timestamp, payload.signature)

    return SessionResponse(
        access_token=_make_session(identity),
        expires_in=SESSION_TTL_SECONDS,
    )


@app.get("/api/v1/me", tags=["Account"])
def me(user: dict[str, Any] = Depends(_current_user)):
    return {
        "authenticated": True,
        "user": {
            "id": user["sub"],
            "email": user["email"],
            "name": user.get("name", ""),
        },
        "premium": bool(user.get("premium", False)),
        "session_expires_at": user["exp"],
    }


@app.get("/api/v1/premium/status", tags=["Premium"])
def premium_status(user: dict[str, Any] = Depends(_current_user)):
    return {
        "authenticated": True,
        "premium": bool(user.get("premium", False)),
        "status": "premium" if user.get("premium", False) else "free",
    }


@app.post("/api/v1/ai/chat", tags=["AI"])
def ai_chat(
    payload: AIChatRequest,
    user: dict[str, Any] = Depends(_current_user),
):
    if not user.get("premium", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Premium access is required for the Lex Monk AI Assistant.",
        )

    if not AI_ENABLED:
        return {
            "enabled": False,
            "message": (
                "AI provider is not connected yet. "
                "Premium authentication is working, but AI is disabled."
            ),
            "user_id": user["sub"],
            "received": payload.message,
        }

    # AI provider integration will be added in the next stage.
    return {
        "enabled": False,
        "message": "AI provider integration is reserved for the next stage.",
    }


@app.get("/api/v1/debug/config", tags=["Diagnostics"])
def debug_config():
    # Deliberately reveals configuration state only, never the secret.
    return {
        "wp_bridge_secret_configured": bool(WP_BRIDGE_SECRET),
        "ai_enabled": AI_ENABLED,
        "session_ttl_seconds": SESSION_TTL_SECONDS,
        "version": APP_VERSION,
    }

