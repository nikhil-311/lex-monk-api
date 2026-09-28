import base64
import hashlib
import hmac
import json
import logging
import os
import threading
import time
from collections import defaultdict, deque
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    AsyncOpenAI,
    AuthenticationError,
    RateLimitError,
)
from pydantic import BaseModel, EmailStr, Field


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
APP_VERSION = "1.3.0"
WP_BRIDGE_SECRET = os.getenv("WP_BRIDGE_SECRET", "").strip()
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "3600"))

AI_ENABLED = os.getenv("AI_ENABLED", "false").strip().lower() == "true"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.6-luna").strip()
OPENAI_TIMEOUT_SECONDS = float(os.getenv("OPENAI_TIMEOUT_SECONDS", "45"))
OPENAI_MAX_OUTPUT_TOKENS = int(os.getenv("OPENAI_MAX_OUTPUT_TOKENS", "2000"))
AI_RATE_LIMIT_PER_MINUTE = int(os.getenv("AI_RATE_LIMIT_PER_MINUTE", "10"))

if SESSION_TTL_SECONDS < 300:
    raise RuntimeError("SESSION_TTL_SECONDS must be at least 300 seconds.")
if OPENAI_MAX_OUTPUT_TOKENS < 256:
    raise RuntimeError("OPENAI_MAX_OUTPUT_TOKENS must be at least 256.")
if AI_RATE_LIMIT_PER_MINUTE < 0:
    raise RuntimeError("AI_RATE_LIMIT_PER_MINUTE cannot be negative.")


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger("lex_monk_api")

# The client is created only when a key is present. The endpoint also checks
# the configuration at request time so missing configuration produces a
# controlled API response instead of an import/startup failure.
openai_client: Optional[AsyncOpenAI] = None
if OPENAI_API_KEY:
    openai_client = AsyncOpenAI(
        api_key=OPENAI_API_KEY,
        timeout=OPENAI_TIMEOUT_SECONDS,
        max_retries=2,
    )


# ---------------------------------------------------------------------------
# In-memory rate limiter
# ---------------------------------------------------------------------------
# This is deliberately lightweight. It protects the free Render instance and
# limits accidental repeat requests. A future production deployment can move
# this to Redis/PostgreSQL for multi-instance consistency.
_rate_lock = threading.Lock()
_ai_requests: dict[int, deque[float]] = defaultdict(deque)


def _check_ai_rate_limit(user_id: int) -> None:
    if AI_RATE_LIMIT_PER_MINUTE == 0:
        return

    now = time.monotonic()
    cutoff = now - 60.0

    with _rate_lock:
        bucket = _ai_requests[user_id]
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if len(bucket) >= AI_RATE_LIMIT_PER_MINUTE:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many AI requests. Please wait a moment and try again.",
                headers={"Retry-After": "60"},
            )

        bucket.append(now)


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Lex Monk API",
    version=APP_VERSION,
    description=(
        "FastAPI backend for Lex Monk. WordPress remains the identity system; "
        "Premium access is enforced server-side."
    ),
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


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
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
    # The WordPress frontend currently caps this at 12,000 characters. Keep
    # the backend limit aligned so a forged request cannot bypass that limit.
    message: str = Field(..., min_length=1, max_length=12000)


# ---------------------------------------------------------------------------
# Cryptographic helpers / WordPress bridge
# ---------------------------------------------------------------------------
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
    lex_monk_session: Optional[str] = Header(
        default=None,
        alias="X-Lex-Monk-Session",
    ),
) -> dict[str, Any]:
    # WordPress integration plugin is the primary browser authentication path.
    if lex_monk_session:
        return _read_wordpress_session(lex_monk_session)

    # Also accept standard Bearer authentication for API clients.
    if authorization and authorization.lower().startswith("bearer "):
        return _read_session(authorization.split(" ", 1)[1].strip())

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Lex Monk session required.",
    )


# ---------------------------------------------------------------------------
# OpenAI helpers
# ---------------------------------------------------------------------------
LEX_MONK_AI_INSTRUCTIONS = """
You are the Lex Monk AI Assistant, a premium general legal-information assistant
for users seeking information about law in India.

ROLE AND SCOPE
- Provide general legal information and educational explanations only.
- You are not an advocate, do not create an advocate-client relationship, and
  must not present an answer as a formal legal opinion.
- Do not guarantee a legal outcome, court result, deadline, entitlement, or
  success probability.
- Do not pretend to know facts that the user has not provided.

INDIA-FIRST LEGAL CONTEXT
- Prefer Indian law and terminology when the user's question is about India.
- State when an answer depends on the State, court, forum, facts, or procedural
  stage.
- Do not invent section numbers, case names, notifications, judgments, rules,
  fees, limitation periods, or government procedures.
- When the answer depends on recent legal changes or current government rules,
  clearly tell the user to verify the latest position using the relevant official
  source or a qualified advocate.

ANSWER STYLE
- Use plain, easy-to-understand language.
- Start with the direct answer, then give the important details.
- Use short headings and bullet points where helpful.
- When useful, explain practical next steps at a high level, but do not give
  instructions for unlawful conduct or evasion of authorities.
- If the question is ambiguous, state the assumption you are making and answer
  the most likely interpretation rather than unnecessarily refusing.

SAFETY AND PRIVACY
- Do not help a user commit, conceal, facilitate, or optimize unlawful activity.
- Do not request sensitive information such as Aadhaar/PAN numbers, bank/card
  details, passwords, medical records, confidential case documents, or another
  person's private data.
- Encourage the user to remove identifying information before sharing facts.
- For immediate danger or emergencies, advise contacting the appropriate
  emergency service or local authority rather than relying on this assistant.

LEX MONK DISCLAIMER
- Keep the response informational and neutral.
- For consequential matters, recommend verification with an advocate or official
  authority without claiming that Lex Monk has reviewed the user's full matter.
""".strip()


def _extract_response_text(response: Any) -> str:
    """Extract visible assistant text robustly from a Responses API object."""
    direct = getattr(response, "output_text", None)
    if isinstance(direct, str) and direct.strip():
        return direct.strip()

    pieces: list[str] = []
    output_items = getattr(response, "output", None) or []

    for item in output_items:
        item_type = getattr(item, "type", None)
        if item_type is None and isinstance(item, dict):
            item_type = item.get("type")

        if item_type != "message":
            continue

        content = getattr(item, "content", None)
        if content is None and isinstance(item, dict):
            content = item.get("content")

        for part in content or []:
            part_type = getattr(part, "type", None)
            if part_type is None and isinstance(part, dict):
                part_type = part.get("type")

            if part_type != "output_text":
                continue

            text_value = getattr(part, "text", None)
            if text_value is None and isinstance(part, dict):
                text_value = part.get("text")

            if isinstance(text_value, str) and text_value.strip():
                pieces.append(text_value.strip())

    return "\n\n".join(pieces).strip()


# ---------------------------------------------------------------------------
# Basic routes
# ---------------------------------------------------------------------------
@app.get("/", response_model=HealthResponse)
def root():
    return HealthResponse(status="ok", service="Lex Monk API", version=APP_VERSION)


@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(status="ok", service="Lex Monk API", version=APP_VERSION)


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


# ---------------------------------------------------------------------------
# WordPress identity bridge
# ---------------------------------------------------------------------------
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
    Exchange a short-lived, HMAC-signed WordPress identity assertion for a
    short-lived FastAPI session.

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


# ---------------------------------------------------------------------------
# Protected AI Assistant
# ---------------------------------------------------------------------------
@app.post("/api/v1/ai/chat", tags=["AI"])
async def ai_chat(
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
            "answer": "AI Assistant is temporarily unavailable. Please try again later.",
        }

    if not OPENAI_API_KEY or openai_client is None:
        logger.error("AI is enabled but OPENAI_API_KEY is not configured.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI service is not configured correctly. Please try again later.",
        )

    message = payload.message.strip()
    if not message:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please enter a question.",
        )

    _check_ai_rate_limit(int(user["sub"]))

    try:
        response = await openai_client.responses.create(
            model=OPENAI_MODEL,
            instructions=LEX_MONK_AI_INSTRUCTIONS,
            input=message,
            max_output_tokens=OPENAI_MAX_OUTPUT_TOKENS,
            store=False,
        )

        answer = _extract_response_text(response)
        if not answer:
            logger.error(
                "OpenAI returned no visible output for model=%s; response_id=%s",
                OPENAI_MODEL,
                getattr(response, "id", "unknown"),
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="The AI service returned no answer. Please try again.",
            )

        logger.info(
            "AI response generated successfully for user_id=%s model=%s",
            user["sub"],
            OPENAI_MODEL,
        )

        return {
            "enabled": True,
            "answer": answer,
            "model": OPENAI_MODEL,
        }

    except HTTPException:
        raise
    except AuthenticationError:
        logger.exception("OpenAI authentication failed.")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The AI service authentication failed. Please contact Lex Monk support.",
        )
    except RateLimitError:
        logger.warning("OpenAI rate limit reached.")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="The AI service is busy right now. Please wait a moment and try again.",
            headers={"Retry-After": "30"},
        )
    except (APITimeoutError, APIConnectionError):
        logger.exception("OpenAI connection or timeout error.")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="The AI service took too long to respond. Please try again.",
        )
    except APIStatusError as exc:
        logger.exception(
            "OpenAI API status error: status=%s request_id=%s",
            exc.status_code,
            getattr(exc, "request_id", None),
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The AI service returned an error. Please try again later.",
        )
    except Exception:
        # Never expose raw provider exceptions to the browser. Keep the detailed
        # stack trace in Render logs for debugging.
        logger.exception("Unexpected AI provider error.")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The AI service is temporarily unavailable. Please try again later.",
        )


# ---------------------------------------------------------------------------
# Diagnostics (safe: no secrets exposed)
# ---------------------------------------------------------------------------
@app.get("/api/v1/debug/config", tags=["Diagnostics"])
def debug_config():
    return {
        "wp_bridge_secret_configured": bool(WP_BRIDGE_SECRET),
        "ai_enabled": AI_ENABLED,
        "openai_api_key_configured": bool(OPENAI_API_KEY),
        "openai_model": OPENAI_MODEL,
        "openai_timeout_seconds": OPENAI_TIMEOUT_SECONDS,
        "openai_max_output_tokens": OPENAI_MAX_OUTPUT_TOKENS,
        "ai_rate_limit_per_minute": AI_RATE_LIMIT_PER_MINUTE,
        "session_ttl_seconds": SESSION_TTL_SECONDS,
        "version": APP_VERSION,
    }
