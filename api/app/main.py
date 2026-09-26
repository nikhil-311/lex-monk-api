from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

app = FastAPI(
    title="Lex Monk API",
    version="1.1.0",
    description="Backend foundation for Lex Monk.",
)

# WordPress frontend + local development origins.
# Production should be restricted to the Lex Monk site.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://lexmonk.in",
        "https://www.lexmonk.in",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


@app.get("/", response_model=HealthResponse)
def root():
    return HealthResponse(
        status="ok",
        service="Lex Monk API",
        version=app.version,
    )


@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(
        status="ok",
        service="Lex Monk API",
        version=app.version,
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


@app.get("/api/v1/premium/status")
def premium_status():
    # Deployment-stage response only.
    # Premium verification will be connected to the WordPress user
    # after the WordPress <-> FastAPI authentication bridge is added.
    return {
        "authenticated": False,
        "premium": False,
        "status": "backend_ready",
    }


@app.post("/api/auth/login")
def login_placeholder(payload: LoginRequest):
    # IMPORTANT:
    # Do not create a second password database in FastAPI.
    # Lex Monk's production identity should remain in WordPress.
    return {
        "detail": (
            "WordPress authentication bridge is not enabled yet. "
            "Deploy and verify the API first; the existing WordPress "
            "login will be connected in the next stage."
        )
    }


@app.post("/api/auth/register")
def register_placeholder(payload: RegisterRequest):
    return {
        "detail": (
            "WordPress registration bridge is not enabled yet. "
            "WordPress will remain the account system for Lex Monk."
        )
    }


@app.post("/api/feedback")
def feedback_placeholder():
    return {
        "message": "Feedback endpoint is reserved for the next backend stage."
    }


@app.post("/api/ai/chat")
def ai_placeholder():
    return {
        "detail": (
            "AI Assistant is not enabled yet. Premium authentication "
            "and access control must be completed before AI is connected."
        )
    }
