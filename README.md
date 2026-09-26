# Lex Monk API

FastAPI backend for the Lex Monk website.

## Architecture

- WordPress remains the account and identity system.
- FastAPI does not create a second password database.
- WordPress sends a short-lived HMAC-signed identity assertion.
- FastAPI verifies it with `WP_BRIDGE_SECRET`.
- FastAPI issues a short-lived signed session token.
- Premium access is carried from the WordPress-controlled Premium flag.
- The AI endpoint is server-side protected and disabled until an AI provider is connected.

## Render

Build:
`pip install -r requirements.txt`

Start:
`uvicorn app.main:app --host 0.0.0.0 --port $PORT`

Required environment variable:
`WP_BRIDGE_SECRET`

Optional:
`SESSION_TTL_SECONDS` (default 3600)
`AI_ENABLED` (default false)

## Main endpoints

- `GET /`
- `GET /health`
- `GET /api/services`
- `POST /api/v1/identity/exchange`
- `GET /api/v1/me`
- `GET /api/v1/premium/status`
- `POST /api/v1/ai/chat`

AI is intentionally disabled at this stage.
