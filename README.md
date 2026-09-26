# Lex Monk API

FastAPI backend foundation for the Lex Monk website.

## Current stage

This repository is intentionally the **backend deployment foundation**.

It includes:

- `GET /`
- `GET /health`
- `GET /api/services`
- `GET /api/v1/premium/status`
- placeholder authentication endpoints
- placeholder feedback endpoint
- placeholder AI endpoint
- CORS configuration for `https://lexmonk.in`
- Render configuration
- Python 3.13 pin

## Important architecture decision

Lex Monk uses **WordPress as the website account/identity system**.

FastAPI should not create a second password database.

The next backend stage will connect the existing WordPress account/session to FastAPI and then implement:

1. authenticated WordPress user identity
2. user dashboard
3. manual Premium activation
4. Premium access checks
5. protected AI endpoint
6. PostgreSQL
7. AI provider integration

The placeholder `/api/auth/login` and `/api/auth/register` endpoints therefore do **not** create fake accounts or store passwords.

## Deploy on Render

Create a GitHub repository and upload this repository.

In Render:

- New → Web Service
- Runtime: Python 3
- Build Command:
  `pip install -r requirements.txt`
- Start Command:
  `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- Plan: Free

Render documents this FastAPI deployment pattern in its official documentation.

After deployment, test:

- `/`
- `/health`
- `/docs`

## Custom domain

After the Render service is working, connect:

`api.lexmonk.in`

to the Render service through Render's Custom Domains/DNS instructions.

Do not change the WordPress Lex Monk API setting; it should remain:

`https://api.lexmonk.in`

## Security

Never commit:

- OpenAI API keys
- Gemini API keys
- database passwords
- WordPress Application Passwords
- JWT secrets
- other credentials

Put secrets in Render Environment Variables when they are actually needed.

## Current limitation

The Login page on the WordPress site currently contains an older integration flow that expects `/api/auth/login` and a backend token. We will update that flow to use WordPress authentication rather than creating a separate user/password system.

Do not treat this deployment-stage backend as the finished authentication system.
