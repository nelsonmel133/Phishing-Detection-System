# Phishing Detection System

A full-stack phishing detection and mitigation platform combining a heuristic
analysis engine, a FastAPI backend, and a Next.js analyst dashboard.

## Architecture

```
┌─────────────────────┐      ┌──────────────────────┐      ┌─────────────┐
│  Next.js Dashboard   │ ───▶ │   FastAPI Backend     │ ───▶ │ PostgreSQL  │
│  (phishing-dashboard)│      │ (phishing-detection-  │      │             │
│                       │      │  backend)             │      │             │
└─────────────────────┘      └──────────────────────┘      └─────────────┘
```

- **`phishing-detection-backend/`** — FastAPI service exposing scan submission,
  scan retrieval, and JWT-based authentication. Uses SQLAlchemy ORM models with
  Alembic migrations against PostgreSQL.
- **`phishing-dashboard/`** — Next.js 14 + TypeScript SOC analyst dashboard for
  reviewing scan results, risk scoring, and takedown coordination.

## Features

- Heuristic phishing detection engine (URL, SMS, email channels)
- Risk scoring (0–100) with SAFE / SUSPICIOUS / MALICIOUS / CRITICAL tiers
- JWT-based authentication with role-based access (end user vs. analyst)
- Global blocklist for known-bad domains, URLs, and keywords
- Dockerized, multi-service deployment via `docker-compose`

## Getting Started

### Prerequisites

- Docker and Docker Compose
- (For local dev without Docker) Python 3.11+, Node.js 20+, PostgreSQL 16+

### Quick start with Docker

```bash
git clone https://github.com/nelsonmel133/Phishing-Detection-System.git
cd Phishing-Detection-System
cp .env.example .env
```

Edit `.env` and set real values for `SECRET_KEY` and `POSTGRES_PASSWORD`:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"  # generate SECRET_KEY
```

Then start the stack:

```bash
docker-compose up --build
```

This will:
1. Start PostgreSQL
2. Run Alembic migrations against it automatically
3. Start the FastAPI backend at `http://localhost:8000`
4. Start the Next.js dashboard at `http://localhost:3000`

API docs are available at `http://localhost:8000/docs`.

### Manual local development

**Backend**

```bash
cd phishing-detection-backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/phish_db
alembic upgrade head
uvicorn app.main:app --reload
```

**Dashboard**

```bash
cd phishing-dashboard
npm install
npm run dev
```

## Environment Variables

See [`.env.example`](./.env.example) for the full list. Key variables:

| Variable | Description |
|---|---|
| `SECRET_KEY` | JWT signing key — required, no default |
| `POSTGRES_PASSWORD` | Database password |
| `DATABASE_URL` | Full Postgres connection string (backend) |
| `CORS_ORIGINS` | Comma-separated list of allowed frontend origins |
| `NEXT_PUBLIC_API_URL` | Backend URL as seen by the browser |

## Database Migrations

Schema changes are managed with Alembic:

```bash
cd phishing-detection-backend
alembic revision --autogenerate -m "describe your change"
alembic upgrade head
```

## API Overview

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/auth/register` | Create a new account |
| `POST` | `/api/v1/auth/login` | Obtain a JWT access token |
| `POST` | `/api/v1/scan` | Submit a URL/text for phishing analysis |
| `GET` | `/api/v1/scans/{scan_id}` | Retrieve a scan result (analyst only) |

## Tech Stack

- **Backend:** FastAPI, SQLAlchemy, Alembic, PostgreSQL, python-jose, passlib
- **Frontend:** Next.js 14, TypeScript, Tailwind CSS, lucide-react
- **Infra:** Docker, Docker Compose

## Author

**Nelson Mel**
GitHub: [@nelsonmel133](https://github.com/nelsonmel133)
Email: nelsonmel133@gmail.com

## License

This project is currently unlicensed. Add a `LICENSE` file to specify usage terms.
