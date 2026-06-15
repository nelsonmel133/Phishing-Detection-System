-- ============================================================================
-- Phishing Detection & Mitigation Tool — Core Schema
-- PostgreSQL 14+
-- ============================================================================

-- Required for gen_random_uuid() — alternatively use pg_catalog's
-- uuid-ossp extension depending on your Postgres distribution.
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ----------------------------------------------------------------------------
-- Enumerated types
-- ----------------------------------------------------------------------------
CREATE TYPE user_role       AS ENUM ('end_user', 'analyst');
CREATE TYPE input_type      AS ENUM ('url', 'text');
CREATE TYPE threat_status   AS ENUM ('safe', 'suspicious', 'malicious');
CREATE TYPE indicator_type  AS ENUM ('url', 'domain', 'keyword');

-- ----------------------------------------------------------------------------
-- users
-- ----------------------------------------------------------------------------
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(255) UNIQUE NOT NULL,
    -- bcrypt/argon2 hash only — application layer enforces this, never
    -- store plaintext credentials.
    password_hash   VARCHAR(255) NOT NULL,
    role            user_role NOT NULL DEFAULT 'end_user',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_email ON users (email);

-- ----------------------------------------------------------------------------
-- scan_requests
-- ----------------------------------------------------------------------------
CREATE TABLE scan_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Nullable to support anonymous mobile-app scans. Preserve history
    -- on account deletion via SET NULL rather than CASCADE.
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,

    input_type      input_type NOT NULL,
    raw_input       TEXT NOT NULL,

    -- Constrained to a 0-100 scale at the DB layer as a defense-in-depth
    -- measure, in addition to application-level clamping.
    risk_score      INTEGER NOT NULL DEFAULT 0
                        CHECK (risk_score BETWEEN 0 AND 100),

    threat_status   threat_status NOT NULL DEFAULT 'safe',
    dominant_vector VARCHAR(255),

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_scan_requests_user_id       ON scan_requests (user_id);
CREATE INDEX idx_scan_requests_threat_status ON scan_requests (threat_status);
CREATE INDEX idx_scan_requests_created_at    ON scan_requests (created_at DESC);

-- ----------------------------------------------------------------------------
-- global_blocklist
-- ----------------------------------------------------------------------------
CREATE TABLE global_blocklist (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_type  indicator_type NOT NULL,

    -- Unique constraint doubles as a fast existence-check index for the
    -- real-time correlation step in the scan pipeline.
    value           VARCHAR(512) NOT NULL UNIQUE,

    added_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_global_blocklist_value ON global_blocklist (value);

-- ----------------------------------------------------------------------------
-- Notes:
-- 1. Consider partitioning scan_requests by created_at (monthly) once
--    volume grows, for analyst dashboard query performance.
-- 2. Row-Level Security (RLS) is recommended on scan_requests so that
--    end_user role can only SELECT rows where user_id = current_user_id(),
--    while analyst role has unrestricted SELECT.
-- ----------------------------------------------------------------------------
