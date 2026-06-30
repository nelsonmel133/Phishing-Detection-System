"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-30

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')

    user_role = postgresql.ENUM("end_user", "analyst", name="user_role")
    input_type = postgresql.ENUM("url", "text", name="input_type")
    threat_status = postgresql.ENUM("safe", "suspicious", "malicious", name="threat_status")
    indicator_type = postgresql.ENUM("url", "domain", "keyword", name="indicator_type")

    user_role.create(op.get_bind())
    input_type.create(op.get_bind())
    threat_status.create(op.get_bind())
    indicator_type.create(op.get_bind())

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", user_role, nullable=False, server_default="end_user"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("idx_users_email", "users", ["email"])

    op.create_table(
        "scan_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("input_type", input_type, nullable=False),
        sa.Column("raw_input", sa.Text(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("threat_status", threat_status, nullable=False, server_default="safe"),
        sa.Column("dominant_vector", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_scan_requests_risk_score"),
    )
    op.create_index("idx_scan_requests_user_id", "scan_requests", ["user_id"])
    op.create_index("idx_scan_requests_threat_status", "scan_requests", ["threat_status"])
    op.create_index("idx_scan_requests_created_at", "scan_requests", [sa.text("created_at DESC")])

    op.create_table(
        "global_blocklist",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("indicator_type", indicator_type, nullable=False),
        sa.Column("value", sa.String(512), nullable=False, unique=True),
        sa.Column("added_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("idx_global_blocklist_value", "global_blocklist", ["value"])


def downgrade() -> None:
    op.drop_table("global_blocklist")
    op.drop_table("scan_requests")
    op.drop_table("users")

    postgresql.ENUM(name="indicator_type").drop(op.get_bind())
    postgresql.ENUM(name="threat_status").drop(op.get_bind())
    postgresql.ENUM(name="input_type").drop(op.get_bind())
    postgresql.ENUM(name="user_role").drop(op.get_bind())
