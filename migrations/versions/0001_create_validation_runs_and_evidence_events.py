"""create validation_runs and evidence_events tables

Revision ID: 0001
Revises:
Create Date: 2026-07-10

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "evidence_events",
        sa.Column("event_id", sa.String(length=64), primary_key=True),
        sa.Column("action_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("correlation_key", sa.String(length=128), nullable=False),
        sa.Column("technique_ref", sa.String(length=16), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_evidence_events_technique_ref", "evidence_events", ["technique_ref"])

    op.create_table(
        "validation_runs",
        sa.Column("run_id", sa.String(length=64), primary_key=True),
        sa.Column("action_id", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("causal_chain_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["action_id"], ["evidence_events.action_id"], name="fk_validation_runs_action_id"),
    )
    op.create_index("ix_validation_runs_action_id", "validation_runs", ["action_id"])
    op.create_index("ix_validation_runs_verdict", "validation_runs", ["verdict"])


def downgrade() -> None:
    op.drop_index("ix_validation_runs_verdict", table_name="validation_runs")
    op.drop_index("ix_validation_runs_action_id", table_name="validation_runs")
    op.drop_table("validation_runs")

    op.drop_index("ix_evidence_events_technique_ref", table_name="evidence_events")
    op.drop_table("evidence_events")
