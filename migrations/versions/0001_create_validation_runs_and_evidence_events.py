"""create validation_runs and evidence_events tables

Revision ID: 0001
Revises:
Create Date: 2026-07-10

N-B4/m3: this baseline revision originally created `evidence_events` with only
`event_id, action_id, correlation_key, technique_ref, timestamp, created_at`,
omitting `target_asset_ref` and `expected_observable`, which the frozen
EvidenceEvent contract requires and the Pydantic model enforces as required
fields. It also gave `validation_runs` no `regulatory_control_refs` and no
`content_hash`, so the verdict columns the plan's v2.0 payload requires had
nowhere to live and no follow-up revision existed. Both tables are now created
with the full frozen column set.

The revision is extended in place rather than superseded: it is the initial
baseline (`down_revision = None`) in a repository whose only migration is this
one, so there is no deployed schema to keep compatible and no second revision
would be better documentation than fixing the one that under-delivers.
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
        # Frozen contract fields the previous revision omitted.
        sa.Column("target_asset_ref", sa.String(length=128), nullable=False),
        sa.Column("expected_observable", sa.Text(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_evidence_events_technique_ref", "evidence_events", ["technique_ref"])
    op.create_index("ix_evidence_events_target_asset_ref", "evidence_events", ["target_asset_ref"])

    op.create_table(
        "validation_runs",
        sa.Column("run_id", sa.String(length=64), primary_key=True),
        sa.Column("action_id", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("technique_ref", sa.String(length=16), nullable=True),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("mttd_seconds", sa.Float(), nullable=True),
        sa.Column("matched_evidence_ref", sa.String(length=128), nullable=True),
        sa.Column("causal_chain_json", sa.JSON(), nullable=True),
        # Verdict contract fields the previous revision omitted.
        sa.Column("regulatory_control_refs", sa.JSON(), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["action_id"], ["evidence_events.action_id"], name="fk_validation_runs_action_id"),
    )
    op.create_index("ix_validation_runs_action_id", "validation_runs", ["action_id"])
    op.create_index("ix_validation_runs_verdict", "validation_runs", ["verdict"])
    op.create_index("ix_validation_runs_content_hash", "validation_runs", ["content_hash"])


def downgrade() -> None:
    op.drop_index("ix_validation_runs_verdict", table_name="validation_runs")
    op.drop_index("ix_validation_runs_action_id", table_name="validation_runs")
    op.drop_table("validation_runs")

    op.drop_index("ix_evidence_events_technique_ref", table_name="evidence_events")
    op.drop_table("evidence_events")
