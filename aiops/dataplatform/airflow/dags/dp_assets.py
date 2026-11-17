"""Assets that chain the phase DAGs: Bronze -> Silver -> Gold -> Validate.

A phase DAG emits its asset only after its builds are committed, so the next
phase runs on committed manifests (docs/data-platform/02 §4).
"""
from datetime import datetime, timezone

from airflow.sdk import Asset

START = datetime(2026, 11, 1, tzinfo=timezone.utc)

BRONZE = Asset(name="dp_bronze", uri="file:///opt/airflow/lake/lake-meta/manifests/bronze")
SILVER = Asset(name="dp_silver", uri="file:///opt/airflow/lake/lake-meta/current/silver")
GOLD = Asset(name="dp_gold", uri="file:///opt/airflow/lake/lake-meta/current/gold")
