"""Key layout of 02 §3. Every data path carries a unique build id, so nothing is overwritten."""
from __future__ import annotations

from contracts.canonical import parse_ts


def _date(ts: str) -> str:
    return parse_ts(ts).strftime("%Y-%m-%d")


def build_date(build_id: str) -> str:
    """`acq_20261110T032000Z_…` -> `2026-11-10` (UTC partition of the build's creation)."""
    stamp = build_id.split("_")[1]
    return f"{stamp[0:4]}-{stamp[4:6]}-{stamp[6:8]}"


def acquisition_file(acquisition_id: str) -> str:
    return f"s3://lake-bronze/v1/acquisition/acq_date={build_date(acquisition_id)}/{acquisition_id}.parquet"


def loki_entry_file(acquisition_id: str, stream_class: str) -> str:
    return (f"s3://lake-bronze/v1/loki_entry/stream_class={stream_class}/acq_date={build_date(acquisition_id)}/"
            f"{acquisition_id}/part-0000.parquet")


def prometheus_sample_file(acquisition_id: str) -> str:
    return (f"s3://lake-bronze/v1/prometheus_sample/acq_date={build_date(acquisition_id)}/"
            f"{acquisition_id}/part-0000.parquet")


def raw_page(source_system: str, acquisition_id: str, page: int) -> str:
    return (f"s3://lake-bronze/raw/{source_system}/acq_date={build_date(acquisition_id)}/"
            f"{acquisition_id}/page-{page:04d}.json.gz")


def silver_file(dataset: str, build_id: str, event_date: str) -> str:
    name = dataset.split(".", 1)[1]
    partition = "acq_date" if name == "quarantine" else "event_date"
    return f"s3://lake-silver/v1/{name}/{partition}={event_date}/{build_id}/part-0000.parquet"


def gold_file(dataset: str, incident_id: str, incident_date: str, build_id: str) -> str:
    name = dataset.split(".", 1)[1]
    return f"s3://lake-gold/v1/{name}/incident_date={incident_date}/{incident_id}/{build_id}/part-0000.parquet"


def edge_file(build_id: str) -> str:
    return f"s3://lake-meta/lineage/v1/edge/run_date={build_date(build_id)}/{build_id}.parquet"


def run_file(run_id: str, started_at: str) -> str:
    return f"s3://lake-meta/lineage/v1/run/run_date={_date(started_at)}/{run_id}.parquet"


def date_of(ts: str) -> str:
    return _date(ts)
