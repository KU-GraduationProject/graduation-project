"""
### Phase 1 — Bronze 획득 (Track A)

사건 요청(`dag_run.conf`, 없으면 Mock fixture 요청)과 `OBSERVATION_BINDINGS`로 획득 계획을 만들고
(`bronze.plan.plan_incident`), 원천별 pool(`loki_read`/`prom_read` = 1)로 직렬화해 Loki/Prometheus를
읽기 전용으로 질의한다(`bronze.acquire.acquire`). 획득마다 raw page·Bronze 행·acquisition 행을 쓰고
manifest를 commit한다. 실패한 질의도 acquisition 행을 남긴다(DQ-B01).
완료하면 `dp_bronze` asset을 내보내 Silver phase를 시작한다.

원천 주소: `DP_LOKI_URL`, `DP_PROMETHEUS_URL` (Compose 기본값은 fixture mock `dp-mock-sources`).
시나리오 실행 기록(`scenarios/v2` runs.jsonl)은 `DP_SCENARIO_RUN_LOG` 파일을 통째로 읽는 별도 lane이다(#71).
"""
from airflow.sdk import TriggerRule, dag, get_current_context, task

from dp_assets import BRONZE, START
from orchestration import phases


def _run(params: dict | None = None):
    return phases.airflow_run(get_current_context(), params)


def _label(item: dict) -> None:
    """Name each mapped acquisition in the UI instead of showing its index."""
    get_current_context()["label"] = phases.label(item)


@dag(dag_id="dp_bronze_acquire", schedule=None, start_date=START, max_active_runs=1,
     tags=["data-platform", "phase:1-bronze"], doc_md=__doc__)
def dp_bronze_acquire():
    @task
    def plan_incident(source: str) -> list[dict]:
        # Each lane plans the same incident; the plan record is rewritten with identical content.
        request = phases.load_request(get_current_context()["dag_run"].conf or None)
        grouped = phases.plan(request, phases.store(), _run({"source_system": source}))
        return grouped[source]

    @task(pool="loki_read", retries=2, map_index_template="{{ label }}")
    def acquire_loki(item: dict) -> dict:
        _label(item)
        return phases.acquire(item, phases.store(), _run({"acquisition_key": item["acquisition_key"]}))

    @task(pool="prom_read", retries=2, map_index_template="{{ label }}")
    def acquire_prometheus(item: dict) -> dict:
        _label(item)
        return phases.acquire(item, phases.store(), _run({"acquisition_key": item["acquisition_key"]}))

    @task(retries=2, map_index_template="{{ label }}")
    def acquire_scenario_runs(item: dict) -> dict:
        _label(item)
        return phases.acquire(item, phases.store(), _run({"acquisition_key": item["acquisition_key"]}))

    # NONE_FAILED: a lane with no plan items (e.g. a db_log-only reprocess) is skipped, not failed.
    @task(trigger_rule=TriggerRule.NONE_FAILED, outlets=[BRONZE])
    def commit_bronze(loki: list[dict] | None, prometheus: list[dict] | None,
                      scenario_runs: list[dict] | None) -> dict:
        return phases.summarize(list(loki or []) + list(prometheus or []) + list(scenario_runs or []))

    # One lane per source system so each lane keeps its own read pool.
    loki = acquire_loki.expand(item=plan_incident.override(task_id="plan_loki")("loki"))
    prometheus = acquire_prometheus.expand(item=plan_incident.override(task_id="plan_prometheus")("prometheus"))
    scenario_runs = acquire_scenario_runs.expand(
        item=plan_incident.override(task_id="plan_scenario_runs")("scenario_run_log"))
    commit_bronze(loki, prometheus, scenario_runs)


dp_bronze_acquire()
