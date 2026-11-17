"""
### Phase 1 — Bronze 획득 (Track A)

사건 요청(`dag_run.conf`, 없으면 Mock fixture 요청)으로 획득 계획을 만들고,
원천별 pool(`loki_read`/`prom_read` = 1)로 직렬화해 획득한 뒤 Bronze manifest를 commit한다.
완료하면 `dp_bronze` asset을 내보내 Silver phase를 시작한다.

**현재 stub:** `orchestration.fixture_stubs`가 fixture 획득을 그대로 commit한다.
Track A 구현 시 같은 시그니처의 `plan_incident`/`acquire`로 교체한다.
"""
from airflow.sdk import dag, get_current_context, task

from dp_assets import BRONZE, START
from orchestration import fixture_stubs as phase
from orchestration.lake import LocalLake



def _label(item: dict) -> None:
    """Name each mapped acquisition in the UI instead of showing its index."""
    get_current_context()["label"] = (
        f"{item['scope_role']}:{item['stream_class']}:{item['query_name']}:{item['acquisition_id'][-8:]}")


@dag(dag_id="dp_bronze_acquire", schedule=None, start_date=START, max_active_runs=1,
     tags=["data-platform", "phase:1-bronze"], doc_md=__doc__)
def dp_bronze_acquire():
    @task
    def plan_incident(source: str) -> list[dict]:
        conf = get_current_context()["dag_run"].conf
        return phase.plan_incident(phase.load_request(conf or None))[source]

    @task(pool="loki_read", retries=2, map_index_template="{{ label }}")
    def acquire_loki(item: dict) -> dict:
        _label(item)
        return phase.acquire(item, LocalLake())

    @task(pool="prom_read", retries=2, map_index_template="{{ label }}")
    def acquire_prometheus(item: dict) -> dict:
        _label(item)
        return phase.acquire(item, LocalLake())

    @task(outlets=[BRONZE])
    def commit_bronze(loki: list[dict], prometheus: list[dict]) -> dict:
        results = list(loki) + list(prometheus)
        committed = [r for r in results if r["status"] == "committed"]
        if not committed:
            raise RuntimeError("no Bronze acquisition committed")
        return {"committed": len(committed),
                "by_status": {s: sum(r.get("build_status") == s for r in committed)
                              for s in sorted({r.get("build_status") for r in committed})}}

    # One lane per source system so each lane keeps its own read pool.
    loki = acquire_loki.expand(item=plan_incident.override(task_id="plan_loki")("loki"))
    prometheus = acquire_prometheus.expand(item=plan_incident.override(task_id="plan_prometheus")("prometheus"))
    commit_bronze(loki, prometheus)


dp_bronze_acquire()
