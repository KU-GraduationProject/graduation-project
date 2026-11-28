"""
### Phase 0 — 사건 발견 (Track D `dp_incident_discover`)

10분마다 Loki `{job="aiops-llm"}`(실시간 Pipeline의 RCA envelope)를 **읽기 전용**으로 질의해 사건을 찾고,
획득 창 종료 + `lateness_margin_s`(기본 10분)가 지난 사건만 `dp_bronze_acquire`를 conf=IncidentRequest로 trigger한다.
- `find_due`: `loki_read` pool(1)에서 15분 이하 창 단위로 스캔, timeout 30s, 페이지 간 지연(05 §6)
- `trigger_bronze`: run id `discover__{incident_id}` — 이미 있으면 건너뛴다
- `mark_triggered`: `lake-meta/discover/triggered/`에 1회 기록. 같은 사건은 다시 trigger하지 않는다

수동 실행 conf `{"scan_start": "...Z", "scan_end": "...Z"}`는 그 범위만 다시 스캔하고 cursor는 옮기지 않는다.
설정: `DP_DISCOVER_*` (orchestration/discover.py).
"""
from datetime import datetime, timezone

from airflow.providers.standard.operators.trigger_dagrun import TriggerDagRunOperator
from airflow.sdk import TriggerRule, dag, get_current_context, task

from dp_assets import START
from orchestration import discover, phases


@dag(dag_id="dp_incident_discover", schedule="*/10 * * * *", start_date=START, catchup=False,
     max_active_runs=1, tags=["data-platform", "phase:0-discover"], doc_md=__doc__)
def dp_incident_discover():
    @task(pool="loki_read")
    def find_due() -> list[dict]:
        conf = get_current_context()["dag_run"].conf or {}
        scan_range = None
        if conf.get("scan_start") and conf.get("scan_end"):
            scan_range = (discover.parse_ts(conf["scan_start"]), discover.parse_ts(conf["scan_end"]))
        result = discover.discover(phases.store(), datetime.now(timezone.utc), scan_range=scan_range)
        print(f"discover: {result['stats']} pending={result['pending']} due={len(result['due'])} "
              f"scanned_until={result['scanned_until']}")
        if result["stats"]["error"] and not result["stats"]["windows"]:
            raise RuntimeError(f"Loki aiops-llm scan failed: {result['stats']['error']}")
        return result["due"]

    @task(trigger_rule=TriggerRule.NONE_FAILED)
    def mark_triggered(due: list[dict]) -> list[str]:
        run_id = get_current_context()["dag_run"].run_id
        return discover.mark_triggered(phases.store(), due, datetime.now(timezone.utc), run_id)

    due = find_due()
    triggered = TriggerDagRunOperator.partial(
        task_id="trigger_bronze", trigger_dag_id="dp_bronze_acquire", wait_for_completion=False,
        skip_when_already_exists=True,
    ).expand_kwargs(due)
    triggered >> mark_triggered(due)


dp_incident_discover()
