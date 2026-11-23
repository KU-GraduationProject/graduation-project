"""
### Phase 3 — Gold RCA Evidence Mart (Track C)

`dp_silver` asset이 갱신되면 실행한다. 사건마다 현재 Silver build와 Bronze 획득으로 Gold build를 만든다
(사건 창·scope 매칭, 채널 상태, evidence log/metric/flow, rca_link, Gold→Silver edge, `gold.build.build_gold`).
입력이 현재 build와 같으면 건너뛴다. commit 뒤 사건 `current` 포인터를 옮기고 `dp_gold` asset을 내보낸다.
LLM은 호출하지 않는다(DEC-07).
"""
from airflow.sdk import TriggerRule, dag, get_current_context, task

from dp_assets import GOLD, SILVER, START
from orchestration import phases


@dag(dag_id="dp_gold_build", schedule=[SILVER], start_date=START, max_active_runs=1,
     tags=["data-platform", "phase:3-gold"], doc_md=__doc__)
def dp_gold_build():
    @task
    def plan_builds() -> list[dict]:
        return phases.gold_todo(phases.store())

    @task(map_index_template="{{ label }}")
    def build_gold(todo: dict) -> dict:
        context = get_current_context()
        context["label"] = todo["incident"]["incident_id"]
        run = phases.airflow_run(context, {"incident_id": todo["incident"]["incident_id"]})
        return phases.build_gold(todo, phases.store(), run)

    @task(trigger_rule=TriggerRule.NONE_FAILED, outlets=[GOLD])
    def update_current(results: list[dict] | None) -> dict:
        built = [r for r in (results or []) if r]
        pointers = phases.update_gold_pointers(built, phases.store(), phases.airflow_run(get_current_context()))
        return {"built": len(built), "pointers": len(pointers)}

    update_current(build_gold.expand(todo=plan_builds()))


dp_gold_build()
