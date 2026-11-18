"""
### Phase 2 — Silver 변환 (Track B)

`dp_bronze` asset이 갱신되면 실행한다. 사건 plan마다 coverage(데이터셋 × plan × binding 집합 × 획득 창)를
계산하고, 입력 Bronze manifest 집합이 현재 build와 다른 coverage만 새 build로 만든다
(정규화·dedup·quarantine·Silver→Bronze edge, `silver.build.build_silver`).
모든 build가 commit된 뒤에만 `current` 포인터를 옮기고 `dp_silver` asset을 내보낸다.
"""
from airflow.sdk import TriggerRule, dag, get_current_context, task

from dp_assets import BRONZE, SILVER, START
from orchestration import phases


@dag(dag_id="dp_silver_transform", schedule=[BRONZE], start_date=START, max_active_runs=1,
     tags=["data-platform", "phase:2-silver"], doc_md=__doc__)
def dp_silver_transform():
    @task
    def plan_builds() -> list[dict]:
        return phases.silver_todo(phases.store())

    @task(map_index_template="{{ label }}")
    def build_silver(todo: dict) -> dict:
        context = get_current_context()
        context["label"] = f"{todo['dataset']}:{todo['coverage']['coverage_id'][-8:]}"
        run = phases.airflow_run(context, {"dataset": todo["dataset"], "coverage_id": todo["coverage"]["coverage_id"]})
        return phases.build_silver(todo, phases.store(), run)

    @task(trigger_rule=TriggerRule.NONE_FAILED, outlets=[SILVER])
    def update_current(results: list[dict] | None) -> dict:
        built = [r for r in (results or []) if r]
        pointers = phases.update_silver_pointers(built, phases.store(), phases.airflow_run(get_current_context()))
        return {"built": len(built), "pointers": len(pointers)}

    update_current(build_silver.expand(todo=plan_builds()))


dp_silver_transform()
