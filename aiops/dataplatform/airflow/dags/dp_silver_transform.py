"""
### Phase 2 — Silver 변환 (Track B)

`dp_bronze` asset이 갱신되면 실행한다. coverage별 Silver build를 만들고
(정규화·dedup·quarantine·Silver→Bronze edge), 모두 commit된 뒤에만 `current` 포인터를 옮긴다.
완료하면 `dp_silver` asset을 내보내 Gold phase를 시작한다.

**현재 stub:** fixture Silver build를 그대로 commit한다(대체된 build는 fixture에 행이 없어 건너뜀).
Track B 구현 시 `build_silver`를 교체한다.
"""
from airflow.sdk import TriggerRule, dag, get_current_context, task
from airflow.sdk.exceptions import AirflowSkipException

from dp_assets import BRONZE, SILVER, START
from orchestration import fixture_stubs as phase
from orchestration.lake import LocalLake


@dag(dag_id="dp_silver_transform", schedule=[BRONZE], start_date=START, max_active_runs=1,
     tags=["data-platform", "phase:2-silver"], doc_md=__doc__)
def dp_silver_transform():
    @task
    def plan_builds() -> list[dict]:
        return phase.silver_builds()

    @task(map_index_template="{{ label }}")
    def build_silver(build: dict) -> dict:
        get_current_context()["label"] = f"{build['dataset']}:{build['build_id'][-8:]}"
        result = phase.build_silver(build["build_id"], LocalLake())
        if result["status"] != "committed":
            raise AirflowSkipException(result["status"])  # 대체된 build: UI에 skipped로 표시
        return result

    @task(trigger_rule=TriggerRule.NONE_FAILED, outlets=[SILVER])
    def update_current(results: list[dict]) -> dict:
        pointers = phase.update_pointers("silver", LocalLake())
        return {"committed": sum(1 for r in results if r), "pointers": len(pointers)}

    update_current(build_silver.expand(build=plan_builds()))


dp_silver_transform()
