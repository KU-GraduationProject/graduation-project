"""
### Phase 3 — Gold RCA Evidence Mart (Track C)

`dp_silver` asset이 갱신되면 실행한다. 사건별 Gold build(사건 창·scope 매칭, 채널 상태,
evidence log/metric/flow, rca_link, Gold→Silver edge)를 commit하고 사건 `current` 포인터를 옮긴다.
완료하면 `dp_gold` asset을 내보내 검증 phase를 시작한다. LLM은 호출하지 않는다(DEC-07).

**현재 stub:** fixture Gold build를 그대로 commit한다. Track C 구현 시 `build_gold`를 교체한다.
"""
from airflow.sdk import TriggerRule, dag, get_current_context, task
from airflow.sdk.exceptions import AirflowSkipException

from dp_assets import GOLD, SILVER, START
from orchestration import fixture_stubs as phase
from orchestration.lake import LocalLake


@dag(dag_id="dp_gold_build", schedule=[SILVER], start_date=START, max_active_runs=1,
     tags=["data-platform", "phase:3-gold"], doc_md=__doc__)
def dp_gold_build():
    @task
    def plan_builds() -> list[dict]:
        return phase.gold_builds()

    @task(map_index_template="{{ label }}")
    def build_gold(build: dict) -> dict:
        get_current_context()["label"] = f"{build['dataset']}:{build['build_id'][-8:]}"
        result = phase.build_gold(build["build_id"], LocalLake())
        if result["status"] != "committed":
            raise AirflowSkipException(result["status"])  # 대체된 build: UI에 skipped로 표시
        return result

    @task(trigger_rule=TriggerRule.NONE_FAILED, outlets=[GOLD])
    def update_current(results: list[dict]) -> dict:
        pointers = phase.update_pointers("gold", LocalLake())
        return {"committed": sum(1 for r in results if r), "pointers": len(pointers)}

    update_current(build_gold.expand(build=plan_builds()))


dp_gold_build()
