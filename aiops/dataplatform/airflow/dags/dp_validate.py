"""
### Phase 4 — 검증 (Track D `dp_validate`)

`dp_gold` asset이 갱신되면 실행한다. 검사 세 가지를 병렬로 돌리고 하나라도 실패하면 DAG가 실패한다.
- `check_manifests`: manifest가 가리키는 파일의 존재·행 수·bytes·sha256
- `check_pointers`: `current` 포인터가 commit된 manifest와 그 데이터셋을 가리키는지
- `check_lineage`: 모든 edge의 부모 행이 commit된 부모 build에 있는지(DQ-L01 일부)

manifest가 참조하지 않는 데이터 파일(orphan)은 경고로만 보고하고 삭제하지 않는다.
"""
from airflow.sdk import dag, task

from dp_assets import GOLD, START
from orchestration import validate as checks
from orchestration.lake import LocalLake


@dag(dag_id="dp_validate", schedule=[GOLD], start_date=START, max_active_runs=1,
     tags=["data-platform", "phase:4-validate"], doc_md=__doc__)
def dp_validate():
    @task
    def check_manifests() -> list[str]:
        return checks.check_manifests(LocalLake())

    @task
    def check_pointers() -> list[str]:
        return checks.check_pointers(LocalLake())

    @task
    def check_lineage() -> list[str]:
        return checks.check_lineage(LocalLake())

    @task
    def find_orphans() -> list[str]:
        return checks.find_orphans(LocalLake())

    @task
    def report(manifests: list[str], pointers: list[str], lineage: list[str], orphans: list[str]) -> dict:
        return checks.summarize({"manifests": manifests, "pointers": pointers, "lineage": lineage}, orphans)

    report(check_manifests(), check_pointers(), check_lineage(), find_orphans())


dp_validate()
