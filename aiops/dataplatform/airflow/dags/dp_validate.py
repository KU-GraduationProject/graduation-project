"""
### Phase 4 — 검증 (Track D `dp_validate`)

`dp_gold` asset이 갱신되면 실행하고, 갱신이 없어도 매일 19:00 UTC(04:00 KST)에 1회 실행한다. 검사를 병렬로 돌리고 하나라도 실패하면 DAG가 실패한다.
- `check_manifests`: manifest가 가리키는 파일의 존재·행 수·bytes·sha256 (DQ-B02)
- `check_raw_pages`: raw page 존재와 압축 전 sha256, acquisition `row_count` (DQ-B02)
- `check_pointers`: `current` 포인터가 commit된 manifest와 그 데이터셋을 가리키는지
- `check_silver`: 현재 Silver build의 PK 유일·모든 Bronze 행 설명 (DQ-S01/S02)
- `check_lineage`: edge 부모·inputs 체인·run 기록·git_sha (DQ-L01, 03 §7)

manifest가 참조하지 않는 데이터 파일(orphan)은 경고로만 보고하고 삭제하지 않는다.
"""
from airflow.sdk import AssetOrTimeSchedule, CronTriggerTimetable, dag, task

from dp_assets import GOLD, START
from orchestration import phases
from orchestration import validate as checks


# Gold 갱신 직후 + 일 1회(05 §5 Track D 후속). 일 1회 실행은 build가 없는 날에도 포인터·orphan을 검사한다.
DAILY = CronTriggerTimetable("0 19 * * *", timezone="UTC")


@dag(dag_id="dp_validate", schedule=AssetOrTimeSchedule(timetable=DAILY, assets=GOLD), start_date=START,
     catchup=False, max_active_runs=1,
     tags=["data-platform", "phase:4-validate"], doc_md=__doc__)
def dp_validate():
    @task
    def check_manifests() -> list[str]:
        return checks.check_manifests(phases.store())

    @task
    def check_raw_pages() -> list[str]:
        return checks.check_raw_pages(phases.store())

    @task
    def check_pointers() -> list[str]:
        return checks.check_pointers(phases.store())

    @task
    def check_silver() -> list[str]:
        return checks.check_silver(phases.store())

    @task
    def check_lineage() -> list[str]:
        return checks.check_lineage(phases.store())

    @task
    def find_orphans() -> list[str]:
        return checks.find_orphans(phases.store())

    @task
    def report(manifests: list[str], raw_pages: list[str], pointers: list[str], silver: list[str],
               lineage: list[str], orphans: list[str]) -> dict:
        return checks.summarize({"manifests": manifests, "raw_pages": raw_pages, "pointers": pointers,
                                 "silver": silver, "lineage": lineage}, orphans)

    report(check_manifests(), check_raw_pages(), check_pointers(), check_silver(), check_lineage(), find_orphans())


dp_validate()
