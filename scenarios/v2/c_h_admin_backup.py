"""
C-h — 정상 관리 작업(백업·내보내기) (F2-c·S2-e 대조, scenarios-v2 2차).

정상 상황: 운영자가 **읽기 전용 백업(pg_dump) 1회**를 돈다. 짧은 시간에 전체 테이블을 순차로 읽어
  DB 읽기량이 튀지만 쓰기·연결 고갈이 없고 1회로 끝난다. S2-e(반복 대량 조회)·F2-c(연결 고갈)와
  구분돼야 한다.

주입: F3-a 의 실행 전 백업과 같은 경로(f3a.preflight_backup: docker exec 안 pg_dump -Fc →
  pg_restore --list 검증, 자격증명은 컨테이너 env 로만)로 저장소 밖 backup_dir 에 1회 덤프.
정리: 없음(읽기 전용). 덤프 파일은 저장소 밖에 남는다(운영 백업과 같음).
"""

from __future__ import annotations

import os

from v2 import f3a_bad_image_deploy as f3a


def inject(backup_dir: str | None = None):
    backup_dir = backup_dir or os.environ.get("CH_BACKUP_DIR") or os.environ.get("F3A_BACKUP_DIR")
    if not backup_dir:
        raise ValueError("backup_dir(저장소 밖 경로) 필요: CH_BACKUP_DIR")
    return f3a.preflight_backup(backup_dir)


def dry_run() -> dict:
    return {"dump_argv": f3a.pg_dump_argv(), "verify_argv": f3a.pg_restore_list_argv(),
            "pair": ["f2_c_db_pool_exhaustion", "s2_e_db_bulk_read"],
            "env": ["CH_BACKUP_DIR", "F3A_DB_CONTAINER"], "note": "pg_dump 1회, 읽기 전용"}


def main(**kw):
    return inject(**kw)


if __name__ == "__main__":
    main()
