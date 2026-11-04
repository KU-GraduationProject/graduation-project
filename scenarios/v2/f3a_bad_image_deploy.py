"""
F3-a — 잘못된 이미지 배포 (scenarios-v2).

위협 정의: 서비스가 깨진 이미지/설정으로 배포돼 기동에 실패한다(crashloop 또는 헬스 실패).
  증거는 반복 재시작 또는 기동/헬스 실패 로그다.

주입: 대상 컨테이너를 실패하는 명령으로 재생성해 "잘못된 배포"를 만든다.
  - crashloop        : 즉시 비정상 종료 → 재시작 반복.
  - healthcheck-fail : 떠 있지만 서비스를 열지 않아 헬스가 계속 실패.
정리: 주입 전에 **원본 이미지/설정을 기록**하고, 정리에서 원본으로 재배포한다(완전 가역).
  상태 저장 서비스(DB·MinIO)는 대상에서 제외한다 — 데이터 볼륨 무변경.

파라미터: 실패 양상(mode)과 지속 시간. 근거는 룰 임계가 아니라 실제 배포 실패 양상이다.

자기신고 없음: Loki/pipeline 에 아무것도 쓰지 않는다. 증거는 "실제 기동 실패"뿐이다.

순수 로직(mode → 실패 명령, 원본 기록 형식)은 단위 테스트, 재생성은 Docker 필요 — UNVERIFIED.
"""

from __future__ import annotations

DEFAULT_TARGET = "leafy-backend"
# 상태 저장 서비스는 대상에서 제외(데이터 안전).
FORBIDDEN_TARGETS = ("leafy-db", "leafy-minio")

MODES = ("crashloop", "healthcheck-fail")
DEFAULT_MODE = "crashloop"
DEFAULT_DURATION_SECONDS = 180


# --------------------------------------------------------------------------- #
# 순수 로직 (단위 테스트 대상)
# --------------------------------------------------------------------------- #

def failing_command(mode: str = DEFAULT_MODE) -> list[str]:
    """실패 양상 → 컨테이너 엔트리 명령."""
    if mode == "crashloop":
        return ["sh", "-c", "exit 1"]                 # 즉시 비정상 종료 → 재시작 반복
    if mode == "healthcheck-fail":
        return ["sh", "-c", "sleep infinity"]         # 떠 있지만 서비스 미개방 → 헬스 실패
    raise ValueError(f"unknown mode: {mode}")


def assert_target_allowed(target: str) -> None:
    """상태 저장 서비스는 대상 금지(데이터 안전 가드)."""
    if target in FORBIDDEN_TARGETS:
        raise ValueError(f"대상 금지(상태 저장 서비스): {target}")


def capture_original(container_attrs: dict) -> dict:
    """정리 때 복원할 원본 배포 정보. 이미지/엔트리/명령만 보관."""
    cfg = container_attrs.get("Config", {})
    return {"image": cfg.get("Image"),
            "entrypoint": cfg.get("Entrypoint"),
            "cmd": cfg.get("Cmd")}


# --------------------------------------------------------------------------- #
# docker 런타임 (UNVERIFIED)
# --------------------------------------------------------------------------- #

def inject(mode: str = DEFAULT_MODE, target: str = DEFAULT_TARGET,
           duration_seconds: int = DEFAULT_DURATION_SECONDS):
    """
    원본을 기록하고 대상을 실패 명령으로 재생성한다. 반환된 원본 정보로 cleanup 이 복원한다.
    실제 재생성은 측정 PC에서 compose 기반으로 하는 것을 권장(여기선 docker-py 경로를 기록).
    """
    import docker
    assert_target_allowed(target)
    client = docker.from_env()
    container = client.containers.get(target)
    original = capture_original(container.attrs)
    print(f"[F3-a] mode={mode} target={target} original_image={original['image']}", flush=True)
    # 재생성은 환경에 따라 다르므로 측정 PC에서 확정. 여기선 원본 정보와 실패 명령만 돌려준다.
    return {"mode": mode, "target": target, "original": original,
            "failing_command": failing_command(mode), "duration_seconds": duration_seconds}


def cleanup(meta: dict) -> None:
    """원본 이미지/설정으로 재배포(완전 가역). 데이터 볼륨은 건드리지 않는다."""
    if not meta:
        return
    print(f"[F3-a] cleanup: {meta.get('target')} 를 원본({meta.get('original', {}).get('image')})"
          f"으로 복원 (측정 PC: compose up -d --force-recreate)", flush=True)


def dry_run() -> dict:
    return {"mode": DEFAULT_MODE, "target": DEFAULT_TARGET,
            "failing_command": failing_command(DEFAULT_MODE),
            "forbidden_targets": list(FORBIDDEN_TARGETS)}


def main():
    meta = None
    try:
        meta = inject()
    finally:
        cleanup(meta)


if __name__ == "__main__":
    main()
