"""
2차 네트워크형 시나리오 공용 — backend netns 공유 사이드카 실행.

S2-b(비컨) / S2-d(내부 정찰) / C-j(허용 목적지 호출)는 연결이 backend 의 eth0 으로 나가야
Zeek(backend netns 캡처)가 src=backend 로 관측한다. 그래서 팀원 S2/C-a 와 같은 방식으로
`--network container:<backend>` 사이드카에서 짧은 Python 스크립트를 돌린다(Spring 이미지 무수정).

이미지: 기본은 팀원 송신기 이미지(s2-sender, python 포함). env V2_NET_IMAGE 로 바꾼다.
자기신고 없음: 사이드카 이름은 중립(run 별 랜덤), 스크립트·헤더에 정답 암시 문자열을 넣지 않는다.

순수 로직(argv 생성)은 단위 테스트, 실행은 Docker 필요 — UNVERIFIED (측정 PC).
"""

from __future__ import annotations

import os
import secrets
import shlex

NET_IMAGE = os.getenv("V2_NET_IMAGE", "s2-sender:latest")
BACKEND_CONTAINER = os.getenv("V2_BACKEND_CONTAINER", "leafy-backend")


def sidecar_name(prefix: str = "v2net") -> str:
    """run 별 중립 이름(정리 대상 식별용)."""
    return f"{prefix}-{secrets.token_hex(4)}"


def sidecar_argv(script: str, name: str, backend: str = BACKEND_CONTAINER,
                 image: str = NET_IMAGE) -> list[str]:
    """backend netns 를 공유하는 detached 사이드카 argv. --rm 으로 끝나면 스스로 지워진다."""
    if not script.strip():
        raise ValueError("script 가 비어 있음")
    return ["docker", "run", "-d", "--rm", "--name", name,
            "--network", f"container:{backend}",
            "--entrypoint", "python", image, "-c", script]


def kill_sh(name: str) -> str:
    """정리/워치독 복구 명령(호스트 sh): 사이드카 강제 종료. 이미 끝났으면 무시."""
    return f"docker rm -f {shlex.quote(name)} >/dev/null 2>&1; true"


def start(script: str, name: str, backend: str = BACKEND_CONTAINER, image: str = NET_IMAGE) -> None:
    """사이드카 기동(런타임, UNVERIFIED). 출력은 버린다(목적지·비밀 노출 방지)."""
    import subprocess
    subprocess.run(sidecar_argv(script, name, backend, image), check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop(name: str) -> None:
    import subprocess
    subprocess.run(["sh", "-c", kill_sh(name)], check=False)
