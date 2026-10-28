"""
Container remediation actions using docker-py SDK.

DEPRECATED (Phase 2): main.py 는 더 이상 이 모듈을 쓰지 않는다.
조치는 executor/local_docker.py 의 LocalDockerExecutor 가 수행한다 — 조치 후 상태를
재조회해 확인하고, 복구 조치(UNPAUSE/RECONNECT/UNTHROTTLE)와 짝을 이루며, 네트워크
이름을 하드코딩하지 않는다. 이 파일의 isolate() 는 네트워크를 찾지 못해도 예외를
던지지 않아 호출자가 성공으로 기록하던 문제가 있었다.

Phase 3(원격 Agent) 작업 때 함께 제거한다. 새 코드는 실행기 인터페이스를 쓴다.
"""

import logging
import os
import docker

logger = logging.getLogger(__name__)

LEAFY_NETWORK = os.getenv("LEAFY_NETWORK", "graduation-project_leafy-net")


class ContainerActions:
    def __init__(self):
        self.client = docker.from_env()

    def restart(self, container_name: str) -> None:
        """Restart a container by name."""
        container = self.client.containers.get(container_name)
        logger.info(f"[ContainerActions] Restarting: {container_name}")
        container.restart()
        logger.info(f"[ContainerActions] Restarted: {container_name}")

    def isolate(self, container_name: str) -> None:
        """Isolate a container by disconnecting it from leafy-net."""
        container = self.client.containers.get(container_name)
        try:
            network = self.client.networks.get(LEAFY_NETWORK)
            network.disconnect(container)
            logger.info(f"[ContainerActions] Isolated {container_name} from leafy-net")
        except docker.errors.NotFound:
            logger.warning(f"[ContainerActions] network {LEAFY_NETWORK} not found; skipping isolation")
        except docker.errors.APIError as e:
            logger.error(f"[ContainerActions] Isolate failed for {container_name}: {e}")
            raise

    def pause(self, container_name: str) -> None:
        """Pause all processes in a container (forensic preservation)."""
        container = self.client.containers.get(container_name)
        logger.info(f"[ContainerActions] Pausing: {container_name}")
        container.pause()
        logger.info(f"[ContainerActions] Paused: {container_name}")

    def throttle(self, container_name: str, cpu_quota: int = 50000) -> None:
        """Throttle CPU usage by setting cpu_quota (default 50% of one core).

        cpu_period defaults to 100000 µs (100ms).
        cpu_quota=50000 means 50ms per 100ms → 50% of one core.
        """
        container = self.client.containers.get(container_name)
        logger.info(f"[ContainerActions] Throttling {container_name}: cpu_quota={cpu_quota}")
        container.update(cpu_quota=cpu_quota)
        logger.info(f"[ContainerActions] Throttled: {container_name} cpu_quota={cpu_quota}")
