"""
Container remediation actions using docker-py SDK.
"""

import logging
import docker

logger = logging.getLogger(__name__)


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
            network = self.client.networks.get("graduation-project_leafy-net")
            network.disconnect(container)
            logger.info(f"[ContainerActions] Isolated {container_name} from leafy-net")
        except docker.errors.NotFound:
            logger.warning(f"[ContainerActions] leafy-net not found; skipping isolation")
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
