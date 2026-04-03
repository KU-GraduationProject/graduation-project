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
            network = self.client.networks.get("leafy-net")
            network.disconnect(container)
            logger.info(f"[ContainerActions] Isolated {container_name} from leafy-net")
        except docker.errors.NotFound:
            logger.warning(f"[ContainerActions] leafy-net not found; skipping isolation")
        except docker.errors.APIError as e:
            logger.error(f"[ContainerActions] Isolate failed for {container_name}: {e}")
            raise
