"""
Identity enrichment: observed IP -> (service, container, runtime, network).

3단계 fallback (NETWORK_EVENT_SCHEMA.md §7):
  1. Container endpoint : Docker runtime metadata 기반 매핑
  2. Host endpoint      : 설정 기반 명시적 (ip, port) 매핑
  3. Unknown            : 해석 실패 시 unknown (event를 버리지 않는다)

원칙:
  - service는 logical identity (compose service 이름)
  - container는 runtime deployment identity -> nullable
  - IP는 identity가 아니라 observed fact -> 매핑 입력으로만 쓰고 키로 보존하지 않는다
  - IP / subnet / 컨테이너 이름을 코드에 하드코딩하지 않는다 (전부 설정 또는 Docker API 유래)
"""

import logging
import threading
import time

import docker

logger = logging.getLogger(__name__)

RUNTIME_CONTAINER = "container"
RUNTIME_HOST = "host"
RUNTIME_UNKNOWN = "unknown"

# Canonical Event가 요구하는 endpoint identity 묶음
class Endpoint:
    __slots__ = ("service", "container", "runtime", "network")

    def __init__(self, service, container, runtime, network):
        self.service = service
        self.container = container
        self.runtime = runtime
        self.network = network


class IdentityResolver:
    """
    Docker metadata와 설정을 결합해 endpoint identity를 해석한다.

    Docker metadata는 컨테이너 재생성 시 IP가 바뀌므로 주기적으로 갱신한다.
    """

    def __init__(self, config, docker_client=None):
        self._cfg = config
        self._docker = docker_client
        self._lock = threading.Lock()
        self._ip_index = {}      # ip -> Endpoint (container runtime)
        self._last_refresh = 0.0

        self._docker_networks = config.get("docker_networks") or {}
        self._refresh_interval = float(config.get("refresh_interval_sec", 30))

        unknown_cfg = config.get("unknown") or {}
        self._unknown_service = unknown_cfg.get("service", "unknown")
        self._unknown_runtime = unknown_cfg.get("runtime", RUNTIME_UNKNOWN)

        # host_endpoints: 설정 기반 명시적 매핑. Docker로는 해결 불가한 endpoint용.
        self._host_endpoints = []
        for entry in (config.get("host_endpoints") or []):
            self._host_endpoints.append({
                "ip": entry.get("ip"),            # None이면 port만으로 매칭
                "port": entry.get("port"),
                "service": entry.get("service", self._unknown_service),
                "network": entry.get("network", "host-bound"),
            })

    # ------------------------------------------------------------------ #
    # Docker metadata
    # ------------------------------------------------------------------ #

    def refresh(self, force=False):
        """Docker에서 ip -> (service, container, network) 인덱스를 다시 만든다."""
        now = time.monotonic()
        if not force and (now - self._last_refresh) < self._refresh_interval:
            return

        if self._docker is None:
            self._last_refresh = now
            return

        index = {}
        try:
            for container in self._docker.containers.list():
                labels = container.labels or {}
                # compose service 이름이 곧 canonical logical service다.
                # 없으면(비-compose 컨테이너) 컨테이너 이름으로 대체한다.
                service = labels.get("com.docker.compose.service") or container.name
                networks = (
                    container.attrs.get("NetworkSettings", {}).get("Networks", {}) or {}
                )
                for docker_net_name, net in networks.items():
                    logical_network = self._docker_networks.get(docker_net_name)
                    if logical_network is None:
                        # 설정에 없는 network는 매핑 대상이 아니다 (범위 밖 트래픽)
                        continue
                    for ip in (net.get("IPAddress"), net.get("GlobalIPv6Address")):
                        if ip:
                            index[ip] = Endpoint(
                                service=service,
                                container=container.name,
                                runtime=RUNTIME_CONTAINER,
                                network=logical_network,
                            )
        except Exception as exc:  # Docker 접근 실패가 event 유실로 이어지면 안 된다
            logger.warning("Docker metadata 갱신 실패 (unknown으로 처리): %s", exc)
            self._last_refresh = now
            return

        with self._lock:
            self._ip_index = index
            self._last_refresh = now
        logger.info("Docker metadata 갱신: %d개 IP 매핑", len(index))

    # ------------------------------------------------------------------ #
    # Resolution
    # ------------------------------------------------------------------ #

    def resolve(self, ip, port):
        """
        observed (ip, port) -> Endpoint.

        순서가 중요하다. host_endpoints를 먼저 보는 이유는, Docker Desktop에서
        host 목적지가 gateway 주소로 관측되는데 그 주소가 Docker network 대역과
        겹칠 가능성을 배제할 수 없기 때문이다. 명시적 설정이 항상 우선한다.
        """
        host_ep = self._match_host_endpoint(ip, port)
        if host_ep is not None:
            return host_ep

        with self._lock:
            container_ep = self._ip_index.get(ip)
        if container_ep is not None:
            return container_ep

        # 캐시에 없으면 1회 강제 갱신 후 재시도 (새로 뜬 컨테이너 대응)
        self.refresh(force=True)
        with self._lock:
            container_ep = self._ip_index.get(ip)
        if container_ep is not None:
            return container_ep

        return Endpoint(
            service=self._unknown_service,
            container=None,
            runtime=self._unknown_runtime,
            network=None,
        )

    def _match_host_endpoint(self, ip, port):
        for entry in self._host_endpoints:
            if entry["port"] is not None and entry["port"] != port:
                continue
            if entry["ip"] is not None and entry["ip"] != ip:
                continue
            return Endpoint(
                service=entry["service"],
                container=None,          # host runtime에는 container가 없다
                runtime=RUNTIME_HOST,
                network=entry["network"],
            )
        return None
