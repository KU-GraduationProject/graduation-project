"""
Application Log / Network Event correlation identity (#9)

canonical identity는 `service`다 (docs/network-observability/NETWORK_EVENT_SCHEMA.md §4).
  - Application Log (#6): Loki label `service`
  - Network Event  (#8): Loki label `src_service` / `dst_service`
둘 다 Compose의 com.docker.compose.service 라벨에서 온 같은 이름(frontend/backend/db)을 쓴다.

container 이름(leafy-backend)은 runtime metadata일 뿐 Loki 조회 identity로 쓰지 않는다.
  - legacy {container="..."} 조회는 Fluentd tag 기준이라 값이 섞여 있고(frontend/backend/leafy-db),
    {container="leafy-backend"}는 application log가 아니라 aiops-llm 자체 출력을 반환한다.
"""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx

DOCKER_UDS = "/var/run/docker.sock"
COMPOSE_SERVICE_LABEL = "com.docker.compose.service"

# 주기적 스캔 대상 (canonical service 이름)
MONITORED_SERVICES = ("backend", "frontend", "db")

# Compose service 이름 규칙. LogQL selector에 넣기 전에 검증한다.
_SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def _checked(service: str) -> str:
    if not service or not _SERVICE_NAME.match(service):
        raise ValueError(f"invalid service name: {service!r}")
    return service


def service_log_selector(service: str) -> str:
    """canonical service의 Application Log 조회 selector."""
    return f'{{service="{_checked(service)}"}}'


def network_event_selectors(service: str) -> tuple[str, str]:
    """
    canonical service가 관여한 Network Event selector (#8 label 기준).

    LogQL stream selector는 서로 다른 label 간 OR를 지원하지 않으므로
    출발(src) / 도착(dst) 두 개로 나눈다. (NETWORK_EVENT_SCHEMA.md §10.2)
    """
    s = _checked(service)
    return (
        f'{{log_type="network", src_service="{s}"}}',
        f'{{log_type="network", dst_service="{s}"}}',
    )


async def resolve_service(
    container_name: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[str | None, str | None]:
    """
    container 이름 -> (service, runtime).

    Docker metadata(compose service 라벨)로만 해석한다. 이름 문자열을 가공하지 않는다.
    컨테이너가 없거나 compose 라벨이 없으면 (None, None) — 호출 측은 app log 조회를 건너뛴다.
    잘못된 identity로 조회해 엉뚱한 로그를 얻는 것보다 빈 결과가 낫다.
    """
    if not container_name:
        return None, None
    try:
        async with httpx.AsyncClient(
            transport=transport or httpx.AsyncHTTPTransport(uds=DOCKER_UDS),
            base_url="http://docker",
            timeout=3,
        ) as client:
            resp = await client.get(f"/containers/{container_name}/json")
            if resp.status_code != 200:
                return None, None
            labels = (resp.json().get("Config") or {}).get("Labels") or {}
    except (httpx.HTTPError, ValueError):
        return None, None

    service = labels.get(COMPOSE_SERVICE_LABEL)
    return (service, "container") if service else (None, None)


def to_instant(value) -> datetime:
    """
    timestamp -> UTC aware datetime (instant).

    Application Log와 Network Event는 offset 표기가 다를 수 있다 (예: +09:00 vs Z).
    문자열로 비교하지 말고 이 함수로 instant를 만든 뒤 비교한다.

    허용: aware datetime / ISO-8601 문자열(offset 또는 Z 필수) / epoch nanoseconds(int 또는 숫자 문자열, Loki 형식)
    offset 없는 시각은 어느 timezone인지 알 수 없으므로 거부한다.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        return datetime.fromtimestamp(int(value) / 1e9, tz=timezone.utc)
    elif isinstance(value, str):
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise TypeError(f"unsupported timestamp: {value!r}")

    if dt.tzinfo is None:
        raise ValueError(f"timestamp without offset is ambiguous: {value!r}")
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class CorrelationContext:
    """
    Application Log / Network Event / Metrics를 같은 기준으로 조회하기 위한 문맥.

    service        : canonical identity. 조회 기준.
    start / end    : 조회 구간 (UTC instant)
    anchor         : 기준 시각 (alert 발생 시각 등)
    container_name : 보조 runtime metadata. host service(Target의 db)는 None
    runtime        : container | host | external | unknown
    request_id     : HTTP-aware 소스가 줄 때만 (L4 Network Event에는 없음)
    """

    service: str | None
    start: datetime
    end: datetime
    anchor: datetime | None = None
    container_name: str | None = None
    runtime: str | None = None
    request_id: str | None = None

    @classmethod
    def around(cls, service, anchor, window: timedelta, **meta) -> "CorrelationContext":
        """anchor ± window (alert 분석용)"""
        a = to_instant(anchor)
        return cls(service=service, start=a - window, end=a + window, anchor=a, **meta)

    @classmethod
    def trailing(cls, service, window: timedelta, now=None, **meta) -> "CorrelationContext":
        """[now - window, now] (주기적 스캔용)"""
        n = to_instant(now) if now is not None else datetime.now(timezone.utc)
        return cls(service=service, start=n - window, end=n, anchor=n, **meta)

    @property
    def start_ns(self) -> int:
        return int(self.start.timestamp() * 1e9)

    @property
    def end_ns(self) -> int:
        return int(self.end.timestamp() * 1e9)

    def contains(self, ts) -> bool:
        """ts가 구간 안인지 instant 기준으로 판단 (offset 표기와 무관)."""
        return self.start <= to_instant(ts) <= self.end
