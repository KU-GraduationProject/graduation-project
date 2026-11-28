from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from urllib.parse import urlsplit

from .state import IDENTITY_KEYS


@dataclass
class Config:
    name: str = "mac-dev"
    remediation_url: str = "http://127.0.0.1:8001"
    pipeline_url: str = "http://127.0.0.1:8000"
    prometheus_url: str = "http://127.0.0.1:9090"
    loki_url: str = "http://127.0.0.1:3100"
    airflow_url: str = "http://127.0.0.1:18080"
    identity: dict = field(default_factory=dict)
    metric_selector: dict = field(default_factory=dict)
    log_selector: dict = field(default_factory=dict)
    metric_names: dict = field(default_factory=lambda: {
        "CPU cores": "rate(container_cpu_usage_seconds_total{selector}[1m])",
        "Memory bytes": "container_memory_working_set_bytes{selector}",
        "Network RX B/s": "rate(container_network_receive_bytes_total{selector}[1m])"})
    runner: dict = field(default_factory=lambda: {"mode": "local"})
    history: str = "~/.leafy-presentation/history.sqlite3"
    timeout: int = 900
    poll_seconds: float = 3.0
    scenario_profiles: dict = field(default_factory=dict)

    def for_scenario(self, scenario_id):
        from dataclasses import asdict
        values = asdict(self)
        values.update(self.scenario_profiles.get(scenario_id, {}))
        result = Config(**values)
        result.validate()
        return result

    @classmethod
    def load(cls, path, profile=None):
        body = json.loads(Path(path).read_text(encoding="utf-8"))
        name = profile or body.get("default", "mac-dev")
        values = dict(body["profiles"][name])
        values.setdefault("history", f"~/.leafy-presentation/{name}.sqlite3")
        config = cls(name=name, **values)
        config.validate()
        return config

    def validate(self):
        if (set(self.identity) != set(IDENTITY_KEYS)
                or any(not isinstance(v, str) or not v.strip() or "REPLACE" in v for v in self.identity.values())):
            raise ValueError("프로필에 검증된 site/service/source/runtime/target을 설정하세요")
        for name in ("remediation_url", "pipeline_url", "prometheus_url", "loki_url", "airflow_url"):
            url = urlsplit(getattr(self, name))
            if (url.scheme not in {"http", "https"} or not url.hostname or url.username
                    or url.password or url.query or url.fragment):
                raise ValueError(f"{name}: credential 없는 http(s) origin이 필요합니다")
        if not 60 <= self.timeout <= 1800 or not 1 <= self.poll_seconds <= 30:
            raise ValueError("timeout=60..1800, poll_seconds=1..30")
        if self.runner.get("mode", "local") not in {"local", "ssh"}:
            raise ValueError("runner.mode must be local or ssh")
        if any("REPLACE" in str(value) for value in (self.metric_selector, self.log_selector, self.runner)):
            raise ValueError("환경 프로필의 REPLACE 값을 실제 호스트/경로/관측 라벨로 바꾸세요")


def selector(labels):
    if not labels:
        raise ValueError("정확한 관측 label selector를 설정하세요")
    import re
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) or not isinstance(v, str) or not v for k, v in labels.items()):
        raise ValueError("invalid observation selector")
    return "{" + ",".join(f"{k}={json.dumps(v)}" for k, v in sorted(labels.items())) + "}"
