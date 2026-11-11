"""Source-aware RCA identity. All bindings are operator-verified, never discovered locally."""
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field

UNKNOWN = "UNKNOWN"
FIELDS = ("site", "service", "runtime", "target", "source", "job", "instance", "observer")
PLACEHOLDERS = {"unknown", "unknown (host-level)", "n/a", "none", ""}
LABEL = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def known(value):
    return value if isinstance(value, str) and value.strip().lower() not in PLACEHOLDERS else None


def selector(labels):
    return "{" + ",".join(f"{k}={json.dumps(v, ensure_ascii=False)}" for k, v in sorted(labels.items())) + "}"


def matches(actual, expected):
    return all(actual.get(k) == v for k, v in expected.items())


@dataclass(frozen=True)
class ObservationIdentity:
    site: str | None = None
    service: str | None = None
    runtime: str | None = None
    target: str | None = None
    source: str | None = None
    job: str | None = None
    instance: str | None = None
    observer: str | None = None

    def to_dict(self):
        return {k: v or UNKNOWN for k, v in asdict(self).items()}

    @property
    def complete(self):
        return all(known(getattr(self, k)) for k in FIELDS[:5]) and self.runtime in ("host", "container")


@dataclass(frozen=True)
class ObservationBinding:
    identity: ObservationIdentity
    match: dict = field(default_factory=dict)
    logs: dict = field(default_factory=dict)
    metrics: dict = field(default_factory=dict)
    network: dict = field(default_factory=dict)
    metrics_profile: str = "cadvisor"


def parse_bindings(raw):
    """OBSERVATION_BINDINGS JSON list. No endpoints, credentials or implicit defaults."""
    rows = json.loads(raw or "[]")
    if not isinstance(rows, list):
        raise ValueError("OBSERVATION_BINDINGS must be a list")
    out = []
    for row in rows:
        if set(row) - {"identity", "match", "logs", "metrics", "network", "metrics_profile"}:
            raise ValueError("unsupported observation binding fields")
        identity = ObservationIdentity(**row["identity"])
        if not identity.complete or identity.source.lower() in ("stdout", "stderr"):
            raise ValueError("binding requires site/service/runtime/target/source")
        maps = {k: row.get(k, {}) for k in ("match", "logs", "metrics", "network")}
        for values in maps.values():
            if not isinstance(values, dict) or any(
                not LABEL.fullmatch(k) or not isinstance(v, str) or not known(v) for k, v in values.items()
            ):
                raise ValueError("binding selectors must contain nonempty exact label values")
        for k, v in maps["match"].items():
            if k in FIELDS and getattr(identity, k) and v != getattr(identity, k):
                raise ValueError("match contradicts binding identity")
        m = maps["match"]
        if not ((m.get("source") and m["source"] not in ("stdout", "stderr"))
                or (m.get("observer") and m.get("observer_instance")) or (m.get("job") and m.get("instance"))
                or (m.get("site") and m.get("target"))):
            raise ValueError("binding match needs an explicit source or site/target")
        logs, metrics, network = maps["logs"], maps["metrics"], maps["network"]
        if logs and not (logs.get("service") == identity.service and logs.get("runtime") == identity.runtime
                         and logs.get("site") == identity.site
                         and (logs.get("target") == identity.target or logs.get("container_name") == identity.target)):
            raise ValueError("logs require verified site/service/runtime and target (or container_name)")
        if metrics and any(metrics.get(k) and metrics[k] != getattr(identity, k) for k in ("site", "service", "runtime")):
            raise ValueError("metrics scope contradicts binding identity")
        if metrics and not (metrics.get("job") and metrics.get("instance")):
            raise ValueError("metrics require exact job/instance mapped to this site")
        if metrics and identity.runtime == "container" and not re.fullmatch(r"/docker/[a-f0-9]{64}", metrics.get("id", "")):
            raise ValueError("container metrics require a verified full cAdvisor /docker/<id>")
        if identity.runtime == "host" and metrics.get("id"):
            raise ValueError("host metrics cannot use a container id")
        if network and not (network.get("observer") and network.get("observer_instance")):
            raise ValueError("network requires verified observer and observer_instance")
        if network and set(network) - {"observer", "observer_instance"}:
            raise ValueError("network supports observer and observer_instance only")
        profile = row.get("metrics_profile", "cadvisor")
        if profile not in ("cadvisor", "gc-telemetry-v1"):
            raise ValueError("unsupported metrics profile")
        if profile == "gc-telemetry-v1" and (identity.runtime != "container" or
                any(metrics.get(k) != getattr(identity, k) for k in FIELDS[:5])):
            raise ValueError("GC telemetry metrics need all five exact identity labels")
        out.append(ObservationBinding(identity, **maps, metrics_profile=profile))
    return tuple(out)


def resolve_identity(labels, annotations, bindings=(), legacy_map=None):
    """Return (identity, binding, status). Never inspect the Pipeline PC's Docker daemon."""
    supplied = {k: known(labels.get(k)) or known(annotations.get(k)) for k in FIELDS}
    # Existing Fluentd `source` is stdout/stderr, not a PC or producer identity.
    # Retain it in raw alert labels and dedup, but do not promote it to observation source.
    if (supplied["source"] or "").lower() in ("stdout", "stderr"):
        supplied["source"] = None
    invalid_runtime = supplied["runtime"] not in (None, "host", "container")
    if invalid_runtime:
        supplied["runtime"] = None
    target = (supplied["target"] or known(annotations.get("container"))
              or known(labels.get("container")) or known(labels.get("name")))
    supplied["target"] = target
    host = labels.get("id") == "/" or any(
        str(v).lower() == "unknown (host-level)" for v in (annotations.get("container"), labels.get("container"))
    )
    conflict = invalid_runtime or any(known(labels.get(k)) and known(annotations.get(k))
                   and labels[k] != annotations[k] for k in FIELDS)
    if host:
        conflict = conflict or supplied["runtime"] not in (None, "host")
        supplied["runtime"] = "host"
        # A root cgroup's name is never an application container identity.
        supplied["target"] = known(labels.get("target")) or known(annotations.get("target"))
    identity = ObservationIdentity(**supplied)
    if conflict:
        return identity, None, "identity_conflict"
    actual = {**annotations, **labels, **{k: v for k, v in supplied.items() if v is not None}}
    candidates = [b for b in bindings if matches(actual, b.match)]
    def compatible_source(b):
        for k, value in supplied.items():
            expected = getattr(b.identity, k) or b.match.get(k)
            if k in ("job", "instance"):
                expected = expected or b.metrics.get(k)
            if k == "observer":
                expected = expected or b.network.get(k)
            if value and expected and value != expected:
                return False
            if value and k in ("job", "instance", "observer") and not expected:
                return False
        if host and not supplied["target"] and b.identity.service != "host":
            return False
        if b.identity.runtime == "container":
            if known(labels.get("id")) and b.metrics.get("id") != labels["id"]:
                return False
            if any(known(labels.get(k)) and labels[k] != b.identity.target for k in ("name", "container")):
                return False
        return True
    compatible = [b for b in candidates if compatible_source(b)]
    if len(compatible) == 1:
        b = compatible[0]
        values = {k: supplied[k] or getattr(b.identity, k) for k in FIELDS}
        return ObservationIdentity(**values), b, "resolved"
    if candidates:
        return identity, None, "identity_conflict" if not compatible else "ambiguous_source"
    # Old alias maps are metadata hints only. They cannot establish site/source or runtime.
    if not identity.service and legacy_map and target in legacy_map:
        supplied["service"] = legacy_map[target][0]
        identity = ObservationIdentity(**supplied)
    return identity, None, "source_unmapped" if identity.source or identity.job or identity.site else "source_unknown"


def dedup_key(alertname, identity, labels, annotations):
    # Keep producer distinctions even for incomplete identities. startsAt/fingerprint are excluded
    # so repeat notifications retain the existing 300s policy.
    dimensions = {k: labels.get(k) or annotations.get(k) for k in
                  (*FIELDS, "id", "container", "name", "rulepack_target", "rulepack_source", "observer_instance")}
    # Preserve unrecognized producer labels too (e.g. an existing cluster/source_pc label).
    dimensions["labels"] = {k: v for k, v in labels.items() if v is not None and k not in ("alertname", "severity")}
    raw = json.dumps([alertname, identity.to_dict(), dimensions], sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()


class LogEvidence(list):
    """List-compatible collector result with explicit availability/provenance metadata."""
    def __init__(self, rows=(), **report):
        super().__init__(rows)
        self.report = report


class MetricEvidence(dict):
    def __init__(self, rows=None, **report):
        super().__init__(rows or {})
        self.report = report
