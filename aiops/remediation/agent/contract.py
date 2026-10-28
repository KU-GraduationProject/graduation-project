"""Versioned, narrow wire contract; no arbitrary Docker options or recovery evidence."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Authorization(StrictModel):
    # Attested by the authenticated Controller, not supplied by an LLM.
    decision_id: str = Field(min_length=1, max_length=128)
    approval_id: str = Field(min_length=1, max_length=128)
    kind: Literal["manual", "policy"]
    approved_by: str = Field(min_length=1, max_length=128)


class Command(StrictModel):
    remediation_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")
    action_type: Literal["RESTART", "PAUSE", "ISOLATE", "THROTTLE",
                         "UNPAUSE", "RECONNECT", "UNTHROTTLE"]
    target: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    authorization: Authorization
    expires_at: int
    ttl_seconds: int | None = Field(default=None, ge=1, le=86400)
    recovery_mode: Literal["none", "auto", "require_approval"] = "none"


class Target(StrictModel):
    container_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    image_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    labels: dict[str, str] = Field(min_length=1)
    actions: list[Literal["RESTART", "PAUSE", "ISOLATE", "THROTTLE",
                          "UNPAUSE", "RECONNECT", "UNTHROTTLE"]]
    isolate_networks: list[str] = Field(default_factory=list)
    preserve_networks: list[str] = Field(default_factory=list)


class AgentConfig(StrictModel):
    controller_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    targets: dict[str, Target] = Field(default_factory=dict)
