"""Configuration loader."""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Defaults:
    timeout_seconds: float = 5.0
    threads: int = 50
    user_agent: str = "PareekSecurityKit/2.0 (+authorized-testing)"
    rate_limit_per_second: float = 5.0
    output_dir: str = "reports"


@dataclass(frozen=True, slots=True)
class Safety:
    require_authorization_prompt: bool = True
    allow_raw_sockets: bool = False
    allow_root_features: bool = False


@dataclass(frozen=True, slots=True)
class Config:
    defaults: Defaults = field(default_factory=Defaults)
    safety: Safety = field(default_factory=Safety)
    raw: dict = field(default_factory=dict)


def _root() -> Path:
    return Path(__file__).resolve().parent.parent


@lru_cache(maxsize=1)
def load_config(path=None):
    cfg = path or (_root() / "config" / "config.json")
    try:
        data = json.loads(cfg.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return Config()
    d = data.get("defaults", {}) or {}
    s = data.get("safety", {}) or {}
    return Config(
        defaults=Defaults(
            timeout_seconds=float(d.get("timeout_seconds", 5.0)),
            threads=int(d.get("threads", 50)),
            user_agent=str(d.get("user_agent", Defaults.user_agent)),
            rate_limit_per_second=float(d.get("rate_limit_per_second", 5.0)),
            output_dir=str(d.get("output_dir", "reports")),
        ),
        safety=Safety(
            require_authorization_prompt=bool(s.get("require_authorization_prompt", True)),
            allow_raw_sockets=bool(s.get("allow_raw_sockets", False)),
            allow_root_features=bool(s.get("allow_root_features", False)),
        ),
        raw=data,
    )


def project_root(): return _root()
