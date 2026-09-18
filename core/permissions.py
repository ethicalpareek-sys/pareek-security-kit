"""Environment + permission detection."""
from __future__ import annotations
import os, platform, shutil
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class Environment:
    is_termux: bool
    is_android: bool
    is_root: bool
    is_windows: bool
    python_version: str
    platform: str


@lru_cache(maxsize=1)
def detect_environment():
    p = os.environ.get("PREFIX", "")
    is_termux = "com.termux" in p or Path("/data/data/com.termux/files").exists()
    is_android = "ANDROID_ROOT" in os.environ or "ANDROID_DATA" in os.environ
    return Environment(
        is_termux=is_termux, is_android=is_android,
        is_root=(os.geteuid() == 0) if hasattr(os, "geteuid") else False,
        is_windows=(os.name == "nt"),
        python_version=platform.python_version(),
        platform=platform.platform(),
    )


def is_root(): return detect_environment().is_root
def is_termux(): return detect_environment().is_termux
def is_windows(): return detect_environment().is_windows
def has_command(cmd): return shutil.which(cmd) is not None


def require_root(feature):
    if not is_root():
        raise PermissionError(f"'{feature}' requires root. Aborting.")


def describe():
    from core.banner import Colors
    e = detect_environment()
    pill = lambda label, ok, color: color(f" {label} ") if ok else Colors.dim(f" {label} ")
    return (
        pill("TERMUX", e.is_termux, Colors.green) + " " +
        pill("ANDROID", e.is_android, Colors.green) + " " +
        pill("ROOT", e.is_root, Colors.yellow) + " " +
        pill(f"PY {e.python_version}", True, Colors.cyan)
    )
