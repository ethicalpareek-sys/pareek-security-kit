#!/usr/bin/env python3
"""PAREEK SECURITY KIT v2.0 - Next-Level Authorized Testing Toolkit."""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.cli import main  # noqa: E402


def _entry() -> int:
    try:
        return main()
    except KeyboardInterrupt:
        print("\n\033[33m[!] Interrupted by user.\033[0m")
        return 130
    except BrokenPipeError:
        return 0
    except Exception as exc:
        print(f"\033[31m[!] Fatal: {exc}\033[0m", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(_entry())
