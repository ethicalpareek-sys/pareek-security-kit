"""Structured logger with color + rotation."""
from __future__ import annotations
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from core.banner import Colors

_LOGGER_NAME = "pareek"
_configured = False


class _ColorFormatter(logging.Formatter):
    _MAP = {
        "DEBUG":    Colors.dim,
        "INFO":     Colors.cyan,
        "WARNING":  Colors.yellow,
        "ERROR":    Colors.red,
        "CRITICAL": lambda s: Colors.bold(Colors.red(s)),
    }
    _ICONS = {"DEBUG": "·", "INFO": "▸", "WARNING": "⚠", "ERROR": "✗", "CRITICAL": "☠"}

    def format(self, record):
        msg = super().format(record)
        paint = self._MAP.get(record.levelname)
        painted = paint(msg) if paint else msg
        icon = self._ICONS.get(record.levelname, "·")
        return f"{icon} {painted}"


def setup_logger(verbose=False, quiet=False, log_file=None):
    global _configured
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    if _configured:
        return logger
    if not quiet:
        ch = logging.StreamHandler(stream=sys.stderr)
        ch.setLevel(logging.DEBUG if verbose else logging.INFO)
        ch.setFormatter(_ColorFormatter("%(message)s"))
        logger.addHandler(ch)
    if log_file is not None:
        try:
            p = Path(log_file).expanduser().resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            fh = RotatingFileHandler(p, maxBytes=2*1024*1024, backupCount=3, encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
            logger.addHandler(fh)
        except OSError as exc:
            logger.warning("log file: %s", exc)
    _configured = True
    return logger


def get_logger(name=None):
    return logging.getLogger(f"{_LOGGER_NAME}.{name}" if name else _LOGGER_NAME)
