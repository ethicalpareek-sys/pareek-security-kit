"""Robust input validators."""
from __future__ import annotations
import ipaddress, re, urllib.parse
from pathlib import Path

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_ALLOWED = frozenset({"http", "https"})
_FN_RE = re.compile(r"[^A-Za-z0-9._-]+")


class ValidationError(ValueError):
    pass


def validate_domain(value):
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Domain is empty.")
    c = value.strip().rstrip(".").lower()
    if not _DOMAIN_RE.match(c):
        raise ValidationError(f"Invalid domain: {value!r}")
    if "." not in c:
        raise ValidationError(f"Domain must contain a dot: {value!r}")
    return c


def validate_ip(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError) as exc:
        raise ValidationError(f"Invalid IP: {value!r}") from exc


def validate_host(value):
    value = value.strip()
    try:
        return validate_ip(value)
    except ValidationError:
        return validate_domain(value)


def validate_url(value, *, require_scheme=True):
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("URL is empty.")
    c = value.strip()
    if require_scheme and "://" not in c:
        c = "https://" + c
    p = urllib.parse.urlsplit(c)
    if p.scheme.lower() not in _ALLOWED:
        raise ValidationError(f"Unsupported scheme: {p.scheme!r}")
    if not p.netloc or not p.hostname:
        raise ValidationError(f"No host in URL: {value!r}")
    try:
        validate_host(p.hostname)
    except ValidationError as exc:
        raise ValidationError(f"Bad host {p.hostname!r}: {exc}") from exc
    return urllib.parse.urlunsplit(p)


def validate_port(port, *, allow_zero=False):
    try:
        p = int(port)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"Port must be int: {port!r}") from exc
    low = 0 if allow_zero else 1
    if not (low <= p <= 65535):
        raise ValidationError(f"Port out of range: {p}")
    return p


def validate_port_range(spec):
    if not spec or not isinstance(spec, str):
        raise ValidationError("Port range empty.")
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, _, hi_s = chunk.partition("-")
            lo, hi = validate_port(lo_s), validate_port(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(validate_port(chunk))
    if not ports:
        raise ValidationError(f"No valid ports: {spec!r}")
    return sorted(ports)


def validate_threads(value, *, hard_cap=512):
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"Threads must be int: {value!r}") from exc
    if n < 1:
        raise ValidationError("Threads must be >= 1.")
    if n > hard_cap:
        raise ValidationError(f"Threads capped at {hard_cap}.")
    return n


def validate_timeout(value, *, maximum=300.0):
    try:
        t = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"Timeout must be number: {value!r}") from exc
    if t <= 0 or t > maximum:
        raise ValidationError(f"Timeout must be in (0, {maximum}].")
    return t


def safe_output_path(path, *, base=None):
    base = (base or Path.cwd()).resolve()
    cand = (base / Path(path)).resolve()
    try:
        cand.relative_to(base)
    except ValueError as exc:
        raise ValidationError(f"Path escapes base: {cand}") from exc
    return cand


def sanitize_filename(name, *, replacement="_"):
    cleaned = _FN_RE.sub(replacement, name).strip("._-")
    return cleaned or "unnamed"


def confirm_authorization(target, *, assume_yes=False):
    if assume_yes:
        return True
    try:
        print(f"\n\033[93m⚠  About to test: \033[1m{target}\033[0m\n"
              "\033[93m⚠  Do you have explicit written authorization? [y/N]: \033[0m", end="")
        ans = input().strip().lower()
        return ans in {"y", "yes"}
    except (EOFError, KeyboardInterrupt):
        return False
