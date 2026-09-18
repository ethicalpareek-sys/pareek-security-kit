"""Dependency detection with Termux/root matrix."""
from __future__ import annotations
import shutil
from dataclasses import dataclass
from core.banner import Colors
from core.permissions import is_termux
from core.subprocess_runner import Runner


@dataclass(frozen=True, slots=True)
class Dependency:
    name: str
    purpose: str
    version_args: tuple = ("--version",)
    root_required: bool = False
    termux_supported: str = "yes"
    install_hint: str = ""
    optional: bool = False


DEPENDENCIES = (
    Dependency("python3",    "Runtime",                   ("--version",), install_hint="pkg install python"),
    Dependency("pip",        "Python packages",           ("--version",), install_hint="pkg install python-pip"),
    Dependency("curl",       "HTTP requests",             ("--version",), install_hint="pkg install curl"),
    Dependency("git",        "Version control",           ("--version",), install_hint="pkg install git"),
    Dependency("openssl",    "TLS inspection",            ("version",),   install_hint="pkg install openssl-tool"),
    Dependency("dig",        "DNS queries",               ("-v",),        install_hint="pkg install dnsutils"),
    Dependency("whois",      "WHOIS lookups",             ("--version",), install_hint="pkg install whois"),
    Dependency("nmap",       "External scanner",          ("--version",), False, "yes",     "pkg install nmap",        optional=True),
    Dependency("tcpdump",    "Packet capture",            ("--version",), True,  "partial", "pkg install tcpdump",     optional=True),
    Dependency("tshark",     "PCAP analysis",             ("-v",),        False, "partial", "pkg install tshark",      optional=True),
    Dependency("ping",       "ICMP diagnostics",          ("-V",),        False, "partial", "pkg install iputils",     optional=True),
    Dependency("traceroute", "Route diagnostics",         ("--version",), False, "partial", "pkg install traceroute",  optional=True),
    Dependency("john",       "Authorized password audit", ("--version",), False, "yes",     "pkg install john",        optional=True),
    Dependency("hashcat",    "Authorized password audit", ("--version",), False, "yes",     "pkg install hashcat",     optional=True),
    Dependency("iw",         "Wireless info",             ("--version",), True,  "no",      "(requires root+NIC)",     optional=True),
    Dependency("yara",       "File rule matching",        ("--version",), False, "partial", "pip install yara-python", optional=True),
)


@dataclass(slots=True)
class DependencyStatus:
    dep: Dependency
    path: str | None
    version: str = "unknown"

    @property
    def installed(self):
        return self.path is not None


def _probe(dep, runner):
    path = shutil.which(dep.name)
    if path is None:
        return DependencyStatus(dep=dep, path=None)
    version = "unknown"
    try:
        res = runner.run([dep.name, *dep.version_args], timeout=4.0)
        text = (res.stdout or res.stderr).strip().splitlines()
        if text:
            version = text[0].strip()[:80]
    except Exception:
        pass
    return DependencyStatus(dep=dep, path=path, version=version)


def check_all():
    runner = Runner(default_timeout=4.0)
    return [_probe(d, runner) for d in DEPENDENCIES]


def _fmt_termux(v):
    return {"yes": Colors.green("✓ yes"),
            "partial": Colors.yellow("~ partial"),
            "no": Colors.red("✗ no")}.get(v, v)


def print_report(statuses=None):
    statuses = statuses or check_all()
    env_note = Colors.cyan("Termux") if is_termux() else Colors.cyan("Non-Termux")
    print()
    print(f"  {Colors.bold('▸ DEPENDENCY REPORT')}  {Colors.dim('(' + env_note + Colors.dim(')'))}")
    print(f"  {Colors.dim('─' * 78)}")
    print(f"  {Colors.bold('TOOL'):<22} {Colors.bold('STATE'):<20} {Colors.bold('ROOT'):<8} {Colors.bold('TERMUX'):<12} {Colors.bold('PURPOSE')}")
    print(f"  {Colors.dim('─' * 78)}")
    missing_required = 0
    for s in statuses:
        state = Colors.green("✓ installed") if s.installed else Colors.red("✗ missing")
        root = Colors.yellow("yes") if s.dep.root_required else Colors.dim("no")
        purpose = s.dep.purpose + (Colors.dim("  (optional)") if s.dep.optional else "")
        if not s.installed and not s.dep.optional:
            missing_required += 1
        # Strip ANSI for alignment
        name = s.dep.name
        print(f"  {name:<22} {state:<30} {root:<18} {_fmt_termux(s.dep.termux_supported):<24} {purpose}")
    print(f"  {Colors.dim('─' * 78)}")
    if missing_required:
        print(f"  {Colors.yellow(f'⚠  {missing_required} required tool(s) missing')}")
    else:
        print(f"  {Colors.green('✓  All required tools present')}")
    print(f"  {Colors.dim('  See docs/installation.md for install hints.')}")
    print()
    return missing_required
