"""Next-level 3D gradient banner + animated menu."""
from __future__ import annotations
import os
import shutil
import sys
import time
from core import __version__, __codename__

# ── ANSI 256-color gradients ─────────────────────────────
def _rgb(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m"

class Gradient:
    """Pre-built color palettes for modern look."""
    CYAN_MAGENTA = [(0,255,255),(0,200,255),(100,150,255),(180,100,255),(255,80,220)]
    NEON_GREEN   = [(0,255,128),(0,255,180),(0,220,200),(0,200,220),(50,180,255)]
    FIRE         = [(255,220,0),(255,180,0),(255,120,0),(255,60,0),(255,0,60)]
    RAINBOW      = [(255,0,0),(255,165,0),(255,255,0),(0,255,0),(0,0,255),(75,0,130),(238,130,238)]

    @staticmethod
    def paint(text: str, palette: list, offset: int = 0) -> str:
        if not text:
            return ""
        out = []
        n = len(palette)
        for i, ch in enumerate(text):
            r, g, b = palette[(i + offset) % n]
            out.append(f"{_rgb(r, g, b)}{ch}\033[0m")
        return "".join(out)


# ── 3D Block ASCII art (bigger, bolder) ──────────────────
_BANNER_LINES = [
    "██████╗  █████╗ ██████╗ ███████╗███████╗██╗  ██╗",
    "██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██║ ██╔╝",
    "██████╔╝███████║██████╔╝█████╗  █████╗  █████╔╝ ",
    "██╔═══╝ ██╔══██║██╔══██╗██╔══╝  ██╔══╝  ██╔═██╗ ",
    "██║     ██║  ██║██║  ██║███████╗███████╗██║  ██╗",
    "╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝",
]

_SUBTITLE = "  S E C U R I T Y   K I T   v " + __version__ + "  ·  " + __codename__


MENU = (
    ("01", "Information Gathering",     "DNS · WHOIS · HTTP · Tech"),
    ("02", "Network Scanning",          "TCP · UDP · Host discovery"),
    ("03", "Service Enumeration",       "HTTP/SSH/FTP/SMTP/SMB"),
    ("04", "Web Security Testing",      "Headers · Cookies · TLS"),
    ("05", "Packet Analysis",           "PCAP · Live · Stats"),
    ("06", "Network Diagnostics",       "Ping · Trace · MTU"),
    ("07", "Vulnerability Assessment",  "CVE · Misconfig · Score"),
    ("08", "Wireless Security",         "Interface · AP · Signal"),
    ("09", "Password Auditing",         "Hash ID · Entropy · Policy"),
    ("10", "Credential Security",       "Secrets · Keys · Tokens"),
    ("11", "Exploit Lab",               "CTF · PoC · Docs"),
    ("12", "DNS Security",              "DNSSEC · SPF · DMARC"),
    ("13", "SSL/TLS Analysis",          "Cert · Cipher · Chain"),
    ("14", "OSINT",                     "Public data only"),
    ("15", "Cloud Security",            "AWS · Azure · GCP"),
    ("16", "API Security",              "OpenAPI · Endpoints"),
    ("17", "File Security",             "Hash · Meta · YARA"),
    ("18", "Reports",                   "JSON · TXT · HTML"),
    ("19", "Dependency Checker",        "Doctor · Install guide"),
    ("00", "Exit",                      "Quit gracefully"),
)


class Colors:
    """Adaptive color engine with NO_COLOR + TTY detection."""
    enabled = (
        sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
        and os.environ.get("TERM") != "dumb"
    )
    truecolor = enabled and os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")

    @classmethod
    def _w(cls, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if cls.enabled else s

    @classmethod
    def cyan(cls, s: str) -> str:    return cls._w("96", s)
    @classmethod
    def green(cls, s: str) -> str:   return cls._w("92", s)
    @classmethod
    def yellow(cls, s: str) -> str:  return cls._w("93", s)
    @classmethod
    def red(cls, s: str) -> str:     return cls._w("91", s)
    @classmethod
    def magenta(cls, s: str) -> str: return cls._w("95", s)
    @classmethod
    def blue(cls, s: str) -> str:    return cls._w("94", s)
    @classmethod
    def white(cls, s: str) -> str:   return cls._w("97", s)
    @classmethod
    def bold(cls, s: str) -> str:    return cls._w("1", s)
    @classmethod
    def dim(cls, s: str) -> str:     return cls._w("2", s)
    @classmethod
    def italic(cls, s: str) -> str:  return cls._w("3", s)
    @classmethod
    def underline(cls, s: str) -> str: return cls._w("4", s)
    @classmethod
    def blink(cls, s: str) -> str:   return cls._w("5", s)
    @classmethod
    def invert(cls, s: str) -> str:  return cls._w("7", s)


def _gradient_banner() -> str:
    """Render the banner with a 3D gradient."""
    lines = []
    palette = Gradient.CYAN_MAGENTA if Colors.truecolor else None
    for i, line in enumerate(_BANNER_LINES):
        if palette:
            lines.append(Gradient.paint(line, palette, offset=i * 3))
        else:
            lines.append(Colors.cyan(line))
    return "\n".join(lines)


def _styled_subtitle() -> str:
    if Colors.truecolor:
        return Gradient.paint(_SUBTITLE, Gradient.NEON_GREEN)
    return Colors.green(_SUBTITLE)


def _thin_line(char: str = "─", length: int = 60) -> str:
    return Colors.dim(char * length)


def show_banner(stream=sys.stdout) -> None:
    """Big gradient 3D banner with edges."""
    print(file=stream)
    print("  " + _thin_line("╔", 1) + _thin_line("═", 62) + _thin_line("╗", 1), file=stream)
    for line in _gradient_banner().split("\n"):
        print(f"  ║ {line} ║", file=stream)
    print("  ╠" + _thin_line("═", 62) + "╣", file=stream)
    print(f"  ║{_styled_subtitle():<71} ║", file=stream)
    print("  ╚" + _thin_line("═", 62) + "╝", file=stream)
    print(file=stream)


def show_legal(stream=sys.stdout) -> None:
    """Authorization warning block."""
    print(f"  {Colors.yellow('┌─ ⚠  AUTHORIZED USE ONLY ' + '─' * 38)}", file=stream)
    print(f"  {Colors.yellow('│')}  Test only systems you own or have written", file=stream)
    print(f"  {Colors.yellow('│')}  authorization to test. Unauthorized access is", file=stream)
    print(f"  {Colors.yellow('│')}  illegal and punishable by law.", file=stream)
    print(f"  {Colors.yellow('└' + '─' * 62)}", file=stream)
    print(file=stream)


def show_menu(stream=sys.stdout) -> None:
    """Modern boxed menu with descriptions."""
    print(f"  {Colors.bold(Colors.magenta('╔══ MODULES ' + '═' * 54 + '╗'))}", file=stream)
    for num, title, desc in MENU:
        if num == "00":
            num_color = Colors.red
        elif num == "19":
            num_color = Colors.yellow
        else:
            num_color = Colors.green
        badge = num_color(f"▸ {num}")
        title_str = Colors.white(f"{title}")
        desc_str = Colors.dim(desc[:24])
        line = f"  {Colors.magenta('║')} {badge}  {title_str:<28}{desc_str:<28}{Colors.magenta('║')}"
        print(line, file=stream)
    print(f"  {Colors.bold(Colors.magenta('╚' + '═' * 64 + '╝'))}", file=stream)
    print(file=stream)


def typewriter(text: str, delay: float = 0.02, stream=sys.stdout) -> None:
    """Animated typewriter effect for welcome messages."""
    if not sys.stdout.isatty():
        print(text, file=stream)
        return
    for ch in text:
        stream.write(ch)
        stream.flush()
        time.sleep(delay)
    stream.write("\n")


def show_loader(label: str = "Initializing", steps: int = 12, delay: float = 0.04) -> None:
    """Fancy progress bar loader."""
    if not sys.stdout.isatty():
        return
    bar_len = 30
    print(f"  {Colors.cyan('▸')} {label} ", end="", flush=True)
    for i in range(steps + 1):
        filled = int(bar_len * i / steps)
        bar = "█" * filled + "░" * (bar_len - filled)
        pct = int(100 * i / steps)
        sys.stdout.write(f"\r  {Colors.cyan('▸')} {label} [{Colors.green(bar)}] {pct:3d}%")
        sys.stdout.flush()
        time.sleep(delay)
    print()


def terminal_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns
