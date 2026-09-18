"""Report engine - Terminal/JSON/TXT/HTML with secret redaction."""
from __future__ import annotations
import html, json, re, time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from core import __version__

_SECRETS = [
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)(\S+)"),
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)(\S+)"),
    re.compile(r"(?i)(password\s*[=:]\s*)(\S+)"),
    re.compile(r"(?i)(token\s*[=:]\s*)(\S+)"),
    re.compile(r"(?i)(secret\s*[=:]\s*)(\S+)"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
]
_RED = "***REDACTED***"


def redact(text):
    for pat in _SECRETS:
        text = pat.sub(lambda m: (m.group(1) + _RED) if m.groups() else _RED, text)
    return text


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: str
    target: str
    evidence: str = ""
    explanation: str = ""
    remediation: str = ""
    references: list = field(default_factory=list)


@dataclass(slots=True)
class Report:
    module: str
    target: str
    method: str
    findings: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    tool_version: str = __version__
    dependencies: list = field(default_factory=list)

    def to_dict(self):
        data = asdict(self)
        for f in data.get("findings", []):
            for k, v in list(f.items()):
                if isinstance(v, str):
                    f[k] = redact(v)
        for k, v in list(data.get("metadata", {}).items()):
            if isinstance(v, str):
                data["metadata"][k] = redact(v)
        return data

    def write_json(self, p):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    def write_txt(self, p):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.render_text(), encoding="utf-8")

    def write_html(self, p):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.render_html(), encoding="utf-8")

    def render_text(self):
        lines = [
            "PAREEK SECURITY KIT REPORT", "=" * 44,
            f"Module   : {self.module}", f"Target   : {self.target}",
            f"Method   : {self.method}", f"Time     : {time.ctime(self.timestamp)}",
            f"Version  : {self.tool_version}",
        ]
        if self.dependencies:
            lines.append(f"Deps     : {', '.join(self.dependencies)}")
        lines.append("")
        if not self.findings:
            lines.append("(no findings)")
        for f in self.findings:
            lines.append(f"[{f.severity.upper()}] {f.id} - {f.title}")
            lines.append(f"  target     : {redact(f.target)}")
            if f.evidence:    lines.append(f"  evidence   : {redact(f.evidence)}")
            if f.explanation: lines.append(f"  explanation: {redact(f.explanation)}")
            if f.remediation: lines.append(f"  remediation: {redact(f.remediation)}")
            if f.references:  lines.append(f"  references : {', '.join(f.references)}")
            lines.append("")
        return "\n".join(lines)

    def render_html(self):
        def esc(s): return html.escape(redact(s))
        rows = []
        for f in self.findings:
            rows.append(
                f"<tr class='sev-{esc(f.severity)}'>"
                f"<td>{esc(f.id)}</td><td>{esc(f.severity)}</td>"
                f"<td>{esc(f.title)}</td><td><code>{esc(f.target)}</code></td>"
                f"<td>{esc(f.evidence)}</td><td>{esc(f.remediation)}</td></tr>")
        body = "\n".join(rows) or "<tr><td colspan='6'>(no findings)</td></tr>"
        return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pareek Report - {esc(self.module)}</title><style>
:root{{color-scheme:light dark}}
body{{font-family:system-ui,sans-serif;margin:2rem;color:#222;line-height:1.5}}
h1{{border-bottom:3px solid #00bcd4;padding-bottom:.3rem;background:linear-gradient(90deg,#00bcd4,#e91e63);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
table{{border-collapse:collapse;width:100%;margin-top:1rem}}
th,td{{border:1px solid #ccc;padding:.5rem;font-size:.9rem;vertical-align:top}}
th{{background:#f0f0f0;text-align:left}}
.sev-critical{{background:#ffe5e5}}.sev-high{{background:#ffeded}}
.sev-medium{{background:#fff7e0}}.sev-low{{background:#eef7ee}}
.sev-info{{background:#eef4fb}}
code{{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px}}
@media(prefers-color-scheme:dark){{body{{background:#111;color:#eee}}
th{{background:#222}}code{{background:#222}}td,th{{border-color:#333}}}}
</style></head><body>
<h1>Pareek Security Kit - Report</h1>
<p><b>Module:</b> {esc(self.module)}<br>
<b>Target:</b> {esc(self.target)}<br>
<b>Method:</b> {esc(self.method)}<br>
<b>Timestamp:</b> {esc(time.ctime(self.timestamp))}<br>
<b>Version:</b> {esc(self.tool_version)}</p>
<table><thead><tr><th>ID</th><th>Severity</th><th>Title</th>
<th>Target</th><th>Evidence</th><th>Remediation</th></tr></thead>
<tbody>{body}</tbody></table></body></html>"""


def emit_terminal(report, stream=None):
    import sys
    print(report.render_text(), file=stream or sys.stdout)


def save_all(report, base, formats):
    written = []
    for fmt in formats:
        fmt = fmt.lower()
        if fmt == "json":
            p = base.with_suffix(".json"); report.write_json(p); written.append(p)
        elif fmt == "txt":
            p = base.with_suffix(".txt");  report.write_txt(p);  written.append(p)
        elif fmt == "html":
            p = base.with_suffix(".html"); report.write_html(p); written.append(p)
        else:
            raise ValueError(f"Unknown format: {fmt!r}")
    return written
