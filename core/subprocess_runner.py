"""Safe subprocess wrapper - allowlist, no shell, timeout."""
from __future__ import annotations
import shutil, subprocess, time
from dataclasses import dataclass, field

class CommandError(RuntimeError):
    pass

@dataclass(slots=True)
class CommandResult:
    argv: list
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_s: float = 0.0

    @property
    def ok(self):
        return self.returncode == 0 and not self.timed_out

@dataclass(slots=True)
class Runner:
    allowlist: frozenset = field(default_factory=frozenset)
    default_timeout: float = 30.0
    max_output_bytes: int = 4 * 1024 * 1024

    def _resolve(self, binary):
        resolved = shutil.which(binary)
        if resolved is None:
            raise CommandError(f"Not found: {binary!r}")
        if self.allowlist and binary not in self.allowlist:
            raise CommandError(f"Not allowed: {binary!r}")
        return resolved

    def run(self, argv, *, timeout=None, cwd=None, env=None, input_bytes=None):
        if not argv:
            raise CommandError("Empty argv.")
        resolved = self._resolve(argv[0])
        actual = [resolved, *argv[1:]]
        t = timeout or self.default_timeout
        start = time.monotonic()
        try:
            proc = subprocess.run(
                actual, capture_output=True, timeout=t,
                cwd=cwd, env=env, input=input_bytes, check=False,
            )
            dur = time.monotonic() - start
            return CommandResult(
                argv=actual, returncode=proc.returncode,
                stdout=proc.stdout.decode(errors="replace")[: self.max_output_bytes],
                stderr=proc.stderr.decode(errors="replace")[: self.max_output_bytes],
                timed_out=False, duration_s=dur,
            )
        except subprocess.TimeoutExpired as exc:
            dur = time.monotonic() - start
            return CommandResult(
                argv=actual, returncode=-1,
                stdout=(exc.stdout or b"").decode(errors="replace"),
                stderr=(exc.stderr or b"").decode(errors="replace"),
                timed_out=True, duration_s=dur,
            )
