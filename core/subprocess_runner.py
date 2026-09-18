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
        full = [resolved, *argv[1:]]
        t = timeout if timeout is not None else self.default_timeout
        start = time.monotonic()
        try:
            p = subprocess.run(full, shell=False, capture_output=True, timeout=t,
                               cwd=cwd, env=env, input=input_bytes, check=False)
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                argv=full, returncode=-1,
                stdout=(exc.stdout or b"").decode("utf-8", "replace")[: self.max_output_bytes],
                stderr=(exc.stderr or b"").decode("utf-8", "replace")[: self.max_output_bytes],
                timed_out=True, duration_s=time.monotonic() - start)
        except OSError as exc:
            raise CommandError(f"Exec failed: {exc}") from exc
        return CommandResult(
            argv=full, returncode=p.returncode,
            stdout=p.stdout.decode("utf-8", "replace")[: self.max_output_bytes],
            stderr=p.stderr.decode("utf-8", "replace")[: self.max_output_bytes],
            duration_s=time.monotonic() - start)

    def version_of(self, binary, *args, timeout=5.0):
        try:
            res = self.run([binary, *args], timeout=timeout)
        except CommandError:
            return "unknown"
        text = (res.stdout or res.stderr).strip().splitlines()
        return text[0].strip() if text else "unknown"
