"""Thread-safe token bucket rate limiter."""
from __future__ import annotations
import threading, time


class RateLimiter:
    def __init__(self, rate=5.0, burst=None):
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self.rate = float(rate)
        self.capacity = float(burst if burst is not None else max(1, int(rate)))
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens=1.0):
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                wait = (tokens - self._tokens) / self.rate
            time.sleep(wait)
