"""HTTP for every SDK call: one connection pool per thread (requests.Session), so a busy client reuses its TLS
connections instead of opening one per request.

Reads (GET) are retried a few times when the network or the server says "try again" (a dropped connection, a timeout,
HTTP 429/502/503/504), waiting a random part of a growing backoff, and never less than the server's Retry-After.
Writes (POST) are sent ONCE and never retried here: a signed order or transfer that timed out may still have landed, and
sending it again is the caller's decision (with a fresh nonce), not the transport's."""
from __future__ import annotations

import random
import threading
import time
from typing import Any, Callable, Dict, Optional

import requests

RETRY_STATUS = frozenset({429, 502, 503, 504})
GET_RETRIES = 2                 # attempts after the first
BACKOFF_BASE_S = 0.5
BACKOFF_MAX_S = 8.0
RETRY_AFTER_MAX_S = 30.0

_local = threading.local()


def session() -> requests.Session:
    s = getattr(_local, "session", None)
    if s is None:
        s = _local.session = requests.Session()
    return s


def retry_after_seconds(value: Optional[str]) -> Optional[float]:
    """Retry-After as seconds (only the delay-seconds form; a date is ignored), capped at RETRY_AFTER_MAX_S."""
    if not value:
        return None
    try:
        v = float(value.strip())
    except ValueError:
        return None
    return min(max(v, 0.0), RETRY_AFTER_MAX_S) if v == v else None


def retry_wait(attempt: int, retry_after: Optional[str] = None, rand: Callable[[], float] = random.random) -> float:
    """Wait before retry number `attempt` (0-based): a random point in [0, min(base * 2^attempt, max)], and at least the
    server's Retry-After when it sent one."""
    jitter = rand() * min(BACKOFF_BASE_S * (2 ** attempt), BACKOFF_MAX_S)
    ra = retry_after_seconds(retry_after)
    return max(jitter, ra or 0.0)


def get(url: str, *, timeout: float, headers: Optional[Dict[str, str]] = None, retries: int = GET_RETRIES,
        sleep: Callable[[float], None] = time.sleep, rand: Callable[[], float] = random.random) -> requests.Response:
    for attempt in range(retries + 1):
        try:
            r = session().get(url, timeout=timeout, headers=headers)
        except (requests.ConnectionError, requests.Timeout):
            if attempt >= retries:
                raise
            sleep(retry_wait(attempt, None, rand))
            continue
        if r.status_code in RETRY_STATUS and attempt < retries:
            sleep(retry_wait(attempt, r.headers.get("Retry-After"), rand))
            continue
        return r
    raise RuntimeError("unreachable")  # pragma: no cover


def post(url: str, *, json: Any = None, timeout: float, headers: Optional[Dict[str, str]] = None) -> requests.Response:
    """One attempt, never retried (see the module note)."""
    return session().post(url, json=json, timeout=timeout, headers=headers)
