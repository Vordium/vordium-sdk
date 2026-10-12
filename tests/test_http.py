"""The SDK's HTTP layer: one pooled session per thread; reads retried with a jittered backoff that honours Retry-After;
writes sent once and never retried."""
import threading

import pytest
import requests

from vordium import _http


class Resp:
    def __init__(self, code, headers=None):
        self.status_code, self.headers = code, headers or {}


class FakeSession:
    def __init__(self, script):
        self.script, self.calls = list(script), []

    def _next(self, method, url):
        self.calls.append((method, url))
        x = self.script.pop(0)
        if isinstance(x, Exception):
            raise x
        return x

    def get(self, url, timeout=None, headers=None):
        return self._next("GET", url)

    def post(self, url, json=None, timeout=None, headers=None):
        return self._next("POST", url)


def use(monkeypatch, script):
    s = FakeSession(script)
    monkeypatch.setattr(_http, "session", lambda: s)
    return s


def test_one_session_per_thread_reused():
    _http._local.__dict__.pop("session", None)
    a, b = _http.session(), _http.session()
    assert a is b and isinstance(a, requests.Session)
    other = []
    t = threading.Thread(target=lambda: other.append(_http.session()))
    t.start(); t.join()
    assert other[0] is not a


def test_a_read_is_retried_on_try_again_answers_and_dropped_connections(monkeypatch):
    s = use(monkeypatch, [requests.ConnectionError("x"), Resp(503), Resp(200)])
    waits = []
    r = _http.get("https://h/x", timeout=1, sleep=waits.append, rand=lambda: 1.0)
    assert r.status_code == 200 and len(s.calls) == 3 and waits == [0.5, 1.0]


def test_a_read_waits_at_least_retry_after(monkeypatch):
    use(monkeypatch, [Resp(429, {"Retry-After": "7"}), Resp(200)])
    waits = []
    _http.get("https://h/x", timeout=1, sleep=waits.append, rand=lambda: 0.0)
    assert waits == [7.0]


def test_retry_after_is_capped_and_a_date_is_ignored():
    assert _http.retry_after_seconds("9999") == _http.RETRY_AFTER_MAX_S
    assert _http.retry_after_seconds("Wed, 21 Oct 2015 07:28:00 GMT") is None
    assert _http.retry_after_seconds("-3") == 0.0


def test_the_last_answer_is_returned_when_retries_run_out(monkeypatch):
    s = use(monkeypatch, [Resp(503), Resp(503), Resp(503)])
    r = _http.get("https://h/x", timeout=1, sleep=lambda w: None)
    assert r.status_code == 503 and len(s.calls) == 3


def test_a_lasting_connection_failure_is_raised(monkeypatch):
    use(monkeypatch, [requests.Timeout("t")] * 3)
    with pytest.raises(requests.Timeout):
        _http.get("https://h/x", timeout=1, sleep=lambda w: None)


def test_an_error_answer_that_is_not_try_again_is_not_retried(monkeypatch):
    s = use(monkeypatch, [Resp(404)])
    assert _http.get("https://h/x", timeout=1, sleep=lambda w: None).status_code == 404 and len(s.calls) == 1


def test_a_write_is_sent_once_and_never_retried(monkeypatch):
    s = use(monkeypatch, [Resp(503)])
    assert _http.post("https://h/order/place", json={}, timeout=1).status_code == 503 and len(s.calls) == 1
    s2 = use(monkeypatch, [requests.Timeout("t")])
    with pytest.raises(requests.Timeout):
        _http.post("https://h/order/place", json={}, timeout=1)
    assert len(s2.calls) == 1


def test_waits_are_jittered_and_bounded():
    for a in range(10):
        for _ in range(50):
            w = _http.retry_wait(a)
            assert 0.0 <= w <= _http.BACKOFF_MAX_S
