"""Redirects are never followed: not for reads, not for signed writes (a 307/308 would re-send the signed body to
another address), not for the signing-phase read. Two local servers: a "node" that redirects everything, a "canary"."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from vordium import _http, rollb


@pytest.fixture()
def pair():
    hits = []

    class Canary(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _ok(self):
            n = int(self.headers.get("Content-Length") or 0)
            hits.append((self.command, self.path, self.rfile.read(n) if n else b""))
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"{}")

        do_GET = do_POST = _ok

    canary = HTTPServer(("127.0.0.1", 0), Canary)

    class Node(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _move(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n:
                self.rfile.read(n)
            code = 307 if self.command == "POST" else 302
            self.send_response(code)
            self.send_header("Location", f"http://127.0.0.1:{canary.server_address[1]}/stolen{self.path}")
            self.send_header("Content-Length", "0"); self.end_headers()

        do_GET = do_POST = _move

    node = HTTPServer(("127.0.0.1", 0), Node)
    for s in (canary, node):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{node.server_address[1]}", hits
    for s in (canary, node):
        s.shutdown()


def test_reads_do_not_follow_a_redirect(pair):
    base, hits = pair
    with pytest.raises(_http.RedirectRefused, match="redirect not followed: use the https address"):
        _http.get(base + "/status", timeout=5, retries=0)
    assert hits == []


def test_a_signed_post_is_never_resent_to_another_address(pair):
    base, hits = pair
    with pytest.raises(_http.RedirectRefused, match="redirect not followed"):
        _http.post(base + "/order/place", json={"signature": "0x" + "ab" * 65}, timeout=5)
    with pytest.raises(_http.RedirectRefused):
        _http.session().post(base + "/session/create", data=json.dumps({"signature": "x"}), timeout=5, allow_redirects=True)
    assert hits == []


def test_a_redirect_is_not_retried_as_a_lost_connection(pair):
    base, hits = pair
    calls = []
    with pytest.raises(_http.RedirectRefused):
        _http.get(base + "/status", timeout=5, retries=2, sleep=lambda s: calls.append(s))
    assert calls == [] and hits == []


def test_the_signing_phase_read_does_not_follow_a_redirect(pair):
    base, hits = pair
    with pytest.raises(ValueError, match="redirect not followed"):
        rollb._get_json(base + "/releases.json", timeout=5)
    assert hits == []
