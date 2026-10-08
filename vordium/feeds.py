"""Live feeds: order book, trades, your orders and your fills, over one WebSocket.

Subscribe with ``{"method":"subscribe","channel":"book"|"trades","pair":N}`` or
``{"method":"subscribe","channel":"orders"|"fills","account":"0x…"}``. Every subscription starts with a snapshot, then
updates. ``seq`` only rises on a channel; each message's ``prev_seq`` names the message before it (``null`` on the
snapshot). A ``prev_seq`` that is not the last ``seq`` seen means a message was missed: the only correct move is to
subscribe again and start from the new snapshot. :class:`SeqTracker` decides that; :class:`Feeds` does it.

Book updates list only the levels that changed; a size of ``"0"`` removes the level (:class:`Book`). Trades, fills and
orders carry a ``cursor``: to fill a gap in your own history, read the account's events from the REST API from that cursor.

Standard library only (RFC 6455 client over TLS); no extra dependency.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlsplit

CHANNELS = ("book", "trades", "orders", "fills")
_MARKET = ("book", "trades")


class FeedError(RuntimeError):
    """The connection or a message could not be used."""


def sub_key(channel: str, pair: Optional[int] = None, account: Optional[str] = None) -> Tuple[str, str]:
    """The identity of one subscription: ``(channel, pair)`` for market channels, ``(channel, account)`` otherwise."""
    if channel not in CHANNELS:
        raise ValueError(f"channel is one of {CHANNELS}, not {channel!r}")
    if channel in _MARKET:
        if not isinstance(pair, int) or isinstance(pair, bool):
            raise ValueError(f"{channel} needs a pair id")
        return channel, str(pair)
    if not (isinstance(account, str) and account.startswith("0x") and len(account) == 42):
        raise ValueError(f"{channel} needs an account address")
    return channel, account.lower()


def subscribe_message(channel: str, pair: Optional[int] = None, account: Optional[str] = None,
                      method: str = "subscribe") -> Dict[str, Any]:
    ch, who = sub_key(channel, pair, account)
    m: Dict[str, Any] = {"method": method, "channel": ch}
    if ch in _MARKET:
        m["pair"] = int(who)
    else:
        m["account"] = account
    return m


def key_of(msg: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """The subscription a feed message belongs to, or None (pong, acks, errors)."""
    ch = msg.get("channel")
    if ch in _MARKET and isinstance(msg.get("pair"), int):
        return ch, str(msg["pair"])
    if ch in ("orders", "fills") and isinstance(msg.get("account"), str):
        return ch, msg["account"].lower()
    return None


class SeqTracker:
    """Per subscription: accept a snapshot, then only an update whose ``prev_seq`` is the last ``seq``.

    ``observe(msg)`` answers ``"snapshot"``, ``"update"``, ``"gap"`` (missed a message — resubscribe), ``"stale"`` (an
    update before any snapshot, or a seq that does not rise — drop it) or ``"ignore"`` (not a feed message)."""

    def __init__(self) -> None:
        self.last: Dict[Tuple[str, str], int] = {}

    def reset(self, key: Tuple[str, str]) -> None:
        self.last.pop(key, None)

    def observe(self, msg: Dict[str, Any]) -> str:
        k = key_of(msg)
        seq = msg.get("seq")
        if k is None or not isinstance(seq, int) or isinstance(seq, bool):
            return "ignore"
        if msg.get("type") == "snapshot":
            self.last[k] = seq
            return "snapshot"
        if k not in self.last:
            return "stale"
        prev = msg.get("prev_seq")
        if seq <= self.last[k]:
            return "stale"
        if prev != self.last[k]:
            self.last.pop(k, None)
            return "gap"
        self.last[k] = seq
        return "update"


@dataclass
class Book:
    """One pair's book from a snapshot and its updates. Prices and sizes kept exact as integers (8 / 18 decimals)."""
    pair: int
    bids: Dict[int, int] = field(default_factory=dict)
    asks: Dict[int, int] = field(default_factory=dict)
    seq: Optional[int] = None
    height: Optional[int] = None

    def apply(self, msg: Dict[str, Any]) -> None:
        if msg.get("type") == "snapshot":
            self.bids, self.asks = {}, {}
        for side, levels in (("bids", msg.get("bids") or []), ("asks", msg.get("asks") or [])):
            book = self.bids if side == "bids" else self.asks
            for lvl in levels:
                price, size = int(lvl[0]), int(lvl[1])
                if size == 0:
                    book.pop(price, None)
                else:
                    book[price] = size
        self.seq = msg.get("seq", self.seq)
        self.height = msg.get("height", self.height)

    def best_bid(self) -> Optional[Tuple[int, int]]:
        return max(self.bids.items()) if self.bids else None

    def best_ask(self) -> Optional[Tuple[int, int]]:
        return min(self.asks.items()) if self.asks else None


# --- RFC 6455 client ---------------------------------------------------------------------------------------------
class _Socket:
    def __init__(self, url: str, timeout: float = 10.0, headers: Optional[Dict[str, str]] = None):
        u = urlsplit(url)
        if u.scheme not in ("ws", "wss"):
            raise FeedError("feeds URL must be ws:// or wss://")
        port = u.port or (443 if u.scheme == "wss" else 80)
        raw = socket.create_connection((u.hostname, port), timeout=timeout)
        self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=u.hostname) if u.scheme == "wss" else raw
        key = base64.b64encode(os.urandom(16)).decode()
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        hdr = {"Host": u.netloc, "Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Key": key,
               "Sec-WebSocket-Version": "13", "User-Agent": "vordium-sdk"}
        hdr.update(headers or {})
        req = f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdr.items()) + "\r\n"
        self.sock.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise FeedError("connection closed during the handshake")
            resp += chunk
        head, self.buf = resp.split(b"\r\n\r\n", 1)
        status = head.split(b"\r\n", 1)[0]
        if b" 101 " not in status + b" ":
            raise FeedError(f"handshake refused: {status.decode(errors='replace')}")
        import hashlib
        want = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        if want not in head:
            raise FeedError("handshake answer does not match the key")
        self.lock = threading.Lock()

    def _frame(self) -> Optional[Tuple[int, int, bytes]]:
        """One whole frame from the buffer, or None. Nothing is consumed until the frame is complete, so a read that
        times out part-way through a frame loses nothing."""
        buf = self.buf
        if len(buf) < 2:
            return None
        b0, b1 = buf[0], buf[1]
        n, i = b1 & 0x7F, 2
        if n == 126:
            if len(buf) < 4:
                return None
            n, i = struct.unpack(">H", buf[2:4])[0], 4
        elif n == 127:
            if len(buf) < 10:
                return None
            n, i = struct.unpack(">Q", buf[2:10])[0], 10
        mask = None
        if b1 & 0x80:
            if len(buf) < i + 4:
                return None
            mask, i = buf[i:i + 4], i + 4
        if len(buf) < i + n:
            return None
        data = buf[i:i + n]
        self.buf = buf[i + n:]
        if mask:
            data = bytes(x ^ mask[j % 4] for j, x in enumerate(data))
        return b0, b0 & 0x0F, data

    def send_text(self, text: str) -> None:
        self._send(0x1, text.encode())

    def _send(self, op: int, data: bytes) -> None:
        mask = os.urandom(4)
        n = len(data)
        head = bytes([0x80 | op])
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            head += bytes([0x80 | 127]) + struct.pack(">Q", n)
        body = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        with self.lock:
            self.sock.sendall(head + mask + body)

    def recv_text(self) -> Optional[str]:
        """Next text message; answers pings; None when the server closed. Raises socket.timeout when nothing came."""
        parts: List[bytes] = []
        while True:
            f = self._frame()
            if f is None:
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise FeedError("connection closed")
                self.buf += chunk
                continue
            b0, op, data = f
            if op == 0x8:
                return None
            if op == 0x9:
                self._send(0xA, data)
                continue
            if op == 0xA:
                continue
            parts.append(data)
            if b0 & 0x80:
                return b"".join(parts).decode()

    def close(self) -> None:
        try:
            self._send(0x8, b"")
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


class Feeds:
    """One connection, any number of subscriptions, resubscribed by itself after a gap or a reconnect.

    ``events()`` yields ``(kind, message)`` where kind is ``snapshot``, ``update``, ``resubscribed`` (after a gap; the
    next message on that subscription is a fresh snapshot) or ``reconnected``. ``Book`` state per pair is kept in
    ``books`` for book subscriptions."""

    def __init__(self, url: str, timeout: float = 30.0, reconnect: bool = True, max_backoff: float = 30.0,
                 opener: Optional[Callable[[str, float], Any]] = None):
        self.url, self.timeout, self.reconnect, self.max_backoff = url, timeout, reconnect, max_backoff
        self._open = opener or (lambda u, t: _Socket(u, t))
        self.subs: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.seq = SeqTracker()
        self.books: Dict[int, Book] = {}
        self.sock = None
        self._closed = False

    def _connect(self) -> None:
        self.sock = self._open(self.url, self.timeout)
        for k, m in self.subs.items():
            self.seq.reset(k)
            self.sock.send_text(json.dumps(m))

    def subscribe(self, channel: str, pair: Optional[int] = None, account: Optional[str] = None) -> None:
        k = sub_key(channel, pair, account)
        m = subscribe_message(channel, pair, account)
        self.subs[k] = m
        if channel == "book":
            self.books.setdefault(int(pair), Book(int(pair)))
        if self.sock is not None:
            self.seq.reset(k)
            self.sock.send_text(json.dumps(m))

    def unsubscribe(self, channel: str, pair: Optional[int] = None, account: Optional[str] = None) -> None:
        k = sub_key(channel, pair, account)
        self.subs.pop(k, None)
        self.seq.reset(k)
        if self.sock is not None:
            self.sock.send_text(json.dumps(subscribe_message(channel, pair, account, "unsubscribe")))

    def ping(self) -> None:
        if self.sock is not None:
            self.sock.send_text(json.dumps({"method": "ping"}))

    def close(self) -> None:
        self._closed = True
        if self.sock is not None:
            self.sock.close()

    def handle(self, msg: Dict[str, Any]) -> Optional[str]:
        """Apply one message; returns its kind (or None for messages that are not feed data)."""
        verdict = self.seq.observe(msg)
        k = key_of(msg)
        if verdict == "gap" and k in self.subs:
            if k[0] == "book":
                self.books[int(k[1])] = Book(int(k[1]))
            if self.sock is not None:
                self.sock.send_text(json.dumps(self.subs[k]))
            return "resubscribed"
        if verdict in ("snapshot", "update"):
            if k and k[0] == "book":
                self.books.setdefault(int(k[1]), Book(int(k[1]))).apply(msg)
            return verdict
        return None

    def events(self) -> Iterator[Tuple[str, Dict[str, Any]]]:
        backoff = 1.0
        idle = 0
        while not self._closed:
            try:
                if self.sock is None:
                    self._connect()
                    backoff = 1.0
                    idle = 0
                try:
                    text = self.sock.recv_text()
                except socket.timeout:
                    # A quiet feed is not a dead one: ask once, and give up only when even the ping goes unanswered.
                    idle += 1
                    if idle >= 2:
                        raise FeedError("no message and no answer to a ping")
                    self.ping()
                    continue
                idle = 0
                if text is None:
                    raise FeedError("server closed the connection")
                msg = json.loads(text)
                if not isinstance(msg, dict):
                    continue
                kind = self.handle(msg)
                if kind:
                    yield kind, msg
            except (OSError, FeedError, ValueError) as e:
                if self._closed:
                    return
                if self.sock is not None:
                    self.sock.close()
                self.sock = None
                if not self.reconnect:
                    raise FeedError(str(e)) from e
                time.sleep(backoff)
                backoff = min(backoff * 2, self.max_backoff)
                yield "reconnected", {"error": str(e)}
