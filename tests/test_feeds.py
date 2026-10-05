"""Live feeds: sequence checking, book state, resubscribing after a gap or a reconnect, and the frame reader.

The message shapes are the ones the feed sends (book, orders snapshot and updates, recorded on a test chain)."""
import json
import socket
import struct

import pytest

from vordium import feeds

A = "0x3a372e594e322b53aa41174581aeb34d1c23e01f"


def book(t, seq, prev, bids=(), asks=(), pair=1):
    return {"channel": "book", "pair": pair, "type": t, "seq": seq, "prev_seq": prev,
            "bids": [list(x) for x in bids], "asks": [list(x) for x in asks]}


def orders(t, seq, prev):
    return {"channel": "orders", "account": A, "type": t, "seq": seq, "prev_seq": prev, "data": []}


def test_snapshot_then_updates_chained_by_prev_seq():
    s = feeds.SeqTracker()
    # one connection-wide counter, each update naming the previous seq on ITS channel
    assert s.observe(book("snapshot", 17, None)) == "snapshot"
    assert s.observe(orders("snapshot", 18, None)) == "snapshot"
    assert s.observe(orders("update", 19, 18)) == "update"
    assert s.observe(book("update", 20, 17)) == "update"
    assert s.observe(orders("update", 21, 19)) == "update"
    assert s.observe(book("update", 22, 20)) == "update"


def test_a_missed_message_is_a_gap():
    s = feeds.SeqTracker()
    s.observe(book("snapshot", 5, None))
    assert s.observe(book("update", 9, 7)) == "gap"
    assert s.observe(book("update", 10, 9)) == "stale"   # nothing is applied until a new snapshot
    assert s.observe(book("snapshot", 11, None)) == "snapshot"
    assert s.observe(book("update", 12, 11)) == "update"


def test_update_before_snapshot_and_repeated_seq_are_dropped():
    s = feeds.SeqTracker()
    assert s.observe(book("update", 3, 2)) == "stale"
    s.observe(book("snapshot", 4, None))
    assert s.observe(book("update", 4, 4)) == "stale"
    assert s.observe({"type": "pong"}) == "ignore"
    assert s.observe(book("update", True, 4)) == "ignore"


def test_book_applies_changed_levels_and_size_zero_removes():
    b = feeds.Book(1)
    b.apply(book("snapshot", 1, None, bids=[("100", "5"), ("99", "7")], asks=[("101", "3")]))
    b.apply(book("update", 2, 1, bids=[("100", "0"), ("98", "1")], asks=[("101", "4"), ("102", "2")]))
    assert b.bids == {99: 7, 98: 1} and b.asks == {101: 4, 102: 2}
    assert b.best_bid() == (99, 7) and b.best_ask() == (101, 4)
    b.apply(book("snapshot", 3, None, bids=[("244355000000", "4501000000000000")]))
    assert b.bids == {244355000000: 4501000000000000} and b.asks == {}


def test_subscribe_messages():
    assert feeds.subscribe_message("book", pair=1) == {"method": "subscribe", "channel": "book", "pair": 1}
    assert feeds.subscribe_message("fills", account="0x" + "ab" * 20) == {
        "method": "subscribe", "channel": "fills", "account": "0x" + "ab" * 20}
    assert feeds.subscribe_message("trades", pair=2, method="unsubscribe")["method"] == "unsubscribe"
    for bad in (lambda: feeds.sub_key("candles", pair=1), lambda: feeds.sub_key("book"),
                lambda: feeds.sub_key("orders", account="0x12")):
        with pytest.raises(ValueError):
            bad()


class FakeSock:
    """Stands in for a connection: plays scripted messages, records what is sent; None closes it."""

    def __init__(self, script):
        self.script, self.sent, self.closed = list(script), [], False

    def send_text(self, text):
        self.sent.append(json.loads(text))

    def recv_text(self):
        if not self.script:
            raise feeds.FeedError("end of script")
        m = self.script.pop(0)
        if isinstance(m, Exception):
            raise m
        return None if m is None else json.dumps(m)

    def close(self):
        self.closed = True


def test_a_gap_resubscribes_and_rebuilds_the_book():
    sock = FakeSock([book("snapshot", 1, None, bids=[("100", "5")]), book("update", 2, 1, bids=[("101", "1")]),
                     book("update", 5, 3, bids=[("102", "1")]),
                     book("snapshot", 6, None, bids=[("103", "2")])])
    f = feeds.Feeds("wss://example.invalid/feeds", reconnect=False, opener=lambda u, t: sock)
    f.subscribe("book", pair=1)
    got = []
    with pytest.raises(feeds.FeedError):
        for kind, m in f.events():
            got.append(kind)
    assert got == ["snapshot", "update", "resubscribed", "snapshot"]
    assert sock.sent == [{"method": "subscribe", "channel": "book", "pair": 1}] * 2
    assert f.books[1].bids == {103: 2}


def test_a_lost_connection_reconnects_and_resubscribes_everything(monkeypatch):
    monkeypatch.setattr(feeds.time, "sleep", lambda s: None)
    first = FakeSock([book("snapshot", 1, None), orders("snapshot", 2, None), None])
    second = FakeSock([book("snapshot", 1, None), orders("snapshot", 2, None), orders("update", 3, 2)])
    socks = [first, second]
    f = feeds.Feeds("wss://example.invalid/feeds", opener=lambda u, t: socks.pop(0))
    f.subscribe("book", pair=1)
    f.subscribe("orders", account=A)
    kinds = []
    for kind, m in f.events():
        kinds.append(kind)
        if len(kinds) == 6:
            f.close()
            break
    assert kinds == ["snapshot", "snapshot", "reconnected", "snapshot", "snapshot", "update"]
    assert len(second.sent) == 2 and {m["channel"] for m in second.sent} == {"book", "orders"}


def test_a_quiet_feed_is_pinged_not_dropped():
    sock = FakeSock([socket.timeout(), book("snapshot", 1, None), socket.timeout(), socket.timeout()])
    f = feeds.Feeds("wss://example.invalid/feeds", reconnect=False, opener=lambda u, t: sock)
    f.subscribe("book", pair=1)
    got = []
    with pytest.raises(feeds.FeedError):
        for kind, m in f.events():
            got.append(kind)
    assert got == ["snapshot"]
    assert {"method": "ping"} in sock.sent


def _frame(op, data, fin=True):
    n = len(data)
    head = bytes([(0x80 if fin else 0) | op])
    head += bytes([n]) if n < 126 else bytes([126]) + struct.pack(">H", n)
    return head + data


class ChunkSock:
    def __init__(self, chunks):
        self.chunks, self.sent = list(chunks), []

    def recv(self, n):
        c = self.chunks.pop(0)
        if isinstance(c, Exception):
            raise c
        return c

    def sendall(self, b):
        self.sent.append(b)


def _reader(chunks):
    s = object.__new__(feeds._Socket)
    s.sock, s.buf = ChunkSock(chunks), b""
    import threading
    s.lock = threading.Lock()
    return s


def test_frame_reader_survives_a_timeout_in_the_middle_of_a_frame():
    msg = json.dumps(book("snapshot", 1, None, bids=[("1", "1")] * 20)).encode()
    raw = _frame(0x1, msg)
    s = _reader([raw[:3], socket.timeout(), raw[3:]])
    with pytest.raises(socket.timeout):
        s.recv_text()
    assert json.loads(s.recv_text())["seq"] == 1


def test_frame_reader_joins_fragments_answers_pings_and_sees_close():
    s = _reader([_frame(0x9, b"hi") + _frame(0x1, b'{"a":', fin=False) + _frame(0x0, b"1}") + _frame(0x8, b"")])
    assert s.recv_text() == '{"a":1}'
    assert s.sock.sent and s.sock.sent[0][0] & 0x0F == 0xA      # pong
    assert s.recv_text() is None
