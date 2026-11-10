"""One nonce allocator per account and nonce space, and a resend that never signs twice for one intent.

THE CHAIN'S RULES (network spec): an order's client nonce is a millisecond time strictly inside (block time - 2 days,
block time + 1 day), used once per account; a batch, a cancel-all, a modify and the dead-man switch take their nonces
through the same window. Session, agent and margin-mode nonces must be strictly above the last one the chain stored for
that signer, and not too far ahead of block time. The current time in milliseconds satisfies all of them, provided no
two writes of one account ever carry the same value and the value never goes back.

THE ALLOCATOR (:class:`NonceAllocator`) hands out ``max(last + 1, now_ms)``:

* strictly rising across threads AND processes on one machine: a file lock around a high-water mark kept in the SDK's
  state directory (``VORDIUM_STATE_DIR``, else ``~/.vordium/nonces``; directory 0700, files 0600);
* never back when the clock goes back (the mark, not the clock, decides), and never reused after a restart;
* inside the window: before a nonce is handed out it is checked against the network's block time when the client can
  read it (:class:`ChainClock`), else against this computer's clock. A nonce the network would refuse raises
  :class:`ClockOutOfWindow` with a plain message; nothing is signed and the mark does not move.

One mark serves every network: a nonce that rises on all of them is valid on each.

THE RESEND (:func:`send_same`): a write the network applies once per nonce (an order, a TWAP order, the dead-man
switch, a session key) that times out, loses its connection or meets a busy gateway (429, 502, 503, 504) is sent again
with the SAME signed body, never a new nonce. A write the network does not deduplicate (cancel-all, a batch, a modify, a
take-profit / stop-loss, margin mode) is sent again only when the first copy never left this machine; otherwise the
answer is "unknown" and the caller reads state. When a resent copy is answered with the nonce code, the network's
``nonce`` code also means "outside the window" and "used by another signer": the write counts as received only after
a read-back that matches what was signed (``Sent.needs_read_back`` marks every answer that
needs one). A new intent always takes a new
nonce; a retry never does.

With no readable block time (no network set, or a network whose block time cannot be read), the window is checked
against this computer's clock.
"""
from __future__ import annotations

import os
import random
import re
import threading
import time
import warnings
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, Optional, Tuple

DAY_MS = 86_400_000
#: Nonce spaces. ORDERS: client nonces of orders, batches, cancel-all, modify, the dead-man switch and TWAP orders (one
#: window per account). ACCOUNT: session keys, margin mode and agent operations (strictly above the stored nonce).
ORDERS, ACCOUNT = "orders", "account"
STATE_ENV = "VORDIUM_STATE_DIR"


class NonceStateWarning(UserWarning):
    """The nonce state directory cannot be used: nonces still rise in this process, but not across processes."""


class ClockOutOfWindow(ValueError):
    """The nonce this computer would sign is outside the window the network accepts. Nothing was signed."""

    def __init__(self, message: str, nonce: int, reference_ms: int, reference: str):
        super().__init__(message)
        self.nonce, self.reference_ms, self.reference = nonce, reference_ms, reference


class DeliveryUnknown(RuntimeError):
    """The network did not answer any copy of a signed write. It may or may not have arrived: read the account before
    deciding to send a new one (a new one takes a new nonce)."""

    def __init__(self, message: str, nonce: Optional[int] = None, attempts: int = 0, never_sent: bool = False):
        super().__init__(message)
        #: True when no copy left this machine (the connection could not be made on any try): it certainly did not arrive
        self.nonce, self.attempts, self.never_sent = nonce, attempts, never_sent


# ── the window ──────────────────────────────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Window:
    """How far a nonce may be from block time. ``None`` = no limit on that side. ``margin_ms`` keeps a nonce clear of
    each edge, so a copy that arrives late is still inside."""
    behind_ms: Optional[int]
    ahead_ms: Optional[int]
    margin_ms: int = 10 * 60_000


#: Client nonces of orders: strictly inside (block time - 2 days, block time + 1 day).
ORDER_WINDOW = Window(2 * DAY_MS, DAY_MS)
#: Session, agent and margin-mode nonces: above the stored one, at most a day ahead of block time.
ACCOUNT_WINDOW = Window(None, DAY_MS)
WINDOWS: Dict[str, Window] = {ORDERS: ORDER_WINDOW, ACCOUNT: ACCOUNT_WINDOW}


def _span(ms: int) -> str:
    ms = abs(int(ms))
    if ms >= DAY_MS:
        return f"{ms / DAY_MS:.1f} days"
    if ms >= 3_600_000:
        return f"{ms / 3_600_000:.1f} hours"
    if ms >= 60_000:
        return f"{ms / 60_000:.0f} minutes"
    return f"{ms / 1000:.0f} seconds"


def check_window(nonce: int, window: Window, reference_ms: int, reference: str, local_ms: Optional[int] = None) -> None:
    """Raise :class:`ClockOutOfWindow` when ``nonce`` is not safely inside ``window`` around ``reference_ms`` (the
    network's block time, or this computer's clock when the network's time cannot be read)."""
    ahead = nonce - reference_ms
    against = "the network's block time" if reference == "chain" else "this computer's clock"
    if window.ahead_ms is not None and ahead > window.ahead_ms - window.margin_ms:
        if reference == "chain" and local_ms is not None and local_ms - reference_ms > window.ahead_ms - window.margin_ms:
            why = f"this computer's clock is {_span(local_ms - reference_ms)} ahead of the network's block time"
        elif local_ms is not None and nonce - local_ms > window.ahead_ms - window.margin_ms:
            why = (f"the last nonce used for this account is {_span(nonce - local_ms)} ahead of this computer's clock "
                   "(the clock was ahead, or has been set back)")
        else:
            why = f"the nonce would be {_span(ahead)} ahead of {against}"
        raise ClockOutOfWindow(f"Not signed: {why}, and the network accepts a nonce at most {_span(window.ahead_ms)} "
                               f"ahead of its block time. Set this computer's clock right and try again. Nothing was "
                               f"signed or sent.", nonce, reference_ms, reference)
    if window.behind_ms is not None and -ahead >= window.behind_ms - window.margin_ms:
        raise ClockOutOfWindow(f"Not signed: this computer's clock is {_span(-ahead)} behind {against}, and the network "
                               f"accepts a nonce at most {_span(window.behind_ms)} before its block time. Set this "
                               f"computer's clock right and try again. Nothing was signed or sent.",
                               nonce, reference_ms, reference)


# ── the network's block time ────────────────────────────────────────────────────────────────────────────────────────
class ChainClock:
    """The network's block time, estimated as this computer's clock plus the offset measured at the last read.

    It reads the latest block (JSON-RPC ``eth_getBlockByNumber``) and, when a REST base is given, the node's ``/status``
    head: a JSON-RPC that serves another head than the node's (more than ``max_head_gap`` blocks apart) is not this
    chain's clock, and the reading is unavailable. A reading is kept ``ttl_s`` seconds; a failed one is retried after
    a fifth of that. :meth:`__call__` returns None when the time is unavailable."""

    def __init__(self, jsonrpc_url: str, rest_url: Optional[str] = None, ttl_s: float = 300.0, timeout: float = 2.0,
                 max_head_gap: int = 10_000, clock: Callable[[], float] = time.time,
                 rpc: Optional[Callable[[], Optional[Dict[str, Any]]]] = None,
                 status: Optional[Callable[[], Optional[Dict[str, Any]]]] = None):
        self.jsonrpc_url, self.rest_url = jsonrpc_url, (rest_url.rstrip("/") if rest_url else None)
        self.ttl_s, self.timeout, self.max_head_gap, self._clock = ttl_s, timeout, max_head_gap, clock
        self._rpc = rpc or self._read_block
        self._status = status or (self._read_status if self.rest_url else (lambda: None))
        self._offset: Optional[int] = None
        self._next_read = 0.0
        self._measuring = False
        self._lock = threading.Lock()

    def _read_block(self) -> Optional[Dict[str, Any]]:
        from . import _http
        r = _http.post(self.jsonrpc_url, json={"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber",
                                               "params": ["latest", False]}, timeout=self.timeout)
        j = r.json()
        return j.get("result") if isinstance(j, dict) else None

    def _read_status(self) -> Optional[Dict[str, Any]]:
        from . import _http
        r = _http.get(f"{self.rest_url}/status", timeout=self.timeout, retries=0)    # one try: this is on the nonce path
        return r.json() if r.status_code == 200 else None

    @staticmethod
    def _int(v: Any) -> Optional[int]:
        if isinstance(v, bool):
            return None
        if isinstance(v, int):
            return v
        if isinstance(v, str):
            try:
                return int(v, 16) if v.lower().startswith("0x") else int(v)
            except ValueError:
                return None
        return None

    def measure(self) -> Optional[int]:
        """Read the network now: the offset (block time - this computer's clock, ms), or None."""
        try:
            b = self._rpc()
            ts, number = self._int((b or {}).get("timestamp")), self._int((b or {}).get("number"))
            if ts is None or ts <= 0:
                return None
            st = self._status()
            head = self._int((st or {}).get("chain_head")) if isinstance(st, dict) else None
            if head is not None and (number is None or abs(head - number) > self.max_head_gap):
                return None                     # this JSON-RPC does not serve the node's chain head
            return ts * 1000 + 500 - int(self._clock() * 1000)     # the block's ms lies somewhere in its second
        except Exception:
            return None

    def __call__(self) -> Optional[int]:
        """Block time now, or None. When a reading is due, ONE caller reads the network (outside the lock, one try,
        ``timeout`` seconds); every other caller meanwhile is served the last reading at once."""
        with self._lock:
            now = self._clock()
            due = now >= self._next_read and not self._measuring
            if due:
                self._measuring = True
            offset = self._offset
        if due:
            try:
                offset = self.measure()
            finally:
                with self._lock:
                    self._offset, self._measuring = offset, False
                    self._next_read = self._clock() + (self.ttl_s if offset is not None else self.ttl_s / 5)
        return None if offset is None else int(self._clock() * 1000) + offset


_CHAIN_CLOCKS: Dict[Tuple[str, Optional[str]], ChainClock] = {}
_CHAIN_CLOCKS_LOCK = threading.Lock()


def chain_clock_for(rest_url: Optional[str], network: Any = None) -> Optional[ChainClock]:
    """The shared :class:`ChainClock` of a client posting to ``rest_url``, or None when no JSON-RPC address is known
    for it. ``network`` is a resolved network, a network name, or None (the network set with
    :func:`vordium.network.set_network`). A client given ``chain_clock=None`` checks against this computer's clock."""
    from . import network as _net
    jsonrpc = None
    if isinstance(network, str) and network in _net.NETWORKS:
        jsonrpc = _net.NETWORKS[network]["rpc"]
    elif network is not None and isinstance(getattr(network, "rpc_url", None), str):
        jsonrpc = network.rpc_url
    else:
        cur = _net.explicit_network()
        jsonrpc = cur.rpc_url if cur is not None else None
    if not jsonrpc:
        return None
    k = (jsonrpc.rstrip("/"), rest_url.rstrip("/") if rest_url else None)
    with _CHAIN_CLOCKS_LOCK:
        if k not in _CHAIN_CLOCKS:
            _CHAIN_CLOCKS[k] = ChainClock(k[0], k[1])
        return _CHAIN_CLOCKS[k]


# ── the persisted high-water mark ───────────────────────────────────────────────────────────────────────────────────
def state_dir() -> Path:
    """Where the marks live: ``VORDIUM_STATE_DIR``, else ``~/.vordium/nonces``."""
    v = os.environ.get(STATE_ENV)
    return Path(v).expanduser() if v else Path.home() / ".vordium" / "nonces"


@contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        except ImportError:                                    # Windows
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    finally:
        os.close(fd)


_ADDR = re.compile(r"^0x[0-9a-f]{40}$")


class NonceAllocator:
    """Strictly rising millisecond nonces for one account (``account``) in one nonce space (``space``).

    ``state`` is the directory of the marks (default :func:`state_dir`); ``persist=False`` keeps the mark in this
    process only. ``clock`` is this computer's clock in seconds (injectable for tests). Drop-in for
    :class:`vordium.mm.NonceClock`: call it, or use :meth:`next_at_least` and :meth:`seen`."""

    def __init__(self, account: str, space: str = ORDERS, state: Optional[Any] = None, persist: bool = True,
                 clock: Callable[[], float] = time.time, window: Optional[Window] = None):
        a = str(account).lower()
        if not _ADDR.match(a):
            raise ValueError(f"a nonce allocator belongs to one account address, not {account!r}")
        if not re.match(r"^[a-z][a-z0-9_-]{0,31}$", space):
            raise ValueError(f"a nonce space is a short lowercase name, not {space!r}")
        self.account, self.space, self._clock = a, space, clock
        self.window = window if window is not None else WINDOWS.get(space, ACCOUNT_WINDOW)
        self._tlock = threading.Lock()
        self._last = 0
        self.persistent = False
        self.path: Optional[Path] = None
        if persist:
            d = Path(state).expanduser() if state is not None else state_dir()
            try:
                d.mkdir(mode=0o700, parents=True, exist_ok=True)
                try:
                    os.chmod(d, 0o700)
                except OSError:
                    pass
                self.path = d / f"{a}.{space}"
                with _file_lock(self._lock_path()):
                    self._read()
                self.persistent = True
            except OSError as e:
                self.path = None
                warnings.warn(f"nonces for {a[:10]}… rise in this process only: the state directory {d} cannot be "
                              f"used ({e.__class__.__name__}). Set {STATE_ENV} to a writable directory.",
                              NonceStateWarning, stacklevel=2)

    def _lock_path(self) -> Path:
        assert self.path is not None
        return self.path.with_name(self.path.name + ".lock")

    def _read(self) -> int:
        """The mark: the file's (under the lock, it is the one truth for every process), else this process's."""
        if self.path is None:
            return self._last
        try:
            txt = self.path.read_text().strip()
        except FileNotFoundError:
            return 0
        try:
            return int(txt)
        except ValueError:
            warnings.warn(f"the nonce mark for {self.account[:10]}… could not be read; continuing from the clock",
                          NonceStateWarning, stacklevel=3)
            return 0

    def _write(self, n: int) -> None:
        self._last = max(self._last, n)
        if self.path is None:
            return
        tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, f"{n}\n".encode())
        finally:
            os.close(fd)
        os.replace(tmp, self.path)

    def _rewind_path(self) -> Optional[Path]:
        return self.path.with_name(self.path.name + ".rewind") if self.path is not None else None

    def _note_rewind(self, below: int, at_ms: int) -> None:
        """Keep that nonces up to ``below`` may have been handed out before the mark was set back at ``at_ms``."""
        old = self._rewind_read()
        rec = (max(below, old[0]) if old else below, at_ms)
        self._rewind = rec
        p = self._rewind_path()
        if p is not None:
            tmp = p.with_name(f"{p.name}.{os.getpid()}.{threading.get_ident()}.tmp")
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, f"{rec[0]} {rec[1]}\n".encode())
            finally:
                os.close(fd)
            os.replace(tmp, p)

    def _rewind_read(self) -> Optional[Tuple[int, int]]:
        p = self._rewind_path()
        if p is None:
            return getattr(self, "_rewind", None)
        try:
            a, b = p.read_text().split()
            return int(a), int(b)
        except (FileNotFoundError, ValueError):
            return None

    def rewound_before(self, nonce: int) -> Optional[int]:
        """When the mark was set back to the clock and ``nonce`` may also have been handed out before that, the time of
        the set-back (ms): an order found with this nonce counts as this write's only when it is newer. Else None."""
        with self._locked():
            r = self._rewind_read()
        return r[1] if r is not None and int(nonce) <= r[0] else None

    def _replace(self, n: int) -> None:
        """Write ``n`` as the mark even when it is lower (the order space, after a mark left outside the window)."""
        assert self.path is not None
        tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, f"{n}\n".encode())
        finally:
            os.close(fd)
        os.replace(tmp, self.path)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with self._tlock:
            if self.path is None:
                yield
            else:
                with _file_lock(self._lock_path()):
                    yield

    def last(self) -> int:
        """The highest nonce handed out or seen for this account and space (0 when none)."""
        with self._locked():
            return self._read()

    def next_at_least(self, floor: int = 0, chain_ms: Optional[int] = None, now_ms: Optional[int] = None) -> int:
        """The next nonce: above every one handed out before, at least this computer's clock in ms and ``floor``.

        ``chain_ms`` is the network's block time when the caller has it; the nonce is checked against it, else
        against this computer's clock (``now_ms`` when the caller runs on a clock of its own). Raises
        :class:`ClockOutOfWindow` (nothing handed out) when the network would refuse the nonce."""
        with self._locked():
            local = int(self._clock() * 1000) if now_ms is None else int(now_ms)
            last = self._read()
            n = max(last + 1, local, int(floor))
            ref, kind = (int(chain_ms), "chain") if chain_ms is not None else (local, "local")
            try:
                check_window(n, self.window, ref, kind, local)
            except ClockOutOfWindow:
                start = max(local, int(floor))
                if self.space != ORDERS or start >= n:
                    if self.space != ORDERS and n > start and self.path is not None:
                        raise ClockOutOfWindow(
                            f"Not signed: the last nonce used for this account is {_span(n - local)} ahead of this "
                            f"computer's clock, and the network accepts a nonce at most {_span(self.window.ahead_ms or 0)} "
                            f"ahead of its block time. If this computer's clock was ahead when that nonce was used, "
                            f"set the clock right and wait; if the network never received those nonces, delete the "
                            f"file {self.path} to start again from the clock. Nothing was signed or sent.", n, ref, kind)
                    raise
                # the order space only needs each nonce unused by the account: start again from the clock (the network
                # refuses a nonce it already holds, so this can never apply a write twice)
                check_window(start, self.window, ref, kind, local)
                warnings.warn(f"the nonce mark for {self.account[:10]}… was {_span(n - start)} ahead of the clock, "
                              "outside the network's window; client nonces continue from the clock",
                              NonceStateWarning, stacklevel=2)
                # the set-back's time on the network's clock when it is known (records carry block time), else ours
                self._note_rewind(n - 1, int(chain_ms) if chain_ms is not None else local)
                n = start
                self._last = n
                if self.path is not None:
                    self._replace(n)
                return n
            self._write(n)
            return n

    def __call__(self) -> int:
        return self.next_at_least(0)

    def seen(self, nonce: int) -> None:
        """Note a nonce the network already holds for this account, so the next one is above it."""
        with self._locked():
            if int(nonce) > self._read():
                self._write(int(nonce))


_ALLOCATORS: Dict[Tuple[str, str], NonceAllocator] = {}
_ALLOCATORS_LOCK = threading.Lock()


def allocator(account: str, space: str = ORDERS) -> NonceAllocator:
    """The one allocator of ``account`` in ``space`` in this process (persisted in :func:`state_dir`)."""
    k = (str(account).lower(), space)
    with _ALLOCATORS_LOCK:
        a = _ALLOCATORS.get(k)
        if a is None or (a.persistent and a.path is not None and a.path.parent != state_dir()):
            a = _ALLOCATORS[k] = NonceAllocator(account, space)
        return a


def next_nonce(account: str, space: str = ORDERS, chain_ms: Optional[int] = None) -> int:
    """One fresh nonce of ``account`` in ``space`` (see :class:`NonceAllocator`)."""
    return allocator(account, space).next_at_least(0, chain_ms)


def fresh(source: Any, floor: int = 0, chain: Optional[Callable[[], Optional[int]]] = None) -> int:
    """The next nonce of ``source`` (a :class:`NonceAllocator`, or any clock with ``next_at_least``), checked against
    the network's block time from ``chain`` when the source supports it."""
    if isinstance(source, NonceAllocator):
        return source.next_at_least(floor, chain() if chain is not None else None)
    return source.next_at_least(floor) if hasattr(source, "next_at_least") else max(int(source()), int(floor))


# ── the resend ──────────────────────────────────────────────────────────────────────────────────────────────────────
#: Answers that mean "try again". 429 means the write was not taken; 502/503/504 come from a gateway that may have
#: passed the copy on.
RESEND_STATUS = frozenset({429, 502, 503, 504})
_USED = re.compile(r"already used|already applied|duplicate|nonce not above|not above the account's last|"
                   r"must be greater than", re.I)
_USED_CODES = frozenset({"nonce", "nonce_used", "duplicate", "duplicate_nonce", "vault_nonce"})


def nonce_used_answer(status_code: Optional[int], answer: Any) -> bool:
    """Whether an answer names the nonce: used, or (the network's ``nonce`` code says both) outside the window. It
    never proves that a copy WE sent arrived: read the write back before saying so."""
    if status_code == 409:
        return True
    if not isinstance(answer, dict):
        return bool(isinstance(answer, str) and _USED.search(answer))
    code = answer.get("code")
    if isinstance(code, str) and code.lower() in _USED_CODES:
        return True
    words = " ".join(str(answer.get(k) or "") for k in ("error", "reason", "message"))
    return bool(_USED.search(words))


def _transport_errors() -> Tuple[type, ...]:
    errs: Tuple[type, ...] = (ConnectionError, TimeoutError)
    try:
        import requests
        errs = errs + (requests.ConnectionError, requests.Timeout)
    except ImportError:  # pragma: no cover
        pass
    return errs


# raised while the connection was being made (the connect step or the name lookup before it): nothing was sent. A
# refused or unreachable error on its own can also end a connection that was already open, so it is not enough.
_NOT_CONNECTED = re.compile(r"NewConnectionError|NameResolutionError|Failed to establish a new connection|"
                            r"Failed to resolve", re.I)


def never_sent(e: BaseException) -> bool:
    """True when the error happened while the connection was being made (urllib3's NewConnectionError or name
    resolution error, a connect timeout), so the network cannot have the request. A read timeout, a dropped
    connection, a refused or unreachable error that is not tied to the connect step, or a gateway answer is not that:
    the copy may have arrived."""
    try:
        import requests
        if isinstance(e, requests.ConnectTimeout):
            return True
    except ImportError:  # pragma: no cover
        pass
    if isinstance(e, TimeoutError) or type(e).__name__ in ("ReadTimeout", "ReadTimeoutError"):
        return False                   # a read timed out: the request had left
    # the error's own words and its explicit cause chain (never the error that was being handled when it was raised)
    seen, x, words = 0, e, []
    while x is not None and seen < 4:
        words.append(f"{x!r} {x}")
        x, seen = x.__cause__, seen + 1
    return bool(_NOT_CONNECTED.search(" ".join(words)))


@dataclass(frozen=True)
class Sent:
    """What came back for one signed body. ``attempts`` copies were sent. ``needs_read_back`` is True when a copy sent in
    this call may have reached the network (a lost answer, or a gateway error) and the final answer is not a 2xx: that
    answer (a refusal, the nonce code, a 5xx) may be about a LATER copy while an earlier one applied, so it is never a
    plain refusal; only a read-back of the write can say what happened (else it is unknown)."""
    status_code: Optional[int]
    answer: Any
    retry_after: Optional[str]
    attempts: int
    needs_read_back: bool = False


def send_same(send: Callable[[], Tuple[int, Any, Optional[str]]], attempts: int = 3, nonce: Optional[int] = None,
              sleep: Callable[[float], None] = time.sleep, rand: Callable[[], float] = random.random,
              dedup: bool = True) -> Sent:
    """Send one signed body until the network answers it, at most ``attempts`` times, each time the same bytes.

    ``send`` makes one attempt with the body already signed and returns ``(status, answer, retry_after)``.

    ``dedup`` says whether the network applies this write once per nonce. Then a transport error, a timeout or HTTP
    429/502/503/504 sends the same body again after a short random wait (at least the server's Retry-After); when an
    earlier copy may have arrived and the final answer is not a 2xx, ``needs_read_back`` is set. For a write the network
    does NOT deduplicate (``dedup=False``), a copy is sent again only when the first never left this machine (no
    connection was made) or was answered 429; a timeout, a dropped connection or any 5xx raises
    :class:`DeliveryUnknown` at once, so the caller reads state instead of risking a second effect.

    When no copy is answered, :class:`DeliveryUnknown` is raised."""
    from ._http import retry_wait
    errs = _transport_errors()
    last_err: Optional[BaseException] = None
    last: Optional[Tuple[int, Any, Optional[str]]] = None
    maybe_arrived = False              # a copy sent in THIS call may have reached the network
    n = max(1, int(attempts))

    def unknown(i: int, why: str) -> DeliveryUnknown:
        return DeliveryUnknown("It is not known whether the network received this write"
                               + (f" (nonce {nonce})" if nonce is not None else "") + f": {why} after {i} "
                               "tr" + ("y" if i == 1 else "ies") + ". Read the account before sending a new one.",
                               nonce, i)

    def done(code: int, ans: Any, ra: Optional[str], i: int) -> Sent:
        ok = isinstance(code, int) and 200 <= code < 300
        if not ok and isinstance(code, int) and code >= 500:
            if not dedup:
                raise unknown(i, f"the network answered {code}")
            return Sent(code, ans, ra, i, True)                  # a gateway or node error: the copy may have applied
        return Sent(code, ans, ra, i, maybe_arrived and not ok)
    for i in range(n):
        try:
            code, ans, ra = send()
        except errs as e:
            last_err = e
            if not never_sent(e):
                maybe_arrived = True
                if not dedup:
                    raise unknown(i + 1, "the answer was lost") from e
            if i < n - 1:
                sleep(retry_wait(i, None, rand))
            continue
        if code in RESEND_STATUS and i < n - 1:
            if code != 429:
                maybe_arrived = True
                if not dedup:
                    raise unknown(i + 1, f"a gateway answered {code}")
            last, last_err = (code, ans, ra), None
            sleep(retry_wait(i, ra, rand))
            continue
        return done(code, ans, ra, i + 1)
    if last is not None and last_err is None:
        return done(last[0], last[1], last[2], n)
    if not maybe_arrived and last_err is not None:
        raise DeliveryUnknown("The network could not be reached"
                              + (f" (nonce {nonce})" if nonce is not None else "")
                              + f" after {n} tries; nothing was sent.", nonce, n, never_sent=True) from last_err
    raise unknown(n, "no copy was answered") from last_err
