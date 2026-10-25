"""A key pair held in memory, and the one way the SDK writes or reads a key file.

A private key is never printed, logged, or put in a ``repr`` or an exception. A key file is written once, with mode
0600, and never overwritten; reading one refuses a file that other users can read.
"""
import json
import os
import stat
from typing import Optional, Tuple

from eth_account import Account

Account.enable_unaudited_hdwallet_features()

KEY_DIR_NAME = ".vordium"


class KeyFileError(ValueError):
    """A key file could not be written or read safely. The message never carries the key."""


def default_key_dir() -> str:
    """The per-user folder for key files: ``~/.vordium``."""
    return os.path.join(os.path.expanduser("~"), KEY_DIR_NAME)


def default_key_path(address: str) -> str:
    """``~/.vordium/<address>.key``."""
    return os.path.join(default_key_dir(), f"{address}.key")


def _ensure_dir(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if os.path.isdir(parent):
        return
    os.makedirs(parent, mode=0o700, exist_ok=True)
    os.chmod(parent, 0o700)   # makedirs is subject to the umask; the folder the SDK creates is the owner's only


def write_key_file(path: str, address: str, private_key: str) -> str:
    """Write ``{"address", "private_key"}`` to a NEW file with mode 0600 and return its path.

    Refuses to overwrite anything already at ``path``. The file is created 0600 in one step (``O_CREAT|O_EXCL``), so it
    is never readable by anyone else, not even for a moment; a write that fails removes it.
    """
    path = os.path.abspath(os.path.expanduser(path))
    _ensure_dir(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise KeyFileError(f"{path} already exists: a key file is never overwritten") from None
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"address": address, "private_key": private_key}, f, indent=2)
            f.write("\n")
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path


def check_key_file_mode(path: str) -> None:
    """Refuse a key file that is not a regular file or that its group or other users can read or write."""
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode):
        raise KeyFileError(f"{path} is not a regular file")
    if st.st_mode & 0o077:
        raise KeyFileError(
            f"{path} is readable or writable by other users (mode {stat.S_IMODE(st.st_mode):04o}); "
            f"run: chmod 600 {path}")


def read_key_file(path: str) -> Tuple[Optional[str], str]:
    """Read a key file written by :func:`write_key_file`; returns ``(address, private_key)``."""
    path = os.path.abspath(os.path.expanduser(path))
    check_key_file_mode(path)
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        raise KeyFileError(f"{path} is not a readable key file") from None
    key = data.get("private_key") if isinstance(data, dict) else None
    if not isinstance(key, str) or not key:
        raise KeyFileError(f"{path} holds no private_key")
    return data.get("address"), key


def generate_key_file(path: Optional[str] = None) -> Tuple[str, str]:
    """Make a new key and write it to ``path`` (default ``~/.vordium/<address>.key``). Returns ``(address, path)``.

    Only the address and the path come back; the key stays in the file.
    """
    acct = Account.create()
    written = write_key_file(path or default_key_path(acct.address), acct.address, acct.key.hex())
    return acct.address, written


class Wallet:
    def __init__(self, private_key: str = None):
        self._w3 = None
        if private_key:
            self._account = Account.from_key(private_key)
        else:
            self._account = Account.create()

    @classmethod
    def create(cls) -> 'Wallet':
        return cls()

    @classmethod
    def from_key(cls, private_key: str) -> 'Wallet':
        return cls(private_key=private_key)

    @classmethod
    def from_mnemonic(cls, mnemonic: str) -> 'Wallet':
        account = Account.from_mnemonic(mnemonic)
        return cls(private_key=account.key.hex())

    @classmethod
    def load(cls, path: str) -> 'Wallet':
        """Read a key file written by :meth:`save` (refused if other users can read it)."""
        address, key = read_key_file(path)
        w = cls(private_key=key)
        if address and str(address).lower() != w.address.lower():
            raise KeyFileError(f"{path}: the address in the file does not match its key")
        return w

    @property
    def address(self) -> str:
        return self._account.address

    @property
    def private_key(self) -> str:
        return self._account.key.hex()

    def balance(self) -> float:
        if self._w3 is None:
            from web3 import Web3
            from .network import get_network
            self._w3 = Web3(Web3.HTTPProvider(get_network().rpc_url))
        raw = self._w3.eth.get_balance(self.address)
        return float(self._w3.from_wei(raw, 'ether'))

    def save(self, path: Optional[str] = None) -> str:
        """Write the key to a NEW file with mode 0600 (default ``~/.vordium/<address>.key``) and return its path.

        Never overwrites an existing file. Nothing is printed.
        """
        return write_key_file(path or default_key_path(self.address), self.address, self.private_key)

    def __repr__(self):
        return f"Wallet(address={self.address})"

    __str__ = __repr__
