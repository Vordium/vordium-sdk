"""A private key is never printed, logged, put in a repr or an exception, and key files are the owner's only."""

import json
import os
import re
import stat
import warnings

import pytest
from eth_account import Account

import vordium
from vordium import cli, wallet as wallet_mod
from vordium.agent import Agent
from vordium.operator import SessionSigner
from vordium.wallet import KeyFileError, Wallet

HEX64 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
KEY = "0x" + "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"


def no_key_in(*texts):
    for t in texts:
        assert not HEX64.search(t or ""), f"a 64-hex value appears in: {t!r}"


def no_key_text(text, key):
    k = key[2:] if key.startswith("0x") else key
    assert k.lower() not in (text or "").lower(), "the private key appears in the output"
    no_key_in(text)


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.delenv("VORDIUM_PRIVATE_KEY", raising=False)
    return h


# ── Agent ────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_agent_without_key_prints_nothing_and_keeps_key_in_memory(home, capsys):
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        a = Agent()
    out = capsys.readouterr()
    assert out.out == "" and out.err == ""
    assert re.fullmatch(r"0x[0-9a-fA-F]{40}", a.address)
    assert w and all(a.private_key[2:] not in str(x.message) for x in w)
    no_key_in(*[str(x.message) for x in w])
    assert not os.path.exists(home / ".vordium"), "nothing is written without an explicit save"


def test_agent_repr_str_never_carry_the_key(home):
    a = Agent(KEY)
    for t in (repr(a), str(a), repr(a._wallet), str(a._wallet), f"{a}", f"{a._wallet!r}"):
        no_key_text(t, KEY)
        assert a.address in t


def test_agent_save_writes_0600_and_load_reads_it(home, capsys):
    a = Agent(KEY)
    p = a.save()
    assert p == os.path.join(str(home), ".vordium", f"{a.address}.key")
    assert mode(p) == 0o600 and mode(os.path.dirname(p)) == 0o700
    assert json.load(open(p)) == {"address": a.address, "private_key": a.private_key}
    b = Agent(key_file=p)
    assert b.address == a.address
    out = capsys.readouterr()
    no_key_text(out.out + out.err, KEY)


def test_agent_send_never_echoes_the_key(home, capsys):
    a = Agent(KEY)

    class Eth:
        gas_price = 1
        chain_id = 101101                      # the node's eth_chainId, equal to the configured network's pin

        def get_transaction_count(self, _):
            return 0

        account = Account

        def send_raw_transaction(self, raw):
            return bytes.fromhex("ab" * 32)

        def wait_for_transaction_receipt(self, _):
            return {}

    class W3:
        eth = Eth()

        def to_wei(self, v, unit):
            return int(v * 10 ** 18)

    a._w3 = W3()
    a.send("0x" + "22" * 20, 0.5)
    out = capsys.readouterr()
    no_key_text((out.out + out.err).replace("ab" * 32, ""), KEY)   # the tx hash is 64 hex; nothing else is


# ── Wallet / key files ───────────────────────────────────────────────────────────────────────────────────────────

def test_wallet_save_is_0600_never_overwrites_and_prints_nothing(tmp_path, capsys):
    old = os.umask(0)            # even with no umask the file is the owner's only
    try:
        w = Wallet(KEY)
        p = str(tmp_path / "k" / "w.key")
        assert w.save(p) == p
    finally:
        os.umask(old)
    assert mode(p) == 0o600 and mode(os.path.dirname(p)) == 0o700
    assert os.listdir(os.path.dirname(p)) == ["w.key"], "no temp file is left beside the key file"
    before = open(p).read()
    with pytest.raises(KeyFileError) as e:
        Wallet(KEY).save(p)
    no_key_text(str(e.value), KEY)
    assert open(p).read() == before
    out = capsys.readouterr()
    assert out.out == "" and out.err == ""


def test_key_file_is_created_0600_not_chmodded_after(tmp_path, monkeypatch):
    """The file is never readable by others, not even between create and chmod."""
    monkeypatch.setattr(wallet_mod.os, "fchmod", lambda fd, m: None)
    old = os.umask(0)
    try:
        p = Wallet(KEY).save(str(tmp_path / "w.key"))
    finally:
        os.umask(old)
    assert mode(p) == 0o600


def test_wallet_save_refuses_a_symlink(tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text("x")
    link = tmp_path / "link.key"
    link.symlink_to(target)
    with pytest.raises(KeyFileError):
        Wallet(KEY).save(str(link))
    assert target.read_text() == "x"


def test_failed_write_leaves_no_file(tmp_path, monkeypatch):
    p = tmp_path / "w.key"

    def boom(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(wallet_mod.json, "dump", boom)
    with pytest.raises(RuntimeError):
        Wallet(KEY).save(str(p))
    assert not p.exists()


@pytest.mark.parametrize("m", [0o644, 0o640, 0o604, 0o660, 0o606])
def test_loading_a_key_file_others_can_read_is_refused(tmp_path, m):
    p = tmp_path / "w.key"
    Wallet(KEY).save(str(p))
    os.chmod(p, m)
    with pytest.raises(KeyFileError) as e:
        Wallet.load(str(p))
    no_key_text(str(e.value), KEY)
    with pytest.raises(KeyFileError):
        SessionSigner.from_keystore(str(p))
    with pytest.raises(KeyFileError):
        Agent(key_file=str(p))


def test_load_refuses_a_file_whose_address_is_not_its_key(tmp_path):
    p = tmp_path / "w.key"
    wallet_mod.write_key_file(str(p), "0x" + "33" * 20, KEY)
    with pytest.raises(KeyFileError) as e:
        Wallet.load(str(p))
    no_key_text(str(e.value), KEY)


def test_session_signer_reads_a_0600_key_file(tmp_path):
    p = tmp_path / "s.key"
    Wallet(KEY).save(str(p))
    s = SessionSigner.from_keystore(str(p))
    assert s.address == Account.from_key(KEY).address
    no_key_text(repr(s) + str(s), KEY)


def test_a_malformed_key_does_not_appear_in_the_error():
    bad = "0x" + "4c" * 31 + "zz"
    with pytest.raises(Exception) as e:
        Wallet(bad)
    assert "4c" * 31 not in str(e.value)


def test_classes_holding_a_key_do_not_show_it(monkeypatch):
    from vordium import account_ops, mm
    s = SessionSigner(KEY)
    m = mm.MarketMaker("https://node.invalid", KEY, Account.from_key(KEY).address, post=lambda p, b: None)
    for obj in (s, m):
        no_key_text(repr(obj) + str(obj), KEY)
    ops = account_ops.AccountOps(KEY, rest="https://node.invalid")
    no_key_text(repr(ops) + str(ops), KEY)


# ── CLI ──────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_cli_init_writes_a_0600_file_and_prints_only_address_and_path(home, capsys):
    rc = cli.main(["init"])
    out = capsys.readouterr()
    assert rc == 0
    files = os.listdir(home / ".vordium")
    assert len(files) == 1 and files[0].endswith(".key")
    p = os.path.join(str(home), ".vordium", files[0])
    data = json.load(open(p))
    assert mode(p) == 0o600 and mode(home / ".vordium") == 0o700
    assert Account.from_key(data["private_key"]).address == data["address"] == files[0][:-4]
    no_key_text(out.out + out.err, data["private_key"])
    assert data["address"] in out.out and p in out.out


def test_cli_init_out_path_and_refuses_to_overwrite(home, tmp_path, capsys):
    p = str(tmp_path / "agent.key")
    assert cli.main(["init", "--out", p]) == 0
    before = open(p).read()
    assert mode(p) == 0o600
    assert cli.main(["init", "--out", p]) == 2
    out = capsys.readouterr()
    assert open(p).read() == before
    no_key_text(out.out + out.err, json.loads(before)["private_key"])
    assert "never overwritten" in out.err


def test_cli_init_help_names_the_default_path(capsys):
    with pytest.raises(SystemExit):
        cli.main(["init", "--help"])
    out = capsys.readouterr().out
    assert "0600" in out and ".vordium" in out and "--out" in out


def test_cli_balance_without_address_refuses_and_makes_no_key(home, capsys, monkeypatch):
    made = []
    monkeypatch.setattr(wallet_mod.Account, "create", lambda *a, **k: made.append(1) or (_ for _ in ()).throw(AssertionError("a key was made")))
    monkeypatch.setattr(cli, "Chain", lambda: (_ for _ in ()).throw(AssertionError("no read without an address")))
    rc = cli.main(["balance"])
    out = capsys.readouterr()
    assert rc == 2 and not made
    assert "needs an address" in out.err
    no_key_in(out.out, out.err)
    assert not os.path.exists(home / ".vordium")


def test_cli_balance_with_address_reads_it(home, capsys, monkeypatch):
    class C:
        def get_balance(self, a):
            return 1.25
    monkeypatch.setattr(cli, "Chain", C)
    addr = "0x" + "22" * 20
    assert cli.main(["balance", addr]) == 0
    out = capsys.readouterr()
    assert addr in out.out and "1.25" in out.out
    no_key_in(out.out, out.err)


def test_cli_send_without_a_key_refuses_and_makes_no_key(home, capsys, monkeypatch):
    monkeypatch.setattr(wallet_mod.Account, "create", lambda *a, **k: (_ for _ in ()).throw(AssertionError("a key was made")))
    rc = cli.main(["send", "0x" + "22" * 20, "1"])
    out = capsys.readouterr()
    assert rc == 2 and "no key" in out.err
    no_key_in(out.out, out.err)


def test_cli_send_with_a_key_file_never_echoes_it(home, tmp_path, capsys, monkeypatch):
    p = str(tmp_path / "agent.key")
    Wallet(KEY).save(p)
    sent = []
    monkeypatch.setattr(Agent, "send", lambda self, to, amount: sent.append((self.address, to, amount)) or "0x")
    assert cli.main(["send", "0x" + "22" * 20, "1.5", "--key-file", p]) == 0
    out = capsys.readouterr()
    assert sent == [(Account.from_key(KEY).address, "0x" + "22" * 20, 1.5)]
    no_key_text(out.out + out.err, KEY)


def test_cli_send_with_the_env_key_never_echoes_it(home, capsys, monkeypatch):
    monkeypatch.setenv("VORDIUM_PRIVATE_KEY", KEY)
    monkeypatch.setattr(Agent, "send", lambda self, to, amount: "0x")
    assert cli.main(["send", "0x" + "22" * 20, "2"]) == 0
    out = capsys.readouterr()
    no_key_text(out.out + out.err, KEY)


def test_cli_send_refuses_a_key_file_others_can_read(home, tmp_path, capsys):
    p = str(tmp_path / "agent.key")
    Wallet(KEY).save(p)
    os.chmod(p, 0o644)
    assert cli.main(["send", "0x" + "22" * 20, "1", "--key-file", p]) == 2
    out = capsys.readouterr()
    assert "chmod 600" in out.err
    no_key_text(out.out + out.err, KEY)


def test_cli_interactive_and_register_make_no_key(home, capsys, monkeypatch):
    monkeypatch.setattr(wallet_mod.Account, "create", lambda *a, **k: (_ for _ in ()).throw(AssertionError("a key was made")))
    assert cli.main([]) == 2
    assert cli.main(["register", "--name", "x"]) == 2
    out = capsys.readouterr()
    no_key_in(out.out, out.err)


def test_the_package_prints_no_private_key():
    """No module formats a private key into printed text."""
    root = os.path.dirname(vordium.__file__)
    pat = re.compile(r"print\([^\n]*(private_key|\._key\b|\.key\.hex\(\))")
    hits = []
    for name in sorted(os.listdir(root)):
        if name.endswith(".py"):
            for i, line in enumerate(open(os.path.join(root, name)), 1):
                if pat.search(line):
                    hits.append(f"{name}:{i}")
    assert hits == []
