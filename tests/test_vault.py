"""
Test suite for the kasa engine.

These tests exercise the public API in ``kasa.core`` and intentionally use the
fast "interactive" Argon2id tier so the suite (and the Nix build's checkPhase)
runs in seconds rather than minutes.
"""

import os
import struct

import pytest

from kasa import core


def _make_tree(root: str) -> bytes:
    """Create a representative tree; return the random bytes of the big file."""
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "note.txt"), "w", encoding="utf-8") as f:
        f.write("Secret document\nwith multiple lines\n")
    os.makedirs(os.path.join(root, "photos"))
    big = os.urandom(3 * 1024 * 1024 + 7)  # > 1 MiB forces multi-chunk streaming
    with open(os.path.join(root, "photos", "image.bin"), "wb") as f:
        f.write(big)
    with open(os.path.join(root, "photos", "empty.dat"), "wb"):
        pass
    return big


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


@pytest.mark.parametrize("compress", [False, True])
def test_round_trip_is_byte_exact(tmp_path, compress):
    src = tmp_path / "src"
    big = _make_tree(str(src))
    vault = str(tmp_path / "v.enc")
    pw = b"correct horse battery staple"

    core.write_vault(vault, str(src), pw, tier="interactive", compress=compress)
    assert os.path.getsize(vault) > 0

    out = tmp_path / "out"
    out.mkdir()
    core.read_vault(vault, str(out), pw)

    assert _read(str(out / "note.txt")) == _read(str(src / "note.txt"))
    assert _read(str(out / "photos" / "image.bin")) == big
    assert os.path.exists(out / "photos" / "empty.dat")
    assert os.path.getsize(out / "photos" / "empty.dat") == 0


def test_wrong_password_rejected(tmp_path):
    src = tmp_path / "src"
    _make_tree(str(src))
    vault = str(tmp_path / "v.enc")
    core.write_vault(vault, str(src), b"right-password", tier="interactive")

    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(ValueError):
        core.read_vault(vault, str(out), b"WRONG-password")


def test_truncation_detected(tmp_path):
    src = tmp_path / "src"
    _make_tree(str(src))
    vault = str(tmp_path / "v.enc")
    pw = b"a-password"
    core.write_vault(vault, str(src), pw, tier="interactive")

    data = _read(vault)
    trunc = str(tmp_path / "trunc.enc")
    with open(trunc, "wb") as f:
        f.write(data[: len(data) - 64])

    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(Exception):
        core.read_vault(trunc, str(out), pw)


def test_bitflip_detected(tmp_path):
    src = tmp_path / "src"
    _make_tree(str(src))
    vault = str(tmp_path / "v.enc")
    pw = b"a-password"
    core.write_vault(vault, str(src), pw, tier="interactive")

    data = bytearray(_read(vault))
    data[-32] ^= 0x01  # flip a bit inside the ciphertext stream
    tampered = str(tmp_path / "bad.enc")
    with open(tampered, "wb") as f:
        f.write(data)

    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(Exception):
        core.read_vault(tampered, str(out), pw)


def test_password_change_preserves_data_and_revokes_old(tmp_path):
    src = tmp_path / "src"
    big = _make_tree(str(src))
    vault = str(tmp_path / "v.enc")
    old, new = b"old-password", b"new-and-stronger-password"
    core.write_vault(vault, str(src), old, tier="interactive")

    core.rewrap_password(vault, old, new, tier="interactive")

    out = tmp_path / "out"
    out.mkdir()
    core.read_vault(vault, str(out), new)
    assert _read(str(out / "photos" / "image.bin")) == big

    out2 = tmp_path / "out2"
    out2.mkdir()
    with pytest.raises(ValueError):
        core.read_vault(vault, str(out2), old)


def test_not_a_vault_rejected(tmp_path):
    bogus = str(tmp_path / "bogus.enc")
    with open(bogus, "wb") as f:
        f.write(b"NOTAVAULT" + os.urandom(128))
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(ValueError):
        core.read_vault(bogus, str(out), b"whatever")


def test_header_shape_and_magic(tmp_path):
    src = tmp_path / "src"
    _make_tree(str(src))
    vault = str(tmp_path / "v.enc")
    core.write_vault(vault, str(src), b"pw", tier="interactive")

    # Binary magic at the very start.
    with open(vault, "rb") as f:
        assert f.read(len(core.MAGIC)) == core.MAGIC
        (hlen,) = struct.unpack(">I", f.read(4))
        assert 0 < hlen < 4096

    h = core.read_header(vault)
    for key in ("magic", "version", "cipher", "kdf", "kdf_salt", "kdf_ops",
                "kdf_mem", "dek_nonce", "dek_wrapped", "stream_header",
                "chunk", "compress", "created"):
        assert key in h
    assert h["cipher"] == "xchacha20poly1305-secretstream"
    assert h["kdf"] == "argon2id"
    assert h["version"] == core.FORMAT_VERSION


def test_path_traversal_member_rejected(tmp_path):
    """The safe-extraction guard must reject path-escaping members."""
    import tarfile

    class FakeMember:
        name = "../escape.txt"

        def isdev(self):
            return False

        ischr = isblk = isfifo = issym = islnk = isdev

    with pytest.raises(ValueError):
        core._safe_member(FakeMember(), str(tmp_path))  # type: ignore[arg-type]
