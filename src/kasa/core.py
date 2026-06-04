#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kasa.core — the cryptographic engine and on-disk vault format.

This module is intentionally free of any user-interface code (no printing, no
argument parsing). Both the command-line front-end (``kasa.cli``) and the
graphical front-end (``kasa.gui``) import the functions defined here.

Architecture
------------
    password ──Argon2id(salt, ops, mem)──▶ KEK (key-encrypting key, 32 B)
    random DEK (32 B) ──XChaCha20-Poly1305(KEK)──▶ "wrapped DEK" (envelope)
    data (tar stream) ──XChaCha20-Poly1305 secretstream(DEK)──▶ ciphertext chunks

Only a single file ever touches the disk (e.g. ``my-vault.enc``). When opened,
its contents are extracted into a RAM-backed directory (tmpfs:
``XDG_RUNTIME_DIR`` / ``/dev/shm``), edited there, then re-encrypted and written
back atomically, after which the RAM directory is wiped. Plaintext never reaches
persistent disk (provided swap is encrypted or RAM-backed — see the README).

Why these primitives?
    * Argon2id   : modern, memory-hard password hashing (resists GPU/ASIC attacks).
    * XChaCha20-Poly1305 : 192-bit nonce (random-nonce collisions are effectively
                           impossible), AEAD (confidentiality + integrity in one).
    * secretstream : purpose-built for file/stream encryption; automatic chunking,
                     per-chunk authentication, and a FINAL tag that detects
                     truncation. Corruption or trimming cannot pass silently.
    * envelope (KEK/DEK): changing the password re-wraps only the small envelope
                          instead of re-encrypting the entire payload.

All cryptography goes through libsodium (PyNaCl); there is no hand-rolled crypto.

ON-DISK FORMAT (see docs/FORMAT.md for the full specification)
--------------------------------------------------------------
    MAGIC (8 bytes, b"KASAVLT1")
    header_length (uint32, big-endian)
    header (UTF-8 JSON, non-secret metadata)
    repeated: chunk_length (uint32, big-endian) + ciphertext_chunk
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.util
import io
import json
import os
import shutil
import struct
import tarfile
import tempfile
import time

import nacl.bindings as sodium
import nacl.pwhash
import nacl.utils

# ───────────────────────────── constants ─────────────────────────────
# WARNING: these values define the on-disk format. Changing any of them breaks
# compatibility with existing vaults. Do not modify without bumping the format
# version and providing a migration path.

MAGIC = b"KASAVLT1"                 # 8-byte file signature (format guard)
FORMAT_VERSION = 1
CHUNK = 1024 * 1024                 # plaintext chunk size per secretstream push (1 MiB)
STREAM_AD = b"KASAVLT1/stream"      # secretstream first-chunk associated data (fixed)

SS_KEYBYTES = sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES        # 32
SS_HEADERBYTES = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES  # 24
TAG_MSG = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE         # 0
TAG_FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL         # 3
AEAD_NPUB = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES            # 24
SALTBYTES = nacl.pwhash.argon2id.SALTBYTES                                 # 16

KDF_TIERS = {
    "interactive": (nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE,
                    nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE),   # fast, ~64 MiB
    "moderate":    (nacl.pwhash.argon2id.OPSLIMIT_MODERATE,
                    nacl.pwhash.argon2id.MEMLIMIT_MODERATE),      # medium, ~256 MiB
    "sensitive":   (nacl.pwhash.argon2id.OPSLIMIT_SENSITIVE,
                    nacl.pwhash.argon2id.MEMLIMIT_SENSITIVE),     # strongest, ~1 GiB
}
DEFAULT_TIER = "sensitive"

# ───────────────────────────── secure memory ─────────────────────────────

_libc_name = ctypes.util.find_library("c")
_libc = ctypes.CDLL(_libc_name, use_errno=True) if _libc_name else None


class SecureBytes:
    """
    A mutable buffer that is mlock'd (kept out of swap) and zeroed on release.

    Used for key material. Because PyNaCl's high-level APIs return ``bytes``,
    short-lived copies cannot be entirely avoided; this class protects the most
    critical copy. Protecting the decrypted *payload* in RAM relies primarily on
    encrypted/zram swap (see the README).
    """

    def __init__(self, data):
        if isinstance(data, int):
            self._buf = bytearray(data)
        else:
            self._buf = bytearray(data)
        self._locked = False
        self._ctype = None
        self._addr = 0
        n = len(self._buf)
        if n:
            self._ctype = (ctypes.c_char * n).from_buffer(self._buf)
            self._addr = ctypes.addressof(self._ctype)
            if _libc is not None:
                if _libc.mlock(ctypes.c_void_p(self._addr), ctypes.c_size_t(n)) == 0:
                    self._locked = True

    def bytes(self) -> bytes:
        return bytes(self._buf)

    def clear(self):
        n = len(self._buf)
        if n and self._ctype is not None:
            ctypes.memset(self._addr, 0, n)
            if self._locked and _libc is not None:
                _libc.munlock(ctypes.c_void_p(self._addr), ctypes.c_size_t(n))
                self._locked = False
            self._ctype = None
        self._buf = bytearray()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.clear()
        return False


def wipe_bytearray(ba: bytearray):
    """Zero a bytearray's contents in place (for password buffers)."""
    for i in range(len(ba)):
        ba[i] = 0


# ───────────────────────────── crypto helpers ─────────────────────────────

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def derive_kek(password: bytes, salt: bytes, ops: int, mem: int) -> SecureBytes:
    """Derive the key-encrypting key (KEK) from the password using Argon2id."""
    key = nacl.pwhash.argon2id.kdf(SS_KEYBYTES, password, salt,
                                   opslimit=ops, memlimit=mem)
    return SecureBytes(key)


def dek_aad(salt: bytes, ops: int, mem: int) -> bytes:
    """
    Associated data for the DEK envelope: format + KDF parameters + salt.

    If the header is tampered with (e.g. an attempt to downgrade the KDF cost),
    unwrapping the envelope fails.
    """
    return MAGIC + struct.pack(">I", FORMAT_VERSION) + struct.pack(">QQ", ops, mem) + salt


# ───────────────────────────── streaming wrappers ─────────────────────────────

class EncSink(io.RawIOBase):
    """
    A file-like writer: ``tarfile`` writes into this; whenever a full chunk
    accumulates we encrypt it with secretstream and write
    ``[uint32 length][ciphertext chunk]`` to the output file. Constant memory
    usage (~CHUNK).
    """

    def __init__(self, fout, state, first_ad: bytes):
        self.fout = fout
        self.state = state
        self.buf = bytearray()
        self.first_ad = first_ad
        self.first = True
        self.total = 0

    def writable(self):
        return True

    def write(self, b):
        if not isinstance(b, (bytes, bytearray, memoryview)):
            b = bytes(b)
        self.buf += b
        self.total += len(b)
        while len(self.buf) >= CHUNK:
            self._emit(self.buf[:CHUNK], TAG_MSG)
            del self.buf[:CHUNK]
        return len(b)

    def _emit(self, chunk, tag):
        ad = self.first_ad if self.first else b""
        self.first = False
        ct = sodium.crypto_secretstream_xchacha20poly1305_push(
            self.state, bytes(chunk), ad, tag)
        self.fout.write(struct.pack(">I", len(ct)))
        self.fout.write(ct)

    def finalize(self):
        # Emit remaining data with the FINAL tag (a single FINAL chunk => truncation detection).
        self._emit(self.buf, TAG_FINAL)
        self.buf = bytearray()

    def flush(self):
        pass


class DecSource(io.RawIOBase):
    """
    A file-like reader: ``tarfile`` reads from this; we decode the
    ``[uint32][ciphertext chunk]`` framing and return plaintext. We read until
    the FINAL tag arrives; a stream that ends early => 'truncated vault' error.
    """

    def __init__(self, fin, state, first_ad: bytes):
        self.fin = fin
        self.state = state
        self.first_ad = first_ad
        self.first = True
        self.buf = bytearray()
        self.eof = False

    def readable(self):
        return True

    def _pull_one(self):
        lenb = self.fin.read(4)
        if len(lenb) == 0:
            raise ValueError("Vault is truncated/corrupt: never reached the FINAL chunk.")
        if len(lenb) != 4:
            raise ValueError("Vault is corrupt: chunk length is incomplete.")
        (clen,) = struct.unpack(">I", lenb)
        ct = self.fin.read(clen)
        if len(ct) != clen:
            raise ValueError("Vault is corrupt: chunk data is incomplete.")
        ad = self.first_ad if self.first else b""
        self.first = False
        msg, tag = sodium.crypto_secretstream_xchacha20poly1305_pull(self.state, ct, ad)
        self.buf += msg
        if tag == TAG_FINAL:
            self.eof = True

    def readinto(self, b):
        while not self.buf and not self.eof:
            self._pull_one()
        n = min(len(b), len(self.buf))
        b[:n] = self.buf[:n]
        del self.buf[:n]
        return n


# ───────────────────────────── safe tar extraction ─────────────────────────────

def _within(base: str, target: str) -> bool:
    base = os.path.realpath(base)
    target = os.path.realpath(target)
    return target == base or target.startswith(base + os.sep)


def _safe_member(m: tarfile.TarInfo, dest: str):
    name = m.name
    norm = os.path.normpath(name)
    if name.startswith("/") or norm.startswith(".." + os.sep) or norm == "..":
        raise ValueError(f"Unsafe path in archive: {name}")
    if any(part == ".." for part in norm.split(os.sep)):
        raise ValueError(f"Unsafe path in archive: {name}")
    if m.isdev() or m.ischr() or m.isblk() or m.isfifo():
        raise ValueError(f"Device/special file in archive rejected: {name}")
    if m.issym() or m.islnk():
        link = m.linkname
        if link.startswith("/") or ".." in os.path.normpath(link).split(os.sep):
            raise ValueError(f"Unsafe link target in archive: {name} -> {link}")
    target = os.path.join(dest, norm)
    if not _within(dest, target):
        raise ValueError(f"Path escape in archive: {name}")


# Use Python's built-in "data" extraction filter when available (3.12+) as an
# extra layer on top of our own _safe_member() checks, and to opt in explicitly
# to the behaviour that becomes the default in Python 3.14. On older
# interpreters the kwarg is simply omitted (our checks still apply).
_EXTRACT_KW = {"numeric_owner": False}
if hasattr(tarfile, "data_filter"):
    _EXTRACT_KW["filter"] = "data"


def safe_extract_stream(tar: tarfile.TarFile, dest: str):
    """Extract in streaming mode (r|*), member by member, validating paths/devices/symlinks."""
    for m in tar:
        _safe_member(m, dest)
        tar.extract(m, dest, **_EXTRACT_KW)


# ───────────────────────── core: write / read / rewrap ─────────────────────

def write_vault(vault_path: str, src_dir: str, password: bytes,
                tier: str = DEFAULT_TIER, compress: bool = False):
    """Encrypt the contents of ``src_dir`` and write to ``vault_path`` ATOMICALLY."""
    ops, mem = KDF_TIERS[tier]
    salt = nacl.utils.random(SALTBYTES)

    with derive_kek(password, salt, ops, mem) as kek, \
            SecureBytes(nacl.utils.random(SS_KEYBYTES)) as dek:

        # Wrap the DEK with the KEK (envelope).
        aad = dek_aad(salt, ops, mem)
        dek_nonce = nacl.utils.random(AEAD_NPUB)
        dek_wrapped = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            dek.bytes(), aad, dek_nonce, kek.bytes())

        # Initialise the secretstream.
        st = sodium.crypto_secretstream_xchacha20poly1305_state()
        ss_header = sodium.crypto_secretstream_xchacha20poly1305_init_push(st, dek.bytes())

        header = {
            "magic": "KASA",
            "version": FORMAT_VERSION,
            "cipher": "xchacha20poly1305-secretstream",
            "kdf": "argon2id",
            "kdf_salt": b64e(salt),
            "kdf_ops": ops,
            "kdf_mem": mem,
            "dek_nonce": b64e(dek_nonce),
            "dek_wrapped": b64e(dek_wrapped),
            "stream_header": b64e(ss_header),
            "chunk": CHUNK,
            "compress": "gz" if compress else "none",
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")

        tmp = vault_path + f".tmp-{os.getpid()}-{int(time.time())}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as fout:
                fout.write(MAGIC)
                fout.write(struct.pack(">I", len(header_bytes)))
                fout.write(header_bytes)

                sink = EncSink(fout, st, first_ad=STREAM_AD)
                mode = "w|gz" if compress else "w|"
                with tarfile.open(fileobj=sink, mode=mode, format=tarfile.PAX_FORMAT) as tar:
                    for entry in sorted(os.listdir(src_dir)):
                        tar.add(os.path.join(src_dir, entry), arcname=entry, recursive=True)
                sink.finalize()
                fout.flush()
                os.fsync(fout.fileno())
            os.replace(tmp, vault_path)
            os.chmod(vault_path, 0o600)
            # Persist the directory entry as well.
            dirfd = os.open(os.path.dirname(os.path.abspath(vault_path)) or ".", os.O_DIRECTORY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise


def read_header(vault_path: str) -> dict:
    """Read and return the non-secret JSON header of a vault."""
    with open(vault_path, "rb") as f:
        magic = f.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Not a Kasa file (signature mismatch).")
        (hlen,) = struct.unpack(">I", f.read(4))
        header = json.loads(f.read(hlen).decode("utf-8"))
    return header


def read_vault(vault_path: str, dest_dir: str, password: bytes):
    """Decrypt ``vault_path`` and extract its contents into ``dest_dir`` (tmpfs)."""
    with open(vault_path, "rb") as fin:
        magic = fin.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Not a Kasa file (signature mismatch).")
        (hlen,) = struct.unpack(">I", fin.read(4))
        header_bytes = fin.read(hlen)
        header = json.loads(header_bytes.decode("utf-8"))

        salt = b64d(header["kdf_salt"])
        ops = int(header["kdf_ops"])
        mem = int(header["kdf_mem"])
        dek_nonce = b64d(header["dek_nonce"])
        dek_wrapped = b64d(header["dek_wrapped"])
        ss_header = b64d(header["stream_header"])

        with derive_kek(password, salt, ops, mem) as kek:
            aad = dek_aad(salt, ops, mem)
            try:
                dek_plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                    dek_wrapped, aad, dek_nonce, kek.bytes())
            except Exception:
                raise ValueError("Wrong password, or the vault header is corrupt.")

            with SecureBytes(dek_plain) as dek:
                st = sodium.crypto_secretstream_xchacha20poly1305_state()
                sodium.crypto_secretstream_xchacha20poly1305_init_pull(st, ss_header, dek.bytes())
                src = DecSource(fin, st, first_ad=STREAM_AD)
                with tarfile.open(fileobj=src, mode="r|*") as tar:
                    safe_extract_stream(tar, dest_dir)


def rewrap_password(vault_path: str, old_pw: bytes, new_pw: bytes,
                    tier: str = DEFAULT_TIER):
    """
    Change the password WITHOUT touching the plaintext: re-wrap only the DEK
    envelope with the new password and copy the ciphertext stream verbatim
    (the strength of envelope encryption).
    """
    with open(vault_path, "rb") as fin:
        magic = fin.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Not a Kasa file.")
        (hlen,) = struct.unpack(">I", fin.read(4))
        old_header_bytes = fin.read(hlen)
        old = json.loads(old_header_bytes.decode("utf-8"))

        old_salt = b64d(old["kdf_salt"])
        old_ops = int(old["kdf_ops"])
        old_mem = int(old["kdf_mem"])
        with derive_kek(old_pw, old_salt, old_ops, old_mem) as old_kek:
            old_aad = dek_aad(old_salt, old_ops, old_mem)
            try:
                dek_plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                    b64d(old["dek_wrapped"]), old_aad, b64d(old["dek_nonce"]), old_kek.bytes())
            except Exception:
                raise ValueError("Old password is wrong.")

        # Re-wrap the (same) DEK with a new KEK and a fresh salt.
        ops, mem = KDF_TIERS[tier]
        salt = nacl.utils.random(SALTBYTES)
        with SecureBytes(dek_plain) as dek, derive_kek(new_pw, salt, ops, mem) as new_kek:
            aad = dek_aad(salt, ops, mem)
            dek_nonce = nacl.utils.random(AEAD_NPUB)
            dek_wrapped = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
                dek.bytes(), aad, dek_nonce, new_kek.bytes())

        new_header = dict(old)
        new_header.update({
            "kdf_salt": b64e(salt), "kdf_ops": ops, "kdf_mem": mem,
            "dek_nonce": b64e(dek_nonce), "dek_wrapped": b64e(dek_wrapped),
        })
        new_header_bytes = json.dumps(new_header, separators=(",", ":")).encode("utf-8")

        # Because the secretstream AD is a fixed constant (STREAM_AD), copying the
        # ciphertext stream verbatim is safe; the plaintext is never touched.
        tmp = vault_path + f".tmp-{os.getpid()}-{int(time.time())}"
        with open(tmp, "wb") as fout:
            fout.write(MAGIC)
            fout.write(struct.pack(">I", len(new_header_bytes)))
            fout.write(new_header_bytes)
            shutil.copyfileobj(fin, fout, length=1024 * 1024)
            fout.flush()
            os.fsync(fout.fileno())
        os.replace(tmp, vault_path)
        os.chmod(vault_path, 0o600)


# ───────────────────────────── tmpfs workspace ─────────────────────────────

def pick_runtime_base() -> tuple[str, bool]:
    """Pick a RAM-backed base directory. Returns ``(path, is_ram)``."""
    cands = []
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        cands.append(xdg)
    cands.append("/dev/shm")
    for c in cands:
        if c and os.path.isdir(c) and os.access(c, os.W_OK):
            return c, True
    return tempfile.gettempdir(), False  # last resort: /tmp (may NOT be RAM!)


def make_workdir() -> tuple[str, bool]:
    """Create a private working directory under a RAM-backed base."""
    base, is_ram = pick_runtime_base()
    root = os.path.join(base, "kasa")
    os.makedirs(root, mode=0o700, exist_ok=True)
    os.chmod(root, 0o700)
    wd = tempfile.mkdtemp(prefix="vault-", dir=root)
    os.chmod(wd, 0o700)
    return wd, is_ram


def secure_wipe(path: str, is_ram: bool):
    """
    Remove the working directory. On tmpfs, freeing the pages is sufficient;
    otherwise (not RAM) we at least attempt to overwrite, but that is unreliable
    on modern SSDs/filesystems — which is why tmpfs is required.
    """
    if not os.path.isdir(path):
        return
    if not is_ram:
        for dp, _dn, fn in os.walk(path):
            for name in fn:
                fp = os.path.join(dp, name)
                try:
                    sz = os.path.getsize(fp)
                    with open(fp, "r+b", buffering=0) as f:
                        f.write(os.urandom(min(sz, 4 * 1024 * 1024)) if sz else b"")
                        f.flush()
                        os.fsync(f.fileno())
                except OSError:
                    pass
    shutil.rmtree(path, ignore_errors=True)


def tier_name_for(ops, mem) -> str:
    """Return the KDF tier name matching the given parameters, or 'custom'."""
    return next((k for k, (o, m) in KDF_TIERS.items() if o == ops and m == mem), "custom")
