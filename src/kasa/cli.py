#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kasa.cli — the command-line front-end.

All user-facing text is in English. The cryptographic work is delegated to
``kasa.core``; this module handles argument parsing, password prompts, session
bookkeeping, and console output.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

from . import core
from ._version import __version__

# Session state is NOT secret: it only records which working directory a vault
# is currently open in. It lives under XDG_STATE_HOME so it survives a logout
# but is wiped on the next reboot only if placed on tmpfs (it is not — it is a
# tiny pointer file, never plaintext).
STATE_DIR = os.path.join(
    os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state")), "kasa"
)


# ───────────────────────────── console helpers ─────────────────────────────

def eprint(*a):
    print(*a, file=sys.stderr)


def warn_if_not_ram(is_ram: bool):
    if not is_ram:
        eprint("WARNING: the working area is not RAM (tmpfs)! Plaintext is being "
               "written to persistent disk.\n"
               "         Make XDG_RUNTIME_DIR or /dev/shm available.")


def read_password(prompt: str, confirm: bool = False, pwfile: str | None = None) -> bytearray:
    if pwfile:
        with open(pwfile, "rb") as f:
            return bytearray(f.readline().rstrip(b"\n"))
    pw = getpass.getpass(prompt)
    if confirm:
        pw2 = getpass.getpass("Re-enter password: ")
        if pw != pw2:
            del pw, pw2
            raise SystemExit("Passwords did not match.")
    ba = bytearray(pw.encode("utf-8"))
    del pw
    return ba


# ───────────────────────────── session state ─────────────────────────────

def session_file(vault_path: str) -> str:
    key = hashlib.sha256(os.path.abspath(vault_path).encode()).hexdigest()[:16]
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    return os.path.join(STATE_DIR, f"session-{key}.json")


def load_session(vault_path: str):
    p = session_file(vault_path)
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return None


def save_session(vault_path: str, workdir: str, is_ram: bool):
    with open(session_file(vault_path), "w") as f:
        json.dump({"vault": os.path.abspath(vault_path), "workdir": workdir,
                   "is_ram": is_ram, "opened_at": time.time()}, f)
    os.chmod(session_file(vault_path), 0o600)


def clear_session(vault_path: str):
    p = session_file(vault_path)
    if os.path.exists(p):
        os.unlink(p)


# ───────────────────────────── commands ─────────────────────────────

def cmd_init(args):
    if os.path.exists(args.vault) and not args.force:
        raise SystemExit(f"'{args.vault}' already exists. Use --force to overwrite.")
    seed = args.from_dir
    pw = read_password("New master password: ", confirm=True, pwfile=args.password_file)
    try:
        if seed:
            if not os.path.isdir(seed):
                raise SystemExit(f"--from directory does not exist: {seed}")
            core.write_vault(args.vault, seed, bytes(pw), tier=args.kdf, compress=args.compress)
        else:
            tmp = tempfile.mkdtemp(prefix="kasa-seed-")
            try:
                core.write_vault(args.vault, tmp, bytes(pw), tier=args.kdf, compress=args.compress)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
    finally:
        core.wipe_bytearray(pw)
    sz = os.path.getsize(args.vault)
    print(f"Vault created: {args.vault} ({sz} bytes, KDF={args.kdf})")
    print(f"To edit:  kasa session --shell -v {args.vault}")


def cmd_open(args):
    if not os.path.exists(args.vault):
        raise SystemExit(f"Vault not found: {args.vault}")
    if load_session(args.vault):
        raise SystemExit("This vault already appears to be open. Run 'close' or 'discard' first.")
    workdir, is_ram = core.make_workdir()
    warn_if_not_ram(is_ram)
    pw = read_password("Master password: ", pwfile=args.password_file)
    try:
        core.read_vault(args.vault, workdir, bytes(pw))
    except BaseException:
        core.secure_wipe(workdir, is_ram)
        raise
    finally:
        core.wipe_bytearray(pw)
    save_session(args.vault, workdir, is_ram)
    print(workdir)
    eprint(f"Vault opened -> {workdir}")
    eprint(f"Edit your files; when done:  kasa close -v {args.vault}")


def cmd_close(args):
    sess = load_session(args.vault)
    if not sess:
        raise SystemExit("No open session.")
    workdir, is_ram = sess["workdir"], sess["is_ram"]
    if not os.path.isdir(workdir):
        clear_session(args.vault)
        raise SystemExit("Working directory is gone; session cleared.")
    pw = read_password("Master password to save: ", confirm=True, pwfile=args.password_file)
    try:
        core.write_vault(args.vault, workdir, bytes(pw), tier=args.kdf, compress=args.compress)
    finally:
        core.wipe_bytearray(pw)
    core.secure_wipe(workdir, is_ram)
    clear_session(args.vault)
    print(f"Saved and locked: {args.vault} ({os.path.getsize(args.vault)} bytes)")


def cmd_discard(args):
    sess = load_session(args.vault)
    if not sess:
        raise SystemExit("No open session.")
    core.secure_wipe(sess["workdir"], sess["is_ram"])
    clear_session(args.vault)
    print("Changes discarded, working area wiped (the vault file was not modified).")


def cmd_session(args):
    if not os.path.exists(args.vault):
        raise SystemExit(f"Vault not found: {args.vault}")
    if load_session(args.vault):
        raise SystemExit("This vault is already open. Run 'close' or 'discard' first.")
    workdir, is_ram = core.make_workdir()
    warn_if_not_ram(is_ram)
    pw = read_password("Master password: ", pwfile=args.password_file)
    try:
        try:
            core.read_vault(args.vault, workdir, bytes(pw))
        except BaseException:
            core.secure_wipe(workdir, is_ram)
            raise
        save_session(args.vault, workdir, is_ram)
        eprint(f"Vault open -> {workdir}")

        saved = False
        try:
            if args.shell:
                shell = os.environ.get("SHELL", "/bin/bash")
                eprint("Opening a subshell. On exit (exit / Ctrl-D) the vault will be saved and locked.")
                eprint("To exit WITHOUT saving, before leaving run:  touch .kasa-discard")
                env = dict(os.environ, KASA_VAULT=os.path.abspath(args.vault))
                subprocess.run([shell], cwd=workdir, env=env)
                discard_flag = os.path.join(workdir, ".kasa-discard")
                if os.path.exists(discard_flag):
                    eprint(".kasa-discard found: discarding changes.")
                else:
                    core.write_vault(args.vault, workdir, bytes(pw), tier=args.kdf, compress=args.compress)
                    saved = True
            else:
                while True:
                    eprint(f"\nWorking area: {workdir}")
                    choice = input("[s] save+lock  [d] discard & exit  [p] print path > ").strip().lower()
                    if choice == "s":
                        core.write_vault(args.vault, workdir, bytes(pw), tier=args.kdf, compress=args.compress)
                        saved = True
                        break
                    if choice == "d":
                        break
                    if choice == "p":
                        eprint(workdir)
        finally:
            core.secure_wipe(workdir, is_ram)
            clear_session(args.vault)
            if saved:
                print(f"Saved and locked: {args.vault} ({os.path.getsize(args.vault)} bytes)")
            else:
                print("No changes saved; working area wiped.")
    finally:
        core.wipe_bytearray(pw)


def cmd_passwd(args):
    if not os.path.exists(args.vault):
        raise SystemExit(f"Vault not found: {args.vault}")
    old = read_password("Current password: ", pwfile=args.old_password_file)
    new = read_password("New password: ", confirm=True, pwfile=args.new_password_file)
    try:
        core.rewrap_password(args.vault, bytes(old), bytes(new), tier=args.kdf)
    finally:
        core.wipe_bytearray(old)
        core.wipe_bytearray(new)
    print("Password changed (data was not re-encrypted; only the envelope was renewed).")


def cmd_status(args):
    if not os.path.exists(args.vault):
        raise SystemExit(f"Vault not found: {args.vault}")
    h = core.read_header(args.vault)
    sz = os.path.getsize(args.vault)
    tier = core.tier_name_for(h.get("kdf_ops"), h.get("kdf_mem"))
    sess = load_session(args.vault)
    print(f"File        : {args.vault}")
    print(f"Size        : {sz} bytes ({sz / 1048576:.2f} MiB)")
    print(f"Format      : v{h.get('version')}  {h.get('cipher')}")
    print(f"KDF         : {h.get('kdf')}  ops={h.get('kdf_ops')} mem={h.get('kdf_mem')} (~{tier})")
    print(f"Compression : {h.get('compress')}")
    print(f"Created     : {h.get('created')}")
    print(f"Open session: {'YES -> ' + sess['workdir'] if sess else 'no'}")


def cmd_gui(args):
    """Launch the graphical interface."""
    from . import gui
    gui.main(vault_path=args.vault if args.vault != DEFAULT_VAULT else None)


def cmd_selftest(args):
    import filecmp
    print("Kasa self-test starting (interactive KDF, fast)...")
    tmp = tempfile.mkdtemp(prefix="kasa-test-")
    try:
        src = os.path.join(tmp, "data")
        os.makedirs(src)
        # Sample content: text, binary, subdirectory, large file, empty file.
        with open(os.path.join(src, "note.txt"), "w", encoding="utf-8") as f:
            f.write("Secret document — line 1\nline 2\n")
        os.makedirs(os.path.join(src, "photos"))
        big = os.urandom(3 * 1024 * 1024 + 7)  # ~3 MiB, forces multi-chunk streaming
        with open(os.path.join(src, "photos", "image.bin"), "wb") as f:
            f.write(big)
        with open(os.path.join(src, "photos", "empty.dat"), "wb"):
            pass

        vault = os.path.join(tmp, "test.enc")
        pw = b"correct-horse-battery-staple-42"
        core.write_vault(vault, src, pw, tier="interactive", compress=args.compress)
        assert os.path.getsize(vault) > 0
        print(f"  OK  written: {os.path.getsize(vault)} bytes")

        # Correct password => full restore.
        out = os.path.join(tmp, "out")
        os.makedirs(out)
        core.read_vault(vault, out, pw)
        rep = filecmp.dircmp(src, out)

        def assert_equal_tree(d):
            assert not d.left_only and not d.right_only and not d.diff_files, \
                f"differences: only_l={d.left_only} only_r={d.right_only} diff={d.diff_files}"
            for sub in d.subdirs.values():
                assert_equal_tree(sub)
        assert_equal_tree(rep)
        with open(os.path.join(out, "photos", "image.bin"), "rb") as f:
            assert f.read() == big
        print("  OK  decrypted and content is byte-for-byte identical")

        # Wrong password must be rejected.
        out2 = os.path.join(tmp, "out2")
        os.makedirs(out2)
        try:
            core.read_vault(vault, out2, b"wrong-password")
            raise AssertionError("SECURITY FAILURE: wrong password decrypted the vault!")
        except ValueError:
            print("  OK  wrong password rejected")

        # Truncation detection.
        trunc = os.path.join(tmp, "trunc.enc")
        with open(vault, "rb") as a, open(trunc, "wb") as b:
            data = a.read()
            b.write(data[: len(data) - 64])
        out3 = os.path.join(tmp, "out3")
        os.makedirs(out3)
        try:
            core.read_vault(trunc, out3, pw)
            raise AssertionError("SECURITY FAILURE: truncated vault was accepted!")
        except Exception:
            print("  OK  truncated/corrupt vault rejected")

        # Password change (envelope re-wrap), then the old password must fail.
        core.rewrap_password(vault, pw, b"new-long-and-strong-password", tier="interactive")
        out4 = os.path.join(tmp, "out4")
        os.makedirs(out4)
        core.read_vault(vault, out4, b"new-long-and-strong-password")
        with open(os.path.join(out4, "photos", "image.bin"), "rb") as f:
            assert f.read() == big
        print("  OK  password change works, data preserved")
        try:
            out5 = os.path.join(tmp, "out5")
            os.makedirs(out5)
            core.read_vault(vault, out5, pw)
            raise AssertionError("SECURITY FAILURE: the old password still works!")
        except ValueError:
            print("  OK  old password is now rejected")

        print("\nALL TESTS PASSED")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ───────────────────────────── argument parser ─────────────────────────────

DEFAULT_VAULT = "my-vault.enc"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kasa",
        description="Personal encrypted vault (XChaCha20-Poly1305 + Argon2id, single file, RAM-first).")
    p.add_argument("--version", action="version", version=f"kasa {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Options shared by every subcommand, so `kasa <cmd> -v FILE` works (the
    # vault option comes after the subcommand, which reads most naturally).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--vault", default=DEFAULT_VAULT,
                        help=f"Vault file (default: {DEFAULT_VAULT})")

    def add_kdf(sp):
        sp.add_argument("--kdf", choices=list(core.KDF_TIERS), default=core.DEFAULT_TIER,
                        help="Argon2id tier (default: sensitive ~= 1 GiB)")
        sp.add_argument("--compress", action="store_true", help="Apply gzip when writing")

    sp = sub.add_parser("init", parents=[common], help="Create a new vault")
    sp.add_argument("--from", dest="from_dir", help="Seed the vault with this directory's contents")
    sp.add_argument("--force", action="store_true", help="Overwrite an existing file")
    sp.add_argument("--password-file", help="(automation) read the password from a file")
    add_kdf(sp)
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("session", parents=[common],
                        help="Open -> edit -> auto-lock on exit (RECOMMENDED)")
    sp.add_argument("--shell", action="store_true", help="Open a subshell in the tmpfs directory")
    sp.add_argument("--password-file", help="(automation) password file")
    add_kdf(sp)
    sp.set_defaults(func=cmd_session)

    sp = sub.add_parser("open", parents=[common],
                        help="Open the vault into tmpfs (then 'close'/'discard')")
    sp.add_argument("--password-file")
    sp.set_defaults(func=cmd_open)

    sp = sub.add_parser("close", parents=[common], help="Save and lock the open session")
    sp.add_argument("--password-file")
    add_kdf(sp)
    sp.set_defaults(func=cmd_close)

    sp = sub.add_parser("discard", parents=[common],
                        help="Discard the open session without saving")
    sp.set_defaults(func=cmd_discard)

    sp = sub.add_parser("passwd", parents=[common],
                        help="Change the master password (data is not re-encrypted)")
    sp.add_argument("--old-password-file")
    sp.add_argument("--new-password-file")
    sp.add_argument("--kdf", choices=list(core.KDF_TIERS), default=core.DEFAULT_TIER)
    sp.set_defaults(func=cmd_passwd)

    sp = sub.add_parser("status", parents=[common], help="Show information about the vault")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("gui", parents=[common], help="Launch the graphical interface")
    sp.set_defaults(func=cmd_gui)

    sp = sub.add_parser("selftest", parents=[common], help="Run the crypto/round-trip self-test")
    sp.add_argument("--compress", action="store_true")
    sp.set_defaults(func=cmd_selftest)

    return p


def main(argv=None):
    os.umask(0o077)  # all new files/dirs are owner-only
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except KeyboardInterrupt:
        eprint("\nCancelled.")
        sys.exit(130)
    except (ValueError, SystemExit) as e:
        if isinstance(e, SystemExit):
            raise
        eprint("Error:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
