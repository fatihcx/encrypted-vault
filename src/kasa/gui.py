#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kasa.gui — a minimal Tkinter front-end.

Workflow
--------
1. Pick (or create) a vault file and type the master password.
2. "Unlock" decrypts the vault into a RAM-backed temporary folder.
3. Edit the files with your normal applications (file manager, image viewer,
   office suite). Use "Open Folder" to jump straight there.
4. "Lock & Save" re-encrypts the folder back into the vault and wipes the
   plaintext from RAM. "Discard" wipes without saving.

The slow part (Argon2id key derivation, ~1 GiB at the default tier) runs on a
background thread so the window never freezes; results are marshalled back to
the Tk main loop through a queue.

This front-end calls the same engine as the command line (``kasa.core``); the
on-disk format is identical, so vaults are interchangeable between the two.
"""

from __future__ import annotations

import os
import queue
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import core
from ._version import __version__

PAD = 10


class KasaApp:
    def __init__(self, root: tk.Tk, vault_path: str | None = None):
        self.root = root
        self.q: queue.Queue = queue.Queue()

        # Session state (only set while unlocked).
        self.workdir: str | None = None
        self.is_ram = False
        self._password: bytearray | None = None
        self._tier = core.DEFAULT_TIER
        self._compress = False

        root.title("Kasa — Encrypted Vault")
        root.minsize(560, 0)
        try:
            root.tk.call("tk", "scaling", 1.2)
        except tk.TclError:
            pass

        self._build_ui(vault_path)
        self._set_locked()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(80, self._poll)

    # ───────────────────────── UI construction ─────────────────────────

    def _build_ui(self, vault_path: str | None):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        outer = ttk.Frame(self.root, padding=PAD)
        outer.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        outer.columnconfigure(1, weight=1)

        # Vault file row
        ttk.Label(outer, text="Vault file:").grid(row=0, column=0, sticky="w")
        self.var_vault = tk.StringVar(value=vault_path or "")
        self.ent_vault = ttk.Entry(outer, textvariable=self.var_vault)
        self.ent_vault.grid(row=0, column=1, sticky="ew", padx=(PAD, PAD))
        self.btn_browse = ttk.Button(outer, text="Browse…", command=self._browse)
        self.btn_browse.grid(row=0, column=2, sticky="e")

        # Password row
        ttk.Label(outer, text="Password:").grid(row=1, column=0, sticky="w", pady=(PAD, 0))
        self.var_pw = tk.StringVar()
        self.ent_pw = ttk.Entry(outer, textvariable=self.var_pw, show="•")
        self.ent_pw.grid(row=1, column=1, sticky="ew", padx=(PAD, PAD), pady=(PAD, 0))
        self.ent_pw.bind("<Return>", lambda e: self._primary_action())
        self.var_show = tk.BooleanVar(value=False)
        ttk.Checkbutton(outer, text="Show", variable=self.var_show,
                        command=self._toggle_show).grid(row=1, column=2, sticky="e", pady=(PAD, 0))

        # Primary action button (Unlock / Create)
        self.btn_primary = ttk.Button(outer, text="Unlock", command=self._primary_action)
        self.btn_primary.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(PAD, 0))

        # Unlocked panel
        self.panel = ttk.LabelFrame(outer, text="Unlocked", padding=PAD)
        self.panel.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(PAD, 0))
        self.panel.columnconfigure(0, weight=1)

        self.lbl_warn = ttk.Label(
            self.panel,
            text="⚠  Files are decrypted in RAM. Lock when you are done.",
            wraplength=480, justify="left")
        self.lbl_warn.grid(row=0, column=0, columnspan=3, sticky="w")

        self.var_workdir = tk.StringVar(value="")
        self.ent_workdir = ttk.Entry(self.panel, textvariable=self.var_workdir, state="readonly")
        self.ent_workdir.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(PAD, PAD))

        self.btn_open = ttk.Button(self.panel, text="Open Folder", command=self._open_folder)
        self.btn_open.grid(row=2, column=0, sticky="ew", padx=(0, PAD))
        self.btn_save = ttk.Button(self.panel, text="Lock & Save", command=self._lock_and_save)
        self.btn_save.grid(row=2, column=1, sticky="ew", padx=(0, PAD))
        self.btn_discard = ttk.Button(self.panel, text="Discard", command=self._discard)
        self.btn_discard.grid(row=2, column=2, sticky="ew")
        self.panel.columnconfigure(0, weight=1)
        self.panel.columnconfigure(1, weight=1)
        self.panel.columnconfigure(2, weight=1)

        # Status bar
        self.var_status = tk.StringVar(value=f"kasa {__version__} — ready")
        status = ttk.Label(self.root, textvariable=self.var_status, relief="sunken",
                           anchor="w", padding=(PAD, 4))
        status.grid(row=1, column=0, sticky="ew")

    def _toggle_show(self):
        self.ent_pw.config(show="" if self.var_show.get() else "•")

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select a vault file",
            filetypes=[("Kasa vault", "*.enc"), ("All files", "*.*")])
        if path:
            self.var_vault.set(path)
            self._refresh_primary()

    # ───────────────────────── state transitions ─────────────────────────

    def _set_locked(self):
        """No vault is open: show password/unlock, hide the unlocked panel."""
        self.workdir = None
        self.is_ram = False
        self._wipe_password()
        self.var_pw.set("")
        self.panel.grid_remove()
        for w in (self.ent_vault, self.btn_browse, self.ent_pw, self.btn_primary):
            w.config(state="normal")
        self._refresh_primary()

    def _set_unlocked(self):
        """A vault is open: hide password/unlock, show the unlocked panel."""
        self.var_pw.set("")
        self.var_workdir.set(self.workdir or "")
        self.panel.grid()
        self.btn_primary.config(state="disabled")
        self.ent_pw.config(state="disabled")
        self.ent_vault.config(state="disabled")
        self.btn_browse.config(state="disabled")
        for w in (self.btn_open, self.btn_save, self.btn_discard):
            w.config(state="normal")

    def _refresh_primary(self):
        """Label the primary button based on whether the vault file exists."""
        path = self.var_vault.get().strip()
        if path and not os.path.exists(path):
            self.btn_primary.config(text="Create New Vault…")
        else:
            self.btn_primary.config(text="Unlock")

    def _busy(self, msg: str):
        for w in (self.ent_vault, self.btn_browse, self.ent_pw, self.btn_primary,
                  self.btn_open, self.btn_save, self.btn_discard):
            w.config(state="disabled")
        self.var_status.set(msg)
        self.root.config(cursor="watch")
        self.root.update_idletasks()

    def _idle(self, msg: str):
        self.root.config(cursor="")
        self.var_status.set(msg)

    # ───────────────────────── async plumbing ─────────────────────────

    def _run_async(self, work, done, busy_msg: str):
        """Run ``work()`` on a worker thread; call ``done(result)`` on success."""
        self._busy(busy_msg)

        def runner():
            try:
                result = work()
                self.q.put(lambda: self._finish(done, result, None))
            except Exception as exc:  # noqa: BLE001 - surfaced to the user
                self.q.put(lambda: self._finish(done, None, exc))

        threading.Thread(target=runner, daemon=True).start()

    def _finish(self, done, result, err):
        if err is not None:
            self.root.config(cursor="")
            self._on_error(err)
            return
        done(result)

    def _poll(self):
        try:
            while True:
                fn = self.q.get_nowait()
                fn()
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    def _on_error(self, err: Exception):
        # Failed unlock/save: make sure no plaintext is left behind.
        if self.workdir and not self._is_open_succeeded():
            core.secure_wipe(self.workdir, self.is_ram)
            self.workdir = None
        self._wipe_password()
        self._set_locked()
        self._idle("Error")
        messagebox.showerror("Kasa", str(err))

    def _is_open_succeeded(self) -> bool:
        return self.panel.winfo_ismapped()

    # ───────────────────────── primary actions ─────────────────────────

    def _primary_action(self):
        if self.workdir is not None:
            return  # already unlocked
        path = self.var_vault.get().strip()
        if not path:
            messagebox.showwarning("Kasa", "Please choose a vault file first.")
            return
        if os.path.exists(path):
            self._unlock(path)
        else:
            self._create(path)

    def _unlock(self, path: str):
        pw_str = self.var_pw.get()
        if not pw_str:
            messagebox.showwarning("Kasa", "Please enter the password.")
            return
        # Learn this vault's KDF tier / compression so saving preserves them.
        try:
            h = core.read_header(path)
            self._tier = core.tier_name_for(h.get("kdf_ops"), h.get("kdf_mem"))
            if self._tier == "custom":
                self._tier = core.DEFAULT_TIER
            self._compress = (h.get("compress") == "gz")
        except Exception as exc:
            messagebox.showerror("Kasa", f"Not a valid vault:\n{exc}")
            return

        workdir, is_ram = core.make_workdir()
        self.workdir = workdir
        self.is_ram = is_ram
        pw = bytearray(pw_str.encode("utf-8"))
        self._password = pw  # reused for saving; wiped on lock/discard/quit

        def work():
            core.read_vault(path, workdir, bytes(pw))
            return True

        def done(_):
            warn = "" if is_ram else "  (WARNING: not RAM-backed!)"
            self._set_unlocked()
            self._idle(f"Unlocked into {workdir}{warn}")

        self._run_async(work, done, "Unlocking… (deriving key, this can take a few seconds)")

    def _create(self, path: str):
        if not path.endswith(".enc"):
            if not messagebox.askyesno(
                    "Kasa", "The file name does not end with .enc. Create it anyway?"):
                return
        seed = filedialog.askdirectory(
            title="Optional: choose a folder to import (Cancel = start empty)")
        pw = self._ask_new_password()
        if pw is None:
            return

        tier = core.DEFAULT_TIER
        compress = False

        def work():
            if seed:
                core.write_vault(path, seed, bytes(pw), tier=tier, compress=compress)
            else:
                import tempfile
                tmp = tempfile.mkdtemp(prefix="kasa-seed-")
                try:
                    core.write_vault(path, tmp, bytes(pw), tier=tier, compress=compress)
                finally:
                    import shutil
                    shutil.rmtree(tmp, ignore_errors=True)
            return os.path.getsize(path)

        def done(size):
            core.wipe_bytearray(pw)
            self.var_vault.set(path)
            self._set_locked()
            self._idle(f"Vault created: {path} ({size} bytes). Now unlock it.")
            messagebox.showinfo("Kasa", "Vault created. Enter your password and click Unlock.")

        self._run_async(work, done, "Creating vault… (deriving key, this can take a few seconds)")

    def _ask_new_password(self) -> bytearray | None:
        """Modal dialog asking for a new password twice. Returns bytes or None."""
        dlg = tk.Toplevel(self.root)
        dlg.title("New master password")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)
        frm = ttk.Frame(dlg, padding=PAD)
        frm.grid(sticky="nsew")

        ttk.Label(frm, text="New password:").grid(row=0, column=0, sticky="w")
        v1 = tk.StringVar()
        e1 = ttk.Entry(frm, textvariable=v1, show="•", width=32)
        e1.grid(row=0, column=1, padx=PAD, pady=4)
        ttk.Label(frm, text="Confirm:").grid(row=1, column=0, sticky="w")
        v2 = tk.StringVar()
        e2 = ttk.Entry(frm, textvariable=v2, show="•", width=32)
        e2.grid(row=1, column=1, padx=PAD, pady=4)
        ttk.Label(frm, text="Tip: a 5–6 word passphrase is strong and memorable.\n"
                            "If you lose it, the data is unrecoverable.",
                  justify="left", foreground="#555").grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(4, PAD))

        result: dict = {"pw": None}

        def ok():
            if v1.get() != v2.get():
                messagebox.showwarning("Kasa", "Passwords did not match.", parent=dlg)
                return
            if not v1.get():
                messagebox.showwarning("Kasa", "Password cannot be empty.", parent=dlg)
                return
            result["pw"] = bytearray(v1.get().encode("utf-8"))
            dlg.destroy()

        def cancel():
            dlg.destroy()

        btns = ttk.Frame(frm)
        btns.grid(row=3, column=0, columnspan=2, sticky="e")
        ttk.Button(btns, text="Cancel", command=cancel).grid(row=0, column=0, padx=(0, PAD))
        ttk.Button(btns, text="Create", command=ok).grid(row=0, column=1)
        e1.focus_set()
        e1.bind("<Return>", lambda e: e2.focus_set())
        e2.bind("<Return>", lambda e: ok())
        self.root.wait_window(dlg)
        return result["pw"]

    def _open_folder(self):
        if not self.workdir:
            return
        try:
            subprocess.Popen(["xdg-open", self.workdir])
            self._idle(f"Opened {self.workdir} in your file manager")
        except FileNotFoundError:
            messagebox.showinfo("Kasa", f"Open this folder manually:\n{self.workdir}")

    def _lock_and_save(self):
        if not self.workdir or self._password is None:
            return
        path = self.var_vault.get().strip()
        workdir = self.workdir
        pw = self._password
        tier = self._tier
        compress = self._compress

        def work():
            core.write_vault(path, workdir, bytes(pw), tier=tier, compress=compress)
            return os.path.getsize(path)

        def done(size):
            core.secure_wipe(workdir, self.is_ram)
            self._set_locked()
            self._idle(f"Saved and locked: {path} ({size} bytes)")

        self._run_async(work, done, "Saving… (encrypting and deriving key)")

    def _discard(self):
        if not self.workdir:
            return
        if not messagebox.askyesno(
                "Kasa", "Discard all changes since unlocking?\n"
                        "The vault file on disk will not be modified."):
            return
        core.secure_wipe(self.workdir, self.is_ram)
        path = self.var_vault.get().strip()
        self._set_locked()
        self.var_vault.set(path)
        self._idle("Changes discarded; working area wiped.")

    # ───────────────────────── shutdown ─────────────────────────

    def _wipe_password(self):
        if self._password is not None:
            core.wipe_bytearray(self._password)
            self._password = None

    def _on_close(self):
        if self.workdir is not None:
            ans = messagebox.askyesnocancel(
                "Kasa", "The vault is unlocked.\n\n"
                        "Yes = Lock & Save, No = Discard, Cancel = stay open.")
            if ans is None:
                return  # cancel
            if ans:  # save
                path = self.var_vault.get().strip()
                try:
                    core.write_vault(path, self.workdir, bytes(self._password),
                                     tier=self._tier, compress=self._compress)
                except Exception as exc:  # noqa: BLE001
                    messagebox.showerror("Kasa", f"Save failed; not quitting:\n{exc}")
                    return
            core.secure_wipe(self.workdir, self.is_ram)
            self.workdir = None
        self._wipe_password()
        self.root.destroy()


def main(vault_path: str | None = None):
    """Entry point for ``kasa-gui`` and ``kasa gui``."""
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        raise SystemExit(
            f"Cannot start the GUI (no display?): {exc}\n"
            "On a headless machine use the command line instead: kasa --help")
    KasaApp(root, vault_path=vault_path)
    root.mainloop()


if __name__ == "__main__":
    main()
