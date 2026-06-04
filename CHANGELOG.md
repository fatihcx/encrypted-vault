# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-06-02

First public release.

### Added
- Single-file encrypted vault using XChaCha20-Poly1305 `secretstream` for the
  payload and an Argon2id-derived, envelope-wrapped key (KEK/DEK) via libsodium.
- Streaming, bounded-memory encryption/decryption (1 MiB chunks) with
  per-chunk authentication and truncation detection (FINAL tag).
- RAM-backed (`tmpfs`) working directory; plaintext never written to persistent
  disk under normal operation.
- Command-line interface: `init`, `session` (with `--shell`), `open`, `close`,
  `discard`, `passwd`, `status`, `gui`, and `selftest`.
- Selectable Argon2id tiers (`interactive`, `moderate`, `sensitive`; default
  `sensitive`) and optional gzip compression.
- Tkinter GUI (`kasa gui` / `kasa-gui`): unlock to RAM, edit with external apps,
  lock & save or discard; slow key derivation runs off the UI thread.
- Atomic, owner-only (`0600`) writes with `fsync`; safe tar extraction that
  rejects path traversal, device/special files, and escaping symlinks.
- Nix flake: package (CLI + GUI), `apps.default`/`apps.gui`, a dev shell, and a
  `checks` entry that runs the test suite and self-test in a sandbox.
- pytest suite and a documented on-disk format (`docs/FORMAT.md`) for long-term
  recoverability.

### Format
- On-disk format **version 1**. Files written by the original single-file
  `kasa.py` are fully compatible and open without changes.
