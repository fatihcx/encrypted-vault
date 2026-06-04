# kasa

A personal, portable, **single-file encrypted vault**. Keep your private
documents and photos in one encrypted file (`my-vault.enc`). Open it to edit and
the contents are decrypted into **RAM only**; close it and only the encrypted
file remains on disk. Cryptography is XChaCha20-Poly1305 with an Argon2id-derived,
envelope-wrapped key — all via [libsodium](https://doc.libsodium.org/)
(PyNaCl). No hand-rolled crypto.

It ships with a command-line interface **and** a small Tkinter GUI.

---

## Features

- **One file, anywhere.** The whole vault is a single `.enc` file you can sync
  to any cloud; the contents are useless without your password.
- **Plaintext never hits disk.** Opening extracts into a RAM-backed directory
  (`tmpfs`: `XDG_RUNTIME_DIR` / `/dev/shm`); closing re-encrypts and wipes it.
- **Modern, audited primitives.** Argon2id (memory-hard KDF) + XChaCha20-Poly1305
  `secretstream` (authenticated, chunked, with truncation detection).
- **Fast password changes.** Envelope encryption re-wraps only a 48-byte key, so
  changing the password is instant regardless of vault size.
- **Tamper-evident.** Any corruption, truncation, or bit-flip is detected and
  rejected on open.
- **Streaming, bounded memory.** Encrypts/decrypts ~1 MiB at a time, so a 1 GB
  vault never needs 1 GB of working buffers.
- **Recoverable by design.** The on-disk format is fully documented in
  [`docs/FORMAT.md`](docs/FORMAT.md) so the data can be recovered even without
  this exact program.

## How it works

```
password ──Argon2id(salt, ops, mem)──▶ KEK  (key-encrypting key, 32 B)
random DEK (32 B) ──XChaCha20-Poly1305(KEK)──▶ "wrapped DEK"  (stored in header)
your files ─tar→ XChaCha20-Poly1305 secretstream(DEK) ─▶ ciphertext chunks
```

The password never encrypts your data directly; it only protects the random key
that does. See [`docs/FORMAT.md`](docs/FORMAT.md) for the exact byte layout.

## Security model

**What it protects against**
- Theft or loss of the file (laptop stolen, cloud account breached): without the
  password the file is opaque, and Argon2id makes brute force expensive.
- Silent corruption or tampering: detected on open and rejected.

**What it does *not* protect against**
- A weak or forgotten password. **If you lose the password, the data is gone** —
  there is no backdoor.
- A compromised machine while the vault is **open** (malware, someone at your
  unlocked screen): the plaintext is in RAM and in your temp folder by design.
- Plaintext reaching disk **swap** while open. Use encrypted or RAM-backed swap
  (see [Swap hardening](#swap-hardening-nixos)).
- Metadata: the file's *size* roughly reveals how much data you store.

This is a personal tool built on standard primitives; it has not had a formal
third-party audit.

## Requirements

- Linux with a RAM-backed `tmpfs` (standard on NixOS and virtually all distros).
- Python ≥ 3.10 and [PyNaCl](https://pypi.org/project/PyNaCl/).
- For the GUI: Tk (`python3-tk` on most distros; the Nix package pulls it in).

---

## Install (NixOS, flakes)

> Replace `YOUR-GITHUB-USERNAME` with your GitHub account throughout.

### Try it without installing

```bash
nix run github:YOUR-GITHUB-USERNAME/kasa -- selftest
nix run github:YOUR-GITHUB-USERNAME/kasa -- --help
nix run "github:YOUR-GITHUB-USERNAME/kasa#gui"      # launch the GUI
```

### Permanent install via your system flake (recommended)

Add this repo as an input and install its package for your user. In your
**system `flake.nix`**:

```nix
{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    home-manager = {
      url = "github:nix-community/home-manager/master";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Add kasa:
    kasa.url = "github:YOUR-GITHUB-USERNAME/kasa";
    kasa.inputs.nixpkgs.follows = "nixpkgs";   # share one nixpkgs
  };

  outputs = { self, nixpkgs, home-manager, kasa, ... }:
    {
      nixosConfigurations.syst3m = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        # Pass the flake inputs down to home.nix:
        specialArgs = { inherit kasa; };
        modules = [
          ./configuration.nix
          home-manager.nixosModules.home-manager
          {
            home-manager.useGlobalPkgs = true;
            home-manager.useUserPackages = true;
            home-manager.extraSpecialArgs = { inherit kasa; };
            home-manager.users.fatih = import ./home.nix;
          }
        ];
      };
    };
}
```

Then in **`home.nix`** add the package (note the extra `kasa` argument):

```nix
{ config, pkgs, kasa, ... }:
{
  home.packages = [
    kasa.packages.${pkgs.system}.default   # provides `kasa` and `kasa-gui`
    # ... your other packages
  ];
}
```

Rebuild: `nh os switch` or `sudo nixos-rebuild switch --flake .#syst3m`.

A copy-paste example for exactly this host/user is in
[`examples/nixos/`](examples/nixos/).

#### Private repository access

If your GitHub repo is **private**, Nix needs credentials to fetch it. Either:

- **Token** — add to `~/.config/nix/nix.conf` (or the system `nix.settings`):
  ```
  access-tokens = github.com=ghp_yourTokenWithRepoScope
  ```
- **SSH** — reference it over SSH instead of the `github:` shorthand:
  ```nix
  kasa.url = "git+ssh://git@github.com/YOUR-GITHUB-USERNAME/kasa.git";
  ```

#### Local-path fallback (no network, no token)

Clone the repo and point the input at the local path:

```nix
kasa.url = "git+file:///home/fatih/src/kasa";
```

---

## Usage

The default vault file is `my-vault.enc` in the current directory; override with
`-v/--vault`.

### Command line

```bash
# Create a new vault (optionally seeding it from an existing folder)
kasa init -v ~/vault.enc
kasa init -v ~/vault.enc --from ~/Documents/private

# RECOMMENDED workflow: open, edit, auto-lock on exit
kasa session --shell -v ~/vault.enc
#   ... you are dropped into a shell inside the decrypted RAM folder ...
#   ... edit files with any tool; on exit the vault is re-encrypted & locked ...
#   ... to quit WITHOUT saving: `touch .kasa-discard` before you exit ...

# Manual open / close (open prints the temp folder path on stdout)
kasa open  -v ~/vault.enc
kasa close -v ~/vault.enc      # save & lock
kasa discard -v ~/vault.enc    # throw away changes, leave the vault untouched

# Maintenance
kasa passwd -v ~/vault.enc     # change password (data is NOT re-encrypted)
kasa status -v ~/vault.enc     # show format, KDF tier, size, open session
kasa selftest                  # run the crypto round-trip self-test
```

KDF strength is selectable with `--kdf {interactive,moderate,sensitive}`
(default `sensitive`, ~1 GiB). Add `--compress` to gzip the contents.

### GUI

```bash
kasa gui                       # or: kasa-gui
```

1. Choose (or create) a vault file and type the master password.
2. Click **Unlock** — the vault is decrypted into a RAM folder.
3. Click **Open Folder** to edit the files with your normal applications.
4. Click **Lock & Save** to re-encrypt and wipe RAM, or **Discard** to drop
   changes.

The GUI uses the same engine and file format as the CLI, so vaults are fully
interchangeable between them.

---

## Recovery

Your data's longevity does not depend on this program staying installed:

1. Clone the repo and run the tool:
   ```bash
   nix run github:YOUR-GITHUB-USERNAME/kasa -- open -v /path/to/my-vault.enc
   ```
2. If the tool is ever unavailable, the complete byte-level format is in
   [`docs/FORMAT.md`](docs/FORMAT.md). Any libsodium binding can decrypt the
   file from that spec; the only secret required is your master password.

Keeping this repository (the code **and** `docs/FORMAT.md`) is your insurance.

## Swap hardening (NixOS)

While a vault is open, the decrypted files live in `tmpfs`. Under memory
pressure those pages could be written to **disk swap** — leaking plaintext. If
your swap is a plain unencrypted partition, prefer compressed RAM swap and
disable disk swap:

```nix
# configuration.nix
swapDevices = lib.mkForce [ ];          # disable unencrypted disk swap
zramSwap = { enable = true; memoryPercent = 50; };
services.logind.settings.Login.RuntimeDirectorySize = "4G";  # room for a large vault in /run/user
```

(Trade-off: disabling disk swap disables hibernation; suspend-to-RAM is
unaffected.)

## Development

```bash
nix develop          # shell with python + pynacl + tkinter + pytest + ruff
pytest               # run the test suite
python -m kasa selftest
nix flake check      # builds the package and runs tests in a sandbox
```

## License

MIT — see [`LICENSE`](LICENSE).
