{
  description = "kasa — personal, portable, single-file encrypted vault (XChaCha20-Poly1305 + Argon2id)";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f (import nixpkgs { inherit system; }));

      # The package: a Python application exposing two entry points,
      # `kasa` (CLI) and `kasa-gui` (Tkinter GUI).
      kasaFor =
        pkgs:
        pkgs.python3Packages.buildPythonApplication {
          pname = "kasa-vault";
          version = "1.0.0";
          pyproject = true;
          src = ./.;

          build-system = [ pkgs.python3Packages.hatchling ];

          # Runtime dependencies. tkinter is required by the GUI; pulling it in
          # here guarantees `import tkinter` works inside the wrapped program.
          dependencies = [
            pkgs.python3Packages.pynacl
            pkgs.python3Packages.tkinter
          ];

          nativeCheckInputs = [ pkgs.python3Packages.pytest ];

          # The build refuses to complete unless the crypto round-trip passes.
          checkPhase = ''
            runHook preCheck
            python -m pytest -q
            python -m kasa selftest
            runHook postCheck
          '';

          meta = with pkgs.lib; {
            description = "Personal, portable, single-file encrypted vault";
            longDescription = ''
              kasa stores your private documents and photos in a single encrypted
              file. It is decrypted into RAM (tmpfs) for editing and re-encrypted
              on close, so plaintext never reaches persistent disk. Cryptography
              is XChaCha20-Poly1305 (secretstream) with an Argon2id-derived,
              envelope-wrapped key, all via libsodium.
            '';
            license = licenses.mit;
            platforms = platforms.linux;
            mainProgram = "kasa";
          };
        };
    in
    {
      packages = forAllSystems (pkgs: rec {
        kasa = kasaFor pkgs;
        default = kasa;
      });

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = "${kasaFor pkgs}/bin/kasa";
        };
        gui = {
          type = "app";
          program = "${kasaFor pkgs}/bin/kasa-gui";
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.python3.withPackages (ps: [ ps.pynacl ps.tkinter ps.pytest ]))
            pkgs.ruff
          ];
        };
      });

      # `nix flake check` builds the package, which runs the test suite + selftest.
      checks = forAllSystems (pkgs: { kasa = kasaFor pkgs; });

      formatter = forAllSystems (pkgs: pkgs.nixpkgs-fmt);
    };
}
