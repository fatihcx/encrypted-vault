# Example home.nix integration.
#
# This shows ONLY the two changes needed to install kasa from the flake input
# instead of building a local ./kasa.py. Merge these into your real home.nix and
# delete the old `let kasaPython = ...; kasa = pkgs.runCommandLocal ...; in`
# block from the previous (single-file) setup.

# 1) Accept the `kasa` argument that the system flake passes in via
#    home-manager.extraSpecialArgs (see examples/nixos/flake.nix):
{ config, pkgs, kasa, ... }:

{
  home.username = "fatih";
  home.homeDirectory = "/home/fatih";
  home.stateVersion = "23.11"; # never change

  # ... all your other home-manager settings stay exactly as they are ...

  # 2) Install the package. It provides BOTH the `kasa` CLI and the `kasa-gui`
  #    launcher. No local kasa.py and no `git add kasa.py` step anymore.
  home.packages = with pkgs; [
    # ... your other packages (vscode, keepassxc, bitwarden-desktop, ...) ...

    kasa.packages.${pkgs.system}.default
  ];

  programs.home-manager.enable = true;
}
