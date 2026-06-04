{
  # Example NixOS system flake that installs kasa from this repository as a
  # flake input (replacing the older local ./kasa.py build). Adapt the owner,
  # host name ("syst3m") and user ("fatih") to your own.
  description = "Fatih's NixOS + Home Manager configuration";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    home-manager = {
      url = "github:nix-community/home-manager/master";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # kasa — pick ONE of the three forms below:
    #   public or token-authenticated GitHub:
    kasa.url = "github:YOUR-GITHUB-USERNAME/kasa";
    #   private repo over SSH:
    # kasa.url = "git+ssh://git@github.com/YOUR-GITHUB-USERNAME/kasa.git";
    #   local checkout (no network/token needed):
    # kasa.url = "git+file:///home/fatih/src/kasa";
    kasa.inputs.nixpkgs.follows = "nixpkgs"; # build kasa against the same nixpkgs
  };

  outputs =
    { self, nixpkgs, home-manager, kasa, ... }:
    let
      system = "x86_64-linux";
    in
    {
      nixosConfigurations.syst3m = nixpkgs.lib.nixosSystem {
        inherit system;
        # Make `kasa` available to configuration.nix if you ever need it there.
        specialArgs = { inherit kasa; };
        modules = [
          ./configuration.nix

          home-manager.nixosModules.home-manager
          {
            home-manager.useGlobalPkgs = true;
            home-manager.useUserPackages = true;
            # Pass `kasa` down so home.nix can reference it.
            home-manager.extraSpecialArgs = { inherit kasa; };
            home-manager.users.fatih = import ./home.nix;
          }
        ];
      };
    };
}
