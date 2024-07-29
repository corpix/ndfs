{
  inputs = {
    nixpkgs.url = "tarball+https://git.tatikoma.dev/corpix/nixpkgs/archive/v2024-07-26.655033.tar.gz";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }: let
    eachSystem = flake-utils.lib.eachSystem flake-utils.lib.allSystems;
  in eachSystem
    (arch: let
      pkgs = nixpkgs.legacyPackages.${arch}.pkgs;

      inherit (pkgs)
        writeScript
        stdenv
        buildGoModule
        mkShell
      ;
      inherit (pkgs.lib)
        attrValues
        filter
      ;

      envPackages = attrValues {
        inherit (pkgs)
          coreutils
          gnumake
          git
          gcc
          pkg-config
          go
          gopls
          hivemind
        ;
      };
    in {
      packages.default = buildGoModule {
        name = "ndfs";
        src = ./.;
        vendorHash = null;
      };
      devShells.default = mkShell {
        name = "ndfs";
        packages = envPackages;
      };
    });
}
