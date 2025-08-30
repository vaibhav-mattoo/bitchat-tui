{
  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      utils,
      naersk,
    }:
    utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        naersk-lib = pkgs.callPackage naersk { };
        buildInputs = with pkgs; [
          cargo
          rustc
          rustfmt
          rustPackages.clippy
          rust-analyzer
        ];

      in
      rec {
        defaultPackage =
          with pkgs;
          naersk-lib.buildPackage {
            src = ./.;
            inherit buildInputs;
          };
        packages = {
          bitchat-tui = defaultPackage;
        };
        devShell =
          with pkgs;
          mkShell {
            inherit buildInputs;
            RUST_SRC_PATH = rustPlatform.rustLibSrc;
          };
      }
    );
}
