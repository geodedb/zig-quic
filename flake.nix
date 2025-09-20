{
  description = "QUIC v1 transport implementation in Zig";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    dev-env.url = "github:spyderorg/dev-env";
  };

  outputs =
    {
      self,
      nixpkgs,
      dev-env,
      flake-utils,
      ...
    }:
    let
      flakeForSystem =
        nixpkgs: system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config = { allowUnfree = true; };
          };
          zigPkg = dev-env.packages.${system}.zigPackages;

          # Build quic packages
          quicPkg = pkgs.callPackage ./nix/quic.nix {
            zig = zigPkg;
            optimize = "ReleaseSafe";
          };
          
          quicDebugPkg = pkgs.callPackage ./nix/quic.nix {
            zig = zigPkg;
            optimize = "Debug";
          };
          
          # Single source of truth for the development environment packages
          devShellPackages = with pkgs; [
            zigPkg
          ];
        in
        {
          packages = {
            quic = quicPkg;
            quic-debug = quicDebugPkg;
            default = quicPkg;
          };
          devShell = pkgs.mkShell {
            shellHook = '''';
            env = { };
            packages =
              (with dev-env.packages.${system}; [
                zigPackages
                commonPackages
              ])
              ++ ([
                pkgs.file
              ]);
          };
        };
    in
    flake-utils.lib.eachDefaultSystem (system: flakeForSystem nixpkgs system);

  nixConfig = {
    extra-substituters = [ "https://spyder.cachix.org" ];
    extra-trusted-public-keys = [
      "spyder.cachix.org-1:xZG2a8INH6yNyOAwtN2Ojjys0GO9D1pXEe3PNriT04E="
    ];
  };
}
