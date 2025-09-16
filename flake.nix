{
  description = "QUIC v1 transport implementation in Zig";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    # We'll use unstable for newer zig version
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-unstable,
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

          pkgs-unstable = import nixpkgs-unstable {
            inherit system;
            config = { allowUnfree = true; };
          };

          # Use zig from unstable for newer version
          zigPkg = pkgs-unstable.zig or pkgs.zig;

          # Build quic packages
          quicPkg = pkgs.callPackage ./nix/quic.nix {
            zig = zigPkg;
            optimize = "ReleaseSafe";
          };
          
          quicDebugPkg = pkgs.callPackage ./nix/quic.nix {
            zig = zigPkg;
            optimize = "Debug";
          };
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
            packages = with pkgs; [
              zigPkg
              go
              tcpdump
              tshark
              file
            ];
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
