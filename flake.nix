{
  description = "dev";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    dev-env.url = "git+https://github.com/spyderorg/dev-env";
    zigpkgs.url = "github:NixOS/nixpkgs/nixos-unstable"; # to source newer zig (0.15.x)
  };

  outputs =
    {
      self,
      nixpkgs,
      zigpkgs,
      dev-env,
      flake-utils,
      ...
    }:
    let
      flakeForSystem =
        nixpkgs: system:
        let
          # Import nixpkgs with unfree enabled so the forenix package (unfree license) evaluates cleanly
          pkgs = import nixpkgs {
            inherit system;
            config = { allowUnfree = true; };
          };
          unstable = import zigpkgs {
            inherit system;
            config = { allowUnfree = true; };
          };
          # Use zig 0.15.x from unstable (fallback to stable zig if attribute missing)
          zigPkg = unstable.zig_0_15 or unstable.zig or pkgs.zig;
          # Single source of truth for the development environment packages
          devShellPackages = with pkgs; [
            zigPkg
            tcpdump
            file
          ];
        in
        {
          devShell = pkgs.mkShell {
            shellHook = '''';
            env = { };
            packages = devShellPackages;
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
