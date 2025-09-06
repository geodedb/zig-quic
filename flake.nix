{
  description = "dev";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    dev-env.url = "git+https://github.com/spyderorg/dev-env";
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
        in
        {
          devShell = pkgs.mkShell {
            shellHook = '''';
            env = { };
            packages =
              (with dev-env.packages.${system}; [
                zigPackages
                goPackages
                commonPackages
              ])
              ++ (with pkgs; [
                tcpdump
                tshark
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
