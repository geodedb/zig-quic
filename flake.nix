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

          # Python environment for geodetestlab and client test harness
          pythonWithPackages = pkgs.python3.withPackages (ps: with ps; [
            pip
            setuptools
            wheel
            typer
            pydantic
            rich
            jmespath
            psutil
            keyring
            pyyaml
            pytest
            mypy
            black
            isort
            flake8
            aioquic
            cryptography
          ]);

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
            shellHook = ''
              export PYTHONPATH="${pythonWithPackages}/lib/python3.12/site-packages:$PYTHONPATH"
            '';
            env = { };
            packages =
              (with dev-env.packages.${system}; [
                zigPackages
                commonPackages
              ])
              ++ (with pkgs; [
                toybox
                file
                tcpdump
                tshark
                pythonWithPackages

                  # Rust toolchain for client tests
                  rustc
                  cargo
                  rustfmt
                  clippy
                  boringssl

                  # Debugging and analysis
                  gdb
                  valgrind
                  strace

                  # Network tools
                  tcpdump
                  wireshark-cli
                  netcat-gnu
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
