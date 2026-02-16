{
  description = "QUIC v1 transport implementation in Zig";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    dev-env.url = "github:devnw/dev-env";
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
            cffi
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
            pyopenssl
            service-identity
            python-lsp-server
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
              # Keep shell startup side-effect free and offline-friendly.
              # Optional auth/secret loading is available via scripts/devshell_auth.sh.

              # Python path
              export PATH="${pythonWithPackages}/bin:$PATH"

              # Reset PYTHONPATH safely, then prepend env site-packages when present.
              export PYTHONPATH=''${PYTHONPATH:-""}
              if [ -d "${pythonWithPackages}/${pythonWithPackages.sitePackages}" ]; then
                export PYTHONPATH="${pythonWithPackages}/${pythonWithPackages.sitePackages}:$PYTHONPATH"
              fi

              # C/C++ flags used by quiche/BoringSSL and other native dependencies.
              export NIX_CFLAGS_COMPILE="''${NIX_CFLAGS_COMPILE:-""}"
              export NIX_CXXFLAGS_COMPILE="''${NIX_CXXFLAGS_COMPILE:-""}"
              export NIX_LDFLAGS="''${NIX_LDFLAGS:-""} -L${pkgs.glibc}/lib -L${pkgs.gcc.cc.lib}/lib -L${pkgs.libffi}/lib"
              export CFLAGS="''${CFLAGS:-""}"
              export CXXFLAGS="''${CXXFLAGS:-""}"
              export LDFLAGS="''${LDFLAGS:-""} -L${pkgs.glibc}/lib -L${pkgs.gcc.cc.lib}/lib -L${pkgs.libffi}/lib"

              # Ensure libffi is available for cffi.
              export LD_LIBRARY_PATH="${pkgs.libffi}/lib:''${LD_LIBRARY_PATH:-""}"

              # Keep nix config minimal and local to the shell session.
              NIX_CONFIG="experimental-features = nix-command flakes
              access-tokens = github.com=''${GITHUB_TOKEN:-}"
              export NIX_CONFIG

              printf '[devshell] Optional auth/secret setup: %s\n' "./scripts/devshell_auth.sh"
            '';
            env = { };
            packages =
              (with dev-env.packages.${system}; [
                goPackages
                zigPackages
                commonPackages
              ])
              ++ (with pkgs; [
                file
                tcpdump
                tshark
                pythonWithPackages

                  # Rust toolchain for client tests
                  rustc
                  cargo
                  rustfmt
                  rust-analyzer
                  clippy
                  boringssl
                  openssl
                  glibc
                  glibc.dev
                  gcc.cc.lib
                  libev
                  libffi

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
