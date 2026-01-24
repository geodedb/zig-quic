{ stdenv
, lib
, zig
, optimize ? "ReleaseSafe"
}:

stdenv.mkDerivation rec {
  pname = "quic";
  version = "0.1.0";

  src = ../.;

  nativeBuildInputs = [ zig ];

  configurePhase = ''
    runHook preConfigure
    export HOME=$TMPDIR
    runHook postConfigure
  '';

  buildPhase = ''
    runHook preBuild
    
    # Build with the specified optimization level
    local optFlag=""
    if [ "${optimize}" = "ReleaseSafe" ]; then
      optFlag="-Drelease-safe=true"
    elif [ "${optimize}" = "Debug" ]; then
      optFlag="-Doptimize=Debug"
    else
      optFlag="-Doptimize=${optimize}"
    fi
    
    # Build everything
    zig build $optFlag
    zig build tools $optFlag
    zig build cli $optFlag
    
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    
    # Create output directories
    mkdir -p $out/bin
    mkdir -p $out/lib
    mkdir -p $out/include
    
    # Copy binaries if they exist
    if [ -d "zig-out/bin" ]; then
      cp -r zig-out/bin/* $out/bin/
    fi
    
    # Copy libraries if they exist
    if [ -d "zig-out/lib" ]; then
      cp -r zig-out/lib/* $out/lib/
    fi
    
    # Copy the source for module usage by other Zig projects
    mkdir -p $out/src
    cp -r src/* $out/src/
    cp quic.zig $out/
    cp build.zig $out/
    cp build.zig.zon $out/
    
    runHook postInstall
  '';

  meta = with lib; {
    description = "Production-grade QUIC v1 transport implementation in Zig";
    homepage = "https://github.com/spyderorg/quic";
    platforms = platforms.all;
  };
}