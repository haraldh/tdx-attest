{
  inputs = {
    nixify.url = "github:rvolosatovs/nixify";
    nixsgx-flake.url = "github:matter-labs/nixsgx";
    nixpkgs.follows = "nixsgx-flake/nixpkgs";
  };

  outputs = {
    nixify,
    nixsgx-flake,
    ...
  }:
    nixify.lib.rust.mkFlake {
      src = ./.;

      overlays = [
        nixsgx-flake.overlays.default
      ];

      buildOverrides = {
        pkgs,
        pkgsCross ? pkgs,
        ...
      } @ args: {
        buildInputs ? [],
        nativeBuildInputs ? [],
        ...
      } @ craneArgs: let
        buildInputs' =
          buildInputs
          ++ (with pkgs; [
            openssl
            nixsgx.sgx-sdk
            nixsgx.sgx-dcap.dev
            nixsgx.sgx-dcap.libtdx_attest
            libclang
          ]);
        nativeBuildInputs' =
          nativeBuildInputs
          ++ (with pkgs; [
            pkgs.pkg-config
            rustPlatform.bindgenHook
          ]);
      in {
        buildInputs = buildInputs';
        nativeBuildInputs = nativeBuildInputs';
      };
    };
}
