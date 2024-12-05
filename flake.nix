{
  inputs = {
    nixify.url = "github:rvolosatovs/nixify";
    nixsgx-flake.url = "github:matter-labs/nixsgx";
    nixpkgs.follows = "nixsgx-flake/nixpkgs";
  };

  outputs = { nixify, nixsgx-flake, ... }:
    nixify.lib.rust.mkFlake {
      src = ./.;

      overlays = [
        nixsgx-flake.overlays.default
      ];

      withDevShells =
        { devShells
        , pkgs
        , ...
        }:
        nixify.lib.extendDerivations
          {
            nativeBuildInputs = with pkgs; [
              pkg-config
              rustPlatform.bindgenHook
            ];

            buildInputs = with pkgs; [
              openssl
              nixsgx.sgx-sdk
              nixsgx.sgx-dcap
              nixsgx.sgx-dcap.libtdx_attest
            ];
          }
          devShells;
    };
}
