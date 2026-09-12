{
  description = "Nitro Enclave - reproducible build (Rust)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    aws-nitro-util.url = "github:monzo/aws-nitro-util";
  };

  outputs = { self, nixpkgs, flake-utils, aws-nitro-util }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        eifPkgs = if system == "x86_64-linux" then pkgs
                  else import nixpkgs { system = "x86_64-linux"; };
        nitro = aws-nitro-util.lib.x86_64-linux;

        configPath = let p = builtins.getEnv "BUILD_CONFIG_PATH"; in
          if p != "" then p else "../.enclave/build-config.json";
        buildCfg = builtins.fromJSON (builtins.readFile configPath);
        appCfg = buildCfg.app;
        runtimeCfg = buildCfg.runtime;

        version = buildCfg.version;
        region = buildCfg.region;
        deployment = buildCfg.prefix;

        # Resolve user-supplied package names from enclave.yaml
        # (nix_build_inputs / nix_native_build_inputs) against nixpkgs.
        resolveInputs = names: map (n: eifPkgs.${n}) names;

        # Enclave supervisor — built from the runtime repo.
        runtime = eifPkgs.buildGoModule {
          pname = "runtime";
          version = buildCfg.version;

          src = eifPkgs.fetchFromGitHub {
            owner = "ArkLabsHQ";
            repo = "introspector-enclave";
            rev = runtimeCfg.rev;
            hash = runtimeCfg.hash;
          };

          sourceRoot = "source/runtime";
          vendorHash = runtimeCfg.vendor_hash;
          subPackages = [ "cmd/runtime" ];
          env.CGO_ENABLED = "0";
          ldflags = [
            "-X" "github.com/ArkLabsHQ/introspector-enclave/runtime.Version=${version}"
          ];
          buildFlags = [ "-trimpath" ];
          tags = [ "netgo" ];
          doCheck = false;
        };

        # Cosigner WASM — pinned by URL+hash so its bytes contribute to PCR0/1/2.
        # To bump: change url, then run
        #   nix store prefetch-file --hash-type sha256 <new-url>
        # and paste the resulting `sha256-…` SRI string below.
        cosignerWasm = eifPkgs.fetchurl {
          name = "cosigner.wasm";
          url = "https://github.com/BitspendPayment/MPCWallet/releases/download/cosigner-8c631a813dff4f34080b83631ce10ebdc8829d26/cosigner.wasm";
          hash = "sha256-0+n22l4k+6wXC+p2N05kZMvGC7N8vSIr2BJWrhi8xxU=";
        };

        # User's Rust app — fetched from GitHub. No runtime dependency needed.
        upstream-app = eifPkgs.rustPlatform.buildRustPackage ({
          pname = appCfg.binary_name;
          version = buildCfg.version;

          src = eifPkgs.fetchFromGitHub {
            owner = appCfg.nix_owner;
            repo = appCfg.nix_repo;
            rev = appCfg.nix_rev;
            hash = appCfg.nix_hash;
          };

          # Build from the committed vendor/ dir (see cosigner/.cargo/config.toml)
          # so the EIF build needs zero crates.io access and survives upstream crates
          # being yanked/removed. Path is relative to cargoRoot (the nix_subdir),
          # so just "vendor" (NOT "${appCfg.nix_subdir}/vendor" — that double-nests).
          cargoVendorDir = "vendor";

          doCheck = false;

          # The enclave build must use the supervisor-backed persistence store,
          # not the default Sled backend (which writes to ephemeral enclave-local
          # disk and is lost on every restart/migration). Disable default features
          # so PERSISTENCE_BACKEND="enclave" can't silently fall back to Sled.
          cargoBuildFlags = [ "--bin" appCfg.binary_name "--no-default-features" "--features" "enclave-backend" ];

          nativeBuildInputs = resolveInputs (appCfg.nix_native_build_inputs or []);
          buildInputs = resolveInputs (appCfg.nix_build_inputs or []);
        } // (if (appCfg.nix_subdir or "") != "" then {
          sourceRoot = "source";
          cargoRoot = appCfg.nix_subdir;
          buildAndTestSubdir = appCfg.nix_subdir;
        } else {}));

        # Nitriding and viproxy are vendored into the runtime binary — no
        # separate derivations needed.

        appDir = eifPkgs.runCommand "enclave-app" { } ''
          mkdir -p $out/app/data
          cp ${upstream-app}/bin/${appCfg.binary_name} $out/app/${appCfg.binary_name}
          cp ${runtime}/bin/runtime $out/app/runtime
          cp ${cosignerWasm} $out/app/cosigner.wasm
        '';

        enclaveRootfs = eifPkgs.buildEnv {
          name = "enclave-rootfs";
          paths = [
            appDir
            eifPkgs.busybox
            eifPkgs.cacert
          ];
          pathsToLink = [ "/" ];
        };

        secretsCfgJson = builtins.toJSON (buildCfg.secrets or []);

        enclaveEnv = let
          appEnvLines = builtins.concatStringsSep "\n"
            (builtins.map (k: "${k}=${builtins.getAttr k appCfg.env}")
              (builtins.attrNames appCfg.env));
        in ''
          PATH=/app:/bin:/usr/bin
          SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
          AWS_REGION=${region}
          ENCLAVE_APP_NAME=${buildCfg.name}
          ENCLAVE_SECRETS_CONFIG=${secretsCfgJson}
          ENCLAVE_MIGRATION_COOLDOWN=${buildCfg.migration_cooldown or "0s"}
          ENCLAVE_PREVIOUS_PCR0=${buildCfg.previous_pcr0 or "genesis"}
          ENCLAVE_KMS_KEY_LOCKED=${if buildCfg.is_kms_key_locked or false then "true" else "false"}
          ENCLAVE_DEPLOYMENT=${deployment}
          ${appEnvLines}
        '';

        eif = nitro.buildEif {
          name = "${buildCfg.name}-enclave";
          inherit version;

          arch = "x86_64";
          kernel = nitro.blobs.x86_64.kernel;
          kernelConfig = nitro.blobs.x86_64.kernelConfig;
          nsmKo = nitro.blobs.x86_64.nsmKo;

          copyToRoot = enclaveRootfs;
          entrypoint = "/app/runtime";
          env = enclaveEnv;
        };

        # Vendor hash check — used by enclave setup to discover the correct hash.
        vendor-hash-check = eifPkgs.rustPlatform.buildRustPackage ({
          pname = "vendor-hash-check";
          version = buildCfg.version;
          src = eifPkgs.fetchFromGitHub {
            owner = appCfg.nix_owner;
            repo = appCfg.nix_repo;
            rev = appCfg.nix_rev;
            hash = appCfg.nix_hash;
          };
          cargoHash = "";
          doCheck = false;

          nativeBuildInputs = resolveInputs (appCfg.nix_native_build_inputs or []);
          buildInputs = resolveInputs (appCfg.nix_build_inputs or []);
        } // (if (appCfg.nix_subdir or "") != "" then {
          sourceRoot = "source";
          cargoRoot = appCfg.nix_subdir;
          buildAndTestSubdir = appCfg.nix_subdir;
        } else {}));

      in
      {
        packages = {
          inherit upstream-app runtime eif vendor-hash-check;
          default = eif;
        };
      }
    );
}
