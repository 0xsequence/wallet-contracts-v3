{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
    foundry.url = "github:shazow/foundry.nix/stable";
  };

  outputs = { self, nixpkgs, utils, foundry }:
    utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ foundry.overlay ];
      };
    in {

      devShell = with pkgs; mkShell {
        buildInputs = [
          nodePackages_latest.nodejs
          nodePackages_latest.pnpm

          # from foundry overlay
          foundry-bin
        ];

        # Decorative prompt override so we know when we're in a dev shell
        shellHook = ''
          if [[ ! -f .env ]]; then
            echo "Copying sample .env, update values as needed"
            echo ">>>"
            tee .env < .env.sample 
            echo "<<<"
          fi
          source .env
          export PS1="[dev] $PS1"
        '';
      };
    }
  );
}
