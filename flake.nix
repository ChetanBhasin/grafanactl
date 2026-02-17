{
  description = "grafanactl - command-line tool for managing Grafana resources";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);

      version = if self ? shortRev then "unstable-${self.shortRev}" else "unstable-dirty";
      commit = if self ? shortRev then self.shortRev else "dirty";

      buildDate =
        if self ? lastModifiedDate then
          let
            ts = self.lastModifiedDate;
          in
          "${builtins.substring 0 4 ts}-${builtins.substring 4 2 ts}-${builtins.substring 6 2 ts}T${builtins.substring 8 2 ts}:${builtins.substring 10 2 ts}:${builtins.substring 12 2 ts}Z"
        else
          "1970-01-01T00:00:00Z";
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        rec {
          grafanactl = pkgs.buildGoModule {
            pname = "grafanactl";
            inherit version;
            src = self;
            subPackages = [ "cmd/grafanactl" ];
            vendorHash = "sha256-zEE4iaZJBneYgo6avCOTG7tWZ88NDskPTYiCMb8pRR4=";
            go = pkgs.go_1_24;
            buildFlagsArray = [ "-buildvcs=false" ];
            ldflags = [
              "-s"
              "-w"
              "-X main.version=${version}"
              "-X main.commit=${commit}"
              "-X main.date=${buildDate}"
            ];
            doCheck = false;

            meta = with pkgs.lib; {
              description = "Command-line tool for managing Grafana resources";
              homepage = "https://github.com/ChetanBhasin/grafanactl";
              license = licenses.asl20;
              mainProgram = "grafanactl";
              platforms = platforms.unix;
            };
          };

          default = grafanactl;
        }
      );

      apps = forAllSystems (system: {
        grafanactl = {
          type = "app";
          program = "${self.packages.${system}.grafanactl}/bin/grafanactl";
        };

        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/grafanactl";
        };
      });
    };
}
