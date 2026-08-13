# PortClue

[![CI](https://github.com/pbxqdown/portclue/actions/workflows/ci.yml/badge.svg)](https://github.com/pbxqdown/portclue/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/pbxqdown/portclue)](https://github.com/pbxqdown/portclue/releases/latest)
[![License](https://img.shields.io/github/license/pbxqdown/portclue)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/pbxqdown/portclue)](go.mod)

PortClue explains **why a TCP port on a Linux machine may or may not be reachable**.
It turns socket, process, firewall, and Docker state into a short evidence chain instead
of making you correlate `ss`, `/proc`, nftables, iptables, and `docker inspect` by hand.

![PortClue demo: an overview of local TCP listeners, then the evidence chain for port 8080](docs/demo/portclue-demo.gif)

Run it without a port to discover which local TCP endpoints deserve attention:

```console
$ sudo portclue
LOCAL TCP LISTENERS

PORT    SERVICE                   CONFIDENCE BIND            OWNER       SOURCE BIND SCOPE
22      OpenSSH server            HIGH       0.0.0.0,::      ssh.service host   ALL_INTERFACES
8080    NGINX web server          HIGH       0.0.0.0,::      nginx       host   ALL_INTERFACES
8443    api service               MEDIUM     192.0.2.10      demo-api    docker SPECIFIC_INTERFACE
9000    Python HTTP server        MEDIUM     127.0.0.1       python3     host   LOOPBACK_ONLY

BIND SCOPE describes socket binding, not firewall reachability.
Run `portclue PORT` for the complete evidence chain and local exposure verdict.
```

`ALL_INTERFACES`, `SPECIFIC_INTERFACE`, and `LOOPBACK_ONLY` describe where a
socket accepts traffic. They deliberately do not claim that a firewall permits it.
Inspect a port for the full local firewall analysis:

```console
$ sudo portclue 8080
POTENTIAL EXTERNAL EXPOSURE

TCP port 8080

  0.0.0.0:8080/tcp  [POTENTIAL]
    Service            NGINX web server
    Category           web
    Confidence         HIGH
    Identity evidence  executable basename matched "nginx"
    -> LISTEN             NETLINK_INET_DIAG reports socket inode 123456 bound to 0.0.0.0:8080/tcp
    -> OWNED              PID 4242 (nginx), systemd unit nginx.service
    -> ALL_INTERFACES     0.0.0.0 accepts traffic addressed to any local interface
    -> ACCEPT             nftables: a direct rule matches TCP destination port 8080 and returns accept

Unknown outside this machine:
  - router port forwarding
  - cloud firewall or security group
  - upstream NAT, including carrier-grade NAT
```

> [!IMPORTANT]
> PortClue v0.1 is an early, conservative Linux prototype. `POTENTIAL` means the
> observed local path allows traffic; it does **not** claim that a port is reachable
> from the public internet. Unsupported firewall expressions produce `UNKNOWN`.

## What it reads

- TCP listeners through `NETLINK_INET_DIAG`, not by scraping `ss` output
- process ownership, executable, command line, cgroup, and network namespace through `/proc`
- systemd unit descriptions from installed unit files and active socket triggers through `systemctl show`
- nftables through `nft --json list ruleset`
- iptables through `iptables-save` when nftables is unavailable
- Docker published ports through the local Docker Engine HTTP API, including image and labels

## Service identity

PortClue identifies what a port belongs to before explaining exposure. Evidence is
ranked in this order:

1. observed executable, systemd unit, and active socket trigger;
2. Docker image, container name, and labels;
3. the embedded curated service catalog;
4. the local `/etc/services` port convention.

An actual owner always overrides a conventional port name. If only the port convention
is known, the identity is explicitly marked `LOW` confidence. The embedded catalog is
stored in [`internal/identify/catalog.json`](internal/identify/catalog.json) and ships
inside the single binary; PortClue does not download identity data at runtime.

PortClue is read-only. It does not connect to the queried port, scan another host,
change firewall rules, stop processes or containers, upload data, or run a daemon.

## Install

### Release archive (recommended)

Download the matching `portclue-VERSION-linux-ARCH.tar.gz` and `SHA256SUMS` from
[GitHub Releases](https://github.com/pbxqdown/portclue/releases), verify the
checksum, then install:

```bash
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf portclue-0.1.0-linux-amd64.tar.gz   # or linux-arm64
sudo install -m 0755 portclue-0.1.0-linux-amd64/portclue /usr/local/bin/portclue
portclue --version
```

Architecture mapping:

| `uname -m` | Archive |
|---|---|
| `x86_64` | `linux-amd64` |
| `aarch64`, `arm64` | `linux-arm64` |

Each archive includes the binary, README, Apache-2.0 license, and third-party notices.

### Go install

Requires Linux and Go 1.24+:

```bash
go install github.com/pbxqdown/portclue/cmd/portclue@v0.1.0
```

This puts the binary in `$(go env GOPATH)/bin`. Prefer the checksum-verified
release archive when you want reproducible install artifacts.

## Build and run from source

Requirements: Linux and Go 1.24 or newer.

```bash
go build -o portclue ./cmd/portclue
./portclue
./portclue --json
./portclue 8080
./portclue --json 8080
```

Overview mode accepts optional filters (ignored fields stay unconstrained):

```bash
./portclue --bind-scope ALL_INTERFACES,SPECIFIC_INTERFACE
./portclue --source docker
./portclue --min-confidence MEDIUM
./portclue --json --bind-scope ALL_INTERFACES --min-confidence HIGH
```

`--bind-scope` accepts a comma-separated list of `ALL_INTERFACES`,
`SPECIFIC_INTERFACE`, and `LOOPBACK_ONLY`. `--source` accepts `host` and/or
`docker`. `--min-confidence` keeps entries at or above `HIGH`, `MEDIUM`, `LOW`,
or `UNKNOWN`. These flags apply only when `PORT` is omitted.

Running without root still gives useful listener, Docker mapping, and bind-address
evidence. Process identity and firewall evidence may be incomplete when `/proc` or
firewall state is restricted; PortClue reports this under `Incomplete evidence`.
Use `sudo` for the most complete result:

```bash
sudo ./portclue
sudo ./portclue --bind-scope ALL_INTERFACES,SPECIFIC_INTERFACE
sudo ./portclue 8080
```

## Versioned JSON

The JSON forms are intended for scripts and agents. Overview JSON uses
`schema_version: 2`, `mode: "overview"`, and `entries` with
`service_identity` and `bind_scope`. A detailed report uses
`schema_version: 1`, `query`, `verdict`, `paths` with
`service_identity`, `unknowns`, and `warnings`.

Within a schema version, existing field names and meanings are treated as stable.
New optional fields may be added. A removal, rename, or incompatible meaning change
requires a new `schema_version`. Both contracts have regression tests.

## Verdicts

| Verdict | Meaning |
|---|---|
| `POTENTIAL` | A non-loopback local path is observed and the supported firewall evidence permits it. External routing is unknown. |
| `NOT_EXPOSED_LOCALLY` | No listener/mapping exists, the bind is loopback-only, or supported local firewall evidence blocks the path. |
| `UNKNOWN` | A required fact is unavailable or a potentially relevant firewall expression is not supported. |
| `CONFIRMED` | Reserved for a future explicit external probe. The current local-only CLI never emits it. |

## Supported in v0.1

- Linux, TCP, host network namespace
- IPv4 listener and local filtering analysis
- correct IPv6 listener/bind classification; full IPv6 firewall simulation is not promised
- simple nftables/iptables base chains, direct TCP destination-port rules, and base policies
- Docker bridge published-port attribution
- systemd socket-activated TCP service attribution
- terminal and JSON output
- overview filters: `--bind-scope`, `--source`, `--min-confidence`

Not included: UDP, Podman, Kubernetes, cloud security groups, router discovery,
remote scanning, eBPF, continuous monitoring, or remediation.

### Conservative firewall behavior

PortClue intentionally does not attempt to implement the entire Netfilter virtual
machine. The first version understands a small set of direct rules. Multiple base
chains, jumps, sets, maps, `fib`, dynamic expressions, or other unrecognized logic
cause `UNKNOWN` when they can affect the query. This is safer than silently treating
an unparsed rule as accept or drop.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for scope, testing, and how to report
firewall `UNKNOWN` results.

```bash
make check
make release VERSION=0.1.0
```

`make release` requires a clean Git worktree and creates versioned amd64/arm64
archives plus `dist/SHA256SUMS`. Pushing a `v*` tag to the configured
GitHub remote runs the same checks and creates a GitHub release. No tag is created
by the Makefile.

The long-term design keeps the analyzer, causal model, and renderers platform-neutral.
Linux is the first evidence backend; Windows is the likely second backend if the Linux
prototype earns real usage.

## License

PortClue is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
Binary archives also include [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

See [CHANGELOG.md](CHANGELOG.md) for release history and JSON compatibility notes,
[SECURITY.md](SECURITY.md) for supported versions and private vulnerability reporting,
and [CONTRIBUTING.md](CONTRIBUTING.md) to contribute.
