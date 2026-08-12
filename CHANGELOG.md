# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for tagged releases. Versioned JSON contracts also bump `schema_version` on
incompatible field changes.

## [0.1.0] - 2026-08-11

First public preview release.

### Added

- Local TCP listener overview with service identity, bind scope, owner, and source
- Per-port evidence chain and local exposure verdicts (`POTENTIAL`,
  `NOT_EXPOSED_LOCALLY`, `UNKNOWN`)
- Evidence from `NETLINK_INET_DIAG`, `/proc`, systemd socket activation, nftables
  or iptables, and Docker published ports
- Overview filters: `--bind-scope`, `--source`, `--min-confidence`
- Versioned JSON output for overview (`schema_version: 2`) and detailed reports
  (`schema_version: 1`)
- Linux amd64/arm64 release archives with `SHA256SUMS`

### Known limitations

- `POTENTIAL` means a local path looks allowed; it does **not** prove public
  internet reachability
- Host network namespace and TCP-focused prototype only
- IPv6 listeners are classified; full IPv6 firewall simulation is not promised
- Firewall analysis covers a small set of direct rules; jumps, sets, maps, and
  unrecognized expressions become `UNKNOWN` when they may affect the query
- No UDP, Podman, Kubernetes, cloud security groups, remote scanning, eBPF,
  continuous monitoring, remediation, or external probe (`CONFIRMED` is reserved)

### JSON compatibility notes

- Overview JSON: `schema_version: 2`, `mode: "overview"`, `entries` with
  `service_identity` and `bind_scope`
- Detailed JSON: `schema_version: 1`, `query`, `verdict`, `paths` with
  `service_identity`, plus `unknowns` and `warnings`
- Within a schema version, existing field names and meanings are treated as
  stable; new optional fields may appear
- Removals, renames, or incompatible meaning changes require a new
  `schema_version`

[0.1.0]: https://github.com/pbxqdown/portclue/releases/tag/v0.1.0
