# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| older / unreleased builds | No security fixes promised |

PortClue 0.1.x is an early public preview. Security fixes land on the latest
0.1.x release when feasible.

## Scope

Please report issues that could cause:

- incorrect exposure verdicts that systematically understate risk when evidence is available
- privilege misuse or unexpected writes (PortClue is intended to be read-only)
- path handling, command execution, or parsing bugs that can escalate when run as root
- supply-chain problems in release artifacts or CI publishing

Out of scope for private security reports:

- missing features (UDP, cloud firewalls, remote scanning, fuller nftables coverage)
- `UNKNOWN` or incomplete results caused by unsupported firewall expressions
- local environment quirks that need ordinary bug reports

## How to report privately

Prefer [GitHub private vulnerability reporting](https://github.com/pbxqdown/portclue/security/advisories/new)
for this repository.

Include:

1. affected version (`portclue --version`) and OS/arch
2. whether the tool was run with root
3. reproduction steps and a minimal evidence sample (redact secrets)
4. expected vs actual security impact

Do **not** open a public issue for exploitable flaws until a fix or advisory is ready.

## Response expectations

This is a small maintainer-run project. Typical targets:

- acknowledgement within **7 days**
- initial severity/triage assessment within **14 days**
- fix or public advisory timeline communicated after triage

Complex firewall or privilege bugs may take longer; you will still get a status update.

## Release artifacts

Prefer GitHub Release archives and verify `SHA256SUMS` before installing.
Report compromised or mismatched checksums privately using the same channel.
