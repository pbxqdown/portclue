# Contributing

Thanks for helping improve PortClue. Keep changes small, evidence-based, and
aligned with the tool's read-only, conservative posture.

## Develop

Requirements: Linux and Go 1.24+.

```bash
make check    # gofmt, go mod verify, race tests, vet
go test ./... # faster local loop while iterating
```

Add or update tests next to the code you change. Prefer table-driven cases and
fixture files under `testdata/` for firewall and identity behavior. Do not commit
binaries, `dist/` archives, or personal host dumps.

## Scope

In scope: clearer local evidence, safer firewall parsing, better identity, and
documentation that reduces misuse of `POTENTIAL` / `UNKNOWN`.

Out of scope unless discussed first: remote scanning, auto-remediation, cloud
security-group discovery, curl-pipe installers, and broadening firewall coverage
in ways that guess accept/drop for unrecognized expressions.

## Reporting firewall `UNKNOWN`

`UNKNOWN` is often intentional when nftables/iptables logic is not fully modeled.
A useful report includes:

1. `portclue --version`, OS/arch, and whether you used root
2. the exact command and the `UNKNOWN` / warning text
3. a **redacted** minimal ruleset sample (`nft --json list ruleset` or
   `iptables-save`) that reproduces the gap
4. whether you believe PortClue should parse the rule or keep `UNKNOWN`

Open a [bug report](https://github.com/pbxqdown/portclue/issues/new/choose) for
ordinary gaps. Use [SECURITY.md](SECURITY.md) for issues that understate exposure
when evidence is available, or for privilege/supply-chain problems.

## Pull requests

Use the PR template checklist. Update `CHANGELOG.md` for user-facing changes.
Bump JSON `schema_version` only for incompatible field changes.
