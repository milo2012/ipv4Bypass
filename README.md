# ipv4Bypass

**Using IPv6 to Bypass Security** — Go edition

`ipv4Bypass` audits dual-stack hosts on your LAN: it discovers neighbours on
both address families, correlates their IPv4 and IPv6 identities, scans both
stacks concurrently, and reports services that are reachable over IPv6 but
firewalled over IPv4 (and the inverse) with severity ratings, service
fingerprints and machine-readable output.

This is a ground-up rewrite of the original `bypass.py` in Go.

## Why

IPv6 firewall rules are frequently less strict than the equivalent IPv4 rules.
A host may expose SSH, SMB, RDP or a database only via its IPv6 address while
the v4 side is properly locked down. This tool finds exactly those gaps.

## Features

- **Dual-stack discovery & correlation**
  - Native raw-socket ARP sweep (Linux/root), `arp-scan` binary, or an
    unprivileged TCP-connect probe fallback
  - Kernel NDP table correlation (`ip -6 neigh`, `ndp -an`, Windows netsh) as
    the *primary* MAC<->IPv6 matcher — covers RFC 4941 privacy addresses
  - ICMPv6 all-nodes multicast ping (`ff02::1`)
  - EUI-64 derivation used **only as a verified fallback** (unicast-probe
    confirmed), never trusted blindly
  - Link-local addresses carry their `%zone` scope through the whole pipeline
- **Concurrent scanning** — worker pool (`-c`) plus global token-bucket rate
  cap (`--rate`, `-T 0..5` timing templates)
- **Service fingerprinting** — banner grabbing (server-speaks-first protocols,
  HTTP HEAD probes, TLS certificate inspection), well-known port fallbacks
- **UDP service probing** — DNS, NTP, SNMP, TFTP, NetBINS, mDNS, SIP, CoAP,
  SSDP, IKE, memcached with reply classification (`--udp`)
- **Findings engine**
  - `new_exposure_ipv6` / `udp_new_exposure` — open on v6, firewalled on v4
    (the headline finding; the only category shown by default)
  - `missing_on_ipv6`, `protocol_mismatch`, `gua_exposed`, `ptr_mismatch`
    (shown with `-v`)
  - Severity tags: critical/high/medium/low/info (bypass direction is boosted)
- **Router advertisement inventory** (`--ra`, root/Linux): prefixes + default routers
- **mDNS/DNS-SD hostname correlation** (on by default)
- **Output formats**: coloured terminal report, full JSON report, streamed
  NDJSON per host, findings CSV

## Build

Requires Go 1.22+ (only dependency: `golang.org/x/net`).

```
go build -o ipv4Bypass .          # current platform
./build.sh                        # all release targets -> dist/
./build.sh native                 # just this machine
./build.sh linux/amd64 darwin/arm64 windows/amd64   # selected targets
```

`build.sh` produces stripped, `CGO_ENABLED=0` static binaries named
`dist/ipv4Bypass-<os>-<arch>[.exe]` for the full matrix (linux amd64/arm64/arm,
darwin amd64/arm64, windows amd64/arm64), embeds a version string
(override with `VERSION=v1.2.3 ./build.sh`) and writes `dist/SHA256SUMS`.

## Automated releases

Two GitHub Actions workflows live in `.github/workflows/`:

- **CI** (`ci.yml`) — on every push to `master`/`main` and every PR:
  `go vet`, `-race` tests, gofmt check and a native build, across
  Linux, macOS and Windows runners.
- **Release** (`release.yml`) — push a tag and GitHub builds all seven
  platforms, packages them and publishes a release:

  ```
  git tag v1.2.3
  git push origin v1.2.3
  ```

  Artifacts per release: `ipv4Bypass-vX.Y.Z-<os>-<arch>.tar.gz`
  (`.zip` for Windows) plus a `SHA256SUMS` file. Release notes are generated
  from commit history. The workflow can also be triggered manually from the
  Actions tab (`workflow_dispatch`) — that builds and stores artifacts without
  publishing a release.

## Usage

```
$ ./ipv4Bypass -i eth0 -r 10.5.192.0/24

Usage: ipv4Bypass -i <iface> -r <cidr> [options]

Options:
  -i string            network interface (required)
  -r string            IPv4 target CIDR (required)
  -p string            TCP port list/ranges ("22,80,443", "1-1024")
  --top-ports int      curated port set: 100 | 1000 | 65535 (default 1000)
  -T int               timing template 0(paranoid)..5(insane) (default 3)
  -c int               concurrent host scans (default 10)
  --rate float         max probes/sec across all workers
  --timeout duration   TCP connect timeout override
  --udp                enable UDP service probing
  --no-banner          disable banner grabbing
  --mdns               mDNS hostname correlation (default true)
  --ra                 router solicitation / prefix inventory (root, linux)
  --json string        write full JSON report
  --ndjson string      stream host results as NDJSON ('-' for stdout)
  --csv string         write findings CSV
  --strict             refuse degraded unprivileged runs
  --self               include this machine in the scan
  -v                   verbose logging
```

Examples:

```
# quick audit of the local /24, top-100 ports, quiet
sudo ./ipv4Bypass -i eth0 -r 10.5.192.0/24 --top-ports 100

# thorough: all ports, UDP probes, JSON + CSV out
sudo ./ipv4Bypass -i eth0 -r 10.5.192.0/24 --top-ports 65535 --udp \
    --json report.json --csv findings.csv -T2

# pipe results into other tools as they arrive
sudo ./ipv4Bypass -i eth0 -r 10.5.192.0/24 --ndjson - | jq 'select(.open)'
```

## Privileges

| Capability                  | Root needed?                    |
|-----------------------------|---------------------------------|
| Raw ARP sweep               | yes                             |
| ICMPv4/v6 ping discovery    | yes (Linux: or `ping_group_range`) |
| arp-scan binary             | yes                             |
| Neighbour tables (read)     | no                              |
| TCP connect scanning        | no                              |
| UDP probing                 | no                              |

The tool detects privileges up front and tells you exactly what is degraded;
`--strict` makes it refuse reduced-capability runs instead.

## Output focus

By default the terminal report shows only what matters for this technique:
ports reachable over IPv6 that IPv4 blocks. Everything else (v4-only ports,
fingerprint mismatches, PTR discrepancies) is summarised in a one-line count;
pass `-v` to see the complete comparison. JSON, NDJSON and CSV output always
contain every finding regardless of `-v`.

## Layout

```
main.go                     CLI entry point, orchestration
internal/model/             shared types (hosts, services, findings, report)
internal/discovery/         ARP/NDP/multicast/EUI-64/mDNS/RA discovery + correlation
internal/scanner/           concurrent TCP scanner, UDP prober, banner grabs
internal/report/            diff engine, severity scoring, text/JSON/CSV renderers
internal/sysutil/           interfaces, privilege checks, neighbour-table parsers
internal/netutil/           CIDR expansion, EUI-64 maths, rate limiter, port specs
bypass.py                   legacy Python implementation (kept for reference)
```

## Note on the original

The original Python tool matched hosts by converting ARP MACs to EUI-64 link-
locals. Modern operating systems use randomised (RFC 4941) addresses most of
the time, so this rewrite reads the NDP table first and treats EUI-64 purely
as a liveness-confirmed fallback. See
https://milo2012.wordpress.com/2018/06/22/using-ipv6-to-bypass-security-tool/
for background on the technique.

Only scan networks you own or are authorised to test.
