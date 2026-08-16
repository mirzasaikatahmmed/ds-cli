# `ds` — Domain Search CLI

A fast, cross-platform CLI for checking domain name availability across many
TLDs in parallel. RDAP is the primary protocol with a WHOIS fallback, and a
special handler takes care of `.bd` (which has no public RDAP/WHOIS).

```
$ ds dolkana --tld bd,net,org,app
Checking 4 domains (20 concurrent)

+ dolkana.app   AVAILABLE   rdap    442ms
+ dolkana.net   AVAILABLE   rdap    522ms
+ dolkana.bd    AVAILABLE   bd      536ms
+ dolkana.org   AVAILABLE   rdap   1050ms

summary: 4 available  0 taken  0 unknown   (4 checked in 1.1s)
```

`+` / green = AVAILABLE, `x` / red = TAKEN, `?` / yellow = UNKNOWN.

This is **free and open source** software, distributed under the MIT license.

---

## Install

The recommended install path is a **prebuilt binary** — no Rust toolchain
required on your machine, and the binary is ~3 MB.

### macOS / Linux (one-liner)

```sh
curl -fsSL https://raw.githubusercontent.com/mirzasaikatahmmed/ds-cli/main/install.sh | sh
```

This downloads the matching prebuilt release, verifies the SHA-256 checksum,
and installs to `~/.local/bin/ds`. Make sure `~/.local/bin` is on your
`PATH` (it's where most Unix package managers and Rust cargo put
per-user binaries).

You can also pass a specific version or force a source build:

```sh
curl -fsSL https://raw.githubusercontent.com/mirzasaikatahmmed/ds-cli/main/install.sh | sh -s -- --version v0.1.0
curl -fsSL https://raw.githubusercontent.com/mirzasaikatahmmed/ds-cli/main/install.sh | sh -s -- --from-source
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/mirzasaikatahmmed/ds-cli/main/install.ps1 | iex
```

Same flow: prebuilt `ds.exe` first, `rustup` fallback only if no matching
binary is available.

### From source (`cargo install`)

If you already have Rust installed:

```sh
cargo install --git https://github.com/mirzasaikatahmmed/ds-cli
```

---

## Usage

```
$ ds --help
Check domain availability over RDAP with a WHOIS fallback.

Examples:
  ds apple --tld all
  ds apple --tld com,net --details
  ds apple,orange,bangla,english --tld com,net
  ds @names.txt --tld popular --available-only --save
  ds apple --tld all --level second
  ds apple --tld com,io --where
  ds apple google --tld popular --whois --dns-records
  ds apple.com --details --registry

Usage: ds [OPTIONS] <NAMES>...
```

### Flags

| Flag | What it does |
|---|---|
| `<NAMES>...` | One or more base names. Comma- or space-separated. `@file.txt` to bulk-load (one per line). |
| `--tld <list>` | TLDs to check. Comma-separated, or a named group: `all`, `popular`, `bd`. |
| `--details` | Show registrar, creation date, expiry date, nameservers. |
| `--whois` | Force WHOIS instead of RDAP-first. |
| `--dns-records` | Resolve A/AAAA/MX/NS for taken domains. |
| `--registry` | Show which registry/RDAP server answered. |
| `--where` | Show which protocol + server were used. |
| `--available-only` | Only print AVAILABLE results. |
| `--save` | Write `ds-results-<timestamp>.csv` and `.json` in the current directory. |
| `--level <first\|second>` | Domain level to check (`second` for `name.co.uk` style). |
| `--concurrent <n>` | Override default concurrency (default 20). |
| `--timeout <ms>` | Per-lookup timeout in milliseconds. |
| `--rdap-json <path>` | User-supplied RDAP bootstrap JSON (merges with bundled). |
| `--whois-json <path>` | User-supplied WHOIS server JSON (merges with bundled). |
| `--no-merge` | Replace instead of merge when custom JSON is given. |
| `--bd-endpoint <url>` | Override the `.bd` lookup endpoint template (must contain `{domain}`). Also accepts the `DS_BD_ENDPOINT` env var. |

### Examples

```sh
# Check one name across the default TLD (.com)
ds apple

# Check many names across many TLDs
ds apple,orange,banana --tld com,net,org,io

# Bulk-check from a file
ds @names.txt --tld popular --available-only

# Check a single fully-qualified domain
ds apple.com --details

# Force WHOIS for TLDs where RDAP is unreliable
ds redbullexample --tld io --whois

# Show which server answered
ds apple --tld com --where

# Check a .bd domain (works out of the box — uses the default provider)
ds example --tld bd

# Or override the provider with your own
ds example --tld bd --bd-endpoint "https://your-provider.example/?domain={domain}"
```

---

## `.bd` lookup

`.bd` has no public RDAP service and no public WHOIS port 43, so the generic
RDAP/WHOIS resolvers can't reach it. This applies to the direct `.bd` TLD
**and** to its second-level SLDs (`com.bd`, `net.bd`, `org.bd`, `edu.bd`,
`gov.bd`, `ac.bd`, `co.bd`, `info.bd`, `name.bd`) — all of them are
registered through the same registry upstream.

Any TLD ending in `.bd` is automatically routed to the BD provider. The
`--tld bd` shorthand expands to all 10 of these TLDs at once, and you can
also pass them individually (`--tld com.bd,net.bd`).

The default `--bd-endpoint` is
`https://www.limda.net/inc/api/check-domain-availability.php?search={domain}`
(a third-party BD domain-check API). It returns JSON like:

```json
{
  "success": true,
  "domain": "example.bd",
  "available": true,
  "registered": false,
  "reserved": false,
  "status": "available",
  "message": "Domain is available",
  "raw_response": "Domain is available",
  "source": "btcl"
}
```

`ds` honors the `available` boolean first, then falls back to the `status`
string. Extra fields (`message`, `raw_response`, `registered`, `reserved`,
`source`) are surfaced via `--details`.

A 404 response from the provider is treated as Available; 5xx is treated as
a transient error. `success: false` in the body is treated as Unknown.

You can override the endpoint with `--bd-endpoint <URL>` or
`DS_BD_ENDPOINT=<URL>` — the URL template must contain `{domain}`, which is
substituted with the queried name. Any JSON provider that returns
`{ "available": bool }` or `{ "status": "available"/"registered" }` will
work.

---

## Architecture

```
src/
  main.rs           CLI entry, wires everything together
  cli.rs            clap derive + name/TLD expansion
  config.rs         (placeholder — config dir caching lives in `bootstrap`)
  models.rs         LookupResult, DomainStatus, LookupLevel
  dns.rs            A/AAAA/MX/NS resolution for --dns-records
  engine.rs         Concurrency: Semaphore + JoinSet + per-host limiter
  resolvers/
    mod.rs          Resolver trait
    rdap.rs         RDAP implementation
    whois.rs        Raw TCP WHOIS + per-TLD pattern matching
    bd.rs           .bd handler (trait-based, pluggable providers)
  bootstrap/
    mod.rs          Load/merge/cache IANA RDAP + WHOIS JSON
    data/
      rdap-dns.json Bundled IANA snapshot (590 entries)
      whois.json    Curated TLD → WHOIS server map (112 TLDs)
  output/
    table.rs        Colored table rendering
    export.rs       CSV / JSON export for --save
```

All three resolvers implement the `Resolver` trait, so adding a new
country-specific handler (e.g. another ccTLD without RDAP) is one trait impl
away.

---

## Release binary size

The release profile is tuned for size:

```toml
[profile.release]
strip = true
lto = true
opt-level = "z"
codegen-units = 1
panic = "abort"
```

The result is a ~3 MB statically-stripped binary that runs on any modern
Linux/macOS/Windows machine without external dependencies.

---

## Development

```sh
# Build + test
cargo build
cargo test

# Strict lint pass
cargo clippy --no-deps -- -D warnings

# Format
cargo fmt

# Real-world smoke test
ds dolkana --tld bd,net,org,app --timeout 3000
```

---

## License

MIT. See `LICENSE`.
