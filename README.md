# nessus-export

[![CI](https://github.com/setuidloot/nessus-export/actions/workflows/ci.yml/badge.svg)](https://github.com/setuidloot/nessus-export/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/nessus-export.svg)](https://pypi.org/project/nessus-export/)
[![Python](https://img.shields.io/pypi/pyversions/nessus-export.svg)](https://pypi.org/project/nessus-export/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Export [Nessus](https://www.tenable.com/products/nessus) scan results from the
command line via the REST API — **with an automatic fallback that reconstructs a
valid `.nessus` file even when the server's native export is locked** (as it is
on Nessus Essentials / trial installations).

Zero dependencies. Pure Python standard library.

---

## Why this exists

Nessus has a perfectly good export API (`POST /scans/{id}/export`). But on
**Nessus Essentials** and **trial** installations, every export format is
license-gated. Ask for one and the server refuses:

```json
{ "error": "Export is not allowed in trial mode. Please purchase a full Nessus license to enable exports." }
```

That's frustrating, because **the scan data itself is not restricted** — the
per-scan, per-host, and per-plugin *read* endpoints (`GET /scans/{id}`,
`GET /scans/{id}/hosts/{host}`, `GET /scans/{id}/hosts/{host}/plugins/{plugin}`)
return everything: findings, ports/services, severities, CVSS scores, CVEs,
plugin output, remediation text. The export endpoint is gated; the data is not.

**nessus-export** does the obvious thing:

1. **Try the native export API first.** If your server is licensed, you get the
   real, byte-for-byte Nessus export (`.nessus`, CSV, PDF, HTML, DB) — no
   reconstruction, nothing lost.
2. **If the server is in trial mode**, it transparently reads the scan data and
   **reconstructs** a spec-compliant `NessusClientData_v2` (`.nessus`) or CSV
   file itself.

The reconstructed `.nessus` imports cleanly back into Nessus and into anything
else that consumes the format (parsers, dashboards, DefectDojo, etc.).

## Install

```bash
pip install nessus-export
```

Or from source:

```bash
git clone https://github.com/setuidloot/nessus-export
cd nessus-export
pip install .
# or run without installing:
python -m nessus_export --help
```

Requires Python 3.8+. No third-party packages.

## Authentication

Generate API keys in Nessus: **Settings → My Account → API Keys → Generate**.

Provide them any of these ways (checked in order):

- CLI flags: `--access-key` / `--secret-key`
- Environment: `ACCESS_KEY` / `SECRET_KEY` (or `NESSUS_ACCESS_KEY` / `NESSUS_SECRET_KEY`)
- A `.env` file in the working directory (auto-loaded), or `--env-file PATH`

```bash
cp .env.example .env      # then edit in your keys
```

Nessus ships a self-signed TLS certificate, so certificate verification is
**off by default**. Turn it on with `--verify-ssl` (optionally `--ca-bundle`).

## Usage

```bash
# List scans on the server
nessus-export list
nessus-export list --status completed
nessus-export list --json

# Export one scan by name or id (defaults to .nessus, into the current dir)
nessus-export export myscan
nessus-export export 5 -o results.nessus

# Pick a format
nessus-export export myscan -f csv
nessus-export export myscan -f pdf --chapters vuln_by_host,remediations

# Export several scans into a directory
nessus-export export web-scan db-scan -d ./exports
nessus-export export --all --status completed -d ./exports

# Force behavior
nessus-export export myscan -m native       # native API only (fails under trial)
nessus-export export myscan -m reconstruct   # skip the API, rebuild locally
```

### Commands

| Command  | Purpose                                             |
|----------|-----------------------------------------------------|
| `list`   | List scans (`--status`, `--json`)                   |
| `export` | Export one/several/all scans                        |
| `status` | Show server status                                  |

### Key `export` options

| Option              | Description                                                        |
|---------------------|-------------------------------------------------------------------|
| `SCAN…`             | One or more scan names or ids                                     |
| `--all`             | Export every scan (combine with `--status`)                       |
| `-f, --format`      | `nessus` (default), `csv`, `pdf`, `html`, `db`                    |
| `-m, --mode`        | `auto` (default), `native`, `reconstruct`                        |
| `-o, --output`      | Output file (single scan)                                        |
| `-d, --out-dir`     | Output directory (multiple scans; filenames from scan names)     |
| `--chapters`        | `pdf`/`html` sections, comma-separated                           |
| `--db-password`     | Required for `-f db`                                              |
| `-q, --quiet`       | Suppress per-step progress                                       |

### Export modes

- **`auto`** *(default)* — try the native API; if the server reports a
  trial-mode restriction, fall back to reconstruction (for `nessus`/`csv`).
- **`native`** — only use the API. Exits non-zero under trial mode. Use this
  when you specifically want the licensed, byte-exact export or nothing.
- **`reconstruct`** — skip the API export entirely and rebuild locally. Handy
  for consistent output across mixed licensed/trial servers.

### Formats and modes at a glance

| Format   | Native (licensed) | Reconstruction fallback (trial) |
|----------|:-----------------:|:-------------------------------:|
| `nessus` | ✅                | ✅                              |
| `csv`    | ✅                | ✅                              |
| `pdf`    | ✅                | ❌ (needs a licensed server)    |
| `html`   | ✅                | ❌ (needs a licensed server)    |
| `db`     | ✅                | ❌ (needs a licensed server)    |

`pdf`, `html`, and `db` are report renderings Nessus builds server-side; there's
no faithful way to reproduce them from the read API, so they require a licensed
server. In `auto` mode, requesting one on a trial server yields a clear error
rather than a degraded file.

## Caveats when reconstructing (trial mode)

When the tool falls back to reconstruction, the **findings are complete and
faithful** — hosts, ports/services, severities, CVSS v2/v3 scores and vectors,
CVEs/BIDs/xrefs, synopsis, description, solution, see-also, and plugin output
are all carried through. But a reconstructed file is **not byte-identical** to a
licensed export, in these specific ways:

1. **The `<Policy>` block is a stub.** A licensed export embeds the full scan
   policy — every server/plugin preference and the plugin-family selection.
   Trial mode does not expose that data through the API, so the policy elements
   are emitted empty. Your *findings* are intact; the scan *configuration*
   metadata is not.
2. **`HostProperties` is a subset.** It contains what the host-info endpoint
   returns (IP, FQDN, OS, MAC, start/end time, …) — generally fewer tags than a
   native export writes.
3. **Plugin output honors the API's truncation.** Very large outputs flagged
   `max_attachments_exceeded` by the API are carried through exactly as the API
   returned them (i.e. possibly truncated).
4. **No attachments.** Binary attachments some plugins produce are not
   reassembled.
5. **CSV columns approximate** the native Nessus CSV layout; exact column
   ordering/quoting may differ slightly.

If any of that matters for your use case, use a licensed server with
`-m native`. For the common need — "get my findings out in a portable,
importable format" — the reconstructed `.nessus` does the job.

## Supported Nessus versions

Developed and verified against **Nessus 10.12.1** (latest at time of writing);
expected to work on the Nessus 10.x API generally. It uses only long-standing,
stable REST endpoints, so older 8.x/9.x servers will likely work too but are
untested. If you run it against another version, a PR updating this section is
welcome.

| Nessus version | Status              |
|----------------|---------------------|
| 10.12.1        | ✅ Verified         |
| 10.x (other)   | 🟡 Expected to work |
| 8.x – 9.x      | 🟡 Likely, untested |

## How it works

```
export ──► native API export ──► ready? ──► download  (licensed servers)
                │
                └─ trial-mode 403 ──► read scan + hosts + plugins
                                       └─► serialize NessusClientData_v2 / CSV
```

The reconstruction walks every host and every plugin finding, so it makes more
API calls than a native export — expect it to take longer on large scans.

## Library use

```python
from nessus_export.client import NessusClient
from nessus_export.exporter import export_scan

client = NessusClient(url="https://localhost:8834",
                      access_key="…", secret_key="…")
result = export_scan(client, scan_id=5, fmt="nessus", mode="auto")
open("myscan.nessus", "wb").write(result.content)
print(result.mode)   # "native" or "reconstruct"
```

## Security notes

- Never commit your `.env` / API keys. `.gitignore` already excludes `.env` and
  common export artifacts (`*.nessus`, `*.pdf`, `*.db`).
- Exported scan results contain sensitive vulnerability data — handle and store
  them accordingly.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

Not affiliated with or endorsed by Tenable, Inc. "Nessus" is a trademark of
Tenable, Inc. This tool uses only documented REST endpoints and does not
circumvent licensing: it reads data the API already exposes and formats it
locally.
