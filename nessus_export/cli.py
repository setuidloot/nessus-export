"""Command-line interface for nessus-export."""
from __future__ import annotations

import argparse
import os
import re
import sys
from typing import Dict, List, Optional

from . import __version__
from .client import NessusClient, NessusError, AuthError, TrialModeError
from .exporter import (CHAPTERS, EXTENSIONS, NATIVE_FORMATS, export_scan)

_STATUS_ORDER = ["running", "completed", "canceled", "aborted", "empty"]


def _eprint(*a) -> None:
    print(*a, file=sys.stderr)


def _load_env_file(path: str) -> None:
    """Populate os.environ from a simple KEY=VALUE .env file (no deps)."""
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key, val = key.strip(), val.strip().strip('"').strip("'")
                os.environ.setdefault(key, val)
    except FileNotFoundError:
        pass


def _make_client(args) -> NessusClient:
    if args.env_file:
        _load_env_file(args.env_file)
    else:
        # Convenience: auto-load ./.env if present and keys not already set.
        if os.path.exists(".env"):
            _load_env_file(".env")
    access = args.access_key or os.environ.get("ACCESS_KEY") \
        or os.environ.get("NESSUS_ACCESS_KEY", "")
    secret = args.secret_key or os.environ.get("SECRET_KEY") \
        or os.environ.get("NESSUS_SECRET_KEY", "")
    url = args.url or os.environ.get("NESSUS_URL") or "https://localhost:8834"
    if not access or not secret:
        raise AuthError(
            "missing API keys; set ACCESS_KEY/SECRET_KEY (env or .env) "
            "or pass --access-key/--secret-key"
        )
    return NessusClient(
        url=url, access_key=access, secret_key=secret,
        verify_ssl=args.verify_ssl, ca_bundle=args.ca_bundle,
        timeout=args.timeout,
    )


def _sanitize(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "scan"


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_list(client: NessusClient, args) -> int:
    scans = client.list_scans()
    if args.status:
        scans = [s for s in scans if s.get("status") == args.status]
    scans.sort(key=lambda s: (s.get("name") or "").lower())
    if args.json:
        import json
        print(json.dumps(scans, indent=2))
        return 0
    if not scans:
        _eprint("no scans found")
        return 0
    width = max(len(str(s.get("name", ""))) for s in scans)
    print(f"{'ID':>5}  {'NAME':<{width}}  {'STATUS':<10}  FOLDER")
    for s in scans:
        print(f"{s.get('id'):>5}  {str(s.get('name','')):<{width}}  "
              f"{str(s.get('status','')):<10}  {s.get('folder_id','')}")
    return 0


def _select_scan_ids(client: NessusClient, args) -> List[int]:
    if args.all:
        scans = client.list_scans()
        if args.status:
            scans = [s for s in scans if s.get("status") == args.status]
        return [s["id"] for s in scans]
    if not args.scans:
        raise NessusError("no scans specified; pass names/ids, or use --all")
    resolved = []
    for ref in args.scans:
        s = client.resolve_scan(ref)
        resolved.append(s["id"])
    return resolved


def cmd_export(client: NessusClient, args) -> int:
    scan_ids = _select_scan_ids(client, args)
    if not scan_ids:
        _eprint("no matching scans to export")
        return 1

    chapters = None
    if args.chapters:
        chapters = [c.strip() for c in args.chapters.split(",") if c.strip()]
        bad = [c for c in chapters if c not in CHAPTERS]
        if bad:
            raise NessusError(f"invalid chapter(s): {bad}; choose from {CHAPTERS}")

    out_dir = args.out_dir
    single_out = args.output if len(scan_ids) == 1 else None
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    quiet = args.quiet
    progress = (lambda m: None) if quiet else (lambda m: _eprint(f"  … {m}"))

    rc = 0
    used_paths: set = set()
    for scan_id in scan_ids:
        info = client.get_scan(scan_id).get("info", {})
        name = info.get("name", f"scan-{scan_id}")
        _eprint(f"[{name}] (id {scan_id}) → {args.format}")
        try:
            result = export_scan(
                client, scan_id, fmt=args.format, mode=args.mode,
                chapters=chapters, db_password=args.db_password,
                poll_interval=args.poll_interval, max_wait=args.max_wait,
                progress=progress,
            )
        except (TrialModeError, NessusError, ValueError) as e:
            _eprint(f"  ✗ {e}")
            rc = 1
            continue

        if single_out:
            path = single_out
        else:
            base = os.path.join(out_dir or ".", _sanitize(name))
            path = base + result.extension
            # Disambiguate when several scans share a name (append the id).
            if path in used_paths:
                path = f"{base}_{scan_id}{result.extension}"
            used_paths.add(path)
        with open(path, "wb") as fh:
            fh.write(result.content)
        tag = "reconstructed (trial mode)" if result.mode == "reconstruct" else "native"
        _eprint(f"  ✓ wrote {path} ({len(result.content)} bytes, {tag})")
    return rc


def cmd_status(client: NessusClient, args) -> int:
    st = client.server_status()
    print(f"server: {client.url}")
    print(f"status: {st.get('status')}  progress: {st.get('progress')}")
    return 0


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nessus-export",
        description="Export Nessus scan results via the API, with an automatic "
                    "reconstruction fallback for trial-mode servers.",
    )
    p.add_argument("--version", action="version",
                   version=f"nessus-export {__version__}")
    p.add_argument("--url", help="Nessus base URL (default env NESSUS_URL or "
                                 "https://localhost:8834)")
    p.add_argument("--access-key", help="API access key (default env ACCESS_KEY)")
    p.add_argument("--secret-key", help="API secret key (default env SECRET_KEY)")
    p.add_argument("--env-file", help="path to a .env file with the keys")
    p.add_argument("--verify-ssl", action="store_true",
                   help="verify the server TLS certificate (off by default; "
                        "Nessus ships a self-signed cert)")
    p.add_argument("--ca-bundle", help="CA bundle to verify against")
    p.add_argument("--timeout", type=int, default=60, help="HTTP timeout seconds")

    sub = p.add_subparsers(dest="command", required=True)

    lp = sub.add_parser("list", help="list scans on the server")
    lp.add_argument("--status", choices=_STATUS_ORDER, help="filter by status")
    lp.add_argument("--json", action="store_true", help="raw JSON output")
    lp.set_defaults(func=cmd_list)

    sp = sub.add_parser("status", help="show server status")
    sp.set_defaults(func=cmd_status)

    ep = sub.add_parser("export", help="export one or more scans")
    ep.add_argument("scans", nargs="*", metavar="SCAN",
                    help="scan name(s) or id(s) to export")
    ep.add_argument("--all", action="store_true", help="export every scan")
    ep.add_argument("--status", choices=_STATUS_ORDER,
                    help="with --all, only scans in this status")
    ep.add_argument("-f", "--format", default="nessus", choices=NATIVE_FORMATS,
                    help="export format (default: nessus)")
    ep.add_argument("-m", "--mode", default="auto",
                    choices=("auto", "native", "reconstruct"),
                    help="auto: native then fallback; native: API only; "
                         "reconstruct: rebuild locally (nessus/csv)")
    ep.add_argument("-o", "--output", help="output file (single scan only)")
    ep.add_argument("-d", "--out-dir", help="output directory (for multiple scans)")
    ep.add_argument("--chapters",
                    help="pdf/html sections, comma-separated: " + ",".join(CHAPTERS))
    ep.add_argument("--db-password", help="password for the 'db' format")
    ep.add_argument("--poll-interval", type=float, default=2.0,
                    help="seconds between export status polls")
    ep.add_argument("--max-wait", type=float, default=600.0,
                    help="max seconds to wait for a native export")
    ep.add_argument("-q", "--quiet", action="store_true",
                    help="suppress per-step progress")
    ep.set_defaults(func=cmd_export)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        client = _make_client(args)
        return args.func(client, args)
    except AuthError as e:
        _eprint(f"auth error: {e}")
        return 2
    except TrialModeError as e:
        _eprint(f"trial mode: {e}")
        return 3
    except NessusError as e:
        _eprint(f"error: {e}")
        return 1
    except KeyboardInterrupt:
        _eprint("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
