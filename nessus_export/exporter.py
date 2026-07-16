"""Export orchestration: native API export with reconstruction fallback."""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from .client import NessusClient, TrialModeError
from . import reconstruct

ProgressFn = Optional[Callable[[str], None]]

# Formats the native API can produce.
NATIVE_FORMATS = ("nessus", "csv", "pdf", "html", "db")
# Formats we can rebuild ourselves without a license.
RECONSTRUCTABLE = ("nessus", "csv")

EXTENSIONS = {
    "nessus": ".nessus", "csv": ".csv", "pdf": ".pdf",
    "html": ".html", "db": ".db",
}

# Chapter sections valid for pdf/html exports.
CHAPTERS = (
    "vuln_hosts_summary", "vuln_by_host", "vuln_by_plugin",
    "remediations", "compliance_exec", "compliance",
)


def _noop(_: str) -> None:
    pass


class ExportResult:
    def __init__(self, content: bytes, fmt: str, mode: str, trial: bool):
        self.content = content      # bytes to write
        self.fmt = fmt              # requested format
        self.mode = mode           # "native" or "reconstruct"
        self.trial = trial         # server reported trial-mode restriction
        self.extension = EXTENSIONS.get(fmt, ".dat")


def _native_export(client: NessusClient, scan_id: int, fmt: str,
                   chapters: Optional[List[str]], db_password: Optional[str],
                   poll_interval: float, max_wait: float,
                   progress: Callable[[str], None]) -> bytes:
    extra: Dict[str, Any] = {}
    if fmt in ("pdf", "html"):
        # Nessus rejects a pdf/html export request that lacks a chapter list,
        # so default to a per-host vulnerability report when none is given.
        extra["chapters"] = ";".join(chapters or ["vuln_by_host"])
    if fmt == "db":
        if not db_password:
            raise ValueError("the 'db' format requires --db-password")
        extra["password"] = db_password
    progress(f"requesting native {fmt} export")
    file_id, _token = client.export_request(scan_id, fmt, extra)
    progress(f"export queued (file {file_id}); polling")
    content = client.wait_and_download(scan_id, file_id,
                                       poll_interval=poll_interval,
                                       max_wait=max_wait)
    progress(f"downloaded {len(content)} bytes")
    return content


def _reconstruct_export(client: NessusClient, scan_id: int, fmt: str,
                        progress: Callable[[str], None]) -> bytes:
    progress("reconstructing from read API (this walks every host/plugin)")
    data = reconstruct.collect(client, scan_id, progress=progress)
    if fmt == "nessus":
        return reconstruct.build_nessus_xml(data).encode("utf-8")
    if fmt == "csv":
        return reconstruct.build_csv(data).encode("utf-8")
    raise ValueError(f"format {fmt!r} cannot be reconstructed")


def export_scan(client: NessusClient, scan_id: int, fmt: str = "nessus",
                mode: str = "auto", chapters: Optional[List[str]] = None,
                db_password: Optional[str] = None,
                poll_interval: float = 2.0, max_wait: float = 600.0,
                progress: ProgressFn = None) -> ExportResult:
    """Export a single scan.

    mode:
      auto        try native; on trial-mode restriction, fall back to
                  reconstruction if the format supports it.
      native      native API only (errors out under trial mode).
      reconstruct skip the API export and rebuild locally (nessus/csv only).
    """
    progress = progress or _noop
    if fmt not in NATIVE_FORMATS:
        raise ValueError(f"unknown format {fmt!r}; choose from {NATIVE_FORMATS}")

    if mode == "reconstruct":
        content = _reconstruct_export(client, scan_id, fmt, progress)
        return ExportResult(content, fmt, "reconstruct", trial=False)

    try:
        content = _native_export(client, scan_id, fmt, chapters, db_password,
                                 poll_interval, max_wait, progress)
        return ExportResult(content, fmt, "native", trial=False)
    except TrialModeError as e:
        if mode == "native":
            raise
        if fmt not in RECONSTRUCTABLE:
            raise TrialModeError(
                f"{e} — reconstruction fallback only supports "
                f"{RECONSTRUCTABLE}, not {fmt!r}."
            ) from None
        progress(f"native export blocked (trial mode); falling back: {e}")
        content = _reconstruct_export(client, scan_id, fmt, progress)
        return ExportResult(content, fmt, "reconstruct", trial=True)
