"""Reconstruct .nessus (NessusClientData_v2) and CSV output from the read API.

Used as a fallback when the native export endpoint is unavailable (e.g. the
server is in trial mode). The scan/host/plugin read endpoints are not
license-gated, so the findings themselves are fully recoverable; the scan
*policy* metadata is not exposed and is therefore emitted as a stub.
"""
from __future__ import annotations

import csv
import io
from typing import Any, Callable, Dict, List, Optional
from xml.sax.saxutils import escape, quoteattr

from .client import NessusClient

# Host-property tags surfaced from the host "info" block, in a stable order.
_HOST_TAGS = [
    "host-ip", "host-fqdn", "host-rdns", "netbios-name", "mac-address",
    "operating-system", "os", "system-type", "host_start", "host_end",
    "HOST_START", "HOST_END",
]

# risk_information keys emitted verbatim as ReportItem children.
_RISK_KEYS = [
    "cvss_base_score", "cvss_vector", "cvss_temporal_score", "cvss_temporal_vector",
    "cvss3_base_score", "cvss3_vector", "cvss3_temporal_score",
    "cvss3_temporal_vector", "cvss_score_source", "stig_severity",
]

ProgressFn = Optional[Callable[[str], None]]


def _noop(_: str) -> None:
    pass


def collect(client: NessusClient, scan_id: int,
            progress: ProgressFn = None) -> Dict[str, Any]:
    """Fetch scan + per-host + per-plugin data into a normalised structure."""
    progress = progress or _noop
    scan = client.get_scan(scan_id)
    info = scan.get("info", {}) or {}
    hosts_out: List[Dict[str, Any]] = []

    raw_hosts = scan.get("hosts") or []
    for hi, h in enumerate(raw_hosts, 1):
        hid = h["host_id"]
        hd = client.get_host(scan_id, hid)
        hinfo = hd.get("info", {}) or {}
        vulns = hd.get("vulnerabilities") or []
        progress(f"host {hi}/{len(raw_hosts)} "
                 f"({hinfo.get('host-ip') or h.get('hostname')}): "
                 f"{len(vulns)} plugins")
        findings: List[Dict[str, Any]] = []
        for v in vulns:
            pid = v["plugin_id"]
            det = client.get_plugin(scan_id, hid, pid)
            pa = (((det.get("info") or {}).get("plugindescription") or {})
                  .get("pluginattributes", {}) or {})
            pinfo = pa.get("plugin_information", {}) or {}
            risk = pa.get("risk_information", {}) or {}
            vuln = pa.get("vuln_information", {}) or {}

            instances = []  # one per (port, output)
            for o in det.get("outputs") or []:
                output = o.get("plugin_output") or ""
                ports = o.get("ports") or {}
                if not ports:
                    instances.append(("0", "tcp", "", output))
                for pk in ports:
                    parts = [x.strip() for x in pk.split("/")]
                    port = parts[0] if parts and parts[0] else "0"
                    proto = parts[1] if len(parts) > 1 and parts[1] else "tcp"
                    svc = parts[2] if len(parts) > 2 else ""
                    instances.append((port, proto, svc, output))
            if not instances:
                instances.append(("0", "tcp", "", ""))

            cves, bids, xrefs = [], [], []
            for ref in (pa.get("ref_information") or {}).get("ref") or []:
                name = (ref.get("name") or "").lower()
                for val in (ref.get("values") or {}).get("value") or []:
                    if name == "cve":
                        cves.append(val)
                    elif name == "bid":
                        bids.append(val)
                    else:
                        xrefs.append(f"{name.upper()}:{val}")

            findings.append({
                "plugin_id": pid,
                "plugin_name": pa.get("plugin_name") or v.get("plugin_name") or "",
                "plugin_family": pinfo.get("plugin_family")
                                 or v.get("plugin_family") or "",
                "severity": v.get("severity", pa.get("severity", 0)),
                "attrs": pa,
                "risk": risk,
                "vuln": vuln,
                "pinfo": pinfo,
                "cves": cves, "bids": bids, "xrefs": xrefs,
                "instances": instances,
            })
        hosts_out.append({
            "host_id": hid,
            "name": hinfo.get("host-ip") or h.get("hostname") or str(hid),
            "info": hinfo,
            "findings": findings,
        })
    return {"info": info, "hosts": hosts_out}


def _child(tag: str, text: Any) -> str:
    if text is None or text == "":
        return ""
    return f"        <{tag}>{escape(str(text))}</{tag}>\n"


def build_nessus_xml(data: Dict[str, Any]) -> str:
    info = data["info"]
    name = info.get("name", "scan")
    buf = io.StringIO()
    buf.write('<?xml version="1.0" encoding="UTF-8"?>\n<NessusClientData_v2>\n')
    # Policy stub — trial mode does not expose real policy/preferences data.
    buf.write("  <Policy>\n")
    buf.write(f"    <policyName>{escape(name)}</policyName>\n")
    buf.write("    <Preferences>\n"
              "      <ServerPreferences></ServerPreferences>\n"
              "      <PluginsPreferences></PluginsPreferences>\n"
              "    </Preferences>\n")
    buf.write("    <FamilySelection></FamilySelection>\n"
              "    <IndividualPluginSelection></IndividualPluginSelection>\n")
    buf.write("  </Policy>\n")
    buf.write(f'  <Report name={quoteattr(name)} '
              'xmlns:cm="http://www.nessus.org/cm">\n')

    for host in data["hosts"]:
        buf.write(f'    <ReportHost name={quoteattr(str(host["name"]))}>\n')
        buf.write("      <HostProperties>\n")
        hinfo = host["info"]
        for t in _HOST_TAGS:
            if hinfo.get(t) not in (None, ""):
                buf.write(f'        <tag name={quoteattr(t)}>'
                          f'{escape(str(hinfo[t]))}</tag>\n')
        buf.write("      </HostProperties>\n")

        for f in host["findings"]:
            pa, risk, vuln, pinfo = f["attrs"], f["risk"], f["vuln"], f["pinfo"]
            for port, proto, svc, output in f["instances"]:
                attrs = (f'port="{escape(port)}" svc_name={quoteattr(svc)} '
                         f'protocol="{escape(proto)}" severity="{f["severity"]}" '
                         f'pluginID="{f["plugin_id"]}" '
                         f'pluginName={quoteattr(str(f["plugin_name"]))} '
                         f'pluginFamily={quoteattr(str(f["plugin_family"]))}')
                buf.write(f"      <ReportItem {attrs}>\n")
                buf.write(_child("synopsis", pa.get("synopsis")))
                buf.write(_child("description", pa.get("description")))
                buf.write(_child("solution", pa.get("solution")))
                buf.write(_child("risk_factor", risk.get("risk_factor")))
                for k in _RISK_KEYS:
                    buf.write(_child(k, risk.get(k)))
                buf.write(_child("vpr_score", pa.get("vpr_score")))
                buf.write(_child("epss_score", pa.get("epss_score")))
                buf.write(_child("exploit_available", vuln.get("exploit_available")))
                buf.write(_child("exploitability_ease", vuln.get("exploitability_ease")))
                buf.write(_child("cpe", vuln.get("cpe")))
                buf.write(_child("plugin_type", pinfo.get("plugin_type")))
                buf.write(_child("plugin_version", pinfo.get("plugin_version")))
                buf.write(_child("plugin_publication_date",
                                 pinfo.get("plugin_publication_date")))
                buf.write(_child("plugin_modification_date",
                                 pinfo.get("plugin_modification_date")))
                buf.write(_child("fname", pa.get("fname")))
                for sa in pa.get("see_also") or []:
                    buf.write(_child("see_also", sa))
                for cve in f["cves"]:
                    buf.write(_child("cve", cve))
                for bid in f["bids"]:
                    buf.write(_child("bid", bid))
                for xref in f["xrefs"]:
                    buf.write(_child("xref", xref))
                buf.write(_child("plugin_output", output))
                buf.write("      </ReportItem>\n")
        buf.write("    </ReportHost>\n")
    buf.write("  </Report>\n</NessusClientData_v2>\n")
    return buf.getvalue()


_SEV = {0: "None", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def build_csv(data: Dict[str, Any]) -> str:
    """Approximate the native Nessus CSV export column set."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Plugin ID", "CVE", "CVSS v2.0 Base Score", "Risk", "Host",
                "Protocol", "Port", "Name", "Synopsis", "Description",
                "Solution", "See Also", "Plugin Output"])
    for host in data["hosts"]:
        for f in host["findings"]:
            pa, risk = f["attrs"], f["risk"]
            for port, proto, svc, output in f["instances"]:
                w.writerow([
                    f["plugin_id"],
                    ", ".join(f["cves"]),
                    risk.get("cvss_base_score", ""),
                    _SEV.get(f["severity"], f["severity"]),
                    host["name"],
                    proto,
                    port,
                    f["plugin_name"],
                    pa.get("synopsis", ""),
                    pa.get("description", ""),
                    pa.get("solution", ""),
                    "\n".join(pa.get("see_also") or []),
                    output,
                ])
    return buf.getvalue()
