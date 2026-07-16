"""Offline tests for the reconstruction serializers (no live server needed)."""
import io
import unittest
import xml.etree.ElementTree as ET

from nessus_export import reconstruct

# A minimal collect()-shaped structure with one host and two findings.
SAMPLE = {
    "info": {"name": "unit-scan"},
    "hosts": [{
        "host_id": 1,
        "name": "10.0.0.5",
        "info": {"host-ip": "10.0.0.5", "operating-system": "Linux Kernel 5.x"},
        "findings": [
            {
                "plugin_id": 186364,
                "plugin_name": "Apache Tomcat 8.5.0 < 8.5.96",
                "plugin_family": "Web Servers",
                "severity": 3,
                "attrs": {"synopsis": "Vulnerable Tomcat",
                          "description": "Old <tomcat> & \"stuff\"",
                          "solution": "Upgrade", "see_also": ["http://x"]},
                "risk": {"risk_factor": "High", "cvss_base_score": "7.8",
                         "cvss3_base_score": "7.5"},
                "vuln": {"exploit_available": "false", "cpe": "cpe:/a:apache:tomcat"},
                "pinfo": {"plugin_type": "combined", "plugin_version": "1.6"},
                "cves": ["CVE-2023-46589"], "bids": [], "xrefs": ["IAVA:2023-A-0661-S"],
                "instances": [("8080", "tcp", "www", "Installed: 8.5.81")],
            },
            {
                "plugin_id": 19506,
                "plugin_name": "Nessus Scan Information",
                "plugin_family": "Settings",
                "severity": 0,
                "attrs": {"synopsis": "Info"},
                "risk": {}, "vuln": {}, "pinfo": {},
                "cves": [], "bids": [], "xrefs": [],
                "instances": [("0", "tcp", "", "")],
            },
        ],
    }],
}


class TestNessusXml(unittest.TestCase):
    def setUp(self):
        self.xml = reconstruct.build_nessus_xml(SAMPLE)
        self.root = ET.fromstring(self.xml)

    def test_well_formed_root(self):
        self.assertEqual(self.root.tag, "NessusClientData_v2")
        self.assertIsNotNone(self.root.find("Policy"))
        self.assertEqual(self.root.find("Report").get("name"), "unit-scan")

    def test_report_item_attrs(self):
        items = self.root.findall(".//ReportItem")
        self.assertEqual(len(items), 2)
        hi = next(i for i in items if i.get("severity") == "3")
        self.assertEqual(hi.get("port"), "8080")
        self.assertEqual(hi.get("svc_name"), "www")
        self.assertEqual(hi.get("protocol"), "tcp")
        self.assertEqual(hi.get("pluginID"), "186364")

    def test_children_and_refs(self):
        hi = next(i for i in self.root.findall(".//ReportItem")
                  if i.get("severity") == "3")
        self.assertEqual(hi.findtext("risk_factor"), "High")
        self.assertEqual(hi.findtext("cve"), "CVE-2023-46589")
        self.assertEqual(hi.findtext("xref"), "IAVA:2023-A-0661-S")
        # XML-special characters in text must survive a round trip.
        self.assertIn("<tomcat>", hi.findtext("description"))

    def test_host_properties(self):
        tags = {t.get("name"): t.text
                for t in self.root.findall(".//HostProperties/tag")}
        self.assertEqual(tags["host-ip"], "10.0.0.5")


class TestCsv(unittest.TestCase):
    def test_csv_header_and_rows(self):
        import csv
        text = reconstruct.build_csv(SAMPLE)
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(rows[0][0], "Plugin ID")
        self.assertEqual(len(rows), 3)  # header + 2 findings
        high = next(r for r in rows[1:] if r[3] == "High")
        self.assertEqual(high[0], "186364")
        self.assertEqual(high[1], "CVE-2023-46589")
        self.assertEqual(high[6], "8080")


if __name__ == "__main__":
    unittest.main()
