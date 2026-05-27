import io
import sys
import unittest
import zipfile
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import osint_harvester as harvester  # noqa: E402


class ParserTests(unittest.TestCase):
    def test_normalize_target_from_url(self):
        self.assertEqual(
            harvester.normalize_target("https://www.example.com/path?q=1"),
            "www.example.com",
        )

    def test_pdf_metadata(self):
        data = b"%PDF-1.4\n1 0 obj << /Title (Demo) /Author (Alice) /Producer (UnitTest) >> endobj"
        metadata = harvester.extract_document_metadata(data, "demo.pdf", {})
        self.assertEqual(metadata["parser"], "pdf")
        self.assertEqual(metadata["Title"], "Demo")
        self.assertEqual(metadata["Author"], "Alice")

    def test_ooxml_metadata(self):
        buffer = io.BytesIO()
        core_xml = """<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/"
                   xmlns:dcterms="http://purl.org/dc/terms/">
  <dc:title>Demo document</dc:title>
  <dc:creator>Alice</dc:creator>
  <cp:lastModifiedBy>Bob</cp:lastModifiedBy>
</cp:coreProperties>
"""
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("docProps/core.xml", core_xml)
        metadata = harvester.extract_document_metadata(buffer.getvalue(), "demo.docx", {})
        self.assertEqual(metadata["parser"], "ooxml")
        self.assertEqual(metadata["title"], "Demo document")
        self.assertEqual(metadata["creator"], "Alice")
        self.assertEqual(metadata["lastModifiedBy"], "Bob")

    def test_risk_assessment_flags_weak_email_controls(self):
        state = harvester.HarvestState(target="example.com", started_at=harvester.now_utc())
        state.add_dns_record(
            {
                "source": "dns",
                "name": "example.com",
                "type": "TXT",
                "ttl": 300,
                "data": "v=spf1 +all",
            }
        )
        report = harvester.build_report(state)
        titles = {item["title"] for item in report["risk_assessment"]["findings"]}
        self.assertIn("SPF permissif", titles)
        self.assertIn("DMARC absent", titles)
        self.assertGreater(report["summary"]["risk_score"], 0)

    def test_compare_reports_detects_added_values(self):
        old_report = {
            "target": "example.com",
            "generated_at": "2026-05-27T00:00:00+00:00",
            "risk_assessment": {"score": 10, "level": "Low"},
            "subdomains": [{"value": "www.example.com"}],
            "emails": [],
            "documents": [],
            "dns_records": [],
        }
        new_report = {
            "target": "example.com",
            "generated_at": "2026-05-28T00:00:00+00:00",
            "risk_assessment": {"score": 20, "level": "Low"},
            "subdomains": [{"value": "www.example.com"}, {"value": "admin.example.com"}],
            "emails": [{"value": "contact@example.com"}],
            "documents": [],
            "dns_records": [],
        }
        comparison = harvester.compare_reports(old_report, new_report)
        self.assertTrue(comparison["same_target"])
        self.assertEqual(comparison["risk_delta"]["delta"], 10)
        self.assertEqual(comparison["changes"]["subdomains"]["added"], ["admin.example.com"])
        self.assertEqual(comparison["changes"]["emails"]["added"], ["contact@example.com"])


if __name__ == "__main__":
    unittest.main()
