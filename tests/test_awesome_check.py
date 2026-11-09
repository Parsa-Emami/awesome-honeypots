import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from awesome_check import Link, audit_links, classify_http, extract_links, heading_anchors, probe_url, validate_local


class LinkCheckerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "README.md").write_text(
            "# Alpha\n## Honeyd Tools\n## Honeyd Tools\n[local](sub/page.md#install)\n[remote](https://example.org/x#fragment)\n",
            encoding="utf-8",
        )
        (self.root / "sub").mkdir()
        (self.root / "sub/page.md").write_text("## Install\n", encoding="utf-8")

    def test_extract_markdown_and_html_links(self):
        (self.root / "README.md").write_text(
            "[a](https://example.org/a)\n<a href=\"sub/page.md\">x</a>\n", encoding="utf-8"
        )
        links = extract_links(self.root / "README.md", self.root)
        self.assertEqual([link.target for link in links], ["https://example.org/a", "sub/page.md"])

    def test_ignores_fenced_code(self):
        fence = chr(96) * 3
        (self.root / "README.md").write_text(
            f"{fence}\n[x](missing.md)\n{fence}\n[x](sub/page.md)\n", encoding="utf-8"
        )
        self.assertEqual(len(extract_links(self.root / "README.md", self.root)), 1)

    def test_ignores_inline_code_examples(self):
        (self.root / "README.md").write_text(
            "Example: " + chr(96) + "[PACKAGE](LINK)" + chr(96) + "\n[real](sub/page.md)\n",
            encoding="utf-8",
        )
        links = extract_links(self.root / "README.md", self.root)
        self.assertEqual([link.target for link in links], ["sub/page.md"])

    def test_existing_file_and_anchor(self):
        self.assertIsNone(validate_local(Link("README.md", 2, "sub/page.md#install"), self.root, {}))

    def test_missing_file(self):
        finding = validate_local(Link("README.md", 2, "missing.md"), self.root, {})
        self.assertEqual(finding.status, "broken")

    def test_missing_anchor(self):
        finding = validate_local(Link("README.md", 2, "sub/page.md#absent"), self.root, {})
        self.assertEqual(finding.detail, "Heading anchor does not exist")

    def test_unknown_scheme(self):
        finding = validate_local(Link("README.md", 2, "ttps://example.org"), self.root, {})
        self.assertEqual(finding.detail, "Unsupported scheme: ttps")

    def test_path_traversal_is_blocked(self):
        finding = validate_local(Link("README.md", 2, "../../secret.md"), self.root, {})
        self.assertEqual(finding.detail, "Path escapes repository")

    def test_unicode_anchor_and_duplicated_headings(self):
        anchors = heading_anchors("# 最优秀的蜜罐列表 \n## Honeyd Tools\n## Honeyd Tools\n")
        self.assertIn("最优秀的蜜罐列表-", anchors)
        self.assertIn("honeyd-tools-1", anchors)

    def test_badge_heading(self):
        heading = "# Awesome Honeypots [![Badge](https://example.org/badge.svg)](https://example.org)\n"
        self.assertIn("awesome-honeypots-", heading_anchors(heading))

    def test_external_is_ignored_during_local_check(self):
        links = extract_links(self.root / "README.md", self.root)
        findings, counts = audit_links(links, self.root, "local", 1, 0, 1)
        self.assertEqual(findings, [])
        self.assertEqual(counts["local_checked"], 1)
        self.assertEqual(counts["external_checked"], 0)

    def test_http_classification(self):
        self.assertEqual(classify_http(404, None)[0], "broken")
        self.assertEqual(classify_http(403, None)[0], "inconclusive")
        self.assertEqual(classify_http(429, None)[0], "inconclusive")
        self.assertEqual(classify_http(200, None)[0], "ok")

    def test_head_fallback_to_get(self):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def fake_open(request, timeout):
            if request.get_method() == "HEAD":
                raise HTTPError(request.full_url, 405, "Method Not Allowed", {}, None)
            return Response()

        with patch("awesome_check.urllib.request.urlopen", side_effect=fake_open):
            self.assertEqual(probe_url("https://example.org", 1, 0), ("ok", "HTTP 200"))

    def test_local_check_has_no_network(self):
        links = extract_links(self.root / "README.md", self.root)
        with patch("awesome_check.urllib.request.urlopen", side_effect=AssertionError("Unexpected network request")):
            findings, counts = audit_links(links, self.root, "local", 1, 0, 2)
        self.assertEqual(findings, [])
        self.assertEqual(counts["external_checked"], 0)


if __name__ == "__main__":
    unittest.main()
