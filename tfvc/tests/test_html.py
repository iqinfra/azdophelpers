#!/usr/bin/env python3
"""Focused tests for the independent HTML report boundary."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import report_html
import review_data


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "skills" / "security-review-html" / "assets" / "report-template.html"


def fixture_review() -> dict:
    return {
        "schemaVersion": 2,
        "changeset": 10,
        "summary": "Review <script>alert('summary')</script> & preserve this line\nsecond line",
        "findings": [
            {
                "id": "F-low",
                "severity": "low",
                "category": "quality",
                "file": "$/test/Solution1/src/Example.cs",
                "title": "Low finding",
                "description": "Description with <tag> and & text.",
                "impact": "Limited impact.",
                "securityRelevant": False,
                "symbol": None,
                "changeAnalysis": None,
                "securityBoundary": None,
                "attackScenario": None,
                "exploitability": None,
                "evidence": {"summary": "Whitespace evidence", "before": "   ", "after": None},
                "remediationExample": None,
                "verificationSteps": [],
                "standards": [],
                "recommendation": "Review the change.",
                "confidence": "low",
            },
            {
                "id": "F-high",
                "severity": "high",
                "category": "authorization",
                "file": "$/test/Solution1/src/Example.cs",
                "title": "High finding",
                "description": "A high finding.",
                "impact": "Impact.",
                "securityRelevant": True,
                "symbol": "Example.Delete",
                "changeAnalysis": "A check was removed.",
                "securityBoundary": "Tenant boundary",
                "attackScenario": "An attacker calls the endpoint.",
                "exploitability": "Authenticated user required.",
                "evidence": {"summary": "Evidence summary", "before": "old", "after": "new"},
                "remediationExample": "Validate ownership before deletion.",
                "verificationSteps": ["Exercise the endpoint as another tenant."],
                "standards": [{"id": "CWE-639", "name": "Authorization Bypass"}],
                "recommendation": "Restore the ownership check.",
                "confidence": "high",
            },
        ],
        "limitations": [],
    }


def fixture_manifest() -> dict:
    raw = {
        "schemaVersion": 1,
        "helperVersion": "tfvc-rest-diff-1.2",
        "apiVersion": "7.1",
        "changeset": 10,
        "previousChangeset": 9,
        "reviewRoot": "$/test/Solution1",
        "changesetMetadata": {"author": "Synthetic", "createdDate": "2026-09-07T00:00:00Z", "comment": "Synthetic fixture"},
        "coverage": {
            "reviewComplete": True,
            "enumeratedChanges": 1,
            "inScopeChanges": 1,
            "outOfScopeChanges": 0,
            "unreviewableChanges": 0,
            "filesWithTextDiff": 1,
            "diffBytes": 20,
            "diffLines": 2,
        },
        "changes": [
            {
                "index": 1,
                "changeType": "edit",
                "classification": "modify",
                "path": "$/test/Solution1/src/Example.cs",
                "sourceServerItem": None,
                "oldPath": "$/test/Solution1/src/Example.cs",
                "newPath": "$/test/Solution1/src/Example.cs",
                "oldSize": 10,
                "newSize": 20,
                "oldHash": "old-hash",
                "newHash": "new-hash",
                "reviewable": True,
                "textDiff": True,
                "reason": None,
            }
        ],
    }
    return review_data.normalize_manifest(raw, 10)


def fixture_meta(review: dict, manifest: dict, *, status: str = "html-valid") -> dict:
    return review_data.build_metadata(
        review,
        manifest,
        "gpt-5.6-luna",
        "max",
        "codex-cli 0.153.4",
        "0123456789abcdef0123456789abcdef01234567",
        "b" * 64,
        "c" * 64,
        "a" * 64,
        review_source="d" * 64,
        manifest_source="e" * 64,
        generated_at="2026-09-07T00:00:00Z",
        report_status=status,
    )

class ReportHtmlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.review = fixture_review()
        self.manifest = fixture_manifest()
        self.meta = fixture_meta(self.review, self.manifest)
        self.template = TEMPLATE.read_text(encoding="utf-8")

    def test_rendered_document_validates_and_escapes_data(self) -> None:
        candidate = report_html.render_document(self.review, self.meta, self.manifest, self.template)
        report_html.validate_report_with_values(self.review, self.meta, self.manifest, self.template, candidate.encode())
        self.assertNotIn("<script>alert", candidate)
        self.assertIn("&lt;script&gt;alert", candidate)
        self.assertEqual(candidate.count("<dt>Confidence</dt>"), len(self.review["findings"]))

    def test_fallback_is_labeled_and_validated(self) -> None:
        meta = fixture_meta(self.review, self.manifest, status="html-failed")
        candidate = report_html.render_document(self.review, meta, self.manifest, self.template, kind="fallback").encode()
        expected = report_html.render_document(self.review, meta, self.manifest, self.template, kind="fallback").encode()
        report_html.validate_document(candidate, expected, kind="fallback")
        self.assertIn("Deterministic fallback report", candidate.decode())

    def test_child_tail_injection_is_rejected(self) -> None:
        candidate = report_html.render_document(self.review, self.meta, self.manifest, self.template)
        mutated = candidate.replace("</span></p>", "</span>UNASSIGNED TEXT</p>", 1)
        with self.assertRaises(report_html.ReportError):
            report_html.validate_report_with_values(self.review, self.meta, self.manifest, self.template, mutated.encode())

    def test_structured_response_extracts_exact_html_before_validation(self) -> None:
        document = report_html.render_document(self.review, self.meta, self.manifest, self.template).encode()
        response = json.dumps({"html": document.decode()}).encode()
        decoded = report_html.decode_html_response(response)
        self.assertEqual(decoded, document)
        report_html.validate_document(decoded, document, kind="codex")
        for value in (document.replace(b"<h1>", b"<script>alert(1)</script><h1>", 1),
                      document.replace(b"A high finding.", b"MODEL-ONLY-VALUE", 1),
                      b"```html\n" + document + b"\n```", document + document):
            decoded = report_html.decode_html_response(json.dumps({"html": value.decode()}).encode())
            self.assertEqual(decoded, value)
            with self.assertRaises(report_html.ReportError):
                report_html.validate_document(decoded, document, kind="codex")

    def test_structured_response_rejects_invalid_envelopes_without_echoing_values(self) -> None:
        for response in (b'', b'not JSON PRIVATE-VALUE', b'{', b'[]', b'null', b'{}',
                         b'{"html":null}', b'{"html":42}', b'{"html":true}', b'{"html":[]}',
                         b'{"html":""}', b'{"html":" \t "}',
                         b'{"html":"x","PRIVATE-VALUE":1}', b'{"html":"x","html":"PRIVATE-VALUE"}',
                         b'{"html":"x"} {"html":"PRIVATE-VALUE"}', b'{"html":NaN}',
                         b'{"html":"\xff"}', b'{"html":"\\ud800"}',
                         b'```json\n{"html":"PRIVATE-VALUE"}\n```',
                         b'{"html":' + b'9' * 5000 + b'}'):
            with self.subTest(response=response):
                with self.assertRaises(report_html.ResponseError) as error:
                    report_html.decode_html_response(response)
                self.assertNotIn("PRIVATE-VALUE", str(error.exception))
        from unittest.mock import patch
        with patch.object(report_html, "MAX_RESPONSE_BYTES", 10):
            with self.assertRaises(report_html.ResponseError):
                report_html.decode_html_response(b'{"html":"more than ten bytes"}')
        with patch.object(report_html, "MAX_HTML_BYTES", 2):
            with self.assertRaises(report_html.ResponseError):
                report_html.decode_html_response(b'{"html":"abc"}')

    def test_response_diagnostic_reports_only_size_shape_and_stage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "response"
            for data, expected in ((b'{"PRIVATE-VALUE":1}', "json-object"), (b'[]', "json-array"),
                                   (b'<!doctype html>', "raw-html"), (b'```html', "markdown-fenced"),
                                   (b'PRIVATE-VALUE', "other-text"), (b'', "empty")):
                path.write_bytes(data)
                info = report_html.response_diagnostic(path, "response-envelope")
                self.assertEqual(info, {"responseByteCount": len(data), "responseFormatCategory": expected,
                                        "failureStage": "response-envelope"})
                self.assertNotIn("PRIVATE-VALUE", json.dumps(info))
            path.unlink()
            self.assertEqual(report_html.response_diagnostic(path, "output")["responseFormatCategory"], "missing")

    def test_message_envelopes_preserve_html_and_still_require_strict_validation(self) -> None:
        document = report_html.render_document(self.review, self.meta, self.manifest, self.template).encode()
        for message in (document, b"\xef\xbb\xbf" + document,
                        b"```html\n" + document + b"\n```",
                        b" \n```HTML\r\n" + document + b"\r\n```\n",
                        b"\xef\xbb\xbf```\n" + document + b"\n```"):
            with self.subTest(prefix=message[:12]):
                normalized = report_html.normalize_html_message(message)
                self.assertEqual(normalized, document)
                report_html.validate_document(normalized, document, kind="codex")
        # Transport handling must not sanitize active content or factual changes.
        for changed in (document.replace(b"<h1>", b"<script>alert(1)</script><h1>", 1),
                        document.replace(b"A high finding.", b"MODEL-ONLY-VALUE", 1)):
            normalized = report_html.normalize_html_message(b"```html\n" + changed + b"\n```")
            with self.assertRaises(report_html.ReportError):
                report_html.validate_document(normalized, document, kind="codex")

    def test_message_boundary_rejects_ambiguous_or_partial_content(self) -> None:
        document = report_html.render_document(self.review, self.meta, self.manifest, self.template).encode()
        messages = [b"Here is the report:\n" + document,
                    b"```html\n" + document + b"\n```\nMore prose",
                    b"```html\n" + document + b"\n```\n```html\n" + document + b"\n```",
                    b"```html\n" + document,
                    b"```html\n<!doctype html><html>\n```",
                    b"```javascript\n" + document + b"\n```",
                    b"\xef\xbb\xbf\xef\xbb\xbf" + document,
                    b"```html\n" + document + document + b"\n```",
                    b"```html\n" + document + b"EXTRA TEXT\n```"]
        for message in messages:
            with self.subTest(prefix=message[:30]):
                with self.assertRaises(report_html.ReportError):
                    normalized = report_html.normalize_html_message(message)
                    report_html.validate_document(normalized, document, kind="codex")

    def test_html5_doctype_whitespace_keeps_strict_validation(self) -> None:
        document = report_html.render_document(self.review, self.meta, self.manifest, self.template).encode()
        for doctype in (b"<!DOCTYPE  html>", b"<!doctype\nhtml>", b"<!DOCTYPE html >"):
            changed = document.replace(b"<!doctype html>", doctype, 1)
            report_html.validate_document(changed, document, kind="codex")
        for doctype in (b'<!DOCTYPE html SYSTEM "remote">', b"<!doctype html><!doctype html>"):
            with self.assertRaises(report_html.ReportError):
                report_html.validate_document(document.replace(b"<!doctype html>", doctype, 1), document, kind="codex")

    def test_dom_mismatch_diagnostic_is_structural_and_value_free(self) -> None:
        candidate = report_html.render_document(self.review, self.meta, self.manifest, self.template)
        mutated = candidate.replace("A high finding.", "MODEL-ONLY-UNTRUSTED", 1)
        with self.assertRaises(report_html.ReportError) as context:
            report_html.validate_report_with_values(
                self.review,
                self.meta,
                self.manifest,
                self.template,
                mutated.encode(),
            )
        message = str(context.exception)
        self.assertIn("candidate HTML does not exactly match", message)
        self.assertIn("/html", message)
        self.assertIn("text differs", message)
        self.assertNotIn("MODEL-ONLY-UNTRUSTED", message)

    def test_canonical_scaffold_copy_is_accepted_but_markup_rewrite_is_not(self) -> None:
        scaffold = report_html.render_document(self.review, self.meta, self.manifest, self.template)
        report_html.validate_report_with_values(
            self.review,
            self.meta,
            self.manifest,
            self.template,
            scaffold.encode(),
        )
        rewritten = scaffold.replace("<pre>\nA high finding.</pre>", "<p>A high finding.</p>", 1)
        with self.assertRaises(report_html.ReportError):
            report_html.validate_report_with_values(
                self.review,
                self.meta,
                self.manifest,
                self.template,
                rewritten.encode(),
            )

    def test_diff_grounded_source_locations_are_rendered_and_hash_bound(self) -> None:
        locations = {
            "schemaVersion": 1,
            "changeset": self.review["changeset"],
            "reviewSha256": "d" * 64,
            "diffSha256": "e" * 64,
            "locations": {
                "F-low": {"before": None, "after": None},
                "F-high": {
                    "before": {
                        "path": "$/test/Solution1/src/Example.cs",
                        "startLine": 12,
                        "endLine": 13,
                    },
                    "after": {
                        "path": "$/test/Solution1/src/Example.cs",
                        "startLine": 14,
                        "endLine": 14,
                    },
                },
            },
        }
        meta = copy.deepcopy(self.meta)
        meta["provenance"]["hashes"]["review"] = "d" * 64
        meta["provenance"]["hashes"]["diff"] = "e" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source-locations.json"
            path.write_text(json.dumps(locations), encoding="utf-8")
            entries = report_html.load_source_locations(path, self.review, meta, self.manifest)
        candidate = report_html.render_document(
            self.review,
            meta,
            self.manifest,
            self.template,
            locations=entries,
        )
        report_html.validate_report_with_values(
            self.review,
            meta,
            self.manifest,
            self.template,
            candidate.encode(),
            locations=entries,
        )
        self.assertIn("<dt>Source location (before)</dt>", candidate)
        self.assertIn("$/test/Solution1/src/Example.cs:12-13", candidate)
        self.assertIn("$/test/Solution1/src/Example.cs:14", candidate)
        self.assertEqual(candidate.count(report_html.SOURCE_LOCATION_UNAVAILABLE), 2)

        meta["provenance"]["hashes"]["review"] = "f" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source-locations.json"
            path.write_text(json.dumps(locations), encoding="utf-8")
            with self.assertRaises(report_html.ReportError):
                report_html.load_source_locations(path, self.review, meta, self.manifest)

    def test_cli_locations_argument_validates_hashes_and_renders_ranges(self) -> None:
        locations = {
            "schemaVersion": 1,
            "changeset": self.review["changeset"],
            "reviewSha256": "0" * 64,
            "diffSha256": "1" * 64,
            "locations": {
                finding["id"]: {
                    "before": None,
                    "after": {
                        "path": "$/test/Solution1/src/Example.cs",
                        "startLine": 7,
                        "endLine": 9,
                    },
                }
                for finding in self.review["findings"]
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            review_path = root / "review.json"
            manifest_path = root / "manifest.json"
            meta_path = root / "meta.json"
            template_path = root / "template.html"
            locations_path = root / "source-locations.json"
            candidate_path = root / "candidate.html"
            review_path.write_text(json.dumps(self.review), encoding="utf-8")
            manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
            template_path.write_text(self.template, encoding="utf-8")
            meta = copy.deepcopy(self.meta)
            meta["provenance"]["hashes"]["review"] = hashlib.sha256(review_path.read_bytes()).hexdigest()
            meta["provenance"]["hashes"]["normalizedManifest"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            meta["provenance"]["hashes"]["template"] = hashlib.sha256(template_path.read_bytes()).hexdigest()
            meta_path.write_text(json.dumps(meta), encoding="utf-8")
            locations["reviewSha256"] = meta["provenance"]["hashes"]["review"]
            locations["diffSha256"] = meta["provenance"]["hashes"]["diff"]
            locations_path.write_text(json.dumps(locations), encoding="utf-8")

            rendered = report_html.render_document(
                self.review,
                meta,
                self.manifest,
                self.template,
                locations=locations["locations"],
            )
            candidate_path.write_text(rendered, encoding="utf-8")
            self.assertEqual(
                report_html.main(
                    [
                        "validate",
                        "--review",
                        str(review_path),
                        "--meta",
                        str(meta_path),
                        "--manifest",
                        str(manifest_path),
                        "--template",
                        str(template_path),
                        "--locations",
                        str(locations_path),
                        "--input",
                        str(candidate_path),
                    ]
                ),
                0,
            )

            structured_path = root / "response.json"
            validated_path = root / "validated.html"
            diagnostic_path = root / "response-diagnostic.json"
            command = ["validate", "--review", str(review_path), "--meta", str(meta_path),
                       "--manifest", str(manifest_path), "--template", str(template_path),
                       "--locations", str(locations_path), "--input", str(structured_path),
                       "--response-output", str(validated_path), "--diagnostic-output", str(diagnostic_path)]
            structured_path.write_text(json.dumps({"html": rendered}))
            self.assertEqual(report_html.main(command), 0)
            self.assertEqual(validated_path.read_bytes(), rendered.encode())
            self.assertFalse(diagnostic_path.exists())
            validated_path.unlink()
            for response, stage in ((b'{"html":"x","html":"PRIVATE-VALUE"}', "response-envelope"),
                                    (json.dumps({"html": rendered.replace("<h1>", "<script>x</script><h1>", 1)}).encode(), "html-validation")):
                structured_path.write_bytes(response)
                self.assertEqual(report_html.main(command), 1)
                self.assertFalse(validated_path.exists(), "rejected content must never be written as publishable HTML")
                diagnostic = json.loads(diagnostic_path.read_text())
                self.assertEqual(diagnostic["failureStage"], stage)
                self.assertEqual(diagnostic["responseByteCount"], len(response))
                self.assertNotIn("PRIVATE-VALUE", diagnostic_path.read_text())

            output_path = root / "scaffold.html"
            self.assertEqual(
                report_html.main(
                    [
                        "render",
                        "--review",
                        str(review_path),
                        "--meta",
                        str(meta_path),
                        "--manifest",
                        str(manifest_path),
                        "--template",
                        str(template_path),
                        "--locations",
                        str(locations_path),
                        "--output",
                        str(output_path),
                    ]
                ),
                0,
            )
            self.assertIn("$/test/Solution1/src/Example.cs:7-9", output_path.read_text(encoding="utf-8"))

    def test_whitespace_only_evidence_change_is_rejected(self) -> None:
        candidate = report_html.render_document(self.review, self.meta, self.manifest, self.template)
        self.assertIn("<pre>\n   </pre>", candidate)
        mutated = candidate.replace("<pre>\n   </pre>", "<pre>\n </pre>", 1)
        with self.assertRaises(report_html.ReportError):
            report_html.validate_report_with_values(self.review, self.meta, self.manifest, self.template, mutated.encode())

    def test_leading_newline_is_preserved_in_pre_data(self) -> None:
        review = copy.deepcopy(self.review)
        review["summary"] = "\nfirst summary line"
        review["findings"][0]["evidence"]["before"] = "\nfirst evidence line"
        meta = fixture_meta(review, self.manifest)
        candidate = report_html.render_document(review, meta, self.manifest, self.template)
        report_html.validate_report_with_values(review, meta, self.manifest, self.template, candidate.encode())
        mutated = candidate.replace("<pre>\n\nfirst summary line</pre>", "<pre>\nfirst summary line</pre>", 1)
        with self.assertRaises(report_html.ReportError):
            report_html.validate_report_with_values(review, meta, self.manifest, self.template, mutated.encode())

    def test_external_markup_and_url_are_rejected(self) -> None:
        candidate = report_html.render_document(self.review, self.meta, self.manifest, self.template)
        with self.assertRaises(report_html.ReportError):
            report_html.validate_document(candidate.replace('href="#finding-0"', 'href="https://example.invalid"').encode(), candidate.encode(), kind="codex")
        with self.assertRaises(report_html.ReportError):
            report_html.validate_document(candidate.replace("</main>", "<script>alert(1)</script></main>").encode(), candidate.encode(), kind="codex")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schemaVersion":2,"schemaVersion":2}', encoding="utf-8")
            with self.assertRaises(report_html.ReportError):
                report_html.read_json(path)

    def test_report_status_must_be_html_valid_for_candidate(self) -> None:
        meta = fixture_meta(self.review, self.manifest, status="analysis-valid")
        candidate = report_html.render_document(self.review, meta, self.manifest, self.template)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            review_path = root / "review.json"
            meta_path = root / "meta.json"
            manifest_path = root / "manifest.json"
            template_path = root / "template.html"
            input_path = root / "input.html"
            for path, value in ((review_path, self.review), (meta_path, meta), (manifest_path, self.manifest)):
                path.write_text(json.dumps(value), encoding="utf-8")
            template_path.write_text(self.template, encoding="utf-8")
            input_path.write_text(candidate, encoding="utf-8")
            with self.assertRaises(report_html.ReportError):
                report_html.validate_report(review_path, meta_path, manifest_path, template_path, input_path)

    def test_review_relative_file_alias_is_accepted(self) -> None:
        review = copy.deepcopy(self.review)
        review["findings"][0]["file"] = "src/Example.cs"
        meta = fixture_meta(review, self.manifest)
        candidate = report_html.render_document(review, meta, self.manifest, self.template)
        report_html.validate_report_with_values(review, meta, self.manifest, self.template, candidate.encode())

    def test_cross_root_rename_source_is_not_added_to_review_paths(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["files"][0]["sourceServerItem"] = "$/other-project/old.cs"
        manifest["files"][0]["oldPath"] = "$/other-project/old.cs"
        manifest["files"][0]["newPath"] = "$/test/Solution1/src/Example.cs"
        report_html.validate_manifest(manifest)

    def test_empty_findings_use_fixed_empty_overview(self) -> None:
        review = copy.deepcopy(self.review)
        review["findings"] = []
        meta = fixture_meta(review, self.manifest)
        candidate = report_html.render_document(review, meta, self.manifest, self.template)
        report_html.validate_report_with_values(review, meta, self.manifest, self.template, candidate.encode())
        self.assertIn('<p class="empty">No findings reported.</p>', candidate)
        self.assertNotIn('<table class="findings-table">', candidate)

    def test_manifest_index_and_coverage_mutations_are_rejected(self) -> None:
        duplicate = copy.deepcopy(self.manifest)
        duplicate["files"].append(copy.deepcopy(duplicate["files"][0]))
        duplicate["coverage"]["inScopeChanges"] = 2
        duplicate["coverage"]["enumeratedChanges"] = 2
        duplicate["coverage"]["filesWithTextDiff"] = 2
        duplicate["reviewPaths"].append(duplicate["reviewPaths"][0])
        with self.assertRaises(report_html.ReportError):
            report_html.validate_manifest(duplicate)

        reversed_manifest = copy.deepcopy(self.manifest)
        reversed_manifest["files"][0]["index"] = 2
        with self.assertRaises(report_html.ReportError):
            report_html.validate_manifest(reversed_manifest)


if __name__ == "__main__":
    unittest.main()
