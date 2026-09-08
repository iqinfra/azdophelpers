#!/usr/bin/env python3
"""Focused tests for the independent HTML report boundary."""

from __future__ import annotations

import copy
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
