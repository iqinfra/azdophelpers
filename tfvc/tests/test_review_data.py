#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import review_data  # noqa: E402


ROOT = "$/test/Solution1"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def raw_manifest():
    def change(index, path, old_path, new_path, classification):
        return {
            "index": index,
            "changeType": "edit" if classification == "modify" else "rename",
            "classification": classification,
            "path": path,
            "sourceServerItem": old_path if classification.startswith("rename") else None,
            "oldPath": old_path,
            "newPath": new_path,
            "oldSize": 10,
            "newSize": 20,
            "oldHash": None,
            "newHash": None,
            "reviewable": True,
            "textDiff": True,
            "reason": None,
        }

    return {
        "schemaVersion": 1,
        "helperVersion": "tfvc-rest-diff-1.2",
        "apiVersion": "7.1",
        "changeset": 10,
        "previousChangeset": 9,
        "reviewRoot": ROOT,
        "changesetMetadata": {
            "author": "Build user",
            "createdDate": "2026-09-07T00:00:00Z",
            "comment": "<script>do not publish this source comment</script>",
        },
        "coverage": {
            "reviewComplete": True,
            "enumeratedChanges": 3,
            "inScopeChanges": 2,
            "outOfScopeChanges": 1,
            "unreviewableChanges": 0,
            "filesWithTextDiff": 2,
            "diffBytes": 200,
            "diffLines": 20,
        },
        "changes": [
            change(2, f"{ROOT}/foo.cs", f"{ROOT}/foo.cs", f"{ROOT}/foo.cs", "modify"),
            change(3, "$/other/foo.cs", f"{ROOT}/bar.cs", None, "rename-out-of-scope"),
        ],
    }


def finding(file_name="foo.cs", severity="low", identifier="F-1"):
    return {
        "id": identifier,
        "severity": severity,
        "category": "security",
        "file": file_name,
        "title": "Safe <title>",
        "description": "Description with <script>alert(1)</script>.",
        "impact": "Impact",
        "securityRelevant": True,
        "symbol": "Controller.Action",
        "changeAnalysis": "The change removes a check.",
        "securityBoundary": "Authorization boundary",
        "attackScenario": "An unauthenticated caller reaches the action.",
        "exploitability": "Requires the endpoint to be reachable.",
        "evidence": {
            "summary": "The guard is absent after the change.",
            "before": "if (!authorized) return;",
            "after": "<script>alert(2)</script>",
        },
        "remediationExample": "Restore the guard.",
        "verificationSteps": [],
        "standards": [{"id": "CWE-862", "name": "Missing Authorization"}],
        "recommendation": "Restore authorization.",
        "confidence": "high",
    }


class ReviewDataTests(unittest.TestCase):
    def test_normalize_preserves_index_gaps_and_omits_comment(self):
        normalized = review_data.normalize_manifest(raw_manifest(), 10)
        self.assertEqual([item["index"] for item in normalized["files"]], [2, 3])
        self.assertNotIn("changesetMetadata", normalized)
        self.assertEqual(
            normalized["reviewPaths"],
            [f"{ROOT}/foo.cs", f"{ROOT}/bar.cs"],
        )
        self.assertNotIn("$/other/foo.cs", normalized["reviewPaths"])

    def test_review_accepts_relative_and_diff_paths_and_empty_steps(self):
        manifest = review_data.normalize_manifest(raw_manifest(), 10)
        review = {
            "schemaVersion": 2,
            "changeset": 10,
            "summary": "One finding.",
            "findings": [
                finding("a/foo.cs", "low", "F-1"),
                finding(f"{ROOT}/bar.cs", "medium", "F-2"),
            ],
            "limitations": [],
        }
        self.assertEqual(review_data.validate_review(review, manifest, 10), [])

    def test_review_rejects_unknown_path_and_non_integer_schema(self):
        manifest = review_data.normalize_manifest(raw_manifest(), 10)
        review = {
            "schemaVersion": 2.0,
            "changeset": 10,
            "summary": "x",
            "findings": [finding("$/other/foo.cs")],
            "limitations": [],
        }
        errors = review_data.validate_review(review, manifest, 10)
        self.assertTrue(any("schemaVersion" in error for error in errors))
        self.assertTrue(any("not present" in error for error in errors))

    def test_empty_title_is_rejected_by_independent_validation(self):
        manifest = review_data.normalize_manifest(raw_manifest(), 10)
        item = finding("foo.cs")
        item["title"] = ""
        review = {"schemaVersion": 2, "changeset": 10, "summary": "x", "findings": [item], "limitations": []}
        self.assertTrue(any("title" in error for error in review_data.validate_review(review, manifest, 10)))

    def test_metadata_decision_and_hashes_are_authoritative(self):
        manifest = review_data.normalize_manifest(raw_manifest(), 10)
        review = {
            "schemaVersion": 2,
            "changeset": 10,
            "summary": "x",
            "findings": [finding("foo.cs", "high")],
            "limitations": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = {}
            for name, content in {
                "review.json": json.dumps(review),
                "manifest.json": json.dumps(manifest),
                "schema": "schema",
                "template": "template",
                "diff": "diff",
            }.items():
                path = directory_path / name
                path.write_text(content, encoding="utf-8")
                paths[name] = path
            metadata = review_data.build_metadata(
                review,
                manifest,
                "gpt-5.6-luna",
                "max",
                "codex-cli 0.153.4",
                COMMIT,
                paths["schema"],
                paths["template"],
                paths["diff"],
                review_source=paths["review.json"],
                manifest_source=paths["manifest.json"],
                report_status="html-valid",
            )
        self.assertEqual(metadata["securityDecision"], "fail")
        self.assertEqual(metadata["pipelineGate"], "fail")
        self.assertEqual(metadata["finalTaskStatus"], "blocked")
        self.assertEqual(set(metadata["provenance"]["hashes"]), {"diff", "schema", "template", "review", "normalizedManifest"})

    def test_markdown_encodes_model_markup(self):
        manifest = review_data.normalize_manifest(raw_manifest(), 10)
        review = {
            "schemaVersion": 2,
            "changeset": 10,
            "summary": "<script>alert(1)</script>",
            "findings": [finding("foo.cs")],
            "limitations": ["[link](https://evil.invalid)"] ,
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = {name: Path(directory) / name for name in ("schema", "template", "diff")}
            for path in paths.values():
                path.write_text("x", encoding="utf-8")
            metadata = review_data.build_metadata(
                review,
                manifest,
                "deployment",
                "high",
                "codex",
                COMMIT,
                paths["schema"],
                paths["template"],
                paths["diff"],
                report_status="html-valid",
            )
        markdown = review_data.render_markdown(review, metadata)
        self.assertNotIn("> <script>", markdown)
        self.assertIn("&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;", markdown)
        self.assertIn("```text\n<script>alert(2)</script>\n```", markdown)
        self.assertNotIn("[link](https://evil.invalid)", markdown)

    def test_loader_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"a":1,"a":2}', encoding="utf-8")
            with self.assertRaises(review_data.ContractError):
                review_data.load_json(path)

    def test_cli_normalize_validate_and_metadata_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_path = root / "raw.json"
            normalized_path = root / "manifest.json"
            review_path = root / "review.json"
            meta_path = root / "meta.json"
            raw_path.write_text(json.dumps(raw_manifest()), encoding="utf-8")
            normalized = review_data.normalize_manifest(raw_manifest(), 10)
            review = {
                "schemaVersion": 2,
                "changeset": 10,
                "summary": "x",
                "findings": [],
                "limitations": [],
            }
            review_path.write_text(json.dumps(review), encoding="utf-8")
            subprocess.run(
                [sys.executable, str(SCRIPT_DIR / "review_data.py"), "normalize-manifest", "--input", str(raw_path), "--changeset", "10", "--output", str(normalized_path)],
                check=True,
            )
            self.assertEqual(review_data.load_json(normalized_path), normalized)
            subprocess.run(
                [sys.executable, str(SCRIPT_DIR / "review_data.py"), "validate-review", "--input", str(review_path), "--manifest", str(normalized_path), "--changeset", "10"],
                check=True,
            )
            for name in ("schema", "template", "diff"):
                (root / name).write_text("x", encoding="utf-8")
            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "review_data.py"),
                    "metadata",
                    "--review", str(review_path),
                    "--manifest", str(normalized_path),
                    "--changeset", "10",
                    "--deployment", "gpt-5.6-luna",
                    "--effort", "max",
                    "--cli-version", "codex-cli 0.153.4",
                    "--commit", COMMIT,
                    "--schema", str(root / "schema"),
                    "--template", str(root / "template"),
                    "--diff", str(root / "diff"),
                    "--report-status", "html-valid",
                    "--output", str(meta_path),
                ],
                check=True,
            )
            metadata = review_data.load_json(meta_path)
            self.assertEqual(metadata["pipelineGate"], "pass")
            self.assertEqual(metadata["finalTaskStatus"], "succeeded")


if __name__ == "__main__":
    unittest.main()
