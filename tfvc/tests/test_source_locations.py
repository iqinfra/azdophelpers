#!/usr/bin/env python3
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import source_locations  # noqa: E402


ROOT = "$/test/Solution1"


def review(*findings):
    return {"schemaVersion": 2, "changeset": 10, "summary": "x", "findings": list(findings), "limitations": []}


def finding(identifier, file_name=f"{ROOT}/src/Foo.cs", before="old line", after="new line"):
    return {
        "id": identifier,
        "file": file_name,
        "evidence": {"summary": "s", "before": before, "after": after},
    }


MANIFEST = {"changeset": 10, "reviewRoot": ROOT}
DIFF = b"""--- a/src/Foo.cs
+++ b/src/Foo.cs
@@ -1,3 +1,4 @@
 using X;
-old line
+new line
 context
+added line
"""


class SourceLocationTests(unittest.TestCase):
    def test_unique_before_and_after_ranges_are_hunk_grounded(self):
        value = review(finding("F-1"))
        result = source_locations.build_source_locations(
            value,
            MANIFEST,
            DIFF,
            hashlib.sha256(b"review").hexdigest(),
            hashlib.sha256(DIFF).hexdigest(),
        )
        self.assertEqual(
            result["locations"]["F-1"],
            {
                "before": {"path": f"{ROOT}/src/Foo.cs", "startLine": 2, "endLine": 2},
                "after": {"path": f"{ROOT}/src/Foo.cs", "startLine": 2, "endLine": 2},
            },
        )
        self.assertEqual(source_locations.validate_source_locations(result, finding_ids=["F-1"], changeset=10), [])

    def test_ambiguous_or_nonmatching_evidence_is_null(self):
        diff = b"""--- a/src/Foo.cs
+++ b/src/Foo.cs
@@ -1,1 +1,3 @@
 context
+same
+same
"""
        value = review(
            finding("F-1", before="not in diff", after="same"),
            finding("F-2", before=None, after="same\nmissing"),
        )
        result = source_locations.build_source_locations(
            value,
            MANIFEST,
            diff,
            "a" * 64,
            "b" * 64,
        )
        self.assertEqual(result["locations"]["F-1"], {"before": None, "after": None})
        self.assertEqual(result["locations"]["F-2"], {"before": None, "after": None})

    def test_add_and_delete_sides_only_match_present_source(self):
        diff = b"""--- /dev/null
+++ b/src/New.cs
@@ -0,0 +1,2 @@
+first
+second
--- a/src/Old.cs
+++ /dev/null
@@ -1,2 +0,0 @@
-gone
-also gone
"""
        value = review(
            finding("F-add", f"{ROOT}/src/New.cs", before="first", after="first\nsecond"),
            finding("F-del", f"{ROOT}/src/Old.cs", before="gone\nalso gone", after="gone"),
        )
        result = source_locations.build_source_locations(value, MANIFEST, diff, "c" * 64, "d" * 64)
        self.assertEqual(result["locations"]["F-add"]["before"], None)
        self.assertEqual(result["locations"]["F-add"]["after"]["startLine"], 1)
        self.assertEqual(result["locations"]["F-del"]["before"]["startLine"], 1)
        self.assertEqual(result["locations"]["F-del"]["after"], None)

    def test_unparseable_diff_keeps_locations_unknown(self):
        value = review(finding("F-1"))
        result = source_locations.build_source_locations(value, MANIFEST, b"not a unified diff", "e" * 64, "f" * 64)
        self.assertEqual(result["locations"]["F-1"], {"before": None, "after": None})

    def test_cli_writes_hash_bound_artifact(self):
        value = review(finding("F-1"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            review_path = root / "review.json"
            manifest_path = root / "manifest.json"
            diff_path = root / "review.diff"
            output_path = root / "source-locations.json"
            review_path.write_text(json.dumps(value), encoding="utf-8")
            manifest_path.write_text(json.dumps(MANIFEST), encoding="utf-8")
            diff_path.write_bytes(DIFF)
            result = source_locations.main(
                ["--review", str(review_path), "--manifest", str(manifest_path), "--diff", str(diff_path), "--output", str(output_path)]
            )
            self.assertEqual(result, 0)
            output = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(output["reviewSha256"], hashlib.sha256(review_path.read_bytes()).hexdigest())
            self.assertEqual(output["diffSha256"], hashlib.sha256(DIFF).hexdigest())


if __name__ == "__main__":
    unittest.main()
