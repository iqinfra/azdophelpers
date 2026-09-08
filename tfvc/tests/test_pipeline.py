#!/usr/bin/env python3
"""Mocked integration checks for the two-pass TFVC review helper.

The test deliberately exercises the helper as a child process.  Its fake
``curl`` serves only files from the checked-in ``outputs/tfvc`` package and
its fake ``codex`` records the two isolated invocations.  No Azure endpoint,
GitHub endpoint, or real Codex process is contacted.

Run from the workspace with::

    python3 -I outputs/tfvc/tests/test_pipeline.py

The package pins are intentionally not patched.  A package whose helper has
an empty or stale pin block should fail this suite, which catches accidental
release of an unbound helper.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
HELPER = PACKAGE_ROOT / "run-codex-review.sh"
ROOT = PACKAGE_ROOT.parents[1]
STATE_NAME = "mock-state.json"
CHANGESET = 10
TFVC_PATH = "$/test/Solution1/src/Controller.cs"
DIFF_TEXT = "fixture diff\n@@ -1,2 +1,5 @@\n-old\n+new <script>alert(1)</script>\n"
DIFF_BYTES = len(DIFF_TEXT.encode("utf-8"))
DIFF_LINES = DIFF_TEXT.count("\n")


def _read_package_pins() -> list[tuple[str, str]]:
    """Return the helper's committed resource pins.

    The release tool owns this block.  Keeping the parser here intentionally
    small makes the test fail if the helper's release format drifts.
    """

    body = HELPER.read_text(encoding="utf-8")
    match = re.search(
        r"^# BEGIN PACKAGE PINS\n(?P<body>.*?)^# END PACKAGE PINS$",
        body,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise AssertionError("helper is missing its package pin block")
    pins: list[tuple[str, str]] = []
    for line in match.group("body").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            raise AssertionError(f"invalid package pin line: {line!r}")
        relative = parts[1].strip()
        if not relative or relative.startswith("/") or ".." in Path(relative).parts:
            raise AssertionError(f"invalid package pin path: {relative!r}")
        pins.append((parts[0], relative))
    if not pins:
        raise AssertionError("helper package pin block is empty")
    return pins


def _finding(severity: str) -> dict[str, object]:
    """Return a schema-v2 finding with multiline and markup-like data."""

    return {
        "id": "F-001",
        "severity": severity,
        "category": "authorization",
        "file": TFVC_PATH,
        "title": "Ownership check <script>alert(1)</script>",
        "description": "The changed endpoint accepts a caller-controlled identifier.\nThe value is used across a trust boundary.",
        "impact": "A caller may read or change another customer's subscription.",
        "securityRelevant": True,
        "symbol": "Controller.Delete",
        "changeAnalysis": "The ownership predicate was removed by this changeset.",
        "securityBoundary": "Authenticated customer to application data",
        "attackScenario": "A customer submits another customer's identifier.",
        "exploitability": "A normal authenticated request is sufficient.",
        "evidence": {
            "summary": "The authorization check is absent after the edit.",
            "before": "if (!ownsSubscription) return Forbid();\n",
            "after": "return DeleteSubscription(id);\n",
        },
        "remediationExample": "Load the record through the current customer's ownership scope.",
        "verificationSteps": [
            "Submit a delete request for a different customer's identifier.",
            "Assert that the response is forbidden and the record remains unchanged.",
        ],
        "standards": [
            {"id": "CWE-862", "name": "Missing Authorization"},
        ],
        "recommendation": "Restore the ownership check and add a cross-account regression test.",
        "confidence": "high",
    }


def _review(case: str) -> dict[str, object]:
    findings: list[dict[str, object]] = []
    limitations: list[str] = []
    if case == "high":
        findings = [_finding("high")]
    elif case == "medium":
        findings = [_finding("medium")]
    elif case == "limitations":
        limitations = ["The supplied package leaves one generated file without a text diff."]
    return {
        "schemaVersion": 2,
        "changeset": CHANGESET,
        "summary": "Review summary <strong>must remain text</strong>.\nSecond line.",
        "findings": findings,
        "limitations": limitations,
    }


def _raw_manifest() -> dict[str, object]:
    """Minimal raw TFVC manifest accepted by the normalization helper."""

    return {
        "schemaVersion": 1,
        "changeset": CHANGESET,
        "previousChangeset": 9,
        "reviewRoot": "$/test/Solution1",
        "helperVersion": "tfvc-rest-diff-1.2",
        "apiVersion": "7.1",
        "changesetMetadata": {
            "author": "fixture",
            "createdDate": "2026-09-07T00:00:00Z",
            "comment": "fixture review",
        },
        "coverage": {
            "reviewComplete": True,
            "enumeratedChanges": 1,
            "inScopeChanges": 1,
            "outOfScopeChanges": 0,
            "unreviewableChanges": 0,
            "filesWithTextDiff": 1,
            "diffBytes": DIFF_BYTES,
            "diffLines": DIFF_LINES,
        },
        "changes": [
            {
                "index": 1,
                "changeType": "edit",
                "classification": "code",
                "path": TFVC_PATH,
                "sourceServerItem": TFVC_PATH,
                "oldPath": TFVC_PATH,
                "newPath": TFVC_PATH,
                "oldSize": 40,
                "newSize": 55,
                "oldHash": None,
                "newHash": None,
                "reviewable": True,
                "textDiff": True,
                "reason": None,
            }
        ],
    }


MOCK_CURL = r'''#!/usr/bin/env python3
import os
from pathlib import Path
import sys

args = sys.argv[1:]
if os.environ.get("MOCK_CURL_FAIL") == "1":
    print("fixture curl: intentional download failure", file=sys.stderr)
    raise SystemExit(22)
try:
    output = Path(args[args.index("--output") + 1])
    url = args[-1]
except (ValueError, IndexError):
    print("fixture curl: missing output or URL", file=sys.stderr)
    raise SystemExit(2)
marker = "/tfvc/"
if not url.startswith("https://raw.githubusercontent.com/iqinfra/azdophelpers/") or marker not in url:
    print(f"fixture curl: unexpected URL {url!r}", file=sys.stderr)
    raise SystemExit(3)
for name in ("AZURE_OPENAI_API_KEY", "AZURE_KEY", "SYSTEM_ACCESSTOKEN", "OPENAI_API_KEY", "CODEX_API_KEY"):
    if name in os.environ:
        print(f"fixture curl: credential leaked through {name}", file=sys.stderr)
        raise SystemExit(4)
relative = url.split(marker, 1)[1]
source = Path(os.environ["MOCK_PACKAGE_ROOT"]) / relative
if not source.is_file():
    print(f"fixture curl: package resource not found: {relative}", file=sys.stderr)
    raise SystemExit(44)
data = source.read_bytes()
if os.environ.get("MOCK_CURL_BAD_HASH") == "1":
    data += b"\nfixture hash corruption\n"
output.parent.mkdir(parents=True, exist_ok=True)
output.write_bytes(data)
'''


MOCK_CODEX = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import re
import subprocess
import sys

PACKAGE = Path(os.environ["MOCK_PACKAGE_ROOT"])
STATE = Path(os.environ["MOCK_STATE"])
CASE = os.environ.get("MOCK_CASE", "pass")

def after(flag):
    try:
        return Path(sys.argv[sys.argv.index(flag) + 1])
    except (ValueError, IndexError):
        return None

if "--version" in sys.argv:
    print("codex-cli 0.153.4")
    raise SystemExit(0)

work = after("--cd")
candidate = after("--output-last-message")
if work is None or candidate is None:
    print("fixture codex: missing isolated work directory or output path", file=sys.stderr)
    raise SystemExit(2)
required_args = ["exec", "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only", "--ignore-rules", "--color", "never"]
if any(flag not in sys.argv for flag in required_args):
    print("fixture codex: invocation is not isolated and read-only", file=sys.stderr)
    raise SystemExit(2)
if "AZURE_OPENAI_API_KEY" not in os.environ or os.environ["AZURE_OPENAI_API_KEY"] != "fake-secret":
    print("fixture codex: API key was not supplied only to Codex", file=sys.stderr)
    raise SystemExit(3)
for name in ("AZURE_KEY", "SYSTEM_ACCESSTOKEN", "OPENAI_API_KEY", "CODEX_API_KEY"):
    if name in os.environ:
        print(f"fixture codex: credential leaked through {name}", file=sys.stderr)
        raise SystemExit(4)
config_home = Path(os.environ.get("CODEX_HOME", ""))
config = config_home / "config.toml"
config_text = config.read_text(encoding="utf-8") if config.is_file() else ""
if (
    not config.is_file()
    or 'model_reasoning_effort = "max"' not in config_text
    or 'model_provider = "azure"' not in config_text
    or 'wire_api = "responses"' not in config_text
    or 'env_key = "AZURE_OPENAI_API_KEY"' not in config_text
    or 'inherit = "none"' not in config_text
):
    print("fixture codex: max reasoning was not preserved in isolated config", file=sys.stderr)
    raise SystemExit(5)

kind = "html" if work.name == "html" else "analysis" if work.name == "analysis" else "unknown"
if kind == "unknown":
    print(f"fixture codex: unexpected work directory {work}", file=sys.stderr)
    raise SystemExit(6)
prompt = sys.stdin.read()
if "fake-secret" in prompt or "oauth-token" in prompt:
    print("fixture codex: secret reached prompt", file=sys.stderr)
    raise SystemExit(7)
record = {
    "kind": kind,
    "work": str(work),
    "home": str(config_home),
    "skill": (work / ".agents/skills/security-review-html").is_dir(),
    "skillFiles": sorted(str(p.relative_to(work)) for p in (work / ".agents/skills/security-review-html").rglob("*") if p.is_file()) if (work / ".agents/skills/security-review-html").is_dir() else [],
    "promptHasSkill": "$security-review-html" in prompt,
    "promptHasDiff": "fixture diff" in prompt,
    "promptHasManifest": "review-manifest" in prompt,
    "promptHasScaffold": "report-scaffold.html" in prompt,
    "promptHasLocations": "source-locations.json" in prompt,
    "promptHasRetryFeedback": "sanitized feedback" in prompt,
    "hasSchema": "--output-schema" in sys.argv,
    "isolatedFlags": all(flag in sys.argv for flag in ("--ephemeral", "--sandbox", "read-only", "--ignore-rules")),
}
if kind == "analysis":
    if (work / ".agents").exists():
        print("fixture codex: analysis work unexpectedly exposes skills", file=sys.stderr)
        raise SystemExit(8)
    if "fixture diff" not in prompt:
        print("fixture codex: analysis did not receive the review package", file=sys.stderr)
        raise SystemExit(9)
    if CASE == "codex-fail":
        raise SystemExit(27)
    if CASE == "invalid-json":
        candidate.write_text('{"schemaVersion": 2,\n', encoding="utf-8")
    else:
        review = {
            "schemaVersion": 2,
            "changeset": 10,
            "summary": "Review summary <strong>must remain text</strong>.\nSecond line.",
            "findings": [],
            "limitations": [],
        }
        if CASE in ("critical", "high", "medium", "low", "info"):
            severity = CASE
            review["findings"] = [{
                "id": "F-001", "severity": severity, "category": "authorization",
                "file": "$/test/Solution1/src/Controller.cs",
                "title": "Ownership check <script>alert(1)</script>",
                "description": "The changed endpoint accepts a caller-controlled identifier.\nThe value is used across a trust boundary.",
                "impact": "A caller may read or change another customer's subscription.",
                "securityRelevant": True, "symbol": "Controller.Delete",
                "changeAnalysis": "The ownership predicate was removed by this changeset.",
                "securityBoundary": "Authenticated customer to application data",
                "attackScenario": "A customer submits another customer's identifier.",
                "exploitability": "A normal authenticated request is sufficient.",
                "evidence": {"summary": "The authorization check is absent after the edit.", "before": "if (!ownsSubscription) return Forbid();\n", "after": "return DeleteSubscription(id);\n"},
                "remediationExample": "Load the record through the current customer's ownership scope.",
                "verificationSteps": ["Submit a delete request for a different customer's identifier.", "Assert that the response is forbidden and the record remains unchanged."],
                "standards": [{"id": "CWE-862", "name": "Missing Authorization"}],
                "recommendation": "Restore the ownership check and add a cross-account regression test.",
                "confidence": "high",
            }]
        elif CASE == "limitations":
            review["limitations"] = ["The supplied package leaves one generated file without a text diff."]
        candidate.write_text(json.dumps(review), encoding="utf-8")
else:
    if (work / ".agents/skills/security-review-html/SKILL.md").is_file() is False:
        print("fixture codex: HTML pass did not receive the pinned skill", file=sys.stderr)
        raise SystemExit(10)
    if (work / "report-scaffold.html").is_file() is False:
        print("fixture codex: HTML pass did not receive the validated scaffold", file=sys.stderr)
        raise SystemExit(14)
    if (work / "source-locations.json").is_file() is False:
        print("fixture codex: HTML pass did not receive source locations", file=sys.stderr)
        raise SystemExit(15)
    if "fixture diff" in prompt or "codex-context" in prompt:
        print("fixture codex: HTML pass received the original review package", file=sys.stderr)
        raise SystemExit(11)
    if "$security-review-html" not in prompt or "review.json" not in prompt:
        print("fixture codex: HTML skill was not explicitly invoked", file=sys.stderr)
        raise SystemExit(12)
    review = work / "review.json"
    meta = work / "report-meta.json"
    manifest = work / "review-manifest.json"
    if CASE == "render-fail":
        raise SystemExit(29)
    if CASE == "html-mutate":
        # The presentation pass is never allowed to rewrite authoritative
        # inputs.  A harmless byte-level change is enough to prove that the
        # helper fingerprints the report package around the Codex call.
        authoritative = Path(os.environ["BUILD_ARTIFACTSTAGINGDIRECTORY"]) / "codex-review" / "tfvc-changeset-10-codex-review.json"
        authoritative.write_text(authoritative.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    # Use the pinned renderer's canonical command as a deterministic fixture
    # generator.  This keeps the fake model response inside the same HTML
    # contract that the helper independently validates.
    previous_records = json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else []
    html_attempt = sum(record.get("kind") == "html" for record in previous_records)
    if CASE == "html-no-output":
        pass
    elif CASE == "html-dom-mismatch":
        candidate.write_text((work / "report-scaffold.html").read_text().replace("<h1>", "<h1>PRIVATE-MODEL-VALUE", 1), encoding="utf-8")
    elif CASE == "html-attribute-mismatch":
        candidate.write_text((work / "report-scaffold.html").read_text().replace('lang="en"', 'lang="PRIVATE-MODEL-VALUE"', 1), encoding="utf-8")
    elif CASE == "html-malformed":
        candidate.write_text("<!doctype html><html><head><title>PRIVATE-MODEL-VALUE</head>", encoding="utf-8")
    elif CASE == "html-unclassified":
        candidate.write_bytes((work / "report-scaffold.html").read_bytes() + bytes([0]) + b"PRIVATE-MODEL-VALUE")
    elif CASE == "html-prose":
        candidate.write_text("PRIVATE-MODEL-VALUE\n" + (work / "report-scaffold.html").read_text(), encoding="utf-8")
    elif CASE == "html-bom":
        candidate.write_bytes(bytes([239, 187, 191]) + (work / "report-scaffold.html").read_bytes())
    elif CASE == "html-fenced":
        candidate.write_text("```html\n" + (work / "report-scaffold.html").read_text() + "\n```", encoding="utf-8")
    elif CASE == "invalid-html" or (CASE == "html-retry-pass" and html_attempt == 0):
        candidate.write_text("<!doctype html><html><head></head><body><script>alert(1)</script></body></html>", encoding="utf-8")
    else:
        renderer = PACKAGE / "scripts/report_html.py"
        template = PACKAGE / "skills/security-review-html/assets/report-template.html"
        locations = work / "source-locations.json"
        command = ["python3", "-I", str(renderer), "render", "--review", str(review), "--meta", str(meta), "--manifest", str(manifest), "--template", str(template), "--locations", str(locations), "--output", str(candidate), "--kind", "codex"]
        result = subprocess.run(command, text=True, capture_output=True)
        if result.returncode != 0:
            print(result.stderr or result.stdout, file=sys.stderr)
            raise SystemExit(13)

state = []
if STATE.exists():
    state = json.loads(STATE.read_text(encoding="utf-8"))
state.append(record)
STATE.write_text(json.dumps(state), encoding="utf-8")
'''


class PipelineCase:
    def __init__(self, case: str):
        self.case = case
        self._tmp = tempfile.TemporaryDirectory(prefix="tfvc review ")
        self.root = Path(self._tmp.name)
        self.bin = self.root / "mock bin"
        self.artifacts = self.root / "artifact staging with spaces"
        self.agent_tmp = self.root / "agent temp with spaces"
        self.state = self.root / STATE_NAME
        for path in (self.bin, self.artifacts, self.agent_tmp):
            path.mkdir(parents=True)
        self._write_executable("curl", MOCK_CURL)
        self._write_executable("codex", MOCK_CODEX)
        self._write_inputs()

    def _write_executable(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="utf-8")
        path.chmod(0o700)

    def _write_inputs(self) -> None:
        context = "Review objectives: identify security controls changed by the TFVC edit.\n"
        manifest = json.dumps(_raw_manifest(), indent=2) + "\n"
        (self.artifacts / f"tfvc-changeset-{CHANGESET}.diff").write_text(DIFF_TEXT, encoding="utf-8")
        (self.artifacts / f"tfvc-changeset-{CHANGESET}-manifest.json").write_text(manifest, encoding="utf-8")
        (self.artifacts / f"tfvc-changeset-{CHANGESET}-codex-context.md").write_text(context, encoding="utf-8")

    def env(self) -> dict[str, str]:
        inherited_path = os.environ.get("PATH", "")
        venv_bin = ROOT / "work" / "venv" / "bin"
        path = os.pathsep.join(part for part in (str(self.bin), str(venv_bin), inherited_path) if part)
        return {
            **os.environ,
            "PATH": path,
            "HELPER_COMMIT": "a" * 40,
            "BUILD_SOURCEVERSION": "C10",
            "BUILD_ARTIFACTSTAGINGDIRECTORY": str(self.artifacts),
            "AGENT_TEMPDIRECTORY": str(self.agent_tmp),
            "AZURE_OPENAI_API_KEY": "fake-secret",
            "AZURE_KEY": "inherited-azure-key",
            "SYSTEM_ACCESSTOKEN": "oauth-token",
            "OPENAI_API_KEY": "old-openai-key",
            "CODEX_API_KEY": "old-codex-key",
            "AZURE_OPENAI_BASE_URL": "https://example.openai.azure.com/openai/v1",
            "AZURE_OPENAI_MODEL_DEPLOYMENT": "gpt-5.6-luna",
            "CODEX_REASONING_EFFORT": "max",
            "MOCK_CASE": self.case,
            "MOCK_PACKAGE_ROOT": str(PACKAGE_ROOT),
            "MOCK_STATE": str(self.state),
        }

    def run(self, *, curl_failure: bool = False, hash_failure: bool = False) -> subprocess.CompletedProcess[str]:
        env = self.env()
        if curl_failure:
            env["MOCK_CURL_FAIL"] = "1"
        if hash_failure:
            env["MOCK_CURL_BAD_HASH"] = "1"
        return subprocess.run(
            ["bash", str(HELPER)],
            cwd=str(ROOT),
            env=env,
            text=True,
            capture_output=True,
            timeout=90,
        )

    @property
    def report_dir(self) -> Path:
        return self.artifacts / "codex-review"

    def outputs(self) -> set[str]:
        if not self.report_dir.exists():
            return set()
        return {path.name for path in self.report_dir.iterdir() if path.is_file()}

    def state_records(self) -> list[dict[str, object]]:
        if not self.state.exists():
            return []
        return json.loads(self.state.read_text(encoding="utf-8"))

    def close(self) -> None:
        self._tmp.cleanup()


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not HELPER.is_file():
            raise AssertionError(f"missing helper: {HELPER}")
        _read_package_pins()

    def run_case(self, case: str, **kwargs: object) -> tuple[PipelineCase, subprocess.CompletedProcess[str]]:
        harness = PipelineCase(case)
        result = harness.run(**kwargs)
        self.addCleanup(harness.close)
        return harness, result

    def assert_no_secret(self, result: subprocess.CompletedProcess[str]) -> None:
        combined = result.stdout + result.stderr
        self.assertNotIn("fake-secret", combined)
        self.assertNotIn("oauth-token", combined)
        self.assertNotIn("old-openai-key", combined)
        self.assertNotIn("old-codex-key", combined)

    def assert_clean_temp(self, harness: PipelineCase) -> None:
        self.assertEqual(list(harness.agent_tmp.iterdir()), [], "temporary Codex workspace was not removed")

    def assert_common_success_outputs(self, harness: PipelineCase) -> None:
        expected = {
            f"tfvc-changeset-{CHANGESET}-codex-review.json",
            f"tfvc-changeset-{CHANGESET}-codex-review.md",
            f"tfvc-changeset-{CHANGESET}-codex-review.html",
            "report-meta.json",
            "review-manifest.json",
            "source-locations.json",
        }
        self.assertTrue(harness.report_dir.is_dir())
        self.assertTrue(expected.issubset(harness.outputs()), harness.outputs())
        self.assertFalse(any(name.endswith(".diff") or "context" in name for name in harness.outputs()))

    def test_pass_preserves_max_isolates_credentials_and_publishes_all_reports(self) -> None:
        harness, result = self.run_case("pass")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CODEX_REVIEW_GATE]pass", result.stdout)
        self.assert_common_success_outputs(harness)
        self.assert_no_secret(result)
        records = harness.state_records()
        self.assertEqual([record["kind"] for record in records], ["analysis", "html"])
        self.assertTrue(all(record["isolatedFlags"] for record in records))
        self.assertTrue(records[0]["hasSchema"])
        self.assertFalse(records[1]["hasSchema"])
        self.assertFalse(records[0]["skill"])
        self.assertTrue(records[1]["skill"])
        self.assertTrue(any(name.endswith("/SKILL.md") for name in records[1]["skillFiles"]))
        self.assertTrue(records[1]["promptHasSkill"])
        self.assertFalse(records[1]["promptHasDiff"])
        self.assertTrue(records[1]["promptHasManifest"])
        self.assertTrue(records[1]["promptHasScaffold"])
        self.assertTrue(records[1]["promptHasLocations"])
        self.assertFalse(records[1]["promptHasRetryFeedback"])
        self.assertNotEqual(records[0]["home"], records[1]["home"])
        self.assertNotEqual(records[0]["work"], records[1]["work"])
        self.assertIn("artifact.upload", result.stdout)
        self.assertIn("task.uploadsummary", result.stdout)
        self.assert_clean_temp(harness)

    def test_medium_passes_and_high_finding_blocks_after_publication(self) -> None:
        for case, expected_status in (
            ("critical", 2),
            ("high", 2),
            ("medium", 0),
            ("low", 0),
            ("info", 0),
        ):
            with self.subTest(case=case):
                harness, result = self.run_case(case)
                self.assertEqual(result.returncode, expected_status, result.stderr)
                self.assert_common_success_outputs(harness)
                self.assert_no_secret(result)
                if case in {"critical", "high"}:
                    self.assertIn("CODEX_REVIEW_GATE]fail", result.stdout)
                    self.assertIn("Codex gate failed", result.stdout)
                    self.assertLess(result.stdout.index("artifact.upload"), result.stdout.index("Codex gate failed"))
                    html = (harness.report_dir / f"tfvc-changeset-{CHANGESET}-codex-review.html").read_text(encoding="utf-8")
                    self.assertIn("&lt;script&gt;", html)
                    self.assertNotIn("<script>", html)
                else:
                    self.assertIn("CODEX_REVIEW_GATE]pass", result.stdout)
                self.assert_clean_temp(harness)

    def test_limitation_is_a_completed_blocking_review(self) -> None:
        harness, result = self.run_case("limitations")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assert_common_success_outputs(harness)
        self.assertIn("limitations=1", result.stdout)
        self.assertIn("Codex gate failed", result.stdout)
        self.assert_clean_temp(harness)

    def test_html_failure_publishes_valid_analysis_and_labeled_fallback_only(self) -> None:
        for case in ("render-fail", "invalid-html"):
            with self.subTest(case=case):
                harness, result = self.run_case(case)
                self.assertEqual(result.returncode, 1, result.stderr)
                names = harness.outputs()
                self.assertIn(f"tfvc-changeset-{CHANGESET}-codex-review.json", names)
                self.assertIn(f"tfvc-changeset-{CHANGESET}-codex-review.md", names)
                self.assertIn("report-meta.json", names)
                self.assertIn("review-manifest.json", names)
                self.assertNotIn(f"tfvc-changeset-{CHANGESET}-codex-review.html", names)
                fallback = harness.report_dir / "codex-review-fallback.html"
                self.assertTrue(fallback.is_file(), "a valid analysis must produce the labeled fallback")
                self.assertIn("fallback", fallback.read_text(encoding="utf-8").lower())
                diagnostic = json.loads((harness.report_dir / "report-diagnostic.json").read_text(encoding="utf-8"))
                self.assertEqual(diagnostic["schemaVersion"], 1)
                self.assertTrue(diagnostic["failures"])
                self.assertTrue(all(set(item) == {"stage", "code", "exitCode", "action", "validatorFeedback"} for item in diagnostic["failures"]))
                self.assertNotIn("fixture", json.dumps(diagnostic))
                if case == "render-fail":
                    self.assertEqual([item["code"] for item in diagnostic["failures"]], ["HTML_CLI_EXIT"])
                else:
                    self.assertEqual(
                        [item["code"] for item in diagnostic["failures"]],
                        ["HTML_VALIDATION_FAILED", "HTML_RETRY_VALIDATION_FAILED"],
                    )
                self.assertIn("HTML generation or validation failed", result.stdout)
                self.assert_clean_temp(harness)

    def test_html_rejection_feedback_is_actionable_and_value_free(self) -> None:
        for case, expected in (("invalid-html", "forbidden"),
                               ("html-dom-mismatch", "text differs"),
                               ("html-attribute-mismatch", "attributes differ"),
                               ("html-prose", "doctype"),
                               ("html-malformed", "strict HTML5"),
                               ("html-unclassified", "contract mismatch")):
            with self.subTest(case=case):
                harness, result = self.run_case(case)
                self.assertEqual(result.returncode, 1, result.stderr)
                diagnostic = json.loads((harness.report_dir / "report-diagnostic.json").read_text())
                self.assertEqual(len(diagnostic["failures"]), 2)
                for failure in diagnostic["failures"]:
                    self.assertIn(expected, failure["validatorFeedback"])
                    self.assertIn(failure["validatorFeedback"], result.stdout)
                self.assertNotIn("PRIVATE-MODEL-VALUE", json.dumps(diagnostic) + result.stdout)
                self.assert_no_secret(result)
                self.assert_clean_temp(harness)

    def test_wrapped_html_message_publishes_only_validated_document(self) -> None:
        for case in ("html-fenced", "html-bom"):
            with self.subTest(case=case):
                harness, result = self.run_case(case)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assert_common_success_outputs(harness)
                html = (harness.report_dir / f"tfvc-changeset-{CHANGESET}-codex-review.html").read_bytes()
                self.assertTrue(html.lstrip().lower().startswith(b"<!doctype html>"))
                self.assertTrue(html.rstrip().endswith(b"</html>"))
                self.assertEqual([r["kind"] for r in harness.state_records()], ["analysis", "html"])
                self.assertNotIn("report-diagnostic.json", harness.outputs())
                self.assert_clean_temp(harness)

    def test_html_retry_recovers_after_validation_rejection(self) -> None:
        harness, result = self.run_case("html-retry-pass")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_common_success_outputs(harness)
        self.assertNotIn("report-diagnostic.json", harness.outputs())
        self.assertEqual([record["kind"] for record in harness.state_records()], ["analysis", "html", "html"])
        records = harness.state_records()
        self.assertTrue(records[1]["promptHasLocations"])
        self.assertTrue(records[2]["promptHasRetryFeedback"])
        self.assertIn("CODEX_REVIEW_GATE]pass", result.stdout)
        self.assertIn("HTML reporting pass recovered after one bounded retry", result.stdout)
        self.assert_clean_temp(harness)

    def test_html_no_output_publishes_actionable_diagnostic(self) -> None:
        harness, result = self.run_case("html-no-output")
        self.assertEqual(result.returncode, 1, result.stderr)
        diagnostic = json.loads((harness.report_dir / "report-diagnostic.json").read_text(encoding="utf-8"))
        self.assertEqual([item["code"] for item in diagnostic["failures"]], ["HTML_NO_OUTPUT"])
        self.assertEqual(diagnostic["failures"][0]["exitCode"], 0)
        self.assertIn("output-last-message", diagnostic["failures"][0]["action"])
        self.assertNotIn("report.candidate", result.stdout)
        self.assert_clean_temp(harness)

    def test_html_pass_cannot_mutate_authoritative_inputs(self) -> None:
        harness, result = self.run_case("html-mutate")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn(f"tfvc-changeset-{CHANGESET}-codex-review.html", harness.outputs())
        self.assertNotIn("report.candidate.html", result.stdout)
        self.assert_no_secret(result)
        self.assert_clean_temp(harness)

    def test_invalid_json_and_codex_failure_publish_no_report(self) -> None:
        for case in ("invalid-json", "codex-fail"):
            with self.subTest(case=case):
                harness, result = self.run_case(case)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(harness.outputs(), set())
                self.assert_no_secret(result)
                self.assert_clean_temp(harness)

    def test_download_and_hash_failures_fail_closed_without_codex(self) -> None:
        for kwargs in ({"curl_failure": True}, {"hash_failure": True}):
            with self.subTest(**kwargs):
                harness, result = self.run_case("pass", **kwargs)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(harness.state_records(), [])
                self.assertEqual(harness.outputs(), set())
                self.assert_no_secret(result)
                self.assert_clean_temp(harness)

    def test_bash_syntax_and_launcher_presence(self) -> None:
        for path in (HELPER, PACKAGE_ROOT / "azure-devops-launcher.sh", ROOT / "outputs" / "azure-devops-launcher.sh"):
            if path.is_file():
                result = subprocess.run(["bash", "-n", str(path)], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, f"{path}: {result.stderr}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
