#!/usr/bin/env python3
"""Create or independently validate the TFVC Codex HTML report.

The JSON values are the trust boundary.  This module deliberately builds the
expected DOM from those values and compares a model candidate with it after
HTML5 parsing.  The fallback is deterministic and carries an explicit banner.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any, Iterable


MAX_HTML_BYTES = 10 * 1024 * 1024
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
REVIEW_KEYS = {
    "schemaVersion",
    "changeset",
    "summary",
    "findings",
    "limitations",
}
FINDING_KEYS = {
    "id",
    "severity",
    "category",
    "file",
    "title",
    "description",
    "impact",
    "securityRelevant",
    "symbol",
    "changeAnalysis",
    "securityBoundary",
    "attackScenario",
    "exploitability",
    "evidence",
    "remediationExample",
    "verificationSteps",
    "standards",
    "recommendation",
    "confidence",
}
EVIDENCE_KEYS = {"summary", "before", "after"}
STANDARD_KEYS = {"id", "name"}
META_KEYS = {
    "metaVersion",
    "changeset",
    "previousChangeset",
    "reviewRoot",
    "counts",
    "securityDecision",
    "reportStatus",
    "pipelineGate",
    "finalTaskStatus",
    "policy",
    "coverage",
    "provenance",
    "formats",
}
COUNT_KEYS = {"critical", "high", "medium", "low", "info", "limitations", "totalFindings"}
POLICY_KEYS = {"blockingSeverities", "limitationsBlock", "mediumAction", "lowAction", "infoAction"}
COVERAGE_KEYS = {
    "reviewComplete",
    "enumeratedChanges",
    "inScopeChanges",
    "outOfScopeChanges",
    "unreviewableChanges",
    "filesWithTextDiff",
    "diffBytes",
    "diffLines",
}
PROVENANCE_KEYS = {
    "generatedAt",
    "helperCommit",
    "helperVersion",
    "apiVersion",
    "cliVersion",
    "deployment",
    "reasoningEffort",
    "hashes",
}
HASH_KEYS = {"diff", "schema", "template", "review", "normalizedManifest"}
FORMAT_KEYS = {"reviewSchema", "metadataSchema", "htmlContract"}
MANIFEST_KEYS = {
    "schemaVersion",
    "normalizationVersion",
    "helperVersion",
    "apiVersion",
    "changeset",
    "previousChangeset",
    "reviewRoot",
    "coverage",
    "files",
    "reviewPaths",
}
FILE_KEYS = {
    "index",
    "changeType",
    "classification",
    "path",
    "sourceServerItem",
    "oldPath",
    "newPath",
    "oldSize",
    "newSize",
    "oldHash",
    "newHash",
    "reviewable",
    "textDiff",
    "reason",
}
PATH_RE = re.compile(r"^\$/[^\r\n\t]+$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
DEPLOYMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; "
    "img-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; "
    "form-action 'none'"
)
ALLOWED_TAGS = {
    "html",
    "head",
    "meta",
    "title",
    "style",
    "body",
    "main",
    "header",
    "section",
    "article",
    "h1",
    "h2",
    "h3",
    "p",
    "div",
    "span",
    "strong",
    "dl",
    "dt",
    "dd",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "a",
    "ul",
    "li",
    "pre",
    "code",
    "footer",
}
ALLOWED_ATTRS = {
    "html": {"lang"},
    "head": set(),
    "meta": {"charset", "name", "content", "http-equiv"},
    "title": set(),
    "style": {"id"},
    "body": set(),
    "main": {"id", "data-report-kind"},
    "header": {"id", "class"},
    "section": {"id", "class"},
    "article": {"id", "class"},
    "h1": {"id", "class"},
    "h2": {"id", "class"},
    "h3": {"id", "class"},
    "p": {"id", "class"},
    "div": {"id", "class"},
    "span": {"id", "class"},
    "strong": {"id", "class"},
    "dl": {"id", "class"},
    "dt": {"id", "class"},
    "dd": {"id", "class"},
    "table": {"id", "class"},
    "thead": {"id", "class"},
    "tbody": {"id", "class"},
    "tr": {"id", "class"},
    "th": {"id", "class"},
    "td": {"id", "class"},
    "a": {"id", "class", "href"},
    "ul": {"id", "class"},
    "li": {"id", "class"},
    "pre": {"id", "class"},
    "code": {"id", "class"},
    "footer": {"id", "class"},
}


class ReportError(Exception):
    """A safe, user-facing validation error."""


def fail(message: str) -> None:
    raise ReportError(message)


def read_bytes(path: Path, *, limit: int = MAX_HTML_BYTES) -> bytes:
    try:
        # Read one byte beyond the limit so an oversized input is rejected
        # without first loading an unbounded candidate into memory.
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        fail(f"unable to read {path}: {exc}")
    if len(data) > limit:
        fail(f"input exceeds the {limit} byte limit: {path}")
    return data


def read_json(path: Path) -> Any:
    data = read_bytes(path)
    try:
        text = data.decode("utf-8")
        def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in pairs:
                if key in result:
                    fail(f"duplicate JSON key {key!r} in {path}")
                result[key] = item
            return result
        return json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"invalid UTF-8 JSON in {path}: {exc}")


def require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unexpected " + ", ".join(extra))
        fail(f"{label} has an invalid shape ({'; '.join(detail)})")
    return value


def text(value: Any, label: str, *, nullable: bool = False, max_length: int = 12000) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        fail(f"{label} must be a string" + (" or null" if nullable else ""))
    if len(value) > max_length:
        fail(f"{label} exceeds its length limit")
    if any(
        ord(char) == 0
        or 0xD800 <= ord(char) <= 0xDFFF
        or (ord(char) < 0x20 and char not in "\t\n\r")
        for char in value
    ):
        fail(f"{label} contains a control character")
    return value.replace("\r\n", "\n").replace("\r", "\n")


def path_value(value: Any, label: str, *, nullable: bool = False) -> str | None:
    value = text(value, label, nullable=nullable, max_length=2000)
    if value is None:
        return None
    if not PATH_RE.fullmatch(value):
        fail(f"{label} is not a valid TFVC path")
    return value.replace("\\", "/")


def finding_path(value: Any, label: str) -> str:
    value = text(value, label, max_length=1000)
    if not value:
        fail(f"{label} cannot be empty")
    normalized = value.replace("\\", "/")
    if any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in normalized):
        fail(f"{label} contains a control character")
    if normalized.startswith("/") or any(part in ("", ".", "..") for part in normalized.split("/")):
        fail(f"{label} is not a safe review path")
    if normalized.startswith("$/") and not PATH_RE.fullmatch(normalized):
        fail(f"{label} is not a valid TFVC path")
    return normalized


def nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(f"{label} must be a non-negative integer")
    return value


def positive_int(value: Any, label: str) -> int:
    value = nonnegative_int(value, label)
    if value == 0:
        fail(f"{label} must be positive")
    return value


def validate_review(value: Any) -> dict[str, Any]:
    review = require_exact_keys(value, REVIEW_KEYS, "review")
    if not isinstance(review["schemaVersion"], int) or isinstance(review["schemaVersion"], bool) or review["schemaVersion"] != 2:
        fail("review schemaVersion must be 2")
    changeset = positive_int(review["changeset"], "review changeset")
    text(review["summary"], "review summary")
    findings = review["findings"]
    if not isinstance(findings, list) or len(findings) > 500:
        fail("review findings must be an array of at most 500 items")
    seen_ids: set[str] = set()
    for index, raw in enumerate(findings):
        finding = require_exact_keys(raw, FINDING_KEYS, f"finding {index}")
        finding_id = text(finding["id"], f"finding {index} id", max_length=128)
        if not ID_RE.fullmatch(finding_id or ""):
            fail(f"finding {index} id has an invalid format")
        finding_key = finding_id.casefold()
        if finding_key in seen_ids:
            fail(f"duplicate finding id: {finding_id}")
        seen_ids.add(finding_key)
        severity = finding["severity"]
        if not isinstance(severity, str) or severity not in SEVERITY_ORDER:
            fail(f"finding {index} has an invalid severity")
        for field, limit in (
            ("category", 200),
            ("file", 1000),
            ("title", 1000),
            ("description", 12000),
            ("impact", 12000),
            ("recommendation", 12000),
        ):
            field_value = text(finding[field], f"finding {index} {field}", max_length=limit)
            if field in {"category", "title"} and not field_value:
                fail(f"finding {index} {field} cannot be empty")
        finding_path(finding["file"], f"finding {index} file")
        if not isinstance(finding["securityRelevant"], bool):
            fail(f"finding {index} securityRelevant must be boolean")
        text(finding["symbol"], f"finding {index} symbol", nullable=True, max_length=512)
        for field in ("changeAnalysis", "securityBoundary", "attackScenario", "exploitability", "remediationExample"):
            text(finding[field], f"finding {index} {field}", nullable=True)
        evidence = require_exact_keys(finding["evidence"], EVIDENCE_KEYS, f"finding {index} evidence")
        evidence_summary = text(evidence["summary"], f"finding {index} evidence summary", max_length=12000)
        if not evidence_summary:
            fail(f"finding {index} evidence summary cannot be empty")
        text(evidence["before"], f"finding {index} evidence before", nullable=True, max_length=12000)
        text(evidence["after"], f"finding {index} evidence after", nullable=True, max_length=12000)
        steps = finding["verificationSteps"]
        if not isinstance(steps, list) or len(steps) > 50:
            fail(f"finding {index} verificationSteps must be an array of at most 50 items")
        for step_index, step in enumerate(steps):
            text(step, f"finding {index} verificationSteps[{step_index}]", max_length=2000)
            if not step:
                fail(f"finding {index} verificationSteps cannot contain an empty item")
        standards = finding["standards"]
        if not isinstance(standards, list) or len(standards) > 50:
            fail(f"finding {index} standards must be an array of at most 50 items")
        standard_ids: set[str] = set()
        for standard_index, raw_standard in enumerate(standards):
            standard = require_exact_keys(raw_standard, STANDARD_KEYS, f"finding {index} standard {standard_index}")
            standard_id = text(standard["id"], f"finding {index} standard {standard_index} id", max_length=128)
            if not standard_id:
                fail(f"finding {index} standard id cannot be empty")
            if standard_id.casefold() in standard_ids:
                fail(f"duplicate standard id in finding {index}: {standard_id}")
            standard_ids.add(standard_id.casefold())
            standard_name = text(standard["name"], f"finding {index} standard {standard_index} name", max_length=512)
            if not standard_name:
                fail(f"finding {index} standard name cannot be empty")
        if not isinstance(finding["confidence"], str) or finding["confidence"] not in {"high", "medium", "low"}:
            fail(f"finding {index} has an invalid confidence")
    limitations = review["limitations"]
    if not isinstance(limitations, list) or len(limitations) > 100:
        fail("review limitations must be an array of at most 100 items")
    for index, limitation in enumerate(limitations):
        if not text(limitation, f"limitation {index}", max_length=4000):
            fail(f"limitation {index} cannot be empty")
    return review


def validate_manifest(value: Any) -> dict[str, Any]:
    manifest = require_exact_keys(value, MANIFEST_KEYS, "manifest")
    if (
        not isinstance(manifest["schemaVersion"], int)
        or isinstance(manifest["schemaVersion"], bool)
        or manifest["schemaVersion"] != 1
        or not isinstance(manifest["normalizationVersion"], int)
        or isinstance(manifest["normalizationVersion"], bool)
        or manifest["normalizationVersion"] != 1
    ):
        fail("manifest schema or normalization version is unsupported")
    for field in ("helperVersion", "apiVersion"):
        if not text(manifest[field], f"manifest {field}", max_length=256):
            fail(f"manifest {field} cannot be empty")
    changeset = positive_int(manifest["changeset"], "manifest changeset")
    nonnegative_int(manifest["previousChangeset"], "manifest previousChangeset")
    path_value(manifest["reviewRoot"], "manifest reviewRoot")
    coverage = require_exact_keys(manifest["coverage"], COVERAGE_KEYS, "manifest coverage")
    if coverage["reviewComplete"] is not True or coverage["unreviewableChanges"] != 0:
        fail("manifest coverage is incomplete")
    for field in COVERAGE_KEYS - {"reviewComplete"}:
        nonnegative_int(coverage[field], f"manifest coverage.{field}")
    if coverage["enumeratedChanges"] < 1 or coverage["inScopeChanges"] < 1:
        fail("manifest coverage must contain at least one enumerated and in-scope change")
    files = manifest["files"]
    if not isinstance(files, list) or not files or len(files) > 500:
        fail("manifest files must be a non-empty array of at most 500 items")
    expected_paths: set[str] = set()
    review_root = path_value(manifest["reviewRoot"], "manifest reviewRoot") or ""
    review_root_folded = review_root.rstrip("/").casefold()
    seen_indexes: set[int] = set()
    previous_index = 0
    text_diff_count = 0
    for index, raw in enumerate(files):
        item = require_exact_keys(raw, FILE_KEYS, f"manifest files[{index}]")
        if not isinstance(item["index"], int) or isinstance(item["index"], bool) or item["index"] < 1:
            fail(f"manifest files[{index}].index must be a positive integer")
        item_index = item["index"]
        if item_index in seen_indexes:
            fail(f"manifest files[{index}].index is duplicated")
        if item_index < previous_index:
            fail("manifest file indexes must be in ascending order")
        if item_index > coverage["enumeratedChanges"]:
            fail(f"manifest files[{index}].index exceeds enumeratedChanges")
        seen_indexes.add(item_index)
        previous_index = item_index
        for field in ("changeType", "classification"):
            if not text(item[field], f"manifest files[{index}].{field}", max_length=128):
                fail(f"manifest files[{index}].{field} cannot be empty")
        for field in ("path", "sourceServerItem", "oldPath", "newPath"):
            path = path_value(item[field], f"manifest files[{index}].{field}", nullable=field != "path")
            # review_data.normalize_manifest deliberately omits sourceServerItem
            # from reviewPaths when a rename source is outside the review root.
            if path and field != "sourceServerItem":
                folded = path.casefold()
                if folded == review_root_folded or folded.startswith(review_root_folded + "/"):
                    expected_paths.add(folded)
        for field in ("oldSize", "newSize"):
            nonnegative_int(item[field], f"manifest files[{index}].{field}")
        for field in ("oldHash", "newHash"):
            text(item[field], f"manifest files[{index}].{field}", nullable=True, max_length=256)
        if item["reviewable"] is not True or not isinstance(item["textDiff"], bool):
            fail(f"manifest files[{index}] has invalid reviewability flags")
        if item["textDiff"]:
            text_diff_count += 1
        if item["reason"] is not None:
            fail("normalized manifest reason must be null")
    if coverage["inScopeChanges"] != len(files):
        fail("manifest coverage.inScopeChanges does not match the file inventory")
    if coverage["enumeratedChanges"] != coverage["inScopeChanges"] + coverage["outOfScopeChanges"]:
        fail("manifest coverage enumerated/in-scope/out-of-scope counts do not reconcile")
    if coverage["filesWithTextDiff"] != text_diff_count:
        fail("manifest coverage.filesWithTextDiff does not match the file inventory")
    paths = manifest["reviewPaths"]
    if not isinstance(paths, list) or not paths or len(paths) > 1000:
        fail("manifest reviewPaths must be a non-empty array")
    normalized_paths = [path_value(path, f"manifest reviewPaths[{index}]") for index, path in enumerate(paths)]
    if len({path.casefold() for path in normalized_paths if path}) != len(normalized_paths):
        fail("manifest reviewPaths contains duplicates")
    for index, path in enumerate(normalized_paths):
        if path is not None:
            folded = path.casefold()
            if folded != review_root_folded and not folded.startswith(review_root_folded + "/"):
                fail(f"manifest reviewPaths[{index}] is outside reviewRoot")
    if {path.casefold() for path in normalized_paths if path} != expected_paths:
        fail("manifest reviewPaths does not match the file inventory")
    return manifest


def validate_meta(value: Any, review: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    meta = require_exact_keys(value, META_KEYS, "report metadata")
    if not isinstance(meta["metaVersion"], int) or isinstance(meta["metaVersion"], bool) or meta["metaVersion"] != 1:
        fail("report metadata metaVersion must be 1")
    changeset = positive_int(meta["changeset"], "metadata changeset")
    if changeset != review["changeset"] or changeset != manifest["changeset"]:
        fail("metadata, review, and manifest changesets do not match")
    if nonnegative_int(meta["previousChangeset"], "metadata previousChangeset") != manifest["previousChangeset"]:
        fail("metadata and manifest previous changesets do not match")
    if path_value(meta["reviewRoot"], "metadata reviewRoot") != path_value(manifest["reviewRoot"], "manifest reviewRoot"):
        fail("metadata and manifest review roots do not match")
    counts = require_exact_keys(meta["counts"], COUNT_KEYS, "metadata counts")
    for field in COUNT_KEYS:
        nonnegative_int(counts[field], f"metadata counts.{field}")
    actual_counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in review["findings"]:
        actual_counts[finding["severity"]] += 1
    for field, actual in actual_counts.items():
        if counts[field] != actual:
            fail(f"metadata count {field} does not match review")
    if counts["limitations"] != len(review["limitations"]):
        fail("metadata limitation count does not match review")
    if counts["totalFindings"] != len(review["findings"]):
        fail("metadata totalFindings does not match review")
    expected_decision = "manual-review-required" if counts["limitations"] else (
        "fail" if counts["critical"] or counts["high"] else "pass"
    )
    if not isinstance(meta["securityDecision"], str) or meta["securityDecision"] != expected_decision:
        fail("metadata securityDecision does not match deterministic policy")
    if not isinstance(meta["reportStatus"], str) or meta["reportStatus"] not in {"analysis-valid", "html-valid", "html-failed"}:
        fail("metadata reportStatus is invalid")
    if not isinstance(meta["pipelineGate"], str) or meta["pipelineGate"] not in {"pass", "fail"}:
        fail("metadata pipelineGate is invalid")
    expected_gate = "pass" if expected_decision == "pass" and meta["reportStatus"] == "html-valid" else "fail"
    if meta["pipelineGate"] != expected_gate:
        fail("metadata pipelineGate does not match deterministic policy")
    if not isinstance(meta["finalTaskStatus"], str) or meta["finalTaskStatus"] not in {"pending", "succeeded", "blocked", "failed"}:
        fail("metadata finalTaskStatus is invalid")
    expected_task_status = {
        "analysis-valid": "pending",
        "html-valid": "succeeded" if expected_decision == "pass" else "blocked",
        "html-failed": "failed",
    }[meta["reportStatus"]]
    if meta["finalTaskStatus"] != expected_task_status:
        fail("metadata finalTaskStatus does not match report status and security decision")
    policy = require_exact_keys(meta["policy"], POLICY_KEYS, "metadata policy")
    if policy != {
        "blockingSeverities": ["critical", "high"],
        "limitationsBlock": True,
        "mediumAction": "warning",
        "lowAction": "informational",
        "infoAction": "informational",
    }:
        fail("metadata policy is not the fixed review policy")
    coverage = require_exact_keys(meta["coverage"], COVERAGE_KEYS, "metadata coverage")
    if coverage != manifest["coverage"]:
        fail("metadata coverage does not match manifest")
    provenance = require_exact_keys(meta["provenance"], PROVENANCE_KEYS, "metadata provenance")
    for field in ("generatedAt", "helperVersion", "apiVersion", "cliVersion"):
        if not text(provenance[field], f"metadata provenance.{field}", max_length=512):
            fail(f"metadata provenance.{field} cannot be empty")
    if not isinstance(provenance["helperCommit"], str) or not COMMIT_RE.fullmatch(provenance["helperCommit"]):
        fail("metadata provenance.helperCommit is invalid")
    if not isinstance(provenance["deployment"], str) or not DEPLOYMENT_RE.fullmatch(provenance["deployment"]):
        fail("metadata provenance.deployment is invalid")
    if not isinstance(provenance["reasoningEffort"], str) or provenance["reasoningEffort"] not in {"none", "minimal", "low", "medium", "high", "xhigh", "max"}:
        fail("metadata provenance.reasoningEffort is invalid")
    hashes = require_exact_keys(provenance["hashes"], HASH_KEYS, "metadata provenance.hashes")
    for field in HASH_KEYS:
        if not isinstance(hashes[field], str) or not SHA256_RE.fullmatch(hashes[field]):
            fail(f"metadata provenance.hashes.{field} is invalid")
    formats = require_exact_keys(meta["formats"], FORMAT_KEYS, "metadata formats")
    if (
        any(not isinstance(formats[field], int) or isinstance(formats[field], bool) for field in FORMAT_KEYS)
        or formats != {"reviewSchema": 2, "metadataSchema": 1, "htmlContract": 2}
    ):
        fail("metadata formats do not match the supported contract")
    return meta


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").casefold()


def manifest_path_aliases(manifest: dict[str, Any]) -> set[str]:
    root = manifest["reviewRoot"].rstrip("/")
    aliases: set[str] = set()
    for raw_path in manifest["reviewPaths"]:
        canonical = raw_path.replace("\\", "/")
        aliases.add(canonical.casefold())
        if canonical.casefold() == root.casefold():
            continue
        if canonical.casefold().startswith((root + "/").casefold()):
            relative = canonical[len(root) + 1 :]
            aliases.add(relative.casefold())
            aliases.add(("a/" + relative).casefold())
            aliases.add(("b/" + relative).casefold())
    return aliases


def finding_file_matches(value: str, manifest: dict[str, Any]) -> bool:
    candidate = value.replace("\\", "/")
    aliases = manifest_path_aliases(manifest)
    if candidate.casefold() in aliases:
        return True
    stripped = candidate
    while stripped.startswith("./"):
        stripped = stripped[2:]
    if stripped.startswith("a/") or stripped.startswith("b/"):
        stripped = stripped[2:]
    if not stripped or stripped.startswith("/") or any(part in ("", ".", "..") for part in stripped.split("/")):
        return False
    root = manifest["reviewRoot"].rstrip("/")
    return (root + "/" + stripped).casefold() in aliases


def sorted_findings(review: dict[str, Any]) -> list[dict[str, Any]]:
    ordered = sorted(
        enumerate(review["findings"]),
        key=lambda pair: (SEVERITY_ORDER[pair[1]["severity"]], pair[0]),
    )
    return [finding for _, finding in ordered]


def esc(value: Any) -> str:
    rendered = str(value)
    if isinstance(value, str):
        rendered = rendered.replace("\r\n", "\n").replace("\r", "\n")
    return html.escape(rendered, quote=False)


def esc_attr(value: Any) -> str:
    rendered = str(value)
    if isinstance(value, str):
        rendered = rendered.replace("\r\n", "\n").replace("\r", "\n")
    return html.escape(rendered, quote=True)


def element(tag: str, content: str = "", *, attrs: dict[str, Any] | None = None) -> str:
    attrs = attrs or {}
    rendered = "".join(f' {name}="{esc_attr(value)}"' for name, value in attrs.items())
    return f"<{tag}{rendered}>{content}</{tag}>"


def void_element(tag: str, *, attrs: dict[str, Any] | None = None) -> str:
    attrs = attrs or {}
    rendered = "".join(f' {name}="{esc_attr(value)}"' for name, value in attrs.items())
    return f"<{tag}{rendered}>"


def empty_value(value: Any) -> str:
    return "None" if value is None else esc(value)


def dl_rows(rows: Iterable[tuple[str, Any]]) -> str:
    body = []
    for label, value in rows:
        body.append(element("dt", esc(label)))
        body.append(element("dd", empty_value(value)))
    return element("dl", "".join(body))


def text_block(value: str | None) -> str:
    if value is None:
        return element("p", "None", attrs={"class": "empty"})
    return element("pre", "\n" + esc(value))


def pre_block(value: str) -> str:
    # HTML's pre-processing removes one LF immediately after <pre>. Add one
    # sentinel so a supplied leading LF remains data after HTML5 parsing.
    return element("pre", "\n" + esc(value))


def list_block(values: list[Any], *, empty_label: str = "None") -> str:
    if not values:
        return element("p", esc(empty_label), attrs={"class": "empty"})
    return element("ul", "".join(element("li", esc(value), attrs={"class": "list-item"}) for value in values), attrs={"class": "list-plain"})


def extract_style(template: str) -> str:
    tree = parse_html(template.encode("utf-8"), source="template")
    styles = [node for node in tree.iter() if local_name(node.tag) == "style" and node.attrib.get("id") == "report-style"]
    if len(styles) != 1:
        fail("template must contain exactly one style#report-style")
    style = styles[0]
    attrs = {local_name(key): value for key, value in style.attrib.items()}
    if attrs != {"id": "report-style"}:
        fail("template stylesheet has unsupported attributes")
    if style.text is None:
        fail("template stylesheet is empty")
    return style.text.replace("\r\n", "\n").replace("\r", "\n")


def render_document(review: dict[str, Any], meta: dict[str, Any], manifest: dict[str, Any], template: str, *, kind: str = "codex") -> str:
    """Render the canonical document used by the fallback and test fixtures."""
    style = extract_style(template)
    if kind not in {"codex", "fallback"}:
        fail("invalid report kind")
    findings = sorted_findings(review)
    counts = meta["counts"]
    provenance = meta["provenance"]
    status_class = meta["securityDecision"] if meta["securityDecision"] in {"pass", "fail", "manual-review-required"} else "fail"
    report_class = "fallback" if kind == "fallback" else meta["reportStatus"]
    header_content = (
        element("p", esc("Security & code review"), attrs={"class": "eyebrow"})
        + element("h1", f"TFVC changeset C{review['changeset']}")
        + element(
            "p",
            element("span", f"SECURITY DECISION: {meta['securityDecision'].upper()}", attrs={"class": f"badge {status_class}"})
            + element("span", f"REPORT: {meta['reportStatus'].upper()}", attrs={"class": f"report-status {report_class}"}),
        )
    )
    if kind == "fallback":
        header_content += element(
            "p",
            "Deterministic fallback report: the Codex HTML presentation pass failed or was rejected; this document presents validated facts only.",
            attrs={"class": "fallback-banner"},
        )
    header_content += dl_rows(
        [
            ("Review root", meta["reviewRoot"]),
            ("Previous changeset", f"C{meta['previousChangeset']}"),
            ("Deployment", provenance["deployment"]),
            ("Reasoning effort", provenance["reasoningEffort"]),
            ("Total findings", counts["totalFindings"]),
        ]
    )
    metric_items = [("Critical", counts["critical"], "critical"), ("High", counts["high"], "high"), ("Medium", counts["medium"], "medium"), ("Low", counts["low"], "low"), ("Info", counts["info"], "info"), ("Limitations", counts["limitations"], "fail" if counts["limitations"] else "pass")]
    metrics = element(
        "div",
        "".join(element("div", element("span", esc(label)) + element("strong", esc(value)), attrs={"class": f"metric {css_class}"}) for label, value, css_class in metric_items),
        attrs={"class": "metrics"},
    )
    header_content += metrics

    coverage = manifest["coverage"]
    coverage_content = element("h2", "Coverage") + dl_rows(
        [(field, coverage[field]) for field in ("reviewComplete", "enumeratedChanges", "inScopeChanges", "outOfScopeChanges", "unreviewableChanges", "filesWithTextDiff", "diffBytes", "diffLines")]
    )
    coverage_content += element("h3", "Manifest metadata") + dl_rows(
        [
            ("schemaVersion", manifest["schemaVersion"]),
            ("normalizationVersion", manifest["normalizationVersion"]),
            ("helperVersion", manifest["helperVersion"]),
            ("apiVersion", manifest["apiVersion"]),
            ("changeset", manifest["changeset"]),
            ("previousChangeset", manifest["previousChangeset"]),
            ("reviewRoot", manifest["reviewRoot"]),
        ]
    )
    coverage_content += element("h3", "Review paths") + list_block(manifest["reviewPaths"])

    file_cards = []
    for file_item in manifest["files"]:
        file_rows = [(field, file_item[field]) for field in ("index", "changeType", "classification", "path", "sourceServerItem", "oldPath", "newPath", "oldSize", "newSize", "oldHash", "newHash", "reviewable", "textDiff", "reason")]
        file_cards.append(element("article", element("h3", f"Change {file_item['index']}: {esc(file_item['path'])}") + dl_rows(file_rows), attrs={"class": "file-card"}))
    changed_content = element("h2", "Changed files") + ("".join(file_cards) if file_cards else element("p", "None reported.", attrs={"class": "empty"}))

    summary_content = element("h2", "Summary") + pre_block(review["summary"])

    overview_rows = []
    for index, finding in enumerate(findings):
        overview_rows.append(
            element(
                "tr",
                element("td", element("a", esc(finding["id"]), attrs={"href": f"#finding-{index}"}))
                + element("td", esc(finding["severity"].upper()), attrs={"class": finding["severity"]})
                + element("td", esc("yes" if finding["securityRelevant"] else "no"))
                + element("td", esc(finding["title"]))
                + element("td", esc(finding["file"]))
                + element("td", esc(finding["confidence"])),
            )
        )
    overview = element("h2", "Findings overview")
    if overview_rows:
        head = element("tr", "".join(element("th", esc(label)) for label in ("ID", "Severity", "Security", "Finding", "File", "Confidence")))
        overview += element("div", element("table", element("thead", head) + element("tbody", "".join(overview_rows)), attrs={"class": "findings-table"}), attrs={"class": "table-wrap"})
    else:
        overview += element("p", "No findings reported.", attrs={"class": "empty"})

    detail_cards = []
    for index, finding in enumerate(findings):
        evidence = finding["evidence"]
        fields = [
            ("Category", finding["category"]),
            ("Security relevant", "yes" if finding["securityRelevant"] else "no"),
            ("Confidence", finding["confidence"]),
            ("Symbol", finding["symbol"]),
            ("Description", None),
            ("Change analysis", None),
            ("Security boundary", None),
            ("Attack scenario", None),
            ("Exploitability", None),
            ("Impact", None),
            ("Evidence summary", None),
            ("Evidence before", None),
            ("Evidence after", None),
            ("Recommendation", None),
            ("Remediation example", None),
        ]
        dl = []
        for label, value in fields:
            if label == "Description": value = finding["description"]
            elif label == "Change analysis": value = finding["changeAnalysis"]
            elif label == "Security boundary": value = finding["securityBoundary"]
            elif label == "Attack scenario": value = finding["attackScenario"]
            elif label == "Exploitability": value = finding["exploitability"]
            elif label == "Impact": value = finding["impact"]
            elif label == "Evidence summary": value = evidence["summary"]
            elif label == "Evidence before": value = evidence["before"]
            elif label == "Evidence after": value = evidence["after"]
            elif label == "Recommendation": value = finding["recommendation"]
            elif label == "Remediation example": value = finding["remediationExample"]
            if label in {"Category", "Security relevant", "Confidence"}:
                rendered_value = empty_value(value)
            elif label == "Symbol":
                rendered_value = empty_value(value) if value is not None else text_block(None)
            else:
                rendered_value = text_block(value)
            dl.extend((element("dt", esc(label)), element("dd", rendered_value)))
        dl.extend((element("dt", "Verification steps"), element("dd", list_block(finding["verificationSteps"]))))
        standards = [f"{item['id']} — {item['name']}" for item in finding["standards"]]
        dl.extend((element("dt", "Standards"), element("dd", list_block(standards))))
        article = (
            element("span", esc(finding["severity"].upper()), attrs={"class": f"badge {finding['severity']}"})
            + element("h2", f"{esc(finding['id'])} · {esc(finding['title'])}", attrs={"class": "finding-title"})
            + element("p", f"File: {esc(finding['file'])}", attrs={"class": "meta"})
            + element("dl", "".join(dl))
        )
        detail_cards.append(element("article", article, attrs={"id": f"finding-{index}", "class": "finding-card"}))

    if review["limitations"]:
        limitations = list_block(review["limitations"])
    else:
        limitations = element("p", "None reported.", attrs={"class": "empty"})
    limitations_content = element("h2", "Limitations") + limitations

    policy = meta["policy"]
    gate_content = element("h2", "Gate policy") + dl_rows(
        [
            ("Blocking severities", ", ".join(policy["blockingSeverities"])),
            ("Limitations block", policy["limitationsBlock"]),
            ("Medium action", policy["mediumAction"]),
            ("Low action", policy["lowAction"]),
            ("Info action", policy["infoAction"]),
            ("Security decision", meta["securityDecision"]),
            ("Pipeline gate", meta["pipelineGate"]),
            ("Final task status", meta["finalTaskStatus"]),
        ]
    )
    formats = meta["formats"]
    hashes = provenance["hashes"]
    audit_rows = [
        ("Meta version", meta["metaVersion"]),
        ("Report status", meta["reportStatus"]),
        ("Report format", formats["htmlContract"]),
        ("Review schema", formats["reviewSchema"]),
        ("Metadata schema", formats["metadataSchema"]),
        ("Generated at", provenance["generatedAt"]),
        ("Helper commit", provenance["helperCommit"]),
        ("Helper version", provenance["helperVersion"]),
        ("API version", provenance["apiVersion"]),
        ("Codex CLI", provenance["cliVersion"]),
        ("Diff SHA-256", hashes["diff"]),
        ("Schema SHA-256", hashes["schema"]),
        ("Template SHA-256", hashes["template"]),
        ("Review SHA-256", hashes["review"]),
        ("Normalized manifest SHA-256", hashes["normalizedManifest"]),
    ]
    audit_content = element("h2", "Audit metadata") + dl_rows(audit_rows)
    footer_content = (
        f"Schema v{formats['reviewSchema']} · Metadata v{formats['metadataSchema']} · HTML contract v{formats['htmlContract']} · "
        f"Generated {esc(provenance['generatedAt'])} · Helper {esc(provenance['helperCommit'])}"
    )
    sections = (
        element("header", header_content, attrs={"id": "report-header"})
        + element("section", coverage_content, attrs={"id": "coverage"})
        + element("section", changed_content, attrs={"id": "changed-files"})
        + element("section", summary_content, attrs={"id": "summary"})
        + element("section", overview, attrs={"id": "findings-overview"})
        + "".join(detail_cards)
        + element("section", limitations_content, attrs={"id": "limitations"})
        + element("section", gate_content, attrs={"id": "gate-policy"})
        + element("section", audit_content, attrs={"id": "audit-metadata"})
        + element("footer", footer_content, attrs={"id": "report-footer"})
    )
    head = (
        void_element("meta", attrs={"charset": "utf-8"})
        + void_element("meta", attrs={"http-equiv": "Content-Security-Policy", "content": CSP})
        + void_element("meta", attrs={"name": "viewport", "content": "width=device-width, initial-scale=1"})
        + element("title", f"Codex security review · TFVC C{review['changeset']}")
        + element("style", style, attrs={"id": "report-style"})
    )
    body = element("main", sections, attrs={"id": "report", "data-report-kind": kind})
    return "<!doctype html>" + element("html", element("head", head) + element("body", body), attrs={"lang": "en"})


def local_name(tag: Any) -> str:
    if not isinstance(tag, str):
        return "#comment"
    return tag.rsplit("}", 1)[-1].lower()


def import_html5lib() -> Any:
    try:
        import html5lib  # type: ignore
    except Exception as exc:  # pragma: no cover - environment-specific
        fail(f"html5lib 1.1 is required: {exc}")
    if getattr(html5lib, "__version__", None) != "1.1":
        fail(f"html5lib 1.1 is required (found {getattr(html5lib, '__version__', 'unknown')})")
    return html5lib


def parse_html(data: bytes, *, source: str) -> Any:
    if not data.lstrip().lower().startswith(b"<!doctype html>"):
        fail(f"{source} must begin with <!doctype html>")
    if b"\x00" in data:
        fail(f"{source} contains a NUL byte")
    try:
        html_text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{source} is not valid UTF-8: {exc}")
    html5lib = import_html5lib()
    try:
        return html5lib.HTMLParser(strict=True, namespaceHTMLElements=True).parse(html_text)
    except Exception as exc:
        fail(f"{source} is not valid strict HTML5: {exc}")


def validate_tree_security(root: Any, *, kind: str) -> None:
    if local_name(root.tag) != "html":
        fail("HTML root must be html")
    if root.tail and root.tail.strip():
        fail("text outside the html root is not allowed")
    for node in root.iter():
        tag = local_name(node.tag)
        if tag not in ALLOWED_TAGS:
            fail(f"disallowed HTML element: {tag}")
        allowed_attrs = ALLOWED_ATTRS[tag]
        attrs = {local_name(key): value for key, value in node.attrib.items()}
        if set(attrs) - allowed_attrs:
            fail(f"disallowed attribute on {tag}: {sorted(set(attrs) - allowed_attrs)}")
        for attr, value in attrs.items():
            if any(ord(char) < 0x20 and char not in "\t\n\r" for char in value):
                fail(f"control character in {tag}@{attr}")
        if tag == "a":
            href = attrs.get("href", "")
            if not re.fullmatch(r"#finding-[0-9]+", href):
                fail("links must be local finding anchors")
        if tag == "style" and attrs.get("id") != "report-style":
            fail("only style#report-style is allowed")
        if tag == "main" and attrs.get("data-report-kind") != kind:
            fail("report kind marker does not match validation mode")
        if tag == "meta" and attrs.get("http-equiv", "").lower() == "refresh":
            fail("refresh directives are forbidden")
        if node.text and any(ord(char) == 0 for char in node.text):
            fail(f"NUL in {tag} text")
        if node.tail and any(ord(char) == 0 for char in node.tail):
            fail(f"NUL in {tag} tail")
        for child in list(node):
            if local_name(child.tag) == "#comment":
                fail("HTML comments are not allowed")


def canonical_node(node: Any) -> tuple[Any, ...]:
    tag = local_name(node.tag)
    attrs = tuple(sorted((local_name(key), value) for key, value in node.attrib.items()))
    text_value = (node.text or "").replace("\r\n", "\n").replace("\r", "\n")
    # Whitespace in an element with children is formatting indentation. A
    # whitespace-only leaf is data and must remain observable, especially for
    # evidence fields.
    if list(node) and not text_value.strip():
        text_value = ""
    if tag == "style":
        text_value = text_value.strip()
    children = tuple((canonical_node(child), canonical_tail(child)) for child in list(node))
    return (tag, attrs, text_value, children)


def canonical_tail(node: Any) -> str:
    tail = (node.tail or "").replace("\r\n", "\n").replace("\r", "\n")
    # Tail whitespace is formatting indentation; any non-whitespace tail is
    # meaningful text and participates in the exact comparison.
    return "" if not tail.strip() else tail


def expected_template_root(template: str) -> None:
    tree = parse_html(template.encode("utf-8"), source="template")
    # The template is a trusted package resource, but its fixed security
    # boundary is still checked before it supplies CSS to a report.
    validate_tree_security(tree, kind="codex")
    html_nodes = [node for node in tree.iter() if local_name(node.tag) == "html"]
    if len(html_nodes) != 1:
        fail("template must contain exactly one html root")
    metas = [node for node in tree.iter() if local_name(node.tag) == "meta"]
    if not any(node.attrib.get("charset") == "utf-8" for node in metas):
        fail("template must declare UTF-8")
    csp = [node for node in metas if node.attrib.get("http-equiv", "").lower() == "content-security-policy"]
    if len(csp) != 1 or csp[0].attrib.get("content") != CSP:
        fail("template CSP does not match the fixed policy")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_input_hashes(meta: dict[str, Any], review_path: Path, manifest_path: Path, template_path: Path) -> None:
    expected = meta["provenance"]["hashes"]
    actual = {
        "review": sha256_bytes(read_bytes(review_path)),
        "normalizedManifest": sha256_bytes(read_bytes(manifest_path)),
        "template": sha256_bytes(read_bytes(template_path)),
    }
    for field, digest in actual.items():
        if digest != expected[field]:
            fail(f"metadata provenance hash does not match {field} input")


def validate_document(candidate: bytes, expected: bytes, *, kind: str) -> None:
    candidate_tree = parse_html(candidate, source="candidate HTML")
    expected_tree = parse_html(expected, source="expected HTML")
    validate_tree_security(candidate_tree, kind=kind)
    if canonical_node(candidate_tree) != canonical_node(expected_tree):
        fail("candidate HTML does not exactly match the authoritative report DOM")


def validate_report(review_path: Path, meta_path: Path, manifest_path: Path, template_path: Path, input_path: Path) -> None:
    review_value = read_json(review_path)
    meta_value = read_json(meta_path)
    manifest_value = read_json(manifest_path)
    review = validate_review(review_value)
    manifest = validate_manifest(manifest_value)
    meta = validate_meta(meta_value, review, manifest)
    verify_input_hashes(meta, review_path, manifest_path, template_path)
    validate_report_with_values(
        review,
        meta,
        manifest,
        read_bytes(template_path).decode("utf-8"),
        read_bytes(input_path),
    )


def validate_report_with_values(
    review_value: Any,
    meta_value: Any,
    manifest_value: Any,
    template: str,
    candidate: bytes,
) -> None:
    review = validate_review(review_value)
    manifest = validate_manifest(manifest_value)
    meta = validate_meta(meta_value, review, manifest)
    if meta["reportStatus"] != "html-valid":
        fail("HTML candidate validation requires reportStatus=html-valid")
    if any(not finding_file_matches(finding["file"], manifest) for finding in review["findings"]):
        fail("a finding file is outside the normalized manifest review paths")
    expected_template_root(template)
    expected = render_document(review, meta, manifest, template, kind="codex")
    validate_document(candidate, expected.encode("utf-8"), kind="codex")


def fallback_report(review_path: Path, meta_path: Path, manifest_path: Path, template_path: Path, output_path: Path) -> None:
    review = validate_review(read_json(review_path))
    manifest = validate_manifest(read_json(manifest_path))
    meta = validate_meta(read_json(meta_path), review, manifest)
    verify_input_hashes(meta, review_path, manifest_path, template_path)
    if meta["reportStatus"] != "html-failed":
        fail("deterministic fallback requires reportStatus=html-failed")
    template = read_bytes(template_path).decode("utf-8")
    expected_template_root(template)
    expected = render_document(review, meta, manifest, template, kind="fallback").encode("utf-8")
    output = expected
    if len(output) > MAX_HTML_BYTES:
        fail("fallback HTML exceeds the output size limit")
    # Validate the fallback with the same strict parser and canonical DOM
    # comparison before exposing it to the artifact staging directory.
    validate_document(output, expected, kind="fallback")
    output_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = output_path.with_name(output_path.name + ".part")
    try:
        temporary.write_bytes(output)
        temporary.chmod(0o600)
        temporary.replace(output_path)
    except OSError as exc:
        fail(f"unable to write fallback HTML: {exc}")


def check_dependencies() -> None:
    import_html5lib()
    try:
        import six  # type: ignore
        import webencodings  # type: ignore
    except Exception as exc:  # pragma: no cover - environment-specific
        fail(f"pinned html5lib dependencies are required: {exc}")
    if getattr(six, "__version__", None) != "1.17.0":
        fail(f"six 1.17.0 is required (found {getattr(six, '__version__', 'unknown')})")
    try:
        webencodings_version = importlib_metadata.version("webencodings")
    except importlib_metadata.PackageNotFoundError as exc:  # pragma: no cover - environment-specific
        fail(f"webencodings 0.5.1 is required: {exc}")
    if webencodings_version != "0.5.1":
        fail(f"webencodings 0.5.1 is required (found {webencodings_version})")
    print("html5lib==1.1 six==1.17.0 webencodings==0.5.1")


def path_arg(value: str) -> Path:
    path = Path(value)
    if not value or "\x00" in value:
        raise argparse.ArgumentTypeError("path is empty or contains NUL")
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check-deps", help="verify pinned parser dependencies")
    for command in ("validate", "fallback"):
        sub = subparsers.add_parser(command)
        sub.add_argument("--review", required=True, type=path_arg)
        sub.add_argument("--meta", required=True, type=path_arg)
        sub.add_argument("--manifest", required=True, type=path_arg)
        sub.add_argument("--template", required=True, type=path_arg)
        sub.add_argument("--input" if command == "validate" else "--output", required=True, type=path_arg)
    render = subparsers.add_parser("render", help="render a canonical fixture document")
    render.add_argument("--review", required=True, type=path_arg)
    render.add_argument("--meta", required=True, type=path_arg)
    render.add_argument("--manifest", required=True, type=path_arg)
    render.add_argument("--template", required=True, type=path_arg)
    render.add_argument("--output", required=True, type=path_arg)
    render.add_argument("--kind", choices=("codex", "fallback"), default="codex")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "check-deps":
            check_dependencies()
        elif args.command == "validate":
            validate_report(args.review, args.meta, args.manifest, args.template, args.input)
            print("HTML report validated")
        elif args.command == "fallback":
            fallback_report(args.review, args.meta, args.manifest, args.template, args.output)
            print(f"Fallback HTML written to {args.output}")
        else:
            review = validate_review(read_json(args.review))
            manifest = validate_manifest(read_json(args.manifest))
            meta = validate_meta(read_json(args.meta), review, manifest)
            template = read_bytes(args.template).decode("utf-8")
            expected_template_root(template)
            output = render_document(review, meta, manifest, template, kind=args.kind).encode("utf-8")
            args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            args.output.write_bytes(output)
            args.output.chmod(0o600)
    except ReportError as exc:
        print(f"report_html: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"report_html: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
