#!/usr/bin/env python3
"""Validate and render the bounded data contracts used by the TFVC review.

The module intentionally uses only the Python standard library.  The shell
launcher can therefore provision one known Python runtime without installing
packages from data produced by a model or a changeset.

Public helpers:

``load_json(path)``
    Load one UTF-8 JSON document while rejecting duplicate keys, NaN/Infinity,
    control characters and over-sized input.

``validate_review(review, manifest, changeset)``
    Return a list of validation errors.  An empty list means the review is
    independently valid and every finding file belongs to the normalized
    manifest.

``build_metadata(...)``
    Calculate authoritative counts, the security decision, policy and
    provenance metadata outside model control.

The command-line interface is deliberately small so the Bash helper can stage
each result atomically:

    normalize-manifest --input RAW --changeset N --output NORMALIZED
    validate-review --input REVIEW --manifest NORMALIZED --changeset N [--output REVIEW]
    metadata --review REVIEW --manifest NORMALIZED ... --output META
    markdown --review REVIEW --meta META --output SUMMARY
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import hashlib
import json
import os
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")
REASONING_EFFORTS = ("none", "minimal", "low", "medium", "high", "xhigh", "max")

MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_CHANGES = 500
MAX_REVIEW_FINDINGS = 500
MAX_LIMITATIONS = 100
MAX_REVIEW_PATHS = 1000

RAW_MANIFEST_KEYS = {
    "schemaVersion",
    "helperVersion",
    "apiVersion",
    "changeset",
    "previousChangeset",
    "reviewRoot",
    "changesetMetadata",
    "coverage",
    "changes",
}
RAW_METADATA_KEYS = {"author", "createdDate", "comment"}
RAW_COVERAGE_KEYS = {
    "reviewComplete",
    "enumeratedChanges",
    "inScopeChanges",
    "outOfScopeChanges",
    "unreviewableChanges",
    "filesWithTextDiff",
    "diffBytes",
    "diffLines",
}
RAW_CHANGE_KEYS = {
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

NORMALIZED_MANIFEST_KEYS = {
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
NORMALIZED_FILE_KEYS = RAW_CHANGE_KEYS

REVIEW_KEYS = {"schemaVersion", "changeset", "summary", "findings", "limitations"}
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

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_DEPLOYMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
_SERVER_PATH_RE = re.compile(r"^\$/[^\r\n\t]+$")


class ContractError(ValueError):
    """Raised when a contract or bounded input is invalid."""


def _duplicate_key_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ContractError(f"non-finite JSON number: {value}")


def load_json(path: str | os.PathLike[str]) -> Any:
    """Load a bounded JSON document with duplicate-key protection."""

    source = Path(path)
    try:
        with source.open("rb") as handle:
            raw = handle.read(MAX_JSON_BYTES + 1)
    except OSError as exc:
        raise ContractError("unable to read JSON input") from exc
    if len(raw) > MAX_JSON_BYTES:
        raise ContractError("JSON input exceeds the 8 MiB bound")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_key_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ContractError) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError("JSON input is not valid UTF-8 JSON") from exc
    return value


def _json_default(value: Any) -> Any:
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def _write_json(path: str | os.PathLike[str], value: Any) -> None:
    destination = Path(path)
    try:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
            default=_json_default,
        ) + "\n"
        encoded = payload.encode("utf-8")
        if len(encoded) > MAX_JSON_BYTES:
            raise ContractError("JSON output exceeds the 8 MiB bound")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(
            f".{destination.name}.tmp.{os.getpid()}"
        )
        temporary.write_bytes(encoded)
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    except OSError as exc:
        raise ContractError("unable to write JSON output") from exc


def _write_text(path: str | os.PathLike[str], text: str) -> None:
    destination = Path(path)
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_JSON_BYTES:
        raise ContractError("text output exceeds the 8 MiB bound")
    temporary = destination.with_name(f".{destination.name}.tmp.{os.getpid()}")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_bytes(encoded)
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    except OSError as exc:
        raise ContractError("unable to write text output") from exc


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _keys(value: Any, expected: set[str], label: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return False
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        errors.append(f"{label} is missing required fields: {', '.join(missing)}")
    if extra:
        errors.append(f"{label} contains unsupported fields: {', '.join(extra)}")
    return not missing and not extra


def _text(
    value: Any,
    label: str,
    errors: list[str],
    *,
    minimum: int = 0,
    maximum: int = 12000,
    allow_empty: bool = True,
    path: bool = False,
) -> bool:
    if not isinstance(value, str):
        errors.append(f"{label} must be a string")
        return False
    if not allow_empty and not value:
        errors.append(f"{label} must not be empty")
    if len(value) < minimum or len(value) > maximum:
        errors.append(f"{label} length is outside the permitted bound")
    for character in value:
        category = unicodedata.category(character)
        codepoint = ord(character)
        if category == "Cs" or codepoint == 0 or codepoint < 32:
            if path or codepoint not in (9, 10, 13):
                errors.append(f"{label} contains a control character")
                break
    return True


def _nullable_text(
    value: Any,
    label: str,
    errors: list[str],
    *,
    maximum: int = 12000,
) -> bool:
    if value is None:
        return True
    return _text(value, label, errors, maximum=maximum)


def _nonnegative_int(value: Any, label: str, errors: list[str]) -> bool:
    if not _is_int(value) or value < 0:
        errors.append(f"{label} must be a non-negative integer")
        return False
    return True


def _positive_int(value: Any, label: str, errors: list[str]) -> bool:
    if not _is_int(value) or value < 1:
        errors.append(f"{label} must be a positive integer")
        return False
    return True


def _server_path(value: Any, label: str, errors: list[str], *, nullable: bool = False) -> bool:
    if value is None and nullable:
        return True
    if not isinstance(value, str) or not _SERVER_PATH_RE.fullmatch(value):
        errors.append(f"{label} must be a TFVC server path")
        return False
    return _text(value, label, errors, maximum=2000, allow_empty=False, path=True)


def _validate_raw_manifest(manifest: Any, changeset: int) -> list[str]:
    errors: list[str] = []
    if not _keys(manifest, RAW_MANIFEST_KEYS, "manifest", errors):
        return errors
    assert isinstance(manifest, dict)
    if not _is_int(manifest.get("schemaVersion")) or manifest.get("schemaVersion") != 1:
        errors.append("manifest.schemaVersion must be 1")
    if manifest.get("changeset") != changeset:
        errors.append("manifest.changeset does not match the requested changeset")
    _positive_int(manifest.get("changeset"), "manifest.changeset", errors)
    _nonnegative_int(manifest.get("previousChangeset"), "manifest.previousChangeset", errors)
    if _is_int(manifest.get("changeset")) and _is_int(manifest.get("previousChangeset")):
        if manifest["previousChangeset"] != max(0, manifest["changeset"] - 1):
            errors.append("manifest.previousChangeset is not immediately before changeset")
    _text(manifest.get("helperVersion"), "manifest.helperVersion", errors, maximum=128, allow_empty=False)
    _text(manifest.get("apiVersion"), "manifest.apiVersion", errors, maximum=64, allow_empty=False)
    review_root = manifest.get("reviewRoot")
    _server_path(review_root, "manifest.reviewRoot", errors)
    if isinstance(review_root, str) and review_root.endswith("/"):
        errors.append("manifest.reviewRoot must not end with a slash")

    metadata = manifest.get("changesetMetadata")
    if _keys(metadata, RAW_METADATA_KEYS, "manifest.changesetMetadata", errors):
        assert isinstance(metadata, dict)
        _text(metadata["author"], "manifest.changesetMetadata.author", errors, maximum=1000)
        _text(metadata["createdDate"], "manifest.changesetMetadata.createdDate", errors, maximum=256)
        _text(metadata["comment"], "manifest.changesetMetadata.comment", errors, maximum=12000)

    coverage = manifest.get("coverage")
    if _keys(coverage, RAW_COVERAGE_KEYS, "manifest.coverage", errors):
        assert isinstance(coverage, dict)
        if coverage["reviewComplete"] is not True:
            errors.append("manifest.coverage.reviewComplete must be true")
        for field in (
            "enumeratedChanges",
            "inScopeChanges",
            "outOfScopeChanges",
            "unreviewableChanges",
            "filesWithTextDiff",
            "diffBytes",
            "diffLines",
        ):
            _nonnegative_int(coverage[field], f"manifest.coverage.{field}", errors)
        if _is_int(coverage["inScopeChanges"]) and coverage["inScopeChanges"] < 1:
            errors.append("manifest.coverage.inScopeChanges must be positive")
        if coverage["unreviewableChanges"] != 0:
            errors.append("manifest.coverage.unreviewableChanges must be zero")
        numeric_coverage = all(
            _is_int(coverage[field])
            for field in (
                "enumeratedChanges",
                "inScopeChanges",
                "outOfScopeChanges",
                "unreviewableChanges",
                "filesWithTextDiff",
                "diffBytes",
                "diffLines",
            )
        )
        if numeric_coverage and coverage["enumeratedChanges"] < coverage["inScopeChanges"]:
            errors.append("manifest coverage enumeratedChanges is smaller than inScopeChanges")
        if numeric_coverage and coverage["enumeratedChanges"] != coverage["inScopeChanges"] + coverage["outOfScopeChanges"]:
            errors.append("manifest coverage counts do not equal enumeratedChanges")

    changes = manifest.get("changes")
    if not isinstance(changes, list):
        errors.append("manifest.changes must be an array")
        return errors
    if not changes or len(changes) > MAX_MANIFEST_CHANGES:
        errors.append("manifest.changes count is outside the permitted bound")
    indexes: set[int] = set()
    for position, change in enumerate(changes, start=1):
        label = f"manifest.changes[{position}]"
        if not _keys(change, RAW_CHANGE_KEYS, label, errors):
            continue
        assert isinstance(change, dict)
        index = change["index"]
        if not _positive_int(index, f"{label}.index", errors):
            continue
        if index in indexes:
            errors.append(f"{label}.index is duplicated")
        indexes.add(index)
        _text(change["changeType"], f"{label}.changeType", errors, maximum=128, allow_empty=False)
        _text(change["classification"], f"{label}.classification", errors, maximum=128, allow_empty=False)
        _server_path(change["path"], f"{label}.path", errors)
        for field in ("sourceServerItem", "oldPath", "newPath"):
            _server_path(change[field], f"{label}.{field}", errors, nullable=True)
        for field in ("oldSize", "newSize"):
            _nonnegative_int(change[field], f"{label}.{field}", errors)
        for field in ("oldHash", "newHash"):
            _nullable_text(change[field], f"{label}.{field}", errors, maximum=256)
        if change["reviewable"] is not True:
            errors.append(f"{label}.reviewable must be true for a complete manifest")
        if not isinstance(change["textDiff"], bool):
            errors.append(f"{label}.textDiff must be boolean")
        _nullable_text(change["reason"], f"{label}.reason", errors, maximum=4000)
    if indexes:
        ordered_indexes = [change.get("index") for change in changes if isinstance(change, dict) and _is_int(change.get("index"))]
        if ordered_indexes != sorted(ordered_indexes) or any(
            left == right for left, right in zip(ordered_indexes, ordered_indexes[1:])
        ):
            errors.append("manifest change indexes must be strictly increasing")
        if isinstance(coverage, dict) and _is_int(coverage.get("enumeratedChanges")) and any(
            index > coverage["enumeratedChanges"] for index in ordered_indexes if _is_int(index)
        ):
            errors.append("manifest change index exceeds enumeratedChanges")
    if isinstance(coverage, dict) and isinstance(coverage.get("inScopeChanges"), int):
        if coverage["inScopeChanges"] != len(changes):
            errors.append("manifest coverage.inScopeChanges does not match manifest.changes")
        if coverage.get("filesWithTextDiff") != sum(bool(c.get("textDiff")) for c in changes if isinstance(c, dict)):
            errors.append("manifest coverage.filesWithTextDiff does not match manifest.changes")
    return errors


def _normalized_manifest(manifest: Mapping[str, Any], changeset: int) -> dict[str, Any]:
    errors: list[str] = []
    if not _keys(manifest, NORMALIZED_MANIFEST_KEYS, "normalized manifest", errors):
        raise ContractError("; ".join(errors))
    if not _is_int(manifest.get("schemaVersion")) or manifest.get("schemaVersion") != 1:
        errors.append("normalized manifest.schemaVersion must be 1")
    if not _is_int(manifest.get("normalizationVersion")) or manifest.get("normalizationVersion") != 1:
        errors.append("normalized manifest.normalizationVersion must be 1")
    if manifest.get("changeset") != changeset:
        errors.append("normalized manifest.changeset does not match")
    _positive_int(manifest.get("changeset"), "normalized manifest.changeset", errors)
    _nonnegative_int(manifest.get("previousChangeset"), "normalized manifest.previousChangeset", errors)
    if _is_int(manifest.get("changeset")) and _is_int(manifest.get("previousChangeset")):
        if manifest["previousChangeset"] != max(0, manifest["changeset"] - 1):
            errors.append("normalized manifest.previousChangeset is not immediately before changeset")
    _text(manifest.get("helperVersion"), "normalized manifest.helperVersion", errors, maximum=128, allow_empty=False)
    _text(manifest.get("apiVersion"), "normalized manifest.apiVersion", errors, maximum=64, allow_empty=False)
    _server_path(manifest.get("reviewRoot"), "normalized manifest.reviewRoot", errors)
    if isinstance(manifest.get("reviewRoot"), str) and manifest["reviewRoot"].endswith("/"):
        errors.append("normalized manifest.reviewRoot must not end with a slash")
    coverage = manifest.get("coverage")
    if _keys(coverage, RAW_COVERAGE_KEYS, "normalized manifest.coverage", errors):
        assert isinstance(coverage, dict)
        if coverage["reviewComplete"] is not True:
            errors.append("normalized manifest.coverage.reviewComplete must be true")
        for field in (
            "enumeratedChanges",
            "inScopeChanges",
            "outOfScopeChanges",
            "unreviewableChanges",
            "filesWithTextDiff",
            "diffBytes",
            "diffLines",
        ):
            _nonnegative_int(coverage[field], f"normalized manifest.coverage.{field}", errors)
        if _is_int(coverage["inScopeChanges"]) and coverage["inScopeChanges"] < 1:
            errors.append("normalized manifest.coverage.inScopeChanges must be positive")
        if coverage["unreviewableChanges"] != 0:
            errors.append("normalized manifest.coverage.unreviewableChanges must be zero")
    files = manifest.get("files")
    if not isinstance(files, list) or not files or len(files) > MAX_MANIFEST_CHANGES:
        errors.append("normalized manifest.files count is outside the permitted bound")
        files = []
    indexes: set[int] = set()
    for position, record in enumerate(files, start=1):
        label = f"normalized manifest.files[{position}]"
        if not _keys(record, NORMALIZED_FILE_KEYS, label, errors):
            continue
        assert isinstance(record, dict)
        index = record["index"]
        if _positive_int(index, f"{label}.index", errors):
            if index in indexes:
                errors.append(f"{label}.index is duplicated")
            indexes.add(index)
        _text(record["changeType"], f"{label}.changeType", errors, maximum=128, allow_empty=False)
        _text(record["classification"], f"{label}.classification", errors, maximum=128, allow_empty=False)
        _server_path(record["path"], f"{label}.path", errors)
        for field in ("sourceServerItem", "oldPath", "newPath"):
            _server_path(record[field], f"{label}.{field}", errors, nullable=True)
        for field in ("oldSize", "newSize"):
            _nonnegative_int(record[field], f"{label}.{field}", errors)
        for field in ("oldHash", "newHash"):
            _nullable_text(record[field], f"{label}.{field}", errors, maximum=256)
        if record["reviewable"] is not True:
            errors.append(f"{label}.reviewable must be true")
        if not isinstance(record["textDiff"], bool):
            errors.append(f"{label}.textDiff must be boolean")
        if record["reason"] is not None:
            errors.append(f"{label}.reason must be null in normalized output")
    if indexes:
        ordered_indexes = [record.get("index") for record in files if isinstance(record, dict) and _is_int(record.get("index"))]
        if ordered_indexes != sorted(ordered_indexes) or any(
            left == right for left, right in zip(ordered_indexes, ordered_indexes[1:])
        ):
            errors.append("normalized manifest file indexes must be strictly increasing")
        if isinstance(coverage, dict) and _is_int(coverage.get("enumeratedChanges")) and any(
            index > coverage["enumeratedChanges"] for index in ordered_indexes if _is_int(index)
        ):
            errors.append("normalized manifest file index exceeds enumeratedChanges")
    if isinstance(coverage, dict) and _is_int(coverage.get("inScopeChanges")):
        if coverage["inScopeChanges"] != len(files):
            errors.append("normalized manifest coverage.inScopeChanges does not match files")
        if all(_is_int(coverage.get(field)) for field in ("enumeratedChanges", "outOfScopeChanges")) and coverage[
            "enumeratedChanges"
        ] != coverage["inScopeChanges"] + coverage["outOfScopeChanges"]:
            errors.append("normalized manifest coverage counts do not equal enumeratedChanges")
        if _is_int(coverage.get("filesWithTextDiff")) and coverage["filesWithTextDiff"] != sum(
            bool(record.get("textDiff")) for record in files if isinstance(record, dict)
        ):
            errors.append("normalized manifest coverage.filesWithTextDiff does not match files")
    review_paths = manifest.get("reviewPaths")
    if not isinstance(review_paths, list) or not review_paths or len(review_paths) > MAX_REVIEW_PATHS:
        errors.append("normalized manifest.reviewPaths count is outside the permitted bound")
        review_paths = []
    seen_paths: set[str] = set()
    file_paths: set[str] = set()
    root = manifest.get("reviewRoot")
    root_prefix = (root.rstrip("/") + "/").casefold() if isinstance(root, str) else ""
    root_folded = root.casefold() if isinstance(root, str) else ""
    for record in files:
        if not isinstance(record, dict):
            continue
        for field in ("path", "sourceServerItem", "oldPath", "newPath"):
            value = record.get(field)
            if isinstance(value, str):
                file_paths.add(value.casefold())
    for index, value in enumerate(review_paths, start=1):
        if not isinstance(value, str) or not _server_path(value, f"normalized manifest.reviewPaths[{index}]", errors):
            continue
        folded = value.casefold()
        if folded != root_folded and not folded.startswith(root_prefix):
            errors.append(f"normalized manifest.reviewPaths[{index}] is outside reviewRoot")
        if folded in seen_paths:
            errors.append(f"normalized manifest.reviewPaths[{index}] is duplicated")
        seen_paths.add(folded)
        if folded not in file_paths:
            errors.append(f"normalized manifest.reviewPaths[{index}] is not present in files")
    if errors:
        raise ContractError("; ".join(errors))
    return dict(manifest)


def normalize_manifest(manifest: Mapping[str, Any], changeset: int) -> dict[str, Any]:
    """Validate the pinned helper's v1 manifest and expose a bounded v1 view."""

    errors = _validate_raw_manifest(manifest, changeset)
    if errors:
        raise ContractError("; ".join(errors))
    assert isinstance(manifest, dict)
    review_paths: list[str] = []
    seen_paths: set[str] = set()
    files: list[dict[str, Any]] = []
    for change in manifest["changes"]:
        record = dict(change)
        root = manifest["reviewRoot"].rstrip("/")
        for candidate in (record["path"], record["oldPath"], record["newPath"]):
            in_scope = isinstance(candidate, str) and (
                candidate.casefold() == root.casefold()
                or candidate.casefold().startswith((root + "/").casefold())
            )
            if in_scope and candidate.casefold() not in seen_paths:
                seen_paths.add(candidate.casefold())
                review_paths.append(candidate)
        files.append(record)
    result = {
        "schemaVersion": 1,
        "normalizationVersion": 1,
        "helperVersion": manifest["helperVersion"],
        "apiVersion": manifest["apiVersion"],
        "changeset": manifest["changeset"],
        "previousChangeset": manifest["previousChangeset"],
        "reviewRoot": manifest["reviewRoot"],
        # Deliberately omit changesetMetadata.  The raw changeset comment is
        # source-controlled text and is not needed by the report contract;
        # the published normalized manifest therefore cannot expose it.
        "coverage": dict(manifest["coverage"]),
        "files": files,
        "reviewPaths": review_paths,
    }
    return _normalized_manifest(result, changeset)


def _manifest_view(manifest: Any, changeset: int) -> tuple[Mapping[str, Any], Sequence[Mapping[str, Any]]]:
    if not isinstance(manifest, dict):
        raise ContractError("manifest must be an object")
    if manifest.get("normalizationVersion") == 1:
        normalized = _normalized_manifest(manifest, changeset)
        files = normalized.get("files")
        if not isinstance(files, list):
            raise ContractError("normalized manifest.files must be an array")
        return normalized, [item for item in files if isinstance(item, dict)]
    errors = _validate_raw_manifest(manifest, changeset)
    if errors:
        raise ContractError("; ".join(errors))
    return manifest, [item for item in manifest["changes"] if isinstance(item, dict)]


def _canonical_server_path(path: str) -> str | None:
    value = path.replace("\\", "/")
    if value.startswith("a/") or value.startswith("b/"):
        value = value[2:]
    while value.startswith("./"):
        value = value[2:]
    if not value.startswith("$/"):
        return None
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts[1:]):
        return None
    return "/".join(parts)


def _path_aliases(manifest: Mapping[str, Any], files: Sequence[Mapping[str, Any]]) -> set[str]:
    root = manifest.get("reviewRoot")
    if not isinstance(root, str):
        return set()
    root = root.rstrip("/")
    aliases: set[str] = set()
    values: list[str] = []
    supplied = manifest.get("reviewPaths")
    if isinstance(supplied, list):
        values.extend(item for item in supplied if isinstance(item, str))
    else:
        for record in files:
            for field in ("path", "oldPath", "newPath"):
                candidate = record.get(field)
                if isinstance(candidate, str) and (
                    candidate.casefold() == root.casefold()
                    or candidate.casefold().startswith((root + "/").casefold())
                ):
                    values.append(candidate)
    for value in values:
        canonical = _canonical_server_path(value)
        if canonical is None:
            continue
        aliases.add(canonical.casefold())
        if canonical.casefold() == root.casefold():
            continue
        prefix = root + "/"
        if canonical.casefold().startswith(prefix.casefold()):
            relative = canonical[len(prefix) :]
            aliases.add(relative.casefold())
            aliases.add(("a/" + relative).casefold())
            aliases.add(("b/" + relative).casefold())
    return aliases


def _file_matches(file_value: str, manifest: Mapping[str, Any], files: Sequence[Mapping[str, Any]]) -> bool:
    candidate = file_value.replace("\\", "/")
    if any(ord(character) < 32 or unicodedata.category(character) == "Cs" for character in candidate):
        return False
    canonical = _canonical_server_path(candidate)
    if canonical is None:
        stripped = candidate
        while stripped.startswith("./"):
            stripped = stripped[2:]
        if stripped.startswith("a/") or stripped.startswith("b/"):
            stripped = stripped[2:]
        root = manifest.get("reviewRoot")
        if not isinstance(root, str) or not stripped or stripped.startswith("/"):
            return False
        if any(part in ("", ".", "..") for part in stripped.split("/")):
            return False
        canonical = root.rstrip("/") + "/" + stripped
    aliases = _path_aliases(manifest, files)
    return candidate.casefold() in aliases or canonical.casefold() in aliases


def _validate_finding(finding: Any, index: int, manifest: Mapping[str, Any], files: Sequence[Mapping[str, Any]], ids: set[str]) -> list[str]:
    errors: list[str] = []
    label = f"findings[{index}]"
    if not _keys(finding, FINDING_KEYS, label, errors):
        return errors
    assert isinstance(finding, dict)
    identifier = finding["id"]
    if (
        not _text(identifier, f"{label}.id", errors, maximum=128, allow_empty=False)
        or not isinstance(identifier, str)
        or not _ID_RE.fullmatch(identifier)
    ):
        errors.append(f"{label}.id has an unsupported format")
    if isinstance(identifier, str):
        if identifier.casefold() in ids:
            errors.append(f"{label}.id is duplicated")
        ids.add(identifier.casefold())
    severity = finding["severity"]
    if severity not in SEVERITIES:
        errors.append(f"{label}.severity is unsupported")
    _text(finding["category"], f"{label}.category", errors, maximum=200, allow_empty=False)
    file_value = finding["file"]
    if _text(file_value, f"{label}.file", errors, maximum=1000, allow_empty=False, path=True):
        if not _file_matches(file_value, manifest, files):
            errors.append(f"{label}.file is not present in the normalized manifest")
    for field, maximum in (
        ("title", 1000),
        ("description", 12000),
        ("impact", 12000),
        ("recommendation", 12000),
    ):
        _text(finding[field], f"{label}.{field}", errors, maximum=maximum, allow_empty=field != "title")
    if not isinstance(finding["securityRelevant"], bool):
        errors.append(f"{label}.securityRelevant must be boolean")
    if finding["symbol"] is not None:
        _text(finding["symbol"], f"{label}.symbol", errors, maximum=512)
    for field in ("changeAnalysis", "securityBoundary", "attackScenario", "exploitability", "remediationExample"):
        _nullable_text(finding[field], f"{label}.{field}", errors)
    evidence = finding["evidence"]
    if _keys(evidence, EVIDENCE_KEYS, f"{label}.evidence", errors):
        assert isinstance(evidence, dict)
        _text(evidence["summary"], f"{label}.evidence.summary", errors, maximum=12000, allow_empty=False)
        _nullable_text(evidence["before"], f"{label}.evidence.before", errors)
        _nullable_text(evidence["after"], f"{label}.evidence.after", errors)
    steps = finding["verificationSteps"]
    if not isinstance(steps, list) or len(steps) > 50:
        errors.append(f"{label}.verificationSteps must contain at most 50 strings")
    else:
        for step_index, step in enumerate(steps, start=1):
            _text(step, f"{label}.verificationSteps[{step_index}]", errors, maximum=2000, allow_empty=False)
    standards = finding["standards"]
    if not isinstance(standards, list) or len(standards) > 50:
        errors.append(f"{label}.standards must contain at most 50 objects")
    else:
        standard_ids: set[str] = set()
        for standard_index, standard in enumerate(standards, start=1):
            standard_label = f"{label}.standards[{standard_index}]"
            if not _keys(standard, STANDARD_KEYS, standard_label, errors):
                continue
            assert isinstance(standard, dict)
            _text(standard["id"], f"{standard_label}.id", errors, maximum=128, allow_empty=False)
            _text(standard["name"], f"{standard_label}.name", errors, maximum=512, allow_empty=False)
            standard_id = standard["id"].casefold() if isinstance(standard["id"], str) else ""
            if standard_id in standard_ids:
                errors.append(f"{standard_label}.id is duplicated")
            standard_ids.add(standard_id)
    if finding["confidence"] not in CONFIDENCES:
        errors.append(f"{label}.confidence is unsupported")
    return errors


def validate_review(review: Any, manifest: Any, changeset: int) -> list[str]:
    """Return deterministic validation errors for a schema-v2 review.

    The function does not trust a JSON schema validator or the model's own
    claims.  It also checks every finding path against the generated TFVC
    manifest, including full server paths, review-relative paths and the
    ``a/``/``b/`` labels emitted by the diff helper.
    """

    errors: list[str] = []
    try:
        manifest_view, files = _manifest_view(manifest, changeset)
    except ContractError as exc:
        return [str(exc)]
    if not _keys(review, REVIEW_KEYS, "review", errors):
        return errors
    assert isinstance(review, dict)
    if not _is_int(review.get("schemaVersion")) or review.get("schemaVersion") != 2:
        errors.append("review.schemaVersion must be 2")
    if review.get("changeset") != changeset:
        errors.append("review.changeset does not match the requested changeset")
    _positive_int(review.get("changeset"), "review.changeset", errors)
    _text(review["summary"], "review.summary", errors, maximum=12000)
    limitations = review["limitations"]
    if not isinstance(limitations, list) or len(limitations) > MAX_LIMITATIONS:
        errors.append("review.limitations must contain at most 100 strings")
    elif any(not isinstance(item, str) for item in limitations):
        errors.append("review.limitations must contain only strings")
    else:
        for index, limitation in enumerate(limitations, start=1):
            _text(limitation, f"review.limitations[{index}]", errors, maximum=4000, allow_empty=False)
    findings = review["findings"]
    if not isinstance(findings, list) or len(findings) > MAX_REVIEW_FINDINGS:
        errors.append("review.findings must contain at most 500 objects")
    else:
        ids: set[str] = set()
        for index, finding in enumerate(findings, start=1):
            errors.extend(_validate_finding(finding, index, manifest_view, files, ids))
    return errors


def _sha256_reference(value: str | os.PathLike[str], label: str) -> str:
    text = os.fspath(value)
    if _HEX64_RE.fullmatch(text):
        return text
    path = Path(text)
    try:
        if not path.is_file():
            raise ContractError(f"{label} must be a file path or SHA-256 digest")
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > MAX_JSON_BYTES:
                    raise ContractError(f"{label} exceeds the 8 MiB hash bound")
                digest.update(block)
        return digest.hexdigest()
    except OSError as exc:
        raise ContractError(f"unable to hash {label}") from exc


def _object_sha256(value: Any) -> str:
    try:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ContractError("unable to hash in-memory contract") from exc
    if len(payload) > MAX_JSON_BYTES:
        raise ContractError("in-memory contract exceeds the 8 MiB hash bound")
    return hashlib.sha256(payload).hexdigest()


def _utc_now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def build_metadata(
    review: Mapping[str, Any],
    manifest: Mapping[str, Any],
    deployment: str,
    effort: str,
    cli_version: str,
    commit: str,
    schema: str | os.PathLike[str],
    template: str | os.PathLike[str],
    diff: str | os.PathLike[str],
    *,
    review_source: str | os.PathLike[str] | None = None,
    manifest_source: str | os.PathLike[str] | None = None,
    generated_at: str | None = None,
    report_status: str = "analysis-valid",
    final_task_status: str = "pending",
) -> dict[str, Any]:
    """Build authoritative metadata from already validated review inputs."""

    changeset = manifest.get("changeset")
    if not _is_int(changeset):
        raise ContractError("manifest changeset is invalid")
    errors = validate_review(review, manifest, changeset)
    if errors:
        raise ContractError("review is invalid: " + "; ".join(errors))
    if not isinstance(deployment, str) or not _DEPLOYMENT_RE.fullmatch(deployment):
        raise ContractError("deployment name is invalid")
    if effort not in REASONING_EFFORTS:
        raise ContractError("reasoning effort is invalid")
    if not isinstance(cli_version, str) or not cli_version or len(cli_version) > 256:
        raise ContractError("CLI version is invalid")
    if not isinstance(commit, str) or not _COMMIT_RE.fullmatch(commit):
        raise ContractError("helper commit must be a 40-character Git SHA")
    if report_status not in ("analysis-valid", "html-valid", "html-failed"):
        raise ContractError("report status is invalid")
    if final_task_status not in ("pending", "succeeded", "blocked", "failed"):
        raise ContractError("final task status is invalid")
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in review["findings"]:
        counts[finding["severity"]] += 1
    counts["limitations"] = len(review["limitations"])
    counts["totalFindings"] = len(review["findings"])
    if counts["limitations"]:
        security_decision = "manual-review-required"
    elif counts["critical"] or counts["high"]:
        security_decision = "fail"
    else:
        security_decision = "pass"
    derived_task_status = {
        "analysis-valid": "pending",
        "html-valid": "succeeded" if security_decision == "pass" else "blocked",
        "html-failed": "failed",
    }[report_status]
    if final_task_status != "pending" and final_task_status != derived_task_status:
        raise ContractError("final task status conflicts with report status and security decision")
    coverage = manifest.get("coverage")
    if not isinstance(coverage, dict):
        raise ContractError("manifest coverage is invalid")
    provenance = {
        "generatedAt": generated_at or _utc_now(),
        "helperCommit": commit,
        "helperVersion": manifest.get("helperVersion", ""),
        "apiVersion": manifest.get("apiVersion", ""),
        "cliVersion": cli_version,
        "deployment": deployment,
        "reasoningEffort": effort,
        "hashes": {
            "diff": _sha256_reference(diff, "diff"),
            "schema": _sha256_reference(schema, "schema"),
            "template": _sha256_reference(template, "template"),
            # The CLI supplies the exact staged bytes.  The in-memory fallback
            # keeps the importable helper useful to callers that already loaded
            # the contracts, while making that distinction deterministic.
            "review": _sha256_reference(review_source, "review")
            if review_source is not None
            else _object_sha256(review),
            "normalizedManifest": _sha256_reference(manifest_source, "normalized manifest")
            if manifest_source is not None
            else _object_sha256(manifest),
        },
    }
    return {
        "metaVersion": 1,
        "changeset": changeset,
        "previousChangeset": manifest.get("previousChangeset"),
        "reviewRoot": manifest.get("reviewRoot"),
        "counts": counts,
        "securityDecision": security_decision,
        "reportStatus": report_status,
        "pipelineGate": "pass"
        if security_decision == "pass" and report_status == "html-valid"
        else "fail",
        "finalTaskStatus": derived_task_status,
        "policy": {
            "blockingSeverities": ["critical", "high"],
            "limitationsBlock": True,
            "mediumAction": "warning",
            "lowAction": "informational",
            "infoAction": "informational",
        },
        "coverage": dict(coverage),
        "provenance": provenance,
        "formats": {
            "reviewSchema": 2,
            "metadataSchema": 1,
            "htmlContract": 2,
        },
    }


def _entity_text(value: Any) -> str:
    """Encode untrusted prose so Markdown cannot create active markup."""

    text = str(value)
    return "".join(
        character if character in ("\n", "\r", "\t") else f"&#{ord(character)};"
        for character in text
    )


def _inline(value: Any) -> str:
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    text = " ".join(line.strip() for line in text.split("\n"))
    return _entity_text(text)


def _blockquote(value: Any) -> str:
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join("> " + _entity_text(line) for line in text.split("\n"))


def _code_block(value: Any) -> str:
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text}\n{fence}"


def render_markdown(review: Mapping[str, Any], metadata: Mapping[str, Any]) -> str:
    """Render a deterministic Markdown summary from validated facts."""

    counts = metadata["counts"]
    lines = [
        f"# Codex review — TFVC C{metadata['changeset']}",
        "",
        f"**Security decision:** {_inline(metadata['securityDecision'])}  ",
        f"**Report status:** {_inline(metadata['reportStatus'])}  ",
        f"**Pipeline gate:** {_inline(metadata['pipelineGate'])}",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity in SEVERITIES:
        lines.append(f"| {severity.title()} | {counts[severity]} |")
    lines.append(f"| Limitations | {counts['limitations']} |")
    lines.extend(
        [
            "",
            "## Summary",
            "",
            _blockquote(review["summary"]),
            "",
            "## Coverage",
            "",
            f"- Review root: {_inline(metadata['reviewRoot'])}",
            f"- Enumerated changes: {metadata['coverage']['enumeratedChanges']}",
            f"- In-scope changes: {metadata['coverage']['inScopeChanges']}",
            f"- Text diff files: {metadata['coverage']['filesWithTextDiff']}",
            f"- Diff size: {metadata['coverage']['diffBytes']} bytes / {metadata['coverage']['diffLines']} lines",
            "",
            "## Findings",
            "",
        ]
    )
    ordered = sorted(
        enumerate(review["findings"]),
        key=lambda item: (SEVERITIES.index(item[1]["severity"]), item[0]),
    )
    if not ordered:
        lines.append("No findings reported.")
        lines.append("")
    for _, finding in ordered:
        lines.extend(
            [
                f"### [{finding['severity'].upper()}] {_inline(finding['id'])}: {_inline(finding['title'])}",
                "",
                f"- File: {_inline(finding['file'])}",
                f"- Category: {_inline(finding['category'])}",
                f"- Confidence: {_inline(finding['confidence'])}",
                f"- Security relevant: `{str(finding['securityRelevant']).lower()}`",
                "",
                "**Description**",
                "",
                _blockquote(finding["description"]),
                "",
                *( [f"- Symbol: {_inline(finding['symbol'])}", ""] if finding["symbol"] is not None else [] ),
                "**Change analysis**",
                "",
                _blockquote(finding["changeAnalysis"] if finding["changeAnalysis"] is not None else "Not supplied."),
                "",
                "**Impact**",
                "",
                _blockquote(finding["impact"]),
                "",
                "**Evidence summary**",
                "",
                _blockquote(finding["evidence"]["summary"]),
                "",
            ]
        )
        if finding["evidence"]["before"] is not None:
            lines.extend(["**Before**", "", _code_block(finding["evidence"]["before"]), ""])
        if finding["evidence"]["after"] is not None:
            lines.extend(["**After**", "", _code_block(finding["evidence"]["after"]), ""])
        for label, field in (
            ("Security boundary", "securityBoundary"),
            ("Attack scenario", "attackScenario"),
            ("Exploitability", "exploitability"),
            ("Recommendation", "recommendation"),
            ("Remediation example", "remediationExample"),
        ):
            value = finding[field]
            if value is not None:
                lines.extend([f"**{label}**", "", _blockquote(value), ""])
        lines.extend(["**Verification steps**", ""])
        for step in finding["verificationSteps"]:
            lines.append(f"1. {_inline(step)}")
        lines.append("")
        if finding["standards"]:
            lines.extend(["**Standards**", ""])
            for standard in finding["standards"]:
                lines.append(f"- {_inline(standard['id'])} — {_inline(standard['name'])}")
            lines.append("")
    lines.extend(["## Limitations", ""])
    if review["limitations"]:
        lines.extend(f"- {_inline(item)}" for item in review["limitations"])
    else:
        lines.append("None reported.")
    lines.extend(
        [
            "",
            "## Audit metadata",
            "",
            f"- Helper commit: {_inline(metadata['provenance']['helperCommit'])}",
            f"- Helper version: {_inline(metadata['provenance']['helperVersion'])}",
            f"- Codex CLI: {_inline(metadata['provenance']['cliVersion'])}",
            f"- Deployment: {_inline(metadata['provenance']['deployment'])}",
            f"- Reasoning effort: {_inline(metadata['provenance']['reasoningEffort'])}",
            f"- Generated at: {_inline(metadata['provenance']['generatedAt'])}",
            "",
        ]
    )
    return "\n".join(lines)


def _positive_cli_changeset(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("changeset must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("changeset must be a positive integer")
    return parsed


def _load_and_normalize(path: str, changeset: int) -> dict[str, Any]:
    raw = load_json(path)
    return normalize_manifest(raw, changeset)


def _cmd_normalize(args: argparse.Namespace) -> None:
    _write_json(args.output, _load_and_normalize(args.input, args.changeset))


def _cmd_validate(args: argparse.Namespace) -> None:
    review = load_json(args.input)
    manifest = load_json(args.manifest)
    errors = validate_review(review, manifest, args.changeset)
    if errors:
        raise ContractError("review validation failed: " + "; ".join(errors))
    if args.output:
        _write_json(args.output, review)


def _cmd_metadata(args: argparse.Namespace) -> None:
    review = load_json(args.review)
    manifest = load_json(args.manifest)
    normalized = _normalized_manifest(manifest, args.changeset)
    metadata = build_metadata(
        review,
        normalized,
        args.deployment,
        args.effort,
        args.cli_version,
        args.commit,
        args.schema,
        args.template,
        args.diff,
        review_source=args.review,
        manifest_source=args.manifest,
        report_status=args.report_status,
    )
    _write_json(args.output, metadata)


def _cmd_markdown(args: argparse.Namespace) -> None:
    review = load_json(args.review)
    metadata = load_json(args.meta)
    if not isinstance(review, dict) or not isinstance(metadata, dict):
        raise ContractError("review and metadata must be JSON objects")
    _write_text(args.output, render_markdown(review, metadata))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    normalize = commands.add_parser("normalize-manifest")
    normalize.add_argument("--input", required=True)
    normalize.add_argument("--changeset", required=True, type=_positive_cli_changeset)
    normalize.add_argument("--output", required=True)
    normalize.set_defaults(handler=_cmd_normalize)

    validate = commands.add_parser("validate-review")
    validate.add_argument("--input", required=True)
    validate.add_argument("--manifest", required=True)
    validate.add_argument("--changeset", required=True, type=_positive_cli_changeset)
    validate.add_argument("--output")
    validate.set_defaults(handler=_cmd_validate)

    metadata = commands.add_parser("metadata")
    metadata.add_argument("--review", required=True)
    metadata.add_argument("--manifest", required=True)
    metadata.add_argument("--changeset", required=True, type=_positive_cli_changeset)
    metadata.add_argument("--deployment", required=True)
    metadata.add_argument("--effort", required=True, choices=REASONING_EFFORTS)
    metadata.add_argument("--cli-version", required=True)
    metadata.add_argument("--commit", required=True)
    metadata.add_argument("--schema", required=True)
    metadata.add_argument("--template", required=True)
    metadata.add_argument("--diff", required=True)
    metadata.add_argument(
        "--report-status",
        choices=("analysis-valid", "html-valid", "html-failed"),
        default="analysis-valid",
    )
    metadata.add_argument("--output", required=True)
    metadata.set_defaults(handler=_cmd_metadata)

    markdown = commands.add_parser("markdown")
    markdown.add_argument("--review", required=True)
    markdown.add_argument("--meta", required=True)
    markdown.add_argument("--output", required=True)
    markdown.set_defaults(handler=_cmd_markdown)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    if sys.version_info < (3, 10):
        print("review-data: Python 3.10 or newer is required", file=sys.stderr)
        return 1
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        args.handler(args)
    except ContractError as exc:
        print(f"review-data: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
