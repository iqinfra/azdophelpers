#!/usr/bin/env python3
"""Derive source line ranges from validated review evidence and a unified diff.

The analysis model does not write locations.  This module uses the exact
``evidence.before`` and ``evidence.after`` strings from the validated review,
matches them as complete source lines inside the corresponding ``diff -u``
hunk side, and emits a location only when there is exactly one match.  An
unmatched or ambiguous excerpt remains ``null``; no source line is inferred.

The output is a separate artifact so the existing model review contract stays
backward compatible.  It is intentionally standard-library-only and bounded
so it can run in the same isolated Python environment as ``review_data.py``.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


MAX_BYTES = 8 * 1024 * 1024
MAX_LOCATIONS = 500
MAX_PATH_LENGTH = 2000
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>[0-9]+)(?:,(?P<old_count>[0-9]+))? "
    r"\+(?P<new_start>[0-9]+)(?:,(?P<new_count>[0-9]+))? @@(?: .*)?$"
)


class LocationError(ValueError):
    """Raised for malformed location inputs or output."""


@dataclass(frozen=True)
class _DiffLine:
    text: str
    number: int


@dataclass(frozen=True)
class _Hunk:
    old_label: str
    new_label: str
    old_lines: tuple[_DiffLine, ...]
    new_lines: tuple[_DiffLine, ...]


@dataclass(frozen=True)
class _FileDiff:
    old_label: str
    new_label: str
    hunks: tuple[_Hunk, ...]


@dataclass(frozen=True)
class _Match:
    path: str
    start_line: int
    end_line: int


def _normalize_newlines(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _read_bounded(path: str | Path) -> bytes:
    source = Path(path)
    try:
        with source.open("rb") as handle:
            data = handle.read(MAX_BYTES + 1)
    except OSError as exc:
        raise LocationError(f"unable to read {source.name}") from exc
    if len(data) > MAX_BYTES:
        raise LocationError(f"{source.name} exceeds the 8 MiB bound")
    return data


def _read_json(path: str | Path) -> Any:
    raw = _read_bounded(path)

    def duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise LocationError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise LocationError(f"non-finite JSON number: {value}")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=duplicate_keys,
            parse_constant=reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise LocationError("JSON input is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise LocationError("JSON input is malformed") from exc


def _sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    try:
        with Path(path).open("rb") as handle:
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
    except OSError as exc:
        raise LocationError(f"unable to hash {Path(path).name}") from exc
    return digest.hexdigest()


def _label_relative(label: str) -> str | None:
    """Return a normalized relative path for a diff label."""

    value = label.replace("\\", "/")
    if value == "/dev/null":
        return None
    if value.startswith("a/") or value.startswith("b/"):
        value = value[2:]
    if not value or value.startswith("/") or "\x00" in value:
        return None
    if any(part in ("", ".", "..") for part in value.split("/")):
        return None
    return value


def _root_relative(path: str, root: str) -> str | None:
    """Map a finding path to the relative path used by diff labels."""

    value = path.replace("\\", "/")
    if value.startswith("a/") or value.startswith("b/"):
        value = value[2:]
    elif value.startswith("$/"):
        prefix = root.rstrip("/") + "/"
        if value.casefold().startswith(prefix.casefold()):
            value = value[len(prefix) :]
        else:
            return None
    while value.startswith("./"):
        value = value[2:]
    if not value or value.startswith("/") or "\x00" in value:
        return None
    if any(part in ("", ".", "..") for part in value.split("/")):
        return None
    return value


def _display_path(label: str, root: str) -> str:
    """Use a full TFVC path in the artifact while retaining side identity."""

    relative = _label_relative(label)
    if relative is None:
        return label
    return root.rstrip("/") + "/" + relative


def _parse_hunk(lines: Sequence[str], index: int, old_label: str, new_label: str) -> tuple[_Hunk, int]:
    match = _HUNK_RE.fullmatch(lines[index])
    if match is None:
        raise LocationError("malformed unified diff hunk header")
    old_start = int(match.group("old_start"))
    new_start = int(match.group("new_start"))
    old_count = int(match.group("old_count") or "1")
    new_count = int(match.group("new_count") or "1")
    old_seen = 0
    new_seen = 0
    old_number = old_start
    new_number = new_start
    old_lines: list[_DiffLine] = []
    new_lines: list[_DiffLine] = []
    cursor = index + 1

    while old_seen < old_count or new_seen < new_count:
        if cursor >= len(lines):
            raise LocationError("unclosed unified diff hunk")
        line = lines[cursor]
        cursor += 1
        # GNU diff writes this marker after a side without a final newline.
        if line == r"\ No newline at end of file":
            continue
        if not line or line[0] not in " +-":
            raise LocationError("malformed unified diff hunk line")
        prefix = line[0]
        text = line[1:]
        if prefix == " ":
            if old_seen >= old_count or new_seen >= new_count:
                raise LocationError("unified diff hunk count mismatch")
            old_lines.append(_DiffLine(text, old_number))
            new_lines.append(_DiffLine(text, new_number))
            old_seen += 1
            new_seen += 1
            old_number += 1
            new_number += 1
        elif prefix == "-":
            if old_seen >= old_count:
                raise LocationError("unified diff hunk count mismatch")
            old_lines.append(_DiffLine(text, old_number))
            old_seen += 1
            old_number += 1
        else:
            if new_seen >= new_count:
                raise LocationError("unified diff hunk count mismatch")
            new_lines.append(_DiffLine(text, new_number))
            new_seen += 1
            new_number += 1

    return _Hunk(old_label, new_label, tuple(old_lines), tuple(new_lines)), cursor


def parse_unified_diff(data: bytes) -> tuple[_FileDiff, ...]:
    """Parse ``diff -u`` output and retain only hunk line data."""

    try:
        text = _normalize_newlines(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise LocationError("unified diff is not UTF-8") from exc
    lines = text.split("\n")
    sections: list[_FileDiff] = []
    index = 0
    while index + 1 < len(lines):
        if not (lines[index].startswith("--- ") and lines[index + 1].startswith("+++ ")):
            index += 1
            continue
        old_label = lines[index][4:]
        new_label = lines[index + 1][4:]
        index += 2
        hunks: list[_Hunk] = []
        while index < len(lines):
            if lines[index].startswith("--- ") and index + 1 < len(lines) and lines[index + 1].startswith("+++ "):
                break
            if lines[index].startswith("@@ "):
                hunk, index = _parse_hunk(lines, index, old_label, new_label)
                hunks.append(hunk)
            else:
                index += 1
        sections.append(_FileDiff(old_label, new_label, tuple(hunks)))
    return tuple(sections)


def _snippet_lines(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = _normalize_newlines(value)
    lines = tuple(normalized.splitlines())
    return lines or None


def _matches(
    sections: Sequence[_FileDiff],
    relative_path: str,
    side: str,
    snippet: tuple[str, ...] | None,
    root: str,
) -> tuple[_Match, ...]:
    if snippet is None:
        return ()
    expected = relative_path.casefold()
    matches: list[_Match] = []
    for section in sections:
        label = section.old_label if side == "before" else section.new_label
        if (_label_relative(label) or "").casefold() != expected:
            continue
        for hunk in section.hunks:
            source_lines = hunk.old_lines if side == "before" else hunk.new_lines
            if len(snippet) > len(source_lines):
                continue
            for start in range(len(source_lines) - len(snippet) + 1):
                candidate = source_lines[start : start + len(snippet)]
                if tuple(item.text for item in candidate) != snippet:
                    continue
                matches.append(
                    _Match(
                        _display_path(label, root),
                        candidate[0].number,
                        candidate[-1].number,
                    )
                )
    # A duplicate hunk can expose the same range more than once in malformed
    # input; uniqueness here is about distinct source locations.
    return tuple(dict.fromkeys(matches))


def _nullable_range(match: _Match | None) -> dict[str, Any] | None:
    if match is None:
        return None
    return {
        "path": match.path,
        "startLine": match.start_line,
        "endLine": match.end_line,
    }


def _location_for_finding(
    finding: Mapping[str, Any],
    sections: Sequence[_FileDiff],
    root: str,
) -> dict[str, Any]:
    file_value = finding.get("file")
    relative = _root_relative(file_value, root) if isinstance(file_value, str) else None
    evidence = finding.get("evidence")
    if relative is None or not isinstance(evidence, Mapping):
        return {"before": None, "after": None}
    result: dict[str, Any] = {}
    for field, side in (("before", "before"), ("after", "after")):
        candidates = _matches(
            sections,
            relative,
            side,
            _snippet_lines(evidence.get(field)),
            root,
        )
        result[field] = _nullable_range(candidates[0]) if len(candidates) == 1 else None
    return result


def _validate_hash(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        errors.append(f"{label} must be a lowercase SHA-256 digest")


def _validate_range(value: Any, label: str, errors: list[str]) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object or null")
        return
    expected = {"path", "startLine", "endLine"}
    actual = set(value)
    if actual != expected:
        errors.append(f"{label} must contain exactly path, startLine, endLine")
        return
    path = value["path"]
    if (
        not isinstance(path, str)
        or not path.startswith("$/")
        or len(path) > MAX_PATH_LENGTH
        or any(ord(char) < 32 or ord(char) == 127 for char in path)
    ):
        errors.append(f"{label}.path is invalid")
    start = value["startLine"]
    end = value["endLine"]
    if not isinstance(start, int) or isinstance(start, bool) or start < 1:
        errors.append(f"{label}.startLine must be a positive integer")
    if not isinstance(end, int) or isinstance(end, bool) or end < 1:
        errors.append(f"{label}.endLine must be a positive integer")
    if isinstance(start, int) and not isinstance(start, bool) and isinstance(end, int) and not isinstance(end, bool):
        if start > end:
            errors.append(f"{label} has a reversed line range")


def validate_source_locations(
    value: Any,
    *,
    finding_ids: Sequence[str] | None = None,
    changeset: int | None = None,
) -> list[str]:
    """Validate the separate source-location artifact."""

    errors: list[str] = []
    if not isinstance(value, dict):
        return ["source locations must be an object"]
    expected = {"schemaVersion", "changeset", "reviewSha256", "diffSha256", "locations"}
    if set(value) != expected:
        errors.append("source locations have unsupported or missing fields")
        return errors
    if value["schemaVersion"] != 1 or isinstance(value["schemaVersion"], bool):
        errors.append("source locations schemaVersion must be 1")
    if not isinstance(value["changeset"], int) or isinstance(value["changeset"], bool) or value["changeset"] < 1:
        errors.append("source locations changeset must be a positive integer")
    elif changeset is not None and value["changeset"] != changeset:
        errors.append("source locations changeset does not match")
    _validate_hash(value["reviewSha256"], "source locations reviewSha256", errors)
    _validate_hash(value["diffSha256"], "source locations diffSha256", errors)
    locations = value["locations"]
    if not isinstance(locations, dict) or len(locations) > MAX_LOCATIONS:
        errors.append("source locations.locations must contain at most 500 entries")
    else:
        for identifier, location in locations.items():
            if not isinstance(identifier, str) or _ID_RE.fullmatch(identifier) is None:
                errors.append(f"source location id {identifier!r} is invalid")
                continue
            if not isinstance(location, dict) or set(location) != {"before", "after"}:
                errors.append(f"source location {identifier} must contain before and after")
                continue
            _validate_range(location["before"], f"source location {identifier}.before", errors)
            _validate_range(location["after"], f"source location {identifier}.after", errors)
    if finding_ids is not None and isinstance(locations, dict):
        expected_ids = set(finding_ids)
        actual_ids = set(locations)
        if actual_ids != expected_ids:
            errors.append("source locations IDs do not match review finding IDs")
    return errors


def build_source_locations(review: Mapping[str, Any], manifest: Mapping[str, Any], diff: bytes, review_sha256: str, diff_sha256: str) -> dict[str, Any]:
    """Build an artifact from already validated review and manifest values."""

    changeset = review.get("changeset")
    if not isinstance(changeset, int) or isinstance(changeset, bool) or changeset < 1:
        raise LocationError("review changeset is invalid")
    if manifest.get("changeset") != changeset:
        raise LocationError("manifest changeset does not match review")
    root = manifest.get("reviewRoot")
    if not isinstance(root, str) or not root.startswith("$/"):
        raise LocationError("manifest reviewRoot is invalid")
    findings = review.get("findings")
    if not isinstance(findings, list) or len(findings) > MAX_LOCATIONS:
        raise LocationError("review findings are invalid")
    if not _HASH_RE.fullmatch(review_sha256) or not _HASH_RE.fullmatch(diff_sha256):
        raise LocationError("source-location hashes are invalid")
    # A location map is an optional presentation aid.  If the source diff is
    # not parseable, preserve the report and leave every location unknown; the
    # analysis and security gate must not depend on best-effort line mapping.
    try:
        sections = parse_unified_diff(diff)
    except LocationError:
        sections = ()
    locations: dict[str, Any] = {}
    ids: list[str] = []
    seen_ids: set[str] = set()
    for finding in findings:
        if not isinstance(finding, Mapping) or not isinstance(finding.get("id"), str):
            raise LocationError("review finding ID is invalid")
        identifier = finding["id"]
        folded_identifier = identifier.casefold()
        if _ID_RE.fullmatch(identifier) is None or folded_identifier in seen_ids:
            raise LocationError("review finding IDs are invalid or duplicated")
        seen_ids.add(folded_identifier)
        ids.append(identifier)
        locations[identifier] = _location_for_finding(finding, sections, root)
    result = {
        "schemaVersion": 1,
        "changeset": changeset,
        "reviewSha256": review_sha256,
        "diffSha256": diff_sha256,
        "locations": locations,
    }
    errors = validate_source_locations(result, finding_ids=ids, changeset=changeset)
    if errors:
        raise LocationError("; ".join(errors))
    return result


def _write_json(path: str | Path, value: Mapping[str, Any]) -> None:
    destination = Path(path)
    encoded = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False) + "\n").encode("utf-8")
    if len(encoded) > MAX_BYTES:
        raise LocationError("source-location output exceeds the 8 MiB bound")
    temporary = destination.with_name(f".{destination.name}.tmp.{__import__('os').getpid()}")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_bytes(encoded)
        __import__('os').chmod(temporary, 0o600)
        __import__('os').replace(temporary, destination)
    except OSError as exc:
        raise LocationError("unable to write source-location output") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--diff", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        review = _read_json(args.review)
        manifest = _read_json(args.manifest)
        if not isinstance(review, Mapping) or not isinstance(manifest, Mapping):
            raise LocationError("review and manifest must be JSON objects")
        diff = _read_bounded(args.diff)
        result = build_source_locations(
            review,
            manifest,
            diff,
            _sha256(args.review),
            _sha256(args.diff),
        )
        _write_json(args.output, result)
    except LocationError as exc:
        print(f"source_locations: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
