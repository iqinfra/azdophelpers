# Security review HTML contract

This contract describes the input boundary and the exact output shape for the
second Codex presentation pass. It is deliberately narrow so that an
independent validator can compare the generated document with the validated
facts.

## Inputs

The prompt supplies three JSON values and this skill's template:

1. `review.json` is schema version 2. Its top-level keys are exactly
   `schemaVersion`, `changeset`, `summary`, `findings`, and `limitations`.
2. `report-meta.json` is metadata version 1. Its top-level keys are exactly
   `metaVersion`, `changeset`, `previousChangeset`, `reviewRoot`, `counts`,
   `securityDecision`, `reportStatus`, `pipelineGate`, `finalTaskStatus`,
   `policy`, `coverage`, `provenance`, and `formats`.
3. `review-manifest.json` is the trusted normalized TFVC manifest. It contains
   `schemaVersion`, `normalizationVersion`, `helperVersion`, `apiVersion`,
   `changeset`, `previousChangeset`, `reviewRoot`, `coverage`, `files`, and
   `reviewPaths`. The `files` records are the
   changed-file inventory; the original raw helper manifest is not supplied to
   the presentation pass.

The validator is authoritative about these interfaces. A missing value is
represented by `null` only where the JSON schema permits it, or by an empty
array where the schema defines a collection. Do not invent text to fill an
unknown value.

The caller may place a `report-scaffold.html` beside these inputs. The trusted
renderer creates this scaffold from the validated values and the pinned
stylesheet before the presentation call. It is a formatting reference derived
from the same facts, not a second fact source or a fallback report. A model
candidate may reproduce it exactly, and the independent validator still must
validate the candidate. A retry diagnostic may identify only a structural
path/type; it must never contain candidate text or input values.

The caller may also place `source-locations.json` beside the inputs. This
optional artifact is produced by the trusted helper from the validated review
and the unified diff. Its `reviewSha256` and `diffSha256` must match
`provenance.hashes.review` and `provenance.hashes.diff`, its finding IDs must
match the review exactly, and each non-null range must contain a TFVC path and
positive ordered source lines. The presentation validator checks those hashes,
IDs, paths, and ranges before rendering. It is the only source for the fixed
`Source location (before)` and `Source location (after)` values. A null range
is rendered as `Unavailable in supplied diff`.

`counts` contains `critical`, `high`, `medium`, `low`, `info`, `limitations`,
and `totalFindings`. `policy` contains the five fixed policy fields. The
`provenance.hashes` object contains `diff`, `schema`, `template`, `review`,
and `normalizedManifest`; all are lowercase SHA-256 values. `formats` contains
`reviewSchema=2`, `metadataSchema=1`, and `htmlContract=2`.

Each review finding has these fields:

```text
id, securityRelevant, severity, category, file, title, description, impact,
symbol, changeAnalysis, securityBoundary, attackScenario, exploitability,
evidence, recommendation, remediationExample, verificationSteps, standards,
confidence
```

`evidence` is an object with `summary`, `before`, and `after`; the latter two
may be `null`. `verificationSteps` is an array of strings. `standards` is an
array of `{id, name}` objects. `symbol`, `attackScenario`, `exploitability`,
and `remediationExample` may be `null`. All other finding fields are present.
Finding `file` values may use a full TFVC server path, a review-relative path,
or the `a/`/`b/` diff label. The validator resolves those aliases against
`reviewPaths`; the displayed value remains exactly the supplied value.

The normalized manifest inventory includes the fields emitted by the TFVC
helper for each file: `index`, `changeType`, `classification`, `path`,
`sourceServerItem`, `oldPath`, `newPath`, `oldSize`, `newSize`, `oldHash`,
`newHash`, `reviewable`, `textDiff`, and `reason`. Null path/hash/reason values
are displayed as `None`; this is a fixed presentation label, not a finding.

## Document boundary

The output is one standalone HTML document:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; img-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Codex security review · TFVC C{changeset}</title>
    <style id="report-style">{exact stylesheet from the template}</style>
  </head>
  <body>
    <main id="report" data-report-kind="codex">
      ...
    </main>
  </body>
</html>
```

The validator accepts normal HTML serialization differences such as attribute
quote style, attribute order, optional end tags, and indentation. It compares
the parsed element tree, fixed attributes, stylesheet, and meaningful text
against the document reconstructed from the inputs. Whitespace used only to
indent elements is ignored; whitespace inside supplied text fields is kept.

Allowed elements are `html`, `head`, `meta`, `title`, `style`, `body`, `main`,
`header`, `section`, `article`, `h1`, `h2`, `h3`, `p`, `div`, `span`, `dl`,
`dt`, `dd`, `table`, `thead`, `tbody`, `tr`, `th`, `td`, `a`, `ul`, `li`,
`pre`, `code`, and `footer`. Attributes are limited to the fixed `id`, `class`,
`lang`, `charset`, `name`, `content`, `http-equiv`, and `href` values used by
the template and scaffold. `href` values may only be local `#finding-N`
anchors. No script, event attribute, form, frame, object, embed, SVG, MathML,
base element, external URL, data URL, refresh directive, or inline `style`
attribute is allowed.

## Required sections

The `main` element contains these sections in order:

1. `report-header`: changeset, security decision, report status, counts, and
   the principal metadata values.
2. `coverage`: the complete manifest coverage object.
3. `changed-files`: a `h2` followed by one `article.file-card` for every
   `manifest.files` item, in manifest order. Each card contains an `h3` with
   `Change {index}: {path}` and a `dl` with `dt`/`dd` pairs in this exact order:
   `index`, `changeType`, `classification`, `path`, `sourceServerItem`,
   `oldPath`, `newPath`, `oldSize`, `newSize`, `oldHash`, `newHash`,
   `reviewable`, `textDiff`, `reason`.
4. `summary`: an `h2` followed by one `pre` containing the review summary
   exactly as supplied.
5. `findings-overview`: an `h2`, then a `div.table-wrap` containing a table
   with headers `ID`, `Severity`, `Security`, `Finding`, `File`, and
   `Confidence`, in that order, when findings are present. Each row links its
   ID to its detail anchor. When there are no findings, use a fixed `p.empty`
   containing `No findings reported.` instead of the table wrapper.
6. One `article.finding-card` per finding, using `id="finding-N"` where `N` is
   the zero-based position after severity sorting.
7. `limitations`: an `h2` followed by a `ul.list-plain` with one `li.list-item`
   per limitation, or a fixed `p.empty` containing `None reported.`.
8. `gate-policy`: an `h2` followed by a `dl` containing `Blocking severities`,
   `Limitations block`, `Medium action`, `Low action`, `Info action`,
   `Security decision`, `Pipeline gate`, and `Final task status`, in that order.
9. `audit-metadata`: an `h2` followed by a `dl` containing `Meta version`,
   `Report status`, `Report format`, `Review schema`, `Metadata schema`,
   `Generated at`, `Helper commit`, `Helper version`, `API version`, `Codex CLI`,
   `Diff SHA-256`, `Schema SHA-256`, `Template SHA-256`, `Review SHA-256`, and
   `Normalized manifest SHA-256`, in that order.
10. `report-footer`: one fixed text line containing the three format versions,
    generated time, and helper commit.

The `report-header` starts with `p.eyebrow`, `h1`, and a `p` containing the
security-decision badge and report-status badge. It then contains a `dl` with
`Review root`, `Previous changeset`, `Deployment`, `Reasoning effort`, and
`Total findings`, followed by a `div.metrics` with six metric cards in severity
order plus limitations. The `coverage` section contains the eight coverage
fields, a `Manifest metadata` `dl` with all seven normalized-manifest identity
fields, and a `Review paths` list in the exact manifest order. Each metric card
is a `div.metric` containing a `span` label and a `strong` number; its class is
the corresponding severity or `fail`/`pass` for limitations.

The fixed list algorithm is: an empty array becomes `p.empty` with the exact
text `None`; a non-empty array becomes `ul.list-plain`, with one `li.list-item`
per item in input order. Nullable scalar fields use a `p.empty` with exact text
`None`; non-null detail prose uses `pre` with one artificial leading LF before
the supplied text so HTML5's pre-processing preserves a supplied leading LF.
The summary uses the same `pre` sentinel. Category, security-relevant,
confidence, and non-null symbol values are ordinary scalar text nodes in their
`dd`; nullable symbol uses the fixed `p.empty`. All other finding detail prose
uses the `pre`/`p.empty` rule. All ordinary `dl` values use one `dt` followed by
one `dd` for each label/value pair.

Each finding detail card starts with a severity badge, an `h2` containing
`{id} · {title}`, and a file metadata paragraph. Its `dl` then contains the
following labels in order: `Category`, `Security relevant`, `Confidence`, `Symbol`,
`Description`, `Change analysis`, `Security boundary`, `Attack scenario`,
`Exploitability`, `Impact`, `Evidence summary`, `Evidence before`,
`Evidence after`, `Recommendation`, `Remediation example`, `Verification
steps`, and `Standards`. Nullable values use the fixed `None` paragraph;
verification steps and standards use the fixed list rendering. Standards are
rendered as `{id} — {name}`.

The file metadata paragraph and the labeled evidence fields are the source of
truth for a finding's file and code context. The optional source-location map is
the source of truth for diff-grounded before/after line ranges; preserve its
exact path and range. This presentation pass has no diff and therefore cannot
create a source line, range, snippet, impact, recommendation, remediation, or
verification step. If no map or range is available, render
`Unavailable in supplied diff` and keep the supplied path and exact evidence
text.

The fixed fallback renderer uses the same structure and stylesheet, with
`data-report-kind="fallback"`, a `fallback` report-status badge class, and a
visible status banner stating that it is a deterministic fallback. A fallback
is an operational artifact after a failed Codex presentation/validation stage;
it must never be described as a successful AI-generated report.

## Content rules

Escape text as text, preserve line endings as LF, and never interpret source
or finding strings as markup. Keep the complete supplied strings; do not
truncate them. Do not create prose that is absent from the input. Do not use
CSS to hide or collapse supplied findings. The fixed stylesheet is the only
stylesheet permitted.
