# TFVC review data contracts

The normalized manifest adapter is based on the pinned public helper commit
`996773b9fb76f55a643eb7badccd1c4da24b3cd0`, helper version `tfvc-rest-diff-1.2`.
The source was inspected through the raw GitHub endpoint before this contract
was implemented:

<https://raw.githubusercontent.com/iqinfra/azdophelpers/996773b9fb76f55a643eb7badccd1c4da24b3cd0/tfvc/generate-changeset-diff.sh>

The helper's manifest is schema version 1. It contains a `coverage` object and
an in-scope `changes` array. Its `index` is the position in the complete
enumeration, so an out-of-scope item can leave a gap in the indexes retained in
the manifest. The adapter therefore requires indexes to be unique, strictly
increasing, and no greater than `coverage.enumeratedChanges`; it does not
require them to start at one or be contiguous.

The normalized manifest keeps the bounded coverage counts and the file records,
but intentionally omits `changesetMetadata.comment`, which is raw
source-controlled text and is not needed by the HTML contract. `reviewPaths`
contains only paths that were in scope and could have been fetched for review.
For a delete, `oldPath` is retained. For an add, `newPath` is retained. For a
rename, an in-scope old or new path is retained; an out-of-scope side is kept
in the file record for audit context but is not accepted as a finding path.
The validator accepts the full TFVC server path and the diff helper's relative
`a/` and `b/` labels when matching finding files.

`review-v2.schema.json` is the model-output contract. It retains the original
finding fields and adds structured change analysis, security boundary, attack
scenario, exploitability, before/after evidence, remediation example,
verification steps, standards, and an explicit `securityRelevant` value.
`report-meta-v1.schema.json` is generated outside model control and records the
deterministic decision, coverage, hashes, report status, and gate policy.
