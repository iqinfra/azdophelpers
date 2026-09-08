# TFVC security review release checklist

This package is released as one pinned unit. The helper, schema files, data
validators, HTML skill, template, and requirements must come from the same
committed revision. The pipeline launcher must use the full commit SHA and the
SHA-256 values generated for that revision; do not combine a new helper with an
older launcher pin.

## Prepare the package

From the workspace, review the files below and run the mocked integration suite
after the package is complete:

```text
outputs/tfvc/run-codex-review.sh
outputs/tfvc/schemas/
outputs/tfvc/scripts/
outputs/tfvc/skills/security-review-html/
outputs/tfvc/requirements.txt
outputs/tfvc/tests/test_pipeline.py
```

Install the exact versions in `outputs/tfvc/requirements.txt` into the Python
runtime used by the agent. The runtime must be available before the pipeline
starts; the review task must not install packages from diff content or from a
model output.

Refresh the local resource pins only after all package files are final:

```bash
python3 outputs/prepare-release.py
python3 -m unittest discover -s outputs/tfvc/tests -v
bash -n outputs/tfvc/run-codex-review.sh
bash -n outputs/azure-devops-launcher.sh
```

`prepare-release.py` writes `outputs/package-sha256.txt` as a release record,
refreshes the helper copy at `outputs/run-codex-review.sh`, and clears the
launcher commit selection until it is bound to a verified commit. Review the
resulting pin block and make sure it is nonempty before committing.

## Bind the release to a Git commit

Copy the complete `outputs/tfvc/` package into the trusted
`iqinfra/azdophelpers` checkout under `tfvc/`. Include the refreshed helper and
commit the package together. Record the resulting 40-character commit SHA.

Then verify the committed bytes and prepare the launcher pins:

```bash
python3 outputs/prepare-release.py \
  --repo /path/to/azdophelpers \
  --commit FULL_40_CHARACTER_COMMIT_SHA
bash -n outputs/azure-devops-launcher.sh
```

The verification mode reads every packaged resource and both helper scripts
from that commit before updating the launcher. If it reports that a committed
file differs, stop and commit the refreshed package before retrying. Copy the
resulting launcher text into the Classic build Bash action or into the
controlled pipeline source. Confirm that `HELPER_COMMIT` is the new full SHA
and that neither helper digest is left from an earlier release.

Keep the release record with the commit SHA, `outputs/package-sha256.txt`, the
Codex CLI version, the Azure deployment name, and the reasoning effort used by
the controlled build. `max` is accepted by the helper but still requires the
selected Azure deployment and CLI to support it.

## Configure the Classic build task

Use a Classic **build** pipeline Bash task. Provide these values through the
pipeline environment or its existing variable mapping:

```text
SYSTEM_ACCESSTOKEN                 secret OAuth token for TFVC reads
AZURE_OPENAI_API_KEY               secret Azure Foundry key
AZURE_OPENAI_BASE_URL              HTTPS .../openai/v1 endpoint
AZURE_OPENAI_MODEL_DEPLOYMENT      deployment name
CODEX_REASONING_EFFORT             max, or the approved deployment setting
```

Leave `Continue on error` disabled. A completed security review that contains
a Critical or High finding, or a review limitation, exits with status `2` and
blocks the build after its reports have been submitted for upload. A report-generation or
validation failure exits with status `1` and must also block the build.

The launcher creates a private temporary workspace and passes the Azure key to
Codex only for each Codex invocation. Do not add the key, TFVC token, or any
other credential to the review prompt, a command argument, a downloaded
resource, or a published artifact.

## Verify one controlled run

Run a changeset with one known text edit and confirm the task log shows both
analysis and HTML reporting stages. The included integration tests verify
different working directories, fresh configuration files, explicit skill
invocation and the restricted report input package. Raw Codex diagnostics are
withheld and private workspaces are cleaned; do not enable secret-bearing logs
to inspect those details in a live build.

For a successful run, the downloadable `codex-review` artifact must contain:

```text
tfvc-changeset-N-codex-review.json
tfvc-changeset-N-codex-review.md
tfvc-changeset-N-codex-review.html
report-meta.json
review-manifest.json
source-locations.json
```

The model-message boundary permits one initial UTF-8 BOM and one complete enclosing
HTML or unlabelled backtick fence. Only the independently validated inner document
is published. Introductory/trailing prose, ambiguous fences and multiple documents
are rejected; no substring extraction or HTML repair is performed. The HTML5 doctype
may use standard whitespace, but arbitrary doctype extensions are not accepted.
The raw scaffold path still goes directly through HTML validation.

When the HTML pass fails after valid analysis, the artifact also contains
`report-diagnostic.json`. It records only allowlisted stage codes, numeric exit
statuses, fixed next actions, and `validatorFeedback`. That feedback contains only
an allowlisted DOM path/mismatch type or a fixed HTML failure category; it is also
printed in the task log. Raw Codex, validator, and source diagnostics are never
uploaded. If a report still fails, share the next run's `report-diagnostic.json`
including `validatorFeedback`; older diagnostic files omit the rejection detail. A single fresh HTML attempt is made after an independent
contract rejection, and it must pass the same validator before publication.

Open the downloaded HTML and check the changeset, coverage, changed-file
inventory, summary, every finding overview row, every finding detail, gate
policy, limitations, audit metadata, and footer. Check a finding containing
Unicode, multiline evidence, and HTML-like text; it must remain visible text.
The HTML must be standalone and offline, with no scripts, external URLs,
events, forms, frames, SVG, MathML, or hidden finding content.

The helper requests each file with Azure's `artifact.upload` logging command
before enforcing a blocking security gate. Azure documents this command as an
artifact upload action processed from task stdout; the Markdown summary command
is a separate build-summary attachment and is not the downloadable artifact.
See [Azure Pipelines logging commands](https://learn.microsoft.com/en-us/azure/devops/pipelines/scripts/logging-commands?view=azure-devops#upload-upload-an-artifact)
and [UploadSummary](https://learn.microsoft.com/en-us/azure/devops/pipelines/scripts/logging-commands?view=azure-devops#uploadsummary-add-some-markdown-content-to-the-build-summary).

## Expected outcomes

| Condition | Exit | Published output |
| --- | ---: | --- |
| Valid review, no blocking finding or limitation | `0` | JSON, Markdown, HTML, metadata, normalized manifest, source locations |
| Valid review with Critical/High finding or limitation | `2` | The same six files, uploaded before the gate error |
| Analysis API error, malformed JSON, bad schema, bad manifest, or bad pin | `1` | No review report |
| HTML Codex error or independent HTML validation failure | `1` | Valid JSON, Markdown, metadata, normalized manifest, source locations, sanitized `report-diagnostic.json`, and an explicitly labeled deterministic fallback when it can be produced; no rejected `codex-review.html` |

`report-meta.json` is authoritative for the analysis decision, report status,
coverage, counts, provenance, and input hashes. A presentation pass must not
change that file or its validated JSON and manifest. Do not treat an
`artifact.upload` line in the log as proof that Azure has finished storing the
artifact; verify the actual build's artifact list and download each file.

Do not publish the raw diff, review context, Codex stdout/stderr, or temporary
workspace. These files may contain source code or secrets even when the JSON
report is correctly redacted.

## Rollback

Keep the previous helper commit and the complete matching launcher hashes.
To roll back, restore that exact commit SHA and both helper digests together,
then rerun the Bash syntax check and one controlled build. Do not repair a
failed release by changing only a hash or only the launcher commit; the pin
must describe the bytes that are actually present at the trusted Git revision.

If the controlled build shows a missing artifact, an unexpected report status,
credential leakage, a schema or HTML validation error, or a package hash
mismatch, stop rollout and restore the previous known-good pair. Preserve the
failed build's task log and safe JSON metadata for diagnosis, but do not attach
raw review inputs to an issue or artifact.
