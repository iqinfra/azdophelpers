set -Eeuo pipefail

###############################################################################
# Configuration / validation
###############################################################################

log_error() {
    echo "##vso[task.logissue type=error]$1"
}

log_warning() {
    echo "##vso[task.logissue type=warning]$1"
}

# Validate required Azure DevOps variables.
: "${BUILD_SOURCEVERSION:?BUILD_SOURCEVERSION is not set}"
: "${BUILD_SOURCESDIRECTORY:?BUILD_SOURCESDIRECTORY is not set}"
: "${BUILD_ARTIFACTSTAGINGDIRECTORY:?BUILD_ARTIFACTSTAGINGDIRECTORY is not set}"

# TFVC Build.SourceVersion is normally C<number>.
CURRENT_CHANGESET="${BUILD_SOURCEVERSION#C}"
CURRENT_CHANGESET="${CURRENT_CHANGESET#c}"

if ! [[ "$CURRENT_CHANGESET" =~ ^[0-9]+$ ]]; then
    log_error "Invalid TFVC changeset: '${BUILD_SOURCEVERSION}'. Expected format C<number>."
    exit 1
fi

if (( CURRENT_CHANGESET <= 1 )); then
    log_error "Changeset must be greater than C1."
    exit 1
fi

PREVIOUS_CHANGESET=$((CURRENT_CHANGESET - 1))

###############################################################################
# Paths
###############################################################################

mkdir -p "$BUILD_ARTIFACTSTAGINGDIRECTORY"

DIFF_FILE="$BUILD_ARTIFACTSTAGINGDIRECTORY/tfvc-changeset-${CURRENT_CHANGESET}.diff"
DIFF_ERROR_FILE="$BUILD_ARTIFACTSTAGINGDIRECTORY/tfvc-diff-${CURRENT_CHANGESET}.stderr"
SUMMARY_FILE="$BUILD_ARTIFACTSTAGINGDIRECTORY/codex-review-${CURRENT_CHANGESET}.md"

# Temporary wrapper used by Team Explorer Everywhere for textual comparisons.
DIFF_WRAPPER="${AGENT_TEMPDIRECTORY:-/tmp}/tfvc-diff-wrapper-${CURRENT_CHANGESET}.sh"

###############################################################################
# Dependency checks
###############################################################################

if ! TF_COMMAND="$(command -v tf)"; then
    log_error "TFVC command-line client 'tf' was not found in PATH."
    exit 1
fi

if ! DIFF_COMMAND="$(command -v diff)"; then
    log_error "GNU diff was not found in PATH."
    exit 1
fi

echo "TFVC changeset : C${CURRENT_CHANGESET}"
echo "Comparison     : C${PREVIOUS_CHANGESET} -> C${CURRENT_CHANGESET}"
echo "Sources        : ${BUILD_SOURCESDIRECTORY}"
echo "TF client      : ${TF_COMMAND}"
echo "Diff utility   : ${DIFF_COMMAND}"
echo

###############################################################################
# Configure TEE external unified-diff command
###############################################################################
#
# Team Explorer Everywhere (TEE), used for TFVC on Linux, doesn't behave like
# Windows tf.exe for /format:unified.
#
# TEE invokes the command defined by TF_DIFF_COMMAND for each textual file
# comparison.
#
# GNU diff returns:
#
#   0 = files are identical
#   1 = files differ
#   2+ = actual error
#
# A source-code difference is expected here, so normalize exit code 1 to 0.
###############################################################################

cat > "$DIFF_WRAPPER" <<'EOF'
#!/usr/bin/env bash

set -u

SOURCE_FILE="$1"
TARGET_FILE="$2"
SOURCE_LABEL="$3"
TARGET_LABEL="$4"

diff -u \
    --label "$SOURCE_LABEL" \
    --label "$TARGET_LABEL" \
    "$SOURCE_FILE" \
    "$TARGET_FILE"

DIFF_EXIT_CODE=$?

case "$DIFF_EXIT_CODE" in
    0|1)
        # 0 = identical, 1 = differences found.
        # Both are successful outcomes for a source comparison.
        exit 0
        ;;
    *)
        # GNU diff encountered an actual error.
        exit "$DIFF_EXIT_CODE"
        ;;
esac
EOF

chmod 700 "$DIFF_WRAPPER"

# %1 = original/source file
# %2 = modified/target file
# %6 = source label
# %7 = target label
#
# These placeholders are expanded by TEE.
export TF_DIFF_COMMAND="\"${DIFF_WRAPPER}\" \"%1\" \"%2\" \"%6\" \"%7\""

###############################################################################
# Generate TFVC diff
###############################################################################

echo "Generating unified TFVC diff..."
echo

cd "$BUILD_SOURCESDIRECTORY"

# Ensure stale files from an earlier attempt can't be mistaken for new output.
: > "$DIFF_FILE"
: > "$DIFF_ERROR_FILE"

set +e

tf diff . \
    -version:"C${PREVIOUS_CHANGESET}~C${CURRENT_CHANGESET}" \
    -recursive \
    -noprompt \
    > "$DIFF_FILE" \
    2> "$DIFF_ERROR_FILE"

TF_EXIT_CODE=$?

set -e

###############################################################################
# Handle TFVC errors
###############################################################################

if (( TF_EXIT_CODE != 0 )); then
    log_error "TFVC diff failed with exit code ${TF_EXIT_CODE}."

    if [[ -s "$DIFF_ERROR_FILE" ]]; then
        echo
        echo "----- TFVC stderr -----"
        cat "$DIFF_ERROR_FILE"
        echo "-----------------------"
    fi

    if [[ -s "$DIFF_FILE" ]]; then
        echo
        echo "----- TFVC stdout -----"
        cat "$DIFF_FILE"
        echo "-----------------------"
    fi

    exit "$TF_EXIT_CODE"
fi

###############################################################################
# Surface non-fatal stderr
###############################################################################

if [[ -s "$DIFF_ERROR_FILE" ]]; then
    log_warning "TFVC produced output on stderr."

    echo
    echo "----- TFVC stderr -----"
    cat "$DIFF_ERROR_FILE"
    echo "-----------------------"
fi

###############################################################################
# Handle an empty diff
###############################################################################

if [[ ! -s "$DIFF_FILE" ]]; then
    log_warning "No textual differences were returned for changeset C${CURRENT_CHANGESET}."

    cat > "$SUMMARY_FILE" <<EOF
# TFVC Review

No textual differences were found for changeset C${CURRENT_CHANGESET}.

Comparison:

- Previous version: C${PREVIOUS_CHANGESET}
- Current version: C${CURRENT_CHANGESET}
EOF

    echo "##vso[task.uploadsummary]$SUMMARY_FILE"

    rm -f "$DIFF_WRAPPER"

    exit 0
fi

###############################################################################
# Success
###############################################################################

DIFF_SIZE="$(wc -c < "$DIFF_FILE")"
DIFF_LINES="$(wc -l < "$DIFF_FILE")"

echo
echo "TFVC diff generated successfully."
echo
echo "Changeset : C${CURRENT_CHANGESET}"
echo "Compared  : C${PREVIOUS_CHANGESET} -> C${CURRENT_CHANGESET}"
echo "Diff file : ${DIFF_FILE}"
echo "Size      : ${DIFF_SIZE} bytes"
echo "Lines     : ${DIFF_LINES}"

###############################################################################
# Pipeline summary
###############################################################################

cat > "$SUMMARY_FILE" <<EOF
# TFVC Changeset Review

**Changeset:** C${CURRENT_CHANGESET}

**Compared against:** C${PREVIOUS_CHANGESET}

**Unified diff:** \`tfvc-changeset-${CURRENT_CHANGESET}.diff\`

**Diff size:** ${DIFF_SIZE} bytes

**Diff lines:** ${DIFF_LINES}
EOF

echo "##vso[task.uploadsummary]$SUMMARY_FILE"

###############################################################################
# Cleanup
###############################################################################

rm -f "$DIFF_WRAPPER"