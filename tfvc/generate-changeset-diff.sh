#!/usr/bin/env bash
# Generate candidate textual differences using the Linux TEE client.
# This is NOT a complete changeset exporter: TEE may only report added/deleted
# files and folders in its own stdout. Retain and inspect that log.
set +x
set -Eeuo pipefail
umask 077

readonly HELPER_VERSION='tfvc-workspace-fix-1'
TOKEN=''
WORK=''

escape_vso() {
    local text=$1
    text=${text//'%'/'%AZP25'}
    text=${text//$'\r'/'%0D'}
    text=${text//$'\n'/'%0A'}
    printf '%s' "$text"
}
error() { printf '##vso[task.logissue type=error]%s\n' "$(escape_vso "$1")"; }
warning() { printf '##vso[task.logissue type=warning]%s\n' "$(escape_vso "$1")"; }
die() { error "$1"; exit 1; }
cleanup() { [[ -z "$WORK" ]] || rm -rf -- "$WORK"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'rc=$?; error "Helper stopped unexpectedly at line ${LINENO} (exit ${rc})."; exit "$rc"' ERR

for name in BUILD_SOURCEVERSION BUILD_SOURCESDIRECTORY BUILD_ARTIFACTSTAGINGDIRECTORY \
            AGENT_TEMPDIRECTORY TFVC_SERVER_PATH SYSTEM_ACCESSTOKEN; do
    [[ -n ${!name:-} ]] || die "Required variable ${name} is missing. Check the task environment and OAuth-token setting."
done

COLLECTION=${TFVC_COLLECTION_URL:-${SYSTEM_COLLECTIONURI:-${SYSTEM_TEAMFOUNDATIONCOLLECTIONURI:-}}}
WORKSPACE=${TFVC_WORKSPACE:-${BUILD_REPOSITORY_TFVC_WORKSPACE:-}}
[[ -n "$COLLECTION" && "$COLLECTION" == https://* ]] || die 'An HTTPS collection URL is required.'
[[ -n "$WORKSPACE" && "$WORKSPACE" != *'$('* ]] || die 'Build.Repository.Tfvc.Workspace is missing or unresolved.'
[[ "$TFVC_SERVER_PATH" == '$/'* && "$TFVC_SERVER_PATH" != '$/' ]] || die 'TFVC_SERVER_PATH must be a project/folder server path beginning with $/.'
[[ "$SYSTEM_ACCESSTOKEN" != *'$('* ]] || die 'System.AccessToken has not been expanded.'
[[ ${BUILD_REPOSITORY_PROVIDER:-TfsVersionControl} == TfsVersionControl ]] || die 'This helper requires a TFVC build.'
case ${BUILD_REASON:-} in
    CheckInShelveset|ValidateShelveset) die 'This helper compares committed changesets, not shelvesets.' ;;
    BatchedCI) warning 'Only the final changeset is compared, not every changeset in this batch.' ;;
esac

[[ "$BUILD_SOURCEVERSION" =~ ^[Cc]?([0-9]{1,10})$ ]] || die 'Build.SourceVersion is not a numeric TFVC changeset.'
CURRENT=$((10#${BASH_REMATCH[1]}))
(( CURRENT > 1 && CURRENT <= 2147483647 )) || die 'The changeset must be between C2 and C2147483647.'
PREVIOUS=$((CURRENT - 1))
MAX_BYTES=${TFVC_MAX_DIFF_BYTES:-10485760}
[[ "$MAX_BYTES" =~ ^[1-9][0-9]{0,9}$ ]] || die 'TFVC_MAX_DIFF_BYTES must be a positive integer with at most 10 digits.'
ALLOW_EMPTY=${TFVC_ALLOW_EMPTY_DIFF:-false}
[[ "$ALLOW_EMPTY" == true || "$ALLOW_EMPTY" == false ]] || die 'TFVC_ALLOW_EMPTY_DIFF must be true or false.'

TF_COMMAND=$(command -v tf) || die "The TEE 'tf' executable was not found."
GNU_DIFF=$(command -v diff) || die "GNU diff was not found."
[[ -d "$BUILD_SOURCESDIRECTORY" ]] || die 'Build.SourcesDirectory does not exist.'
[[ -d "$AGENT_TEMPDIRECTORY" ]] || die 'Agent.TempDirectory does not exist.'
mkdir -p -- "$BUILD_ARTIFACTSTAGINGDIRECTORY"
WORK=$(mktemp -d "${AGENT_TEMPDIRECTORY%/}/tfvc-review.XXXXXXXX")
DIFF_FILE="${BUILD_ARTIFACTSTAGINGDIRECTORY%/}/tfvc-changeset-${CURRENT}.diff"
SUMMARY_FILE="${BUILD_ARTIFACTSTAGINGDIRECTORY%/}/tfvc-diff-${CURRENT}-summary.md"
rm -f -- "$DIFF_FILE" "$SUMMARY_FILE"

# Retain the token in this shell only. Pass it to TEE over stdin, not OS argv.
TOKEN=$SYSTEM_ACCESSTOKEN
export -n TOKEN
unset SYSTEM_ACCESSTOKEN

sanitize_log() {
    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=${line//"$TOKEN"/'[REDACTED]'}
        line=${line//'##vso['/'##vso ['}
        line=${line//'##['/'## ['}
        printf '%s\n' "$line"
    done < "$1" > "$2"
}

# TEE accepts one command per line via `tf @` (stdin command-file mode).
# Quote for TEE's parser, not Bash. Reject embedded quotes/newlines and a final
# backslash rather than attempting ambiguous Windows-style command quoting.
tee_run() {
    local label=$1 arg command_line='' rc stdout_log stderr_log
    shift
    for arg in "$@" "-collection:$COLLECTION" "-jwt:$TOKEN" '-noprompt'; do
        case "$arg" in
            *'"'*|*$'\r'*|*$'\n'*|*\\) die 'A TEE argument contains unsupported quoting characters.' ;;
        esac
        command_line+="\"${arg}\" "
    done
    stdout_log="${BUILD_ARTIFACTSTAGINGDIRECTORY%/}/tfvc-${label}-${CURRENT}.stdout.log"
    stderr_log="${BUILD_ARTIFACTSTAGINGDIRECTORY%/}/tfvc-${label}-${CURRENT}.stderr.log"
    if printf '%s\n' "$command_line" | "$TF_COMMAND" @ > "$WORK/stdout" 2> "$WORK/stderr"; then
        rc=0
    else
        rc=$?
    fi
    sanitize_log "$WORK/stdout" "$stdout_log"
    sanitize_log "$WORK/stderr" "$stderr_log"
    if (( rc != 0 )); then
        error "TEE ${label} failed with exit ${rc}."
        printf '\n--- TEE stderr ---\n'; cat -- "$stderr_log"
        printf '\n--- TEE stdout ---\n'; cat -- "$stdout_log"
        exit "$rc"
    fi
    if [[ -s "$stderr_log" ]]; then
        warning "TEE ${label} wrote to stderr; inspect the corresponding log before trusting the result."
    fi
}

printf 'Helper version : %s\nChangeset      : C%s\nComparison     : C%s -> C%s\n' \
       "$HELPER_VERSION" "$CURRENT" "$PREVIOUS" "$CURRENT"
printf 'Workspace      : %s\nServer path    : %s\nTF client      : %s\n' \
       "$WORKSPACE" "$TFVC_SERVER_PATH" "$TF_COMMAND"
cd -- "$BUILD_SOURCESDIRECTORY"

# Query the existing build workspace and refresh this account's TEE cache.
# Do not create/delete workspaces or alter mappings.
printf '\nRefreshing the existing workspace cache...\n'
tee_run workspaces workspaces "$WORKSPACE" -format:detailed
printf 'Checking the workspace mappings...\n'
tee_run workfold workfold "-workspace:$WORKSPACE"
printf 'Workspace discovery succeeded.\n'

# Capture only GNU diff output in the candidate patch. TEE stdout is metadata.
export TFVC_PATCH_TEMP="$WORK/patch"
export TFVC_DIFF_STATE="$WORK"
export TFVC_GNU_DIFF="$GNU_DIFF"
: > "$TFVC_PATCH_TEMP"
cat > "$WORK/diff-wrapper.sh" <<'WRAPPER'
#!/usr/bin/env bash
set +x
set -Eeuo pipefail
: "${TFVC_DIFF_STATE:?}" "${TFVC_PATCH_TEMP:?}" "${TFVC_GNU_DIFF:?}"
# TEE runs comparisons synchronously. Record failures independently because
# TEE's external-tool launcher does not propagate every child exit status.
trap 'rc=$?; if (( rc != 0 )); then printf "%s\n" "$rc" >> "$TFVC_DIFF_STATE/failed"; fi' EXIT
printf 'started\n' >> "$TFVC_DIFF_STATE/started"
[[ $# -eq 4 ]] || { printf 'Expected four diff arguments.\n' >&2; exit 2; }
if "$TFVC_GNU_DIFF" -u --label "$3" --label "$4" -- "$1" "$2" >> "$TFVC_PATCH_TEMP"; then
    rc=0
else
    rc=$?
fi
case "$rc" in
    0|1) printf '%s\n' "$rc" >> "$TFVC_DIFF_STATE/completed" ;;
    *) printf 'GNU diff failed with exit %s.\n' "$rc" >&2; exit "$rc" ;;
esac
WRAPPER
chmod 700 "$WORK/diff-wrapper.sh"
[[ "$WORK" != *'"'* && "$WORK" != *$'\n'* && "$WORK" != *$'\r'* ]] || die 'The agent temporary path contains unsupported characters.'
export TF_DIFF_COMMAND="\"$WORK/diff-wrapper.sh\" \"%1\" \"%2\" \"%6\" \"%7\""

printf '\nGenerating candidate textual differences...\n'
tee_run diff difference "$TFVC_SERVER_PATH" \
    "-workspace:$WORKSPACE" "-version:C${PREVIOUS}~C${CURRENT}" -recursive
STARTED=0
COMPLETED=0
[[ ! -f "$WORK/started" ]] || STARTED=$(wc -l < "$WORK/started")
[[ ! -f "$WORK/completed" ]] || COMPLETED=$(wc -l < "$WORK/completed")
[[ ! -e "$WORK/failed" && "$STARTED" -eq "$COMPLETED" ]] || die 'An external diff failed or did not finish. No successful patch has been published.' 

SIZE=$(wc -c < "$TFVC_PATCH_TEMP")
(( SIZE <= MAX_BYTES )) || die 'The candidate diff exceeds TFVC_MAX_DIFF_BYTES. Split or review the changeset separately.'
HAS_TEXT=false
if grep -qE '^@@ -[0-9]+(,[0-9]+)? \+[0-9]+(,[0-9]+)? @@' "$TFVC_PATCH_TEMP"; then
    HAS_TEXT=true
else
    warning 'No unified text hunks were produced. This does not prove the changeset has no changes; inspect the TEE stdout log.'
    [[ "$ALLOW_EMPTY" == true ]] || die 'Stopping before automated review. Set TFVC_ALLOW_EMPTY_DIFF=true only after checking the TEE output.'
fi
mv -- "$TFVC_PATCH_TEMP" "$DIFF_FILE"
LINES=$(wc -l < "$DIFF_FILE")
cat > "$SUMMARY_FILE" <<EOF
# TFVC diff generation

Helper: $HELPER_VERSION

Comparison: C${PREVIOUS} to C${CURRENT}

Candidate diff: tfvc-changeset-${CURRENT}.diff

Size: ${SIZE} bytes; lines: ${LINES}; contains text hunks: ${HAS_TEXT}

**Coverage is not certified complete.** TEE recursive comparison can report
added/deleted files or folders only in its own stdout, without emitting their
contents as unified hunks. Review tfvc-diff-${CURRENT}.stdout.log alongside the
diff. This summary is not a code-review result.
EOF
warning 'Candidate textual diff generated. Inspect the TEE stdout log for changes not represented as text hunks.'
printf 'Diff file: %s\nSize: %s bytes\nLines: %s\n' "$DIFF_FILE" "$SIZE" "$LINES"
printf '##vso[task.setvariable variable=TFVC_DIFF_FILE]%s\n' "$(escape_vso "$DIFF_FILE")"
printf '##vso[task.setvariable variable=TFVC_HAS_TEXT_DIFF]%s\n' "$HAS_TEXT"
printf '##vso[task.setvariable variable=TFVC_DIFF_COVERAGE]unverified\n'
printf '##vso[task.uploadsummary]%s\n' "$(escape_vso "$SUMMARY_FILE")"
