#!/usr/bin/env bash

set +x
set +a
set -Eeuo pipefail
umask 077
export LC_ALL=C

printf '##vso[task.setvariable variable=CODEX_REVIEW_GATE]fail\n'

# Preserve the Azure key without exporting it to ordinary child processes.
AZURE_KEY=${AZURE_OPENAI_API_KEY:-}
export -n AZURE_KEY
unset AZURE_OPENAI_API_KEY CODEX_API_KEY OPENAI_API_KEY

readonly HELPER_COMMIT="996773b9fb76f55a643eb7badccd1c4da24b3cd0"
readonly DIFF_HELPER_URL="https://raw.githubusercontent.com/iqinfra/azdophelpers/${HELPER_COMMIT}/tfvc/generate-changeset-diff.sh"
readonly CODEX_HELPER_URL="https://raw.githubusercontent.com/iqinfra/azdophelpers/${HELPER_COMMIT}/tfvc/run-codex-review.sh"

# These hashes must match the helper files at HELPER_COMMIT.
readonly DIFF_HELPER_SHA256="9b8f675741149b50de59c38d2f486332947dfc7df0ecc9ff92d41923bd9317bd"
readonly CODEX_HELPER_SHA256="b429e548b5cc342ed910d350a6e8091a3491c2fbb82d8312488fa503ede7bec8"

escape_vso() {
    local text=${1-}
    text=${text//'%'/'%AZP25'}
    text=${text//$'\r'/'%0D'}
    text=${text//$'\n'/'%0A'}
    printf '%s' "$text"
}

die() {
    printf '##vso[task.logissue type=error]%s\n' "$(escape_vso "$1")"
    exit 1
}

LAUNCHER_WORK=''
cleanup() {
    local status=$?
    trap - EXIT ERR INT TERM
    AZURE_KEY=''
    TFVC_TOKEN=''
    if [[ -n $LAUNCHER_WORK ]]; then
        if ! rm -rf -- "$LAUNCHER_WORK"; then
            printf '##vso[task.logissue type=error]Unable to remove temporary helpers.\n'
            status=1
        fi
    fi
    if (( status != 0 )); then
        printf '##vso[task.setvariable variable=CODEX_REVIEW_GATE]fail\n'
    fi
    exit "$status"
}

trap cleanup EXIT
trap 'die "Launcher failed unexpectedly at line ${LINENO}."' ERR
trap 'exit 130' INT
trap 'exit 143' TERM

for required_command in curl sha256sum chmod rm mktemp mv; do
    command -v "$required_command" >/dev/null 2>&1 ||
        die "Required command ${required_command} was not found in PATH."
done

for name in AGENT_TEMPDIRECTORY SYSTEM_ACCESSTOKEN \
    AZURE_OPENAI_BASE_URL AZURE_OPENAI_MODEL_DEPLOYMENT; do
    [[ -n ${!name:-} ]] || die "Required variable ${name} is missing."
done
[[ -n $AZURE_KEY ]] || die 'Required variable AZURE_OPENAI_API_KEY is missing.'
[[ $HELPER_COMMIT =~ ^[0-9a-fA-F]{40}$ ]] ||
    die 'HELPER_COMMIT must be a full 40-character Git commit SHA.'
[[ -d $AGENT_TEMPDIRECTORY && -w $AGENT_TEMPDIRECTORY ]] ||
    die 'AGENT_TEMPDIRECTORY must exist and be writable.'

# Use a private directory so concurrent runs do not overwrite each other.
TEMP_ROOT=$(cd -- "$AGENT_TEMPDIRECTORY" && pwd -P)
LAUNCHER_WORK=$(mktemp -d "${TEMP_ROOT%/}/codex-launcher.XXXXXXXX")
chmod 700 "$LAUNCHER_WORK"
readonly DIFF_HELPER="$LAUNCHER_WORK/generate-changeset-diff.sh"
readonly CODEX_HELPER="$LAUNCHER_WORK/run-codex-review.sh"

# Keep the DevOps token away from download processes as well.
TFVC_TOKEN=$SYSTEM_ACCESSTOKEN
export -n TFVC_TOKEN
unset SYSTEM_ACCESSTOKEN

download_helper() {
    local url=$1 output=$2 expected_sha256=$3 actual_sha256
    [[ $expected_sha256 =~ ^[0-9a-f]{64}$ ]] || die 'Invalid pinned SHA-256 digest.'

    # -q must be first: ignore any inherited curl configuration.
    if ! curl -q \
        --connect-timeout 20 \
        --max-time 120 \
        --retry 2 \
        --fail \
        --silent \
        --show-error \
        --location \
        --proto '=https' \
        --proto-redir '=https' \
        --tlsv1.2 \
        --output "${output}.part" \
        "$url"; then
        die "Helper download failed: ${output}"
    fi

    actual_sha256=$(sha256sum < "${output}.part") || die 'Unable to hash downloaded helper.'
    actual_sha256=${actual_sha256%% *}
    [[ $actual_sha256 == "$expected_sha256" ]] ||
        die "SHA-256 verification failed for helper: ${output}"

    chmod 700 "${output}.part"
    mv -- "${output}.part" "$output"
}

download_helper "$DIFF_HELPER_URL" "$DIFF_HELPER" "$DIFF_HELPER_SHA256"

printf 'Generating TFVC security-review package...\n'
SYSTEM_ACCESSTOKEN="$TFVC_TOKEN" "$DIFF_HELPER"
TFVC_TOKEN=''

download_helper "$CODEX_HELPER_URL" "$CODEX_HELPER" "$CODEX_HELPER_SHA256"

printf 'Starting Azure Foundry Codex security review...\n'
# Preserve the pipeline reasoning setting; default to high only when absent.
export HELPER_COMMIT
CODEX_REASONING_EFFORT="${CODEX_REASONING_EFFORT:-high}" \
AZURE_OPENAI_API_KEY="$AZURE_KEY" \
    "$CODEX_HELPER"

AZURE_KEY=''
printf 'Codex review task completed.\n'