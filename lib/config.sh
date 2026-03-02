#!/usr/bin/env bash
# Parses CLI/env inputs, loads `.env`, and validates required runtime configuration.
set -euo pipefail

load_dotenv() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      local key="${BASH_REMATCH[1]}"
      local val="${BASH_REMATCH[2]}"
      val="${val%\"}"; val="${val#\"}"
      val="${val%\'}"; val="${val#\'}"
      export "$key=$val"
    fi
  done < "$file"
}

parse_args() {
  local repo_root="$1"
  shift

  load_dotenv "$repo_root/.env"

  DT_URL="${DT_URL:-}"
  DT_API_KEY="${DT_API_KEY:-}"
  DJ_URL="${DJ_URL:-}"
  DJ_API_KEY="${DJ_API_KEY:-}"

  PROJECT_NAME="${PROJECT_NAME:-}"
  PRODUCT_NAME="${PRODUCT_NAME:-}"
  PRODUCT_TYPE_NAME="${PRODUCT_TYPE_NAME:-}"
  ENGAGEMENT_NAME="${ENGAGEMENT_NAME:-}"
  ENGAGEMENT_ID="${ENGAGEMENT_ID:-}"
  PIPELINE_VERSION="${PRODUCT_VERSION:-}"

  EXTRA_TAGS="${EXTRA_SCAN_TAGS:-}"

  SBOM_PATH="${SBOM_PATH:-$repo_root/tmp/sbom.json}"
  DT_FINDINGS_PATH="${DT_FINDINGS_PATH:-$repo_root/tmp/findings.json}"
  SAST_REPORT_PATH="${SAST_REPORT_PATH:-${SAST_JSON_PATH:-${BANDIT_JSON_PATH:-$repo_root/tmp/sast-report.json}}}"
  TESTS_SOURCE_PATH="${TESTS_SOURCE_PATH:-${SAST_SOURCE_PATH:-$repo_root}}"
  REQUIREMENTS_PATH=""

  SAST_TOOL="${SAST_TOOL:-bandit}"
  SAST_EXCLUDE="${SAST_EXCLUDE:-.venv,.idea,__pycache__}"
  SKIP_SAST="false"
  WAIT_AFTER_SBOM_SECONDS="${WAIT_AFTER_SBOM_SECONDS:-10}"

  MAX_CRITICAL="${MAX_CRITICAL:-0}"
  MAX_HIGH="${MAX_HIGH:-0}"
  MAX_MEDIUM="${MAX_MEDIUM:-999999}"
  MAX_LOW="${MAX_LOW:-999999}"
  MAX_TOTAL="${MAX_TOTAL:-999999}"

  DJ_UPLOAD_TIMEOUT="${DJ_UPLOAD_TIMEOUT:-300}"
  DJ_UPLOAD_RETRIES="${DJ_UPLOAD_RETRIES:-2}"
  DJ_UPLOAD_RETRY_DELAY="${DJ_UPLOAD_RETRY_DELAY:-5}"

  REPORT_OUTPUT_DIR="${REPORT_OUTPUT_DIR:-$repo_root/tmp/reports}"
  REPORT_LANGUAGE="${REPORT_LANGUAGE:-pt-BR}"
  SKIP_DEFECTDOJO_REPORT="false"

  BYPASS="false"
  CLEANUP_JSON="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dt-url) DT_URL="$2"; shift 2 ;;
      --dt-api-key) DT_API_KEY="$2"; shift 2 ;;
      --dj-url) DJ_URL="$2"; shift 2 ;;
      --dj-api-key) DJ_API_KEY="$2"; shift 2 ;;
      --project-name) PROJECT_NAME="$2"; shift 2 ;;
      --product-name) PRODUCT_NAME="$2"; shift 2 ;;
      --product-type-name) PRODUCT_TYPE_NAME="$2"; shift 2 ;;
      --engagement-name) ENGAGEMENT_NAME="$2"; shift 2 ;;
      --engagement-id) ENGAGEMENT_ID="$2"; shift 2 ;;
      --version) PIPELINE_VERSION="$2"; shift 2 ;;
      --extra-tags) EXTRA_TAGS="$2"; shift 2 ;;
      --sbom-path) SBOM_PATH="$2"; shift 2 ;;
      --dt-findings-path) DT_FINDINGS_PATH="$2"; shift 2 ;;
      --sast-report-path|--bandit-report-path) SAST_REPORT_PATH="$2"; shift 2 ;;
      --tests-source-path|--sast-source-path) TESTS_SOURCE_PATH="$2"; shift 2 ;;
      --sast-tool) SAST_TOOL="$2"; shift 2 ;;
      --sast-exclude) SAST_EXCLUDE="$2"; shift 2 ;;
      --skip-sast|--skip-bandit) SKIP_SAST="true"; shift ;;
      --wait-after-sbom-seconds) WAIT_AFTER_SBOM_SECONDS="$2"; shift 2 ;;
      --max-critical) MAX_CRITICAL="$2"; shift 2 ;;
      --max-high) MAX_HIGH="$2"; shift 2 ;;
      --max-medium) MAX_MEDIUM="$2"; shift 2 ;;
      --max-low) MAX_LOW="$2"; shift 2 ;;
      --max-total) MAX_TOTAL="$2"; shift 2 ;;
      --dj-upload-timeout) DJ_UPLOAD_TIMEOUT="$2"; shift 2 ;;
      --dj-upload-retries) DJ_UPLOAD_RETRIES="$2"; shift 2 ;;
      --dj-upload-retry-delay) DJ_UPLOAD_RETRY_DELAY="$2"; shift 2 ;;
      --report-output-dir) REPORT_OUTPUT_DIR="$2"; shift 2 ;;
      --report-language) REPORT_LANGUAGE="$2"; shift 2 ;;
      --skip-defectdojo-report) SKIP_DEFECTDOJO_REPORT="true"; shift ;;
      --by-pass|--bypass) BYPASS="true"; shift ;;
      --cleanup-json) CLEANUP_JSON="true"; shift ;;
      --help|-h)
        cat <<USAGE
Usage: ./run_pipeline.sh [options]

Main options:
  --project-name VALUE
  --product-name VALUE
  --product-type-name VALUE
  --engagement-name VALUE
  --version X.Y.Z
  --tests-source-path PATH
  --skip-sast
  --bypass
  --cleanup-json
USAGE
        exit 0
        ;;
      *) die "Unknown argument: $1" ;;
    esac
  done
}

validate_args() {
  local missing=()

  [[ -z "$DT_URL" ]] && missing+=("dt-url")
  [[ -z "$DT_API_KEY" ]] && missing+=("dt-api-key")
  [[ -z "$DJ_URL" ]] && missing+=("dj-url")
  [[ -z "$DJ_API_KEY" ]] && missing+=("dj-api-key")
  [[ -z "$PROJECT_NAME" ]] && missing+=("project-name")
  [[ -z "$PRODUCT_NAME" ]] && missing+=("product-name")
  [[ -z "$PRODUCT_TYPE_NAME" ]] && missing+=("product-type-name")
  [[ -z "$ENGAGEMENT_NAME" ]] && missing+=("engagement-name")
  [[ -z "$PIPELINE_VERSION" ]] && missing+=("version")

  if [[ ${#missing[@]} -gt 0 ]]; then
    die "Missing required args/env: ${missing[*]}"
  fi

  [[ -e "$TESTS_SOURCE_PATH" ]] || die "Tests source path not found: $TESTS_SOURCE_PATH"

  if [[ -d "$TESTS_SOURCE_PATH" ]]; then
    REQUIREMENTS_PATH="$TESTS_SOURCE_PATH/requirements.txt"
  else
    REQUIREMENTS_PATH="$(dirname "$TESTS_SOURCE_PATH")/requirements.txt"
  fi

  [[ -f "$REQUIREMENTS_PATH" ]] || die "Requirements file not found inside tests source path: $REQUIREMENTS_PATH"

  mkdir -p "$(dirname "$SBOM_PATH")" "$(dirname "$DT_FINDINGS_PATH")" "$(dirname "$SAST_REPORT_PATH")" "$REPORT_OUTPUT_DIR"
}
