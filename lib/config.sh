#!/usr/bin/env bash
# Parses CLI/env inputs, loads `.env`, and validates required runtime configuration.
set -euo pipefail

load_dotenv() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      local key="${BASH_REMATCH[2]}"
      local val="${BASH_REMATCH[3]}"
      val="$(sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' <<<"$val")"
      val="${val%\"}"; val="${val#\"}"
      val="${val%\'}"; val="${val#\'}"
      export "$key=$val"
    fi
  done < "$file"
}

require_arg_value() {
  local flag="$1"
  local remaining="$2"
  (( remaining >= 2 )) || die "Missing value for $flag"
}

normalize_bool() {
  local value="${1:-}"
  value="$(tr '[:upper:]' '[:lower:]' <<<"$value")"
  case "$value" in
    true|1|yes|y|on) printf 'true\n' ;;
    false|0|no|n|off|"") printf 'false\n' ;;
    *) die "Invalid boolean value: $1" ;;
  esac
}

validate_int() {
  local name="$1"
  local value="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || die "Invalid integer for $name: $value"
}

normalize_report_formats() {
  local raw="${1:-}"
  raw="$(tr '[:upper:]' '[:lower:]' <<<"$raw")"
  [[ -z "${raw// }" ]] && return 0

  local out=()
  local token
  IFS=',' read -r -a tokens <<<"$raw"
  for token in "${tokens[@]}"; do
    token="$(sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' <<<"$token")"
    [[ -z "$token" || "$token" == "none" ]] && continue
    case "$token" in
      all)
        out+=("json" "csv" "md")
        ;;
      json|csv|md)
        out+=("$token")
        ;;
      *)
        die "Invalid --pipeline-report value '$token'. Supported: json,csv,md,all"
        ;;
    esac
  done

  if [[ ${#out[@]} -eq 0 ]]; then
    return 0
  fi

  awk 'BEGIN{FS=","; OFS=","} {for(i=1;i<=NF;i++){if(!seen[$i]++){arr[++n]=$i}}} END{for(i=1;i<=n;i++){printf "%s%s", arr[i], (i<n?",":"\n")}}' <<<"$(IFS=','; echo "${out[*]}")"
}

resolve_sca_manifest() {
  local language="$1"
  local source_path="$2"
  local manifest_override="$3"

  local lang
  lang="$(tr '[:upper:]' '[:lower:]' <<<"$language")"

  if [[ -n "$manifest_override" ]]; then
    [[ -f "$manifest_override" ]] || die "SCA manifest file not found: $manifest_override"
    printf '%s\n' "$manifest_override"
    return 0
  fi

  local filename=""
  case "$lang" in
    python) filename="requirements.txt" ;;
    java) filename="pom.xml" ;;
    javascript|js|node) filename="package.json" ;;
    *) die "Unsupported SCA language '$language'. Supported: python, java, javascript" ;;
  esac

  if [[ -d "$source_path" ]]; then
    local candidate="$source_path/$filename"
    [[ -f "$candidate" ]] || die "SCA manifest not found for language '$language': $candidate"
    printf '%s\n' "$candidate"
    return 0
  fi

  if [[ "$(basename "$source_path")" == "$filename" ]]; then
    [[ -f "$source_path" ]] || die "SCA manifest file not found: $source_path"
    printf '%s\n' "$source_path"
    return 0
  fi

  die "SCA source path must be a directory or manifest file for language '$language': $source_path"
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

  SCAN_SOURCE_PATH="${SCAN_SOURCE_PATH:-${TESTS_SOURCE_PATH:-${SAST_SOURCE_PATH:-$repo_root}}}"
  OUTPUT_DIR="${OUTPUT_DIR:-$repo_root/tmp/reports}"

  ENABLE_SCA="$(normalize_bool "${ENABLE_SCA:-false}")"
  SCA_LANGUAGE="${SCA_LANGUAGE:-}"
  SCA_MANIFEST_PATH="${SCA_MANIFEST_PATH:-}"

  ENABLE_SAST="$(normalize_bool "${ENABLE_SAST:-false}")"
  SAST_TOOL="${SAST_TOOL:-bandit}"
  SAST_EXCLUDE="${SAST_EXCLUDE:-.venv,.idea,__pycache__}"
  ENABLE_SECRETS="$(normalize_bool "${ENABLE_SECRETS:-false}")"
  SECRETS_TOOL="${SECRETS_TOOL:-gitleaks}"
  SECRETS_SCAN_TYPE="${SECRETS_SCAN_TYPE:-Gitleaks Scan}"
  SECRETS_EXCLUDE="${SECRETS_EXCLUDE:-.git,.venv,.idea,__pycache__,tmp,node_modules}"
  SECRETS_CONFIG_PATH="${SECRETS_CONFIG_PATH:-${GITLEAKS_CONFIG:-}}"

  PIPELINE_REPORT_FORMATS="$(normalize_report_formats "${PIPELINE_REPORT_FORMATS:-}")"

  WAIT_AFTER_SBOM_SECONDS="${WAIT_AFTER_SBOM_SECONDS:-60}"
  DT_EXPORT_STABILITY_POLLS="${DT_EXPORT_STABILITY_POLLS:-3}"
  DT_EXPORT_STABILITY_INTERVAL_SECONDS="${DT_EXPORT_STABILITY_INTERVAL_SECONDS:-10}"
  DT_EXPORT_STABILITY_TIMEOUT_SECONDS="${DT_EXPORT_STABILITY_TIMEOUT_SECONDS:-180}"

  MAX_CRITICAL="${MAX_CRITICAL:-0}"
  MAX_HIGH="${MAX_HIGH:-0}"
  MAX_MEDIUM="${MAX_MEDIUM:-999999}"
  MAX_LOW="${MAX_LOW:-999999}"
  MAX_TOTAL="${MAX_TOTAL:-999999}"

  DJ_UPLOAD_TIMEOUT="${DJ_UPLOAD_TIMEOUT:-300}"
  DJ_UPLOAD_RETRIES="${DJ_UPLOAD_RETRIES:-2}"
  DJ_UPLOAD_RETRY_DELAY="${DJ_UPLOAD_RETRY_DELAY:-5}"

  REPORT_LANGUAGE="${REPORT_LANGUAGE:-pt-BR}"
  SKIP_DEFECTDOJO_REPORT="$(normalize_bool "${SKIP_DEFECTDOJO_REPORT:-true}")"

  BYPASS="false"
  CLEANUP_JSON="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dt-url) require_arg_value "$1" "$#"; DT_URL="$2"; shift 2 ;;
      --dt-api-key) require_arg_value "$1" "$#"; DT_API_KEY="$2"; shift 2 ;;
      --dj-url) require_arg_value "$1" "$#"; DJ_URL="$2"; shift 2 ;;
      --dj-api-key) require_arg_value "$1" "$#"; DJ_API_KEY="$2"; shift 2 ;;
      --project-name) require_arg_value "$1" "$#"; PROJECT_NAME="$2"; shift 2 ;;
      --product-name) require_arg_value "$1" "$#"; PRODUCT_NAME="$2"; shift 2 ;;
      --product-type-name) require_arg_value "$1" "$#"; PRODUCT_TYPE_NAME="$2"; shift 2 ;;
      --engagement-name) require_arg_value "$1" "$#"; ENGAGEMENT_NAME="$2"; shift 2 ;;
      --engagement-id) require_arg_value "$1" "$#"; ENGAGEMENT_ID="$2"; shift 2 ;;
      --version) require_arg_value "$1" "$#"; PIPELINE_VERSION="$2"; shift 2 ;;
      --extra-tags) require_arg_value "$1" "$#"; EXTRA_TAGS="$2"; shift 2 ;;

      --source-path|--tests-source-path|--sast-source-path) require_arg_value "$1" "$#"; SCAN_SOURCE_PATH="$2"; shift 2 ;;
      --output-dir) require_arg_value "$1" "$#"; OUTPUT_DIR="$2"; shift 2 ;;

      --sca) require_arg_value "$1" "$#"; ENABLE_SCA="true"; SCA_LANGUAGE="$2"; shift 2 ;;
      --sca-manifest-path) require_arg_value "$1" "$#"; SCA_MANIFEST_PATH="$2"; shift 2 ;;

      --sast) ENABLE_SAST="true"; shift ;;
      --sast-tool) require_arg_value "$1" "$#"; SAST_TOOL="$2"; shift 2 ;;
      --sast-exclude) require_arg_value "$1" "$#"; SAST_EXCLUDE="$2"; shift 2 ;;
      --secrets)
        ENABLE_SECRETS="true"
        if [[ $# -gt 1 && ! "$2" =~ ^-- ]]; then
          SECRETS_CONFIG_PATH="$2"
          shift 2
        else
          shift
        fi
        ;;
      --secrets-tool) require_arg_value "$1" "$#"; SECRETS_TOOL="$2"; shift 2 ;;
      --secrets-scan-type) require_arg_value "$1" "$#"; SECRETS_SCAN_TYPE="$2"; shift 2 ;;
      --secrets-exclude) require_arg_value "$1" "$#"; SECRETS_EXCLUDE="$2"; shift 2 ;;

      --pipeline-report) require_arg_value "$1" "$#"; PIPELINE_REPORT_FORMATS="$(normalize_report_formats "$2")"; shift 2 ;;

      --wait-after-sbom-seconds) require_arg_value "$1" "$#"; WAIT_AFTER_SBOM_SECONDS="$2"; shift 2 ;;
      --dt-export-stability-polls) require_arg_value "$1" "$#"; DT_EXPORT_STABILITY_POLLS="$2"; shift 2 ;;
      --dt-export-stability-interval-seconds) require_arg_value "$1" "$#"; DT_EXPORT_STABILITY_INTERVAL_SECONDS="$2"; shift 2 ;;
      --dt-export-stability-timeout-seconds) require_arg_value "$1" "$#"; DT_EXPORT_STABILITY_TIMEOUT_SECONDS="$2"; shift 2 ;;
      --max-critical) require_arg_value "$1" "$#"; MAX_CRITICAL="$2"; shift 2 ;;
      --max-high) require_arg_value "$1" "$#"; MAX_HIGH="$2"; shift 2 ;;
      --max-medium) require_arg_value "$1" "$#"; MAX_MEDIUM="$2"; shift 2 ;;
      --max-low) require_arg_value "$1" "$#"; MAX_LOW="$2"; shift 2 ;;
      --max-total) require_arg_value "$1" "$#"; MAX_TOTAL="$2"; shift 2 ;;

      --dj-upload-timeout) require_arg_value "$1" "$#"; DJ_UPLOAD_TIMEOUT="$2"; shift 2 ;;
      --dj-upload-retries) require_arg_value "$1" "$#"; DJ_UPLOAD_RETRIES="$2"; shift 2 ;;
      --dj-upload-retry-delay) require_arg_value "$1" "$#"; DJ_UPLOAD_RETRY_DELAY="$2"; shift 2 ;;

      --report-language) require_arg_value "$1" "$#"; REPORT_LANGUAGE="$2"; shift 2 ;;
      --defectdojo-report|--enable-defectdojo-report) SKIP_DEFECTDOJO_REPORT="false"; shift ;;
      --skip-defectdojo-report) SKIP_DEFECTDOJO_REPORT="true"; shift ;;

      --by-pass|--bypass) BYPASS="true"; shift ;;
      --cleanup-json) CLEANUP_JSON="true"; shift ;;
      --help|-h)
        cat <<USAGE
Usage: ./run_pipeline.sh [options]

Description:
  Security pipeline orchestrator with DefectDojo as gate authority.
  Runs only scans explicitly enabled via flags/env.

Required core options (flag or env):
  --dt-url URL                   [env: DT_URL]
  --dt-api-key KEY               [env: DT_API_KEY]
  --dj-url URL                   [env: DJ_URL]
  --dj-api-key KEY               [env: DJ_API_KEY]
  --project-name NAME            [env: PROJECT_NAME]
  --product-name NAME            [env: PRODUCT_NAME]
  --product-type-name NAME       [env: PRODUCT_TYPE_NAME]
  --engagement-name NAME         [env: ENGAGEMENT_NAME]
  --version X.Y.Z                [env: PRODUCT_VERSION]

Required scan enablement (at least one):
  --sca LANGUAGE                 Enable SCA; LANGUAGE: python|java|javascript
                                 [env: ENABLE_SCA=true + SCA_LANGUAGE]
  --sast                         Enable SAST (Bandit)
                                 [env: ENABLE_SAST=true]
  --secrets [CONFIG_PATH]        Enable secrets scan (Gitleaks)
                                 Optional config file path (.gitleaks.toml)
                                 [env: ENABLE_SECRETS=true]

Paths:
  --source-path PATH             Base path used by enabled scans
  --tests-source-path PATH       Alias of --source-path
  --sast-source-path PATH        Alias of --source-path
                                 [env fallback: SCAN_SOURCE_PATH, TESTS_SOURCE_PATH, SAST_SOURCE_PATH]
  --output-dir PATH              Global output directory for all local artifacts/reports
                                 [env: OUTPUT_DIR] default: <repo>/tmp/reports

SCA options:
  --sca-manifest-path PATH       Explicit manifest path override [env: SCA_MANIFEST_PATH]
  --wait-after-sbom-seconds N    Delay/poll window after upload [env: WAIT_AFTER_SBOM_SECONDS]
                                 default: 60
  --dt-export-stability-polls N  Consecutive equal DT export counts required before import
                                 [env: DT_EXPORT_STABILITY_POLLS] default: 3
  --dt-export-stability-interval-seconds N
                                 Seconds between DT export count checks
                                 [env: DT_EXPORT_STABILITY_INTERVAL_SECONDS] default: 10
  --dt-export-stability-timeout-seconds N
                                 Max time waiting for DT export stabilization
                                 [env: DT_EXPORT_STABILITY_TIMEOUT_SECONDS] default: 180

SCA manifest resolution when --sca is enabled:
  python      -> requirements.txt
  java        -> pom.xml
  javascript  -> package.json
  Resolution root: --source-path (unless --sca-manifest-path is set)

SAST options:
  --sast-tool TOOL               Current supported: bandit [env: SAST_TOOL]
                                 default: bandit
  --sast-exclude CSV             Exclude patterns for directory scans [env: SAST_EXCLUDE]
                                 default: .venv,.idea,__pycache__

Secrets options:
  --secrets-tool TOOL            Current supported: gitleaks [env: SECRETS_TOOL]
                                 default: gitleaks
  --secrets CONFIG_PATH          Optional gitleaks config path
                                 [env: SECRETS_CONFIG_PATH or GITLEAKS_CONFIG]
  --secrets-scan-type NAME       DefectDojo parser name [env: SECRETS_SCAN_TYPE]
                                 default: Gitleaks Scan
  --secrets-exclude CSV          Exclude path patterns [env: SECRETS_EXCLUDE]
                                 default: .git,.venv,.idea,__pycache__,tmp,node_modules

Pipeline report options (local active-findings report):
  --pipeline-report LIST         Enable local report generation and choose formats
                                 LIST values: json,csv,md,all (comma-separated)
                                 Example: --pipeline-report csv,md
                                 [env: PIPELINE_REPORT_FORMATS]
                                 Default: disabled

DefectDojo report options:
  --defectdojo-report            Enable engagement report request
  --enable-defectdojo-report     Alias of --defectdojo-report
  --skip-defectdojo-report       Disable engagement report request [env: SKIP_DEFECTDOJO_REPORT]
                                 default: true (disabled)
  --report-language CODE         Report language code [env: REPORT_LANGUAGE]
                                 default: pt-BR

DefectDojo upload options:
  --engagement-id ID             Optional fixed engagement override [env: ENGAGEMENT_ID]
  --extra-tags CSV               Extra tags on imports [env: EXTRA_SCAN_TAGS]
  --dj-upload-timeout N          SAST upload timeout seconds [env: DJ_UPLOAD_TIMEOUT]
                                 default: 300
  --dj-upload-retries N          SAST upload retries [env: DJ_UPLOAD_RETRIES]
                                 default: 2
  --dj-upload-retry-delay N      Retry delay seconds [env: DJ_UPLOAD_RETRY_DELAY]
                                 default: 5

Gate thresholds:
  --max-critical N               [env: MAX_CRITICAL] default: 0
  --max-high N                   [env: MAX_HIGH] default: 0
  --max-medium N                 [env: MAX_MEDIUM] default: 999999
  --max-low N                    [env: MAX_LOW] default: 999999
  --max-total N                  [env: MAX_TOTAL] default: 999999

Execution behavior:
  --bypass, --by-pass            Return success even if gate fails
  --cleanup-json                 Remove *.json from --output-dir at end
  --help, -h                     Show this help

Output files under --output-dir:
  - sca-sbom.json (when SCA enabled)
  - sca-findings.json (when SCA enabled)
  - sast-report.json (when SAST enabled)
  - secrets-report.json (when secrets scan enabled)
  - engagement-...-active-findings.<json|csv|md> (when --pipeline-report is set)
  - defectdojo-engagement-report-...json (metadata payload when --defectdojo-report is set)
USAGE
        exit 0
        ;;
      *) die "Unknown argument: $1" ;;
    esac
  done

  SBOM_PATH="$OUTPUT_DIR/sca-sbom.json"
  DT_FINDINGS_PATH="$OUTPUT_DIR/sca-findings.json"
  SAST_REPORT_PATH="$OUTPUT_DIR/sast-report.json"
  SECRETS_REPORT_PATH="$OUTPUT_DIR/secrets-report.json"
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

  [[ "$ENABLE_SCA" == "true" || "$ENABLE_SAST" == "true" || "$ENABLE_SECRETS" == "true" ]] || die "No scan enabled. Pass --sca <language>, --sast and/or --secrets"

  validate_int "wait-after-sbom-seconds" "$WAIT_AFTER_SBOM_SECONDS"
  validate_int "dt-export-stability-polls" "$DT_EXPORT_STABILITY_POLLS"
  validate_int "dt-export-stability-interval-seconds" "$DT_EXPORT_STABILITY_INTERVAL_SECONDS"
  validate_int "dt-export-stability-timeout-seconds" "$DT_EXPORT_STABILITY_TIMEOUT_SECONDS"
  validate_int "max-critical" "$MAX_CRITICAL"
  validate_int "max-high" "$MAX_HIGH"
  validate_int "max-medium" "$MAX_MEDIUM"
  validate_int "max-low" "$MAX_LOW"
  validate_int "max-total" "$MAX_TOTAL"
  validate_int "dj-upload-timeout" "$DJ_UPLOAD_TIMEOUT"
  validate_int "dj-upload-retries" "$DJ_UPLOAD_RETRIES"
  validate_int "dj-upload-retry-delay" "$DJ_UPLOAD_RETRY_DELAY"

  [[ -e "$SCAN_SOURCE_PATH" ]] || die "Source path not found: $SCAN_SOURCE_PATH"
  mkdir -p "$OUTPUT_DIR"

  if [[ "$ENABLE_SCA" == "true" ]]; then
    [[ -n "$SCA_LANGUAGE" ]] || die "SCA enabled but language is empty. Use --sca <python|java|javascript>"
    SCA_MANIFEST_PATH="$(resolve_sca_manifest "$SCA_LANGUAGE" "$SCAN_SOURCE_PATH" "$SCA_MANIFEST_PATH")"
  fi

  if [[ "$ENABLE_SECRETS" == "true" && -n "$SECRETS_CONFIG_PATH" ]]; then
    [[ -f "$SECRETS_CONFIG_PATH" ]] || die "Secrets config file not found: $SECRETS_CONFIG_PATH"
  fi
}
