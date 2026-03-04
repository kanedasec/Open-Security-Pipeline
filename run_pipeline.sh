#!/usr/bin/env bash
# Orchestrates the end-to-end security pipeline:
# config -> optional scans -> DefectDojo imports -> gate -> reports -> optional cleanup.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/logging.sh
source "$SCRIPT_DIR/lib/logging.sh"
# shellcheck source=lib/state.sh
source "$SCRIPT_DIR/lib/state.sh"
# shellcheck source=lib/config.sh
source "$SCRIPT_DIR/lib/config.sh"
# shellcheck source=lib/dt.sh
source "$SCRIPT_DIR/lib/dt.sh"
# shellcheck source=lib/dj.sh
source "$SCRIPT_DIR/lib/dj.sh"
# shellcheck source=lib/sast.sh
source "$SCRIPT_DIR/lib/sast.sh"
# shellcheck source=lib/secrets.sh
source "$SCRIPT_DIR/lib/secrets.sh"
# shellcheck source=lib/gate.sh
source "$SCRIPT_DIR/lib/gate.sh"
# shellcheck source=lib/reporting.sh
source "$SCRIPT_DIR/lib/reporting.sh"
# shellcheck source=lib/cleanup.sh
source "$SCRIPT_DIR/lib/cleanup.sh"

main() {
  parse_args "$SCRIPT_DIR" "$@"
  validate_args

  require_bin curl
  require_bin jq

  log_step "VERSION"
  local version="$PIPELINE_VERSION"
  log_event "INFO" "Pipeline version (argument): $version"
  log_event "INFO" "Stable engagement name: $ENGAGEMENT_NAME"
  log_event "INFO" "Scan source path: $SCAN_SOURCE_PATH"
  log_event "INFO" "Global output directory: $OUTPUT_DIR"
  if [[ -n "${PIPELINE_REPORT_FORMATS:-}" ]]; then
    log_event "INFO" "Pipeline report formats: $PIPELINE_REPORT_FORMATS"
  else
    log_event "INFO" "Pipeline report disabled (use --pipeline-report json,csv,md)"
  fi

  local scan_tags
  scan_tags="$(build_scan_tags "$EXTRA_TAGS")"
  if [[ -n "$scan_tags" ]]; then
    log_event "INFO" "Scan tags: $scan_tags"
  fi

  local dt_response=""
  local sast_response=""
  local secrets_response=""

  if [[ "$ENABLE_SCA" == "true" ]]; then
    log_step "SCA_CONFIG"
    log_event "INFO" "SCA language: $SCA_LANGUAGE"
    log_event "INFO" "SCA manifest source: $SCA_MANIFEST_PATH"

    log_call "run_dependency_track_sca"
    run_dependency_track_sca "$DT_URL" "$DT_API_KEY" "$PROJECT_NAME" "$ENGAGEMENT_NAME" "$version" "$SCA_LANGUAGE" "$SCA_MANIFEST_PATH" "$SBOM_PATH" "$DT_FINDINGS_PATH" "$WAIT_AFTER_SBOM_SECONDS" "$DT_EXPORT_STABILITY_POLLS" "$DT_EXPORT_STABILITY_INTERVAL_SECONDS" "$DT_EXPORT_STABILITY_TIMEOUT_SECONDS"

    log_step "SCA_IMPORT_DEFECTDOJO"
    log_call "upload_dt_to_dj"
    dt_response="$(upload_dt_to_dj "$DJ_URL" "$DJ_API_KEY" "$DT_FINDINGS_PATH" "$PRODUCT_NAME" "$PRODUCT_TYPE_NAME" "$ENGAGEMENT_NAME" "$version" "$scan_tags" "")"
    local resolved_dt_test_id
    resolved_dt_test_id="$(extract_test_id "$dt_response")"
    if [[ -n "$resolved_dt_test_id" ]]; then
      log_event "INFO" "DT test ID: $resolved_dt_test_id"
    fi
  else
    log_event "INFO" "SCA disabled (use --sca <python|java|javascript> to enable)"
  fi

  local sast_scan_type=""
  if [[ "$ENABLE_SAST" == "true" ]]; then
    log_step "SAST_ANALYSIS"
    log_call "execute_sast_scan"
    sast_scan_type="$(execute_sast_scan "$SAST_TOOL" "$SCAN_SOURCE_PATH" "$SAST_REPORT_PATH" "$SAST_EXCLUDE")"

    log_step "DEFECTDOJO_IMPORT_SAST"
    log_call "upload_sast_to_dj"
    sast_response="$(upload_sast_to_dj "$DJ_URL" "$DJ_API_KEY" "$SAST_REPORT_PATH" "$PRODUCT_NAME" "$PRODUCT_TYPE_NAME" "$ENGAGEMENT_NAME" "$version" "$sast_scan_type" "$DJ_UPLOAD_TIMEOUT" "$DJ_UPLOAD_RETRIES" "$DJ_UPLOAD_RETRY_DELAY" "$scan_tags" "")"
    local resolved_sast_test_id
    resolved_sast_test_id="$(extract_test_id "$sast_response")"
    if [[ -n "$resolved_sast_test_id" ]]; then
      log_event "INFO" "SAST test ID: $resolved_sast_test_id"
    fi
  else
    log_event "INFO" "SAST disabled (use --sast to enable)"
  fi

  local secrets_scan_type=""
  if [[ "$ENABLE_SECRETS" == "true" ]]; then
    log_step "SECRETS_ANALYSIS"
    log_call "execute_secrets_scan"
    if [[ -n "${SECRETS_CONFIG_PATH:-}" ]]; then
      log_event "INFO" "Secrets config path: $SECRETS_CONFIG_PATH"
    fi
    secrets_scan_type="$(execute_secrets_scan "$SECRETS_TOOL" "$SCAN_SOURCE_PATH" "$SECRETS_REPORT_PATH" "$SECRETS_EXCLUDE" "$SECRETS_SCAN_TYPE" "${SECRETS_CONFIG_PATH:-}")"

    log_step "DEFECTDOJO_IMPORT_SECRETS"
    log_call "upload_file_to_defectdojo"
    secrets_response="$(upload_file_to_defectdojo "$DJ_URL" "$DJ_API_KEY" "$SECRETS_REPORT_PATH" "$secrets_scan_type" "$PRODUCT_NAME" "$PRODUCT_TYPE_NAME" "$ENGAGEMENT_NAME" "$version" "$DJ_UPLOAD_TIMEOUT" "$DJ_UPLOAD_RETRIES" "$DJ_UPLOAD_RETRY_DELAY" "$scan_tags" "" "Secrets")"
    local resolved_secrets_test_id
    resolved_secrets_test_id="$(extract_test_id "$secrets_response")"
    if [[ -n "$resolved_secrets_test_id" ]]; then
      log_event "INFO" "Secrets test ID: $resolved_secrets_test_id"
    fi
  else
    log_event "INFO" "Secrets scan disabled (use --secrets to enable)"
  fi

  local current_test_ids=()
  if [[ -n "$dt_response" ]]; then
    local tid
    tid="$(extract_test_id "$dt_response")"
    [[ -n "$tid" ]] && current_test_ids+=("$tid")
  fi
  if [[ -n "$sast_response" ]]; then
    local tid
    tid="$(extract_test_id "$sast_response")"
    [[ -n "$tid" ]] && current_test_ids+=("$tid")
  fi
  if [[ -n "$secrets_response" ]]; then
    local tid
    tid="$(extract_test_id "$secrets_response")"
    [[ -n "$tid" ]] && current_test_ids+=("$tid")
  fi

  local current_test_ids_csv=""
  if [[ ${#current_test_ids[@]} -gt 0 ]]; then
    local IFS=,
    current_test_ids_csv="${current_test_ids[*]}"
  fi

  local engagement_id="$ENGAGEMENT_ID"
  if [[ -z "$engagement_id" && -n "$dt_response" ]]; then
    engagement_id="$(extract_engagement_id "$dt_response")"
  fi
  if [[ -z "$engagement_id" && -n "$sast_response" ]]; then
    engagement_id="$(extract_engagement_id "$sast_response")"
  fi
  if [[ -z "$engagement_id" && -n "$secrets_response" ]]; then
    engagement_id="$(extract_engagement_id "$secrets_response")"
  fi

  if [[ -z "$engagement_id" ]]; then
    log_step "DEFECTDOJO_RESOLVE_ENGAGEMENT"
    log_call "resolve_engagement_id"
    engagement_id="$(resolve_engagement_id "$DJ_URL" "$DJ_API_KEY" "$PRODUCT_NAME" "$ENGAGEMENT_NAME")"
  fi

  if [[ -z "$engagement_id" ]]; then
    die "Could not resolve DefectDojo engagement ID for gating"
  fi

  log_event "INFO" "Using engagement ID for gate: $engagement_id"

  log_step "DEFECTDOJO_FETCH_FINDINGS"
  log_call "fetch_open_findings"
  local findings_json
  findings_json="$(fetch_open_findings "$DJ_URL" "$DJ_API_KEY" "$engagement_id" "$current_test_ids_csv")"

  log_step "DEFECTDOJO_GATE"
  log_call "fetch_test_metadata"
  local test_metadata_json
  test_metadata_json="$(fetch_test_metadata "$DJ_URL" "$DJ_API_KEY" "$findings_json")"

  log_call "evaluate_gate"
  local gate_result=0
  if ! evaluate_gate "$findings_json" "$test_metadata_json" "$MAX_CRITICAL" "$MAX_HIGH" "$MAX_MEDIUM" "$MAX_LOW" "$MAX_TOTAL"; then
    gate_result=1
  fi

  if [[ -n "${PIPELINE_REPORT_FORMATS:-}" ]]; then
    log_step "PIPELINE_REPORT"
    log_call "write_active_findings_reports"
    write_active_findings_reports "$findings_json" "$test_metadata_json" "$OUTPUT_DIR" "$ENGAGEMENT_NAME" "$version" "$PIPELINE_REPORT_FORMATS"
  fi

  if [[ "$SKIP_DEFECTDOJO_REPORT" == "false" ]]; then
    log_call "generate_defectdojo_engagement_report"
    local report_payload
    report_payload="$(generate_defectdojo_engagement_report "$DJ_URL" "$DJ_API_KEY" "$engagement_id" "$REPORT_LANGUAGE")"
    local report_timestamp safe_engagement_name report_payload_path
    report_timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    safe_engagement_name="$(sed 's/[^A-Za-z0-9._-]/_/g' <<<"$ENGAGEMENT_NAME")"
    report_payload_path="$OUTPUT_DIR/defectdojo-engagement-report-${safe_engagement_name}-${version}-${report_timestamp}.json"
    printf '%s\n' "$report_payload" | jq . > "$report_payload_path" 2>/dev/null || printf '%s\n' "$report_payload" > "$report_payload_path"
    log_event "INFO" "DefectDojo report metadata saved: $report_payload_path"
    local report_failed
    report_failed="$(jq -r '(.report_request_failed // false)' <<<"$report_payload" 2>/dev/null || echo "false")"
    if [[ "$report_failed" == "true" ]]; then
      log_event "WARN" "DefectDojo engagement report request failed or timed out"
    else
      local report_task
      report_task="$(jq -r '(.task_id // .id // "")' <<<"$report_payload")"
      if [[ -n "$report_task" ]]; then
        log_event "INFO" "DefectDojo engagement report generation started (task=$report_task)"
      else
        log_event "INFO" "DefectDojo engagement report generation requested"
      fi
    fi
  fi

  if [[ "$gate_result" -ne 0 && "$BYPASS" == "true" ]]; then
    log_event "WARN" "Gate failed but bypass is enabled. Returning success."
    gate_result=0
  fi

  if [[ "$CLEANUP_JSON" == "true" ]]; then
    log_step "CLEAN_UP"
    log_call "cleanup_tmp_json"
    cleanup_tmp_json "$OUTPUT_DIR"
  fi

  return "$gate_result"
}

main "$@"
