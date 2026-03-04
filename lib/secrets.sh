#!/usr/bin/env bash
# Runs secrets scanners (currently Gitleaks), normalizes output path, and returns DefectDojo scan type.
set -euo pipefail

build_gitleaks_redact_args() {
  local args=()

  # Prefer --redact if available (newer gitleaks), otherwise continue without it.
  if gitleaks --help 2>/dev/null | grep -q -- '--redact'; then
    args+=(--redact)
  fi

  printf '%s\n' "${args[*]}"
}

execute_secrets_scan() {
  local secrets_tool="$1"
  local source_path="$2"
  local report_path="$3"
  local exclude_paths="$4"
  local scan_type="$5"
  local config_path="${6:-}"

  local tool
  tool="$(tr '[:upper:]' '[:lower:]' <<<"$secrets_tool")"
  [[ "$tool" == "gitleaks" ]] || die "Unsupported --secrets-tool '$secrets_tool'. Supported tools: gitleaks"

  require_bin gitleaks
  mkdir -p "$(dirname "$report_path")"

  local redact_args_raw
  redact_args_raw="$(build_gitleaks_redact_args)"
  local redact_args=()
  if [[ -n "$redact_args_raw" ]]; then
    # shellcheck disable=SC2206
    redact_args=( $redact_args_raw )
  fi

  local cmd=(gitleaks dir "$source_path" --report-format json --report-path "$report_path" --exit-code 0 --no-banner)
  if [[ -n "$config_path" ]]; then
    cmd+=(-c "$config_path")
  fi
  if [[ -n "${exclude_paths// }" ]]; then
    if gitleaks dir --help 2>/dev/null | grep -q -- '--exclude-path'; then
      cmd+=(--exclude-path "$exclude_paths")
    else
      log_event "WARN" "Installed gitleaks does not support --exclude-path; ignoring --secrets-exclude='$exclude_paths'" >&2
    fi
  fi
  if [[ ${#redact_args[@]} -gt 0 ]]; then
    cmd+=("${redact_args[@]}")
  fi

  log_event "INFO" "Secrets (gitleaks) exclude patterns: $exclude_paths" >&2
  log_event "INFO" "Secrets (gitleaks) command: ${cmd[*]}" >&2

  set +e
  "${cmd[@]}" 1>&2
  local rc=$?
  set -e

  # Fallback to legacy 'detect' only when target is a git repository.
  if [[ "$rc" -ne 0 && ! -f "$report_path" ]]; then
    if git -C "$source_path" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      local fallback_cmd=(gitleaks detect --source "$source_path" --report-format json --report-path "$report_path" --exit-code 0 --no-banner)
      if [[ -n "$config_path" ]]; then
        fallback_cmd+=(-c "$config_path")
      fi
      if [[ ${#redact_args[@]} -gt 0 ]]; then
        fallback_cmd+=("${redact_args[@]}")
      fi
      log_event "WARN" "Gitleaks 'dir' failed, trying fallback 'detect' command" >&2
      log_event "INFO" "Secrets (gitleaks) fallback command: ${fallback_cmd[*]}" >&2
      "${fallback_cmd[@]}" 1>&2 || true
    fi
  fi

  # Ensure a valid JSON file exists for downstream DefectDojo upload.
  if [[ ! -f "$report_path" ]]; then
    printf '[]\n' > "$report_path"
  fi

  [[ -f "$report_path" ]] || die "Secrets (gitleaks) report not created: $report_path"

  local total
  total="$(jq 'if type=="array" then length else (.findings // .results // []) | length end' "$report_path" 2>/dev/null || echo "0")"
  log_event "INFO" "Secrets (gitleaks) report findings: total=$total" >&2

  printf '%s\n' "$scan_type"
}
