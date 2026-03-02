#!/usr/bin/env bash
# Runs SAST tools (currently Bandit), normalizes output, and returns DefectDojo scan type.
set -euo pipefail

filter_bandit_json_report() {
  local report_path="$1"
  local exclude_paths="$2"

  local jq_filter
  jq_filter='def trim: sub("^ +";"") | sub(" +$";"");
    ($exclude | split(",") | map(trim) | map(select(length > 0))) as $parts |
    .results |= map(select(
      .filename as $f |
      (any($parts[]; . as $p | ($f | contains($p)))) | not
    ))'

  local tmp
  tmp="$(mktemp)"
  jq --arg exclude "$exclude_paths" "$jq_filter" "$report_path" > "$tmp"
  mv "$tmp" "$report_path"
}

execute_sast_scan() {
  local sast_tool="$1"
  local source_path="$2"
  local report_path="$3"
  local exclude_paths="$4"

  local tool
  tool="$(tr '[:upper:]' '[:lower:]' <<<"$sast_tool")"
  [[ "$tool" == "bandit" ]] || die "Unsupported --sast-tool '$sast_tool'. Supported tools: bandit"

  require_bin bandit
  mkdir -p "$(dirname "$report_path")"

  local cmd=(bandit)
  local cwd
  local target

  local apply_excludes="true"
  if [[ -d "$source_path" ]]; then
    cwd="$source_path"
    cmd+=( -r . )
  else
    cwd="$(dirname "$source_path")"
    target="$(basename "$source_path")"
    cmd+=( "$target" )
    # If scanning a single file, do not apply broad directory excludes
    # (for example "tmp") that can suppress the explicit target.
    apply_excludes="false"
  fi

  if [[ "$apply_excludes" == "true" && -n "${exclude_paths// }" ]]; then
    cmd+=( -x "$exclude_paths" )
  fi
  cmd+=( -f json -o "$report_path" --exit-zero )

  log_event "INFO" "SAST (bandit) exclude patterns: $exclude_paths" >&2
  log_event "INFO" "SAST (bandit) command: ${cmd[*]}" >&2
  (cd "$cwd" && "${cmd[@]}" 1>&2)

  [[ -f "$report_path" ]] || die "SAST (bandit) report not created: $report_path"

  if [[ "$apply_excludes" == "true" && -n "${exclude_paths// }" ]]; then
    filter_bandit_json_report "$report_path" "$exclude_paths"
  fi

  local total high medium low
  total="$(jq '.results | length' "$report_path")"
  high="$(jq '[.results[] | select((.issue_severity // "" | ascii_downcase) == "high")] | length' "$report_path")"
  medium="$(jq '[.results[] | select((.issue_severity // "" | ascii_downcase) == "medium")] | length' "$report_path")"
  low="$(jq '[.results[] | select((.issue_severity // "" | ascii_downcase) == "low")] | length' "$report_path")"
  log_event "INFO" "SAST (bandit) report findings: total=$total high=$high medium=$medium low=$low" >&2

  printf '%s\n' "Bandit Scan"
}
