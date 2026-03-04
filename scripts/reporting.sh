#!/usr/bin/env bash
# Generates selected JSON/CSV/Markdown local reports from active DefectDojo findings payloads.
set -euo pipefail

has_format() {
  local requested_csv="$1"
  local wanted="$2"
  [[ ",$requested_csv," == *",$wanted,"* ]]
}

write_active_findings_reports() {
  local findings_json="$1"
  local test_metadata_json="$2"
  local output_dir="$3"
  local engagement_name="$4"
  local version="$5"
  local requested_formats_csv="$6"

  mkdir -p "$output_dir"
  local timestamp
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"

  local base_name="engagement-${engagement_name}-version-${version}-${timestamp}"
  local json_path="$output_dir/${base_name}-active-findings.json"
  local csv_path="$output_dir/${base_name}-active-findings.csv"
  local md_path="$output_dir/${base_name}-active-findings.md"

  if has_format "$requested_formats_csv" "json"; then
    printf '%s\n' "$findings_json" | jq . > "$json_path"
    log_event "INFO" "Local active findings report (JSON): $json_path"
  fi

  if has_format "$requested_formats_csv" "csv"; then
    {
      echo 'id,test_name,severity,title,cwe,vulnerability_ids,active,verified,date,component_name,component_version,file_path,line,description,impact,mitigation,steps_to_reproduce,references,url,param,payload'
      jq -r --argjson tests "$test_metadata_json" '
        def as_array:
          if . == null then []
          elif type == "array" then .
          else [.] end;
        .[]
        | [
            (.id // ""),
            ($tests[(.test|tostring)] // "unknown-test"),
            (.severity // ""),
            (.title // ""),
            (.cwe // ""),
            ((.vulnerability_ids | as_array) | map(if type=="object" then (.vulnerability_id // .name // .value // "") else tostring end) | join(";")),
            (.active // ""),
            (.verified // ""),
            (.date // ""),
            (.component_name // ""),
            (.component_version // ""),
            (.file_path // ""),
            (.line // ""),
            (.description // ""),
            (.impact // ""),
            (.mitigation // ""),
            (.steps_to_reproduce // ""),
            ((.references | as_array) | map(if type=="object" then (.url // .title // .name // "") else tostring end) | join(";")),
            (.url // ""),
            (.param // ""),
            (.payload // "")
          ]
        | @csv
      ' <<<"$findings_json"
    } > "$csv_path"
    log_event "INFO" "Local active findings report (CSV): $csv_path"
  fi

  if has_format "$requested_formats_csv" "md"; then
    local critical high medium low info total
    critical="$(jq '[.[] | select((.severity // "" | ascii_downcase) == "critical")] | length' <<<"$findings_json")"
    high="$(jq '[.[] | select((.severity // "" | ascii_downcase) == "high")] | length' <<<"$findings_json")"
    medium="$(jq '[.[] | select((.severity // "" | ascii_downcase) == "medium")] | length' <<<"$findings_json")"
    low="$(jq '[.[] | select((.severity // "" | ascii_downcase) == "low")] | length' <<<"$findings_json")"
    info="$(jq '[.[] | select((.severity // "" | ascii_downcase) == "info")] | length' <<<"$findings_json")"
    total="$(jq 'length' <<<"$findings_json")"

    {
      echo "# Relatorio de Findings Ativos - $engagement_name"
      echo
      echo "- Versao do pipeline: \`$version\`"
      echo "- Gerado em (UTC): \`$timestamp\`"
      echo "- Total de findings ativos: \`$total\`"
      echo
      echo "## Resumo por severidade"
      echo
      echo "- Critical: \`$critical\`"
      echo "- High: \`$high\`"
      echo "- Medium: \`$medium\`"
      echo "- Low: \`$low\`"
      echo "- Info: \`$info\`"
      echo
      echo "## Top 50 findings ativos"
      echo
      echo "| id | severidade | teste | titulo | componente | arquivo |"
      echo "|---|---|---|---|---|---|"
      jq -r --argjson tests "$test_metadata_json" '
        def sev_rank: if .=="critical" then 0 elif .=="high" then 1 elif .=="medium" then 2 elif .=="low" then 3 else 4 end;
        sort_by((.severity // "info" | ascii_downcase | sev_rank), (.id // 0))
        | .[:50][]
        | "| \(.id // "") | \(.severity // "") | \($tests[(.test|tostring)] // "unknown-test") | \((.title // "")|gsub("\\|";"/")) | \((.component_name // "")|gsub("\\|";"/")) | \((.file_path // "")|gsub("\\|";"/")) |"
      ' <<<"$findings_json"
    } > "$md_path"
    log_event "INFO" "Local active findings report (MD): $md_path"
  fi
}
