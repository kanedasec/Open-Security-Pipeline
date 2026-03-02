#!/usr/bin/env bash
# Evaluates gate thresholds from active DefectDojo findings and prints pass/fail summary.
set -euo pipefail

evaluate_gate() {
  local findings_json="$1"
  local test_metadata_json="$2"
  local max_critical="$3"
  local max_high="$4"
  local max_medium="$5"
  local max_low="$6"
  local max_total="$7"

  local critical high medium low total
  critical="$(jq '[.[] | select((.severity // "Info" | ascii_downcase) == "critical")] | length' <<<"$findings_json")"
  high="$(jq '[.[] | select((.severity // "Info" | ascii_downcase) == "high")] | length' <<<"$findings_json")"
  medium="$(jq '[.[] | select((.severity // "Info" | ascii_downcase) == "medium")] | length' <<<"$findings_json")"
  low="$(jq '[.[] | select((.severity // "Info" | ascii_downcase) == "low")] | length' <<<"$findings_json")"
  total="$(jq 'length' <<<"$findings_json")"

  echo "Open findings by severity:"
  jq -n --argjson critical "$critical" --argjson high "$high" --argjson medium "$medium" --argjson low "$low" --argjson total "$total" '{critical:$critical,high:$high,medium:$medium,low:$low,total:$total}'

  echo "Vulnerabilities by test:"
  jq -r --argjson tests "$test_metadata_json" '
    sort_by(.test)
    | group_by(.test)[]
    | select((.[0].test | type) == "number")
    | . as $g
    | ($g[0].test | tostring) as $tid
    | "- test_id=\($tid) name='\''\($tests[$tid] // "unknown-test")'\'' critical=\([$g[] | select((.severity // "" | ascii_downcase) == "critical")] | length) high=\([$g[] | select((.severity // "" | ascii_downcase) == "high")] | length) medium=\([$g[] | select((.severity // "" | ascii_downcase) == "medium")] | length) low=\([$g[] | select((.severity // "" | ascii_downcase) == "low")] | length) total=\($g | length)"
  ' <<<"$findings_json"

  local breaches=()
  (( critical > max_critical )) && breaches+=("critical=$critical exceeds max_critical=$max_critical")
  (( high > max_high )) && breaches+=("high=$high exceeds max_high=$max_high")
  (( medium > max_medium )) && breaches+=("medium=$medium exceeds max_medium=$max_medium")
  (( low > max_low )) && breaches+=("low=$low exceeds max_low=$max_low")
  (( total > max_total )) && breaches+=("total=$total exceeds max_total=$max_total")

  if [[ ${#breaches[@]} -gt 0 ]]; then
    echo
    echo "############################################################"
    echo "#               SECURITY GATE STATUS: FAILED               #"
    echo "############################################################"
    log_event "GATE" "DefectDojo gate failed"
    for breach in "${breaches[@]}"; do
      echo "- $breach"
    done
    return 1
  fi

  echo
  echo "############################################################"
  echo "#               SECURITY GATE STATUS: PASSED               #"
  echo "############################################################"
  log_event "GATE" "DefectDojo gate passed"
}
