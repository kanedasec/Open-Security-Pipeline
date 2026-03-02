#!/usr/bin/env bash
# Wraps DefectDojo API calls for engagement resolution, findings retrieval, and scan imports.
set -euo pipefail

dj_request() {
  local method="$1"
  local url="$2"
  local api_key="$3"
  local data="${4:-}"
  local content_type="${5:-application/json}"

  local body_file
  body_file="$(mktemp)"
  local status
  if [[ -n "$data" ]]; then
    status="$(curl -sSL -X "$method" "$url" -H "Authorization: $api_key" -H "Content-Type: $content_type" -d "$data" --connect-timeout 10 --max-time 120 -o "$body_file" -w '%{http_code}')"
  else
    status="$(curl -sSL -X "$method" "$url" -H "Authorization: $api_key" --connect-timeout 10 --max-time 120 -o "$body_file" -w '%{http_code}')"
  fi

  local body
  body="$(cat "$body_file")"
  rm -f "$body_file"

  if [[ ! "$status" =~ ^[0-9]{3}$ ]]; then
    echo "DefectDojo API error (invalid status): $status" >&2
    return 1
  fi

  if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
    echo "DefectDojo API error ($status): ${body:0:2000}" >&2
    return 1
  fi

  jq -e . >/dev/null <<<"$body" || die "DefectDojo API returned non-JSON payload for $method $url"
  printf '%s' "$body"
}

resolve_engagement_id() {
  local dj_url="$1"
  local dj_api_key="$2"
  local product_name="$3"
  local engagement_name="$4"

  local payload
  payload="$(dj_request GET "$dj_url/api/v2/engagements/?name=$(url_encode "$engagement_name")&product_name=$(url_encode "$product_name")&limit=1&offset=0&ordering=-id" "$dj_api_key")"
  jq -r '.results[0].id // ""' <<<"$payload"
}

resolve_recent_test_after_timeout() {
  local dj_url="$1"
  local dj_api_key="$2"
  local product_name="$3"
  local engagement_name="$4"
  local version="$5"
  local scan_type="$6"

  local engagement_id
  engagement_id="$(resolve_engagement_id "$dj_url" "$dj_api_key" "$product_name" "$engagement_name" || true)"
  [[ -n "$engagement_id" ]] || return 1

  local tests_payload
  tests_payload="$(dj_request GET "$dj_url/api/v2/tests/?engagement=$engagement_id&ordering=-id&limit=50" "$dj_api_key" || true)"
  [[ -n "$tests_payload" ]] || return 1

  local matched_test_id
  matched_test_id="$(jq -r --arg version "$version" --arg scan_type "$scan_type" '
    .results[]
    | select((.version // "") == $version)
    | select(
        (.test_type_name // "") == $scan_type
        or ((.title // "" | ascii_downcase) | contains($scan_type | ascii_downcase))
      )
    | .id
  ' <<<"$tests_payload" | head -n1)"

  [[ -n "$matched_test_id" ]] || return 1
  printf '%s,%s\n' "$engagement_id" "$matched_test_id"
}

upload_file_to_defectdojo() {
  local dj_url="$1"
  local dj_api_key="$2"
  local report_path="$3"
  local scan_type="$4"
  local product_name="$5"
  local product_type_name="$6"
  local engagement_name="$7"
  local version="$8"
  local timeout_seconds="$9"
  local retries="${10}"
  local retry_delay_seconds="${11}"
  local tags="${12}"
  local test_id="${13}"
  local label="${14}"

  local attempt max_attempts
  max_attempts=$((retries + 1))
  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    local curl_args=(
      -sS
      -X POST "$dj_url/api/v2/reimport-scan/"
      -H "Authorization: $dj_api_key"
      -F "scan_type=$scan_type"
      -F "product_name=$product_name"
      -F "version=$version"
      -F "product_type_name=$product_type_name"
      -F "auto_create_context=true"
      -F "engagement_name=$engagement_name"
      -F "file=@$report_path;type=application/json"
      --max-time "$timeout_seconds"
      -w '%{http_code}'
    )

    [[ -n "$tags" ]] && curl_args+=( -F "tags=$tags" )
    [[ -n "$test_id" ]] && curl_args+=( -F "test=$test_id" )

    local body_file
    body_file="$(mktemp)"

    set +e
    local status
    status="$(curl "${curl_args[@]}" -o "$body_file")"
    local curl_rc=$?
    set -e

    local body=""
    [[ -f "$body_file" ]] && body="$(cat "$body_file")"
    rm -f "$body_file"

    [[ "$status" =~ ^[0-9]{3}$ ]] || status="000"

    if [[ "$status" -ge 200 && "$status" -lt 300 ]]; then
      echo "$label findings imported into Defect Dojo" >&2
      local resolved_test_id
      resolved_test_id="$(jq -r '(.test_id // .test // "")' <<<"$body")"
      local resolved_engagement_id
      resolved_engagement_id="$(jq -r '(.engagement_id // .engagement // "")' <<<"$body")"
      [[ -n "$resolved_test_id" ]] && echo "DefectDojo test_id: $resolved_test_id" >&2
      [[ -n "$resolved_engagement_id" ]] && echo "DefectDojo engagement_id: $resolved_engagement_id" >&2
      local import_summary
      import_summary="$(jq -r '
        [
          (if has("message") then "message=" + (.message|tostring) else empty end),
          (if has("created_findings") then "created_findings=" + (.created_findings|tostring) else empty end),
          (if has("closed_findings") then "closed_findings=" + (.closed_findings|tostring) else empty end),
          (if has("left_untouched") then "left_untouched=" + (.left_untouched|tostring) else empty end),
          (if has("reactivated_findings") then "reactivated_findings=" + (.reactivated_findings|tostring) else empty end),
          (if has("finding_count") then "finding_count=" + (.finding_count|tostring) else empty end),
          (if has("total_findings") then "total_findings=" + (.total_findings|tostring) else empty end)
        ] | join(", ")
      ' <<<"$body" 2>/dev/null || true)"
      [[ -n "$import_summary" ]] && echo "DefectDojo import summary: $import_summary" >&2
      printf '%s\n' "$body"
      return 0
    fi

    if [[ "$status" == "400" && -n "$test_id" ]]; then
      echo "$label upload returned 400 with persisted test_id=$test_id. Retrying without test_id..." >&2
      upload_file_to_defectdojo "$dj_url" "$dj_api_key" "$report_path" "$scan_type" "$product_name" "$product_type_name" "$engagement_name" "$version" "$timeout_seconds" "$retries" "$retry_delay_seconds" "$tags" "" "$label"
      return 0
    fi

    if [[ "$attempt" -lt "$max_attempts" ]]; then
      echo "$label upload timed out or failed (attempt ${attempt}/${max_attempts}), retrying in ${retry_delay_seconds}s..." >&2
      sleep "$retry_delay_seconds"
      continue
    fi

    if [[ "$curl_rc" -eq 28 ]]; then
      local recovered
      recovered="$(resolve_recent_test_after_timeout "$dj_url" "$dj_api_key" "$product_name" "$engagement_name" "$version" "$scan_type" || true)"
      if [[ -n "$recovered" ]]; then
        local recovered_engagement_id recovered_test_id
        recovered_engagement_id="$(cut -d',' -f1 <<<"$recovered")"
        recovered_test_id="$(cut -d',' -f2 <<<"$recovered")"
        echo "$label upload timed out but matching DefectDojo test was found (engagement_id=$recovered_engagement_id test_id=$recovered_test_id). Continuing." >&2
        jq -n --argjson engagement_id "$recovered_engagement_id" --argjson test_id "$recovered_test_id" \
          '{engagement_id:$engagement_id,test_id:$test_id,recovered_after_timeout:true}'
        return 0
      fi
    fi

    if [[ -z "$body" ]]; then
      die "$label upload failed (curl_rc=$curl_rc, status=$status)"
    fi
    die "$label upload failed ($status): ${body:0:2000}"
  done
}

upload_dt_to_dj() {
  upload_file_to_defectdojo "$1" "$2" "$3" "Dependency Track Finding Packaging Format (FPF) Export" "$4" "$5" "$6" "$7" 120 0 5 "$8" "$9" "SCA (Dependency-Track)"
}

upload_sast_to_dj() {
  upload_file_to_defectdojo "$1" "$2" "$3" "$8" "$4" "$5" "$6" "$7" "$9" "${10}" "${11}" "${12}" "${13}" "SAST"
}

fetch_open_findings() {
  local dj_url="$1"
  local dj_api_key="$2"
  local engagement_id="$3"
  local test_ids_csv="${4:-}"

  local output='[]'
  local limit=200
  local page_count=0
  local started_at
  started_at="$(date +%s)"

  local base_url
  base_url="$dj_url/api/v2/findings/?test__engagement=$engagement_id&active=true&is_mitigated=false&duplicate=false&false_p=false&limit=$limit"
  if [[ -n "${test_ids_csv// }" ]]; then
    local normalized_test_ids_csv
    normalized_test_ids_csv="$(tr ' ' ',' <<<"$test_ids_csv" | sed 's/,,*/,/g; s/^,//; s/,$//')"
    base_url+="&test__in=$(url_encode "$normalized_test_ids_csv")"
  fi

  local offset=0
  while true; do
    local payload
    payload="$(dj_request GET "${base_url}&offset=$offset" "$dj_api_key")"
    jq -e . >/dev/null <<<"$payload" || die "DefectDojo findings API returned non-JSON payload"

    local incoming
    incoming="$(jq -c '.results // []' <<<"$payload")"
    output="$(jq -cs '.[0] + .[1]' <(printf '%s\n' "$output") <(printf '%s\n' "$incoming"))"

    page_count=$((page_count + 1))
    local has_next
    has_next="$(jq -r '.next // empty' <<<"$payload")"
    [[ -z "$has_next" || "$has_next" == "null" ]] && break
    offset=$((offset + limit))
  done

  local finished_at
  finished_at="$(date +%s)"
  local total_count
  total_count="$(jq 'length' <<<"$output")"
  log_event "INFO" "DefectDojo findings fetch completed: pages=$page_count findings=$total_count seconds=$((finished_at - started_at))" >&2
  jq -c 'unique_by(.id)' <<<"$output"
}

fetch_test_metadata() {
  local dj_url="$1"
  local dj_api_key="$2"
  local findings_json="$3"

  local test_ids
  test_ids="$(jq -r '.[] | select(.test|type=="number") | .test' <<<"$findings_json" | sort -n | uniq)"

  local metadata='{}'
  while IFS= read -r test_id; do
    [[ -z "$test_id" ]] && continue
    local payload
    if payload="$(dj_request GET "$dj_url/api/v2/tests/$test_id/" "$dj_api_key")"; then
      local name
      name="$(jq -r '(.title // .test_type_name // .test_type // "unknown-test")' <<<"$payload")"
      metadata="$(jq -c --arg tid "$test_id" --arg name "$name" '. + {($tid): $name}' <<<"$metadata")"
    else
      metadata="$(jq -c --arg tid "$test_id" '. + {($tid): "unknown-test"}' <<<"$metadata")"
    fi
  done <<<"$test_ids"

  printf '%s\n' "$metadata"
}

generate_defectdojo_engagement_report() {
  local dj_url="$1"
  local dj_api_key="$2"
  local engagement_id="$3"
  local report_language="$4"

  local endpoint
  endpoint="$dj_url/api/v2/engagements/$engagement_id/generate_report/"
  local timeout_seconds="${DJ_REPORT_TIMEOUT:-30}"

  local body_file status body curl_rc
  body_file="$(mktemp)"
  local payload
  payload="$(jq -n --arg lang "$report_language" '{include_finding_notes: "true", include_finding_images: "true", include_executive_summary: "true", include_table_of_contents: "true", language: $lang}')"

  set +e
  status="$(curl -sSL -X POST "$endpoint" \
    -H "Authorization: $dj_api_key" \
    -H "Content-Type: application/json" \
    --connect-timeout 10 \
    --max-time "$timeout_seconds" \
    -d "$payload" \
    -o "$body_file" \
    -w '%{http_code}')"
  curl_rc=$?
  set -e

  body="$(cat "$body_file")"
  rm -f "$body_file"

  if [[ $curl_rc -eq 0 && "$status" -ge 200 && "$status" -lt 300 ]]; then
    jq -e . >/dev/null <<<"$body" || die "DefectDojo report API returned non-JSON payload"
    printf '%s\n' "$body"
    return 0
  fi

  # Retry without language only for explicit language validation errors.
  if [[ $curl_rc -eq 0 && "$status" == "400" && "$body" == *language* ]]; then
    body_file="$(mktemp)"
    payload="$(jq -n '{include_finding_notes: "true", include_finding_images: "true", include_executive_summary: "true", include_table_of_contents: "true"}')"
    set +e
    status="$(curl -sSL -X POST "$endpoint" \
      -H "Authorization: $dj_api_key" \
      -H "Content-Type: application/json" \
      --connect-timeout 10 \
      --max-time "$timeout_seconds" \
      -d "$payload" \
      -o "$body_file" \
      -w '%{http_code}')"
    curl_rc=$?
    set -e
    body="$(cat "$body_file")"
    rm -f "$body_file"

    if [[ $curl_rc -eq 0 && "$status" -ge 200 && "$status" -lt 300 ]]; then
      jq -e . >/dev/null <<<"$body" || die "DefectDojo report API returned non-JSON payload"
      printf '%s\n' "$body"
      return 0
    fi
  fi

  log_event "WARN" "DefectDojo engagement report request failed (curl_rc=$curl_rc status=$status). Continuing without blocking."
  printf '%s\n' '{"report_request_failed":true}'
}
