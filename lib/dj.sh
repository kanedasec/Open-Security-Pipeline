#!/usr/bin/env bash
# Wraps DefectDojo API calls for engagement resolution, findings retrieval, and scan imports.
set -euo pipefail

dj_request() {
  local method="$1"
  local url="$2"
  local api_key="$3"
  local data="${4:-}"
  local content_type="${5:-application/json}"

  local response
  if [[ -n "$data" ]]; then
    response="$(curl -sSL -X "$method" "$url" -H "Authorization: $api_key" -H "Content-Type: $content_type" -d "$data" -w '\n%{http_code}')"
  else
    response="$(curl -sSL -X "$method" "$url" -H "Authorization: $api_key" -w '\n%{http_code}')"
  fi

  local status body
  status="$(tail -n1 <<<"$response")"
  body="$(sed '$d' <<<"$response")"

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
      -w '\n%{http_code}'
    )

    [[ -n "$tags" ]] && curl_args+=( -F "tags=$tags" )
    [[ -n "$test_id" ]] && curl_args+=( -F "test=$test_id" )

    set +e
    local response
    response="$(curl "${curl_args[@]}")"
    local curl_rc=$?
    set -e

    local status="000"
    local body=""
    if [[ $curl_rc -eq 0 ]]; then
      status="$(tail -n1 <<<"$response")"
      body="$(sed '$d' <<<"$response")"
    fi

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

  local targets=()
  if [[ -n "$test_ids_csv" ]]; then
    read -r -a targets <<<"$test_ids_csv"
  else
    targets=("ALL")
  fi

  for test_id in "${targets[@]}"; do
    local offset=0
    while true; do
      local url="$dj_url/api/v2/findings/?test__engagement=$engagement_id&active=true&is_mitigated=false&duplicate=false&false_p=false&limit=$limit&offset=$offset"
      [[ "$test_id" != "ALL" ]] && url+="&test=$test_id"
      local payload
      payload="$(dj_request GET "$url" "$dj_api_key")"
      jq -e . >/dev/null <<<"$payload" || die "DefectDojo findings API returned non-JSON payload"

      local incoming
      incoming="$(jq -c '.results // []' <<<"$payload")"
      output="$(jq -cs '.[0] + .[1]' <(printf '%s\n' "$output") <(printf '%s\n' "$incoming"))"

      local has_next
      has_next="$(jq -r '.next // empty' <<<"$payload")"
      [[ -z "$has_next" || "$has_next" == "null" ]] && break
      offset=$((offset + limit))
    done
  done

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

  local payload result
  payload="$(jq -n --arg lang "$report_language" '{include_finding_notes: "true", include_finding_images: "true", include_executive_summary: "true", include_table_of_contents: "true", language: $lang}')"

  if result="$(dj_request POST "$dj_url/api/v2/engagements/$engagement_id/generate_report/" "$dj_api_key" "$payload")"; then
    printf '%s\n' "$result"
    return 0
  fi

  payload="$(jq -n '{include_finding_notes: "true", include_finding_images: "true", include_executive_summary: "true", include_table_of_contents: "true"}')"
  result="$(dj_request POST "$dj_url/api/v2/engagements/$engagement_id/generate_report/" "$dj_api_key" "$payload")"
  printf '%s\n' "$result"
}
