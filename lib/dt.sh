#!/usr/bin/env bash
# Implements Dependency-Track workflow: project handling, SBOM generation/upload, and findings export.
set -euo pipefail

api_json() {
  local method="$1"
  local url="$2"
  local api_key="$3"
  local payload="${4:-}"

  local response
  if [[ -n "$payload" ]]; then
    response="$(curl -sSL -X "$method" "$url" -H "X-Api-Key: $api_key" -H "Content-Type: application/json" -d "$payload" -w '\n%{http_code}')"
  else
    response="$(curl -sSL -X "$method" "$url" -H "X-Api-Key: $api_key" -H "Content-Type: application/json" -w '\n%{http_code}')"
  fi

  local status
  status="$(tail -n1 <<<"$response")"
  local body
  body="$(sed '$d' <<<"$response")"

  if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
    if [[ "$status" == "409" ]]; then
      return 9
    fi
    die "Dependency-Track API error ($status): ${body:0:2000}"
  fi

  printf '%s\n' "$body"
}

create_or_reuse_project() {
  local dt_url="$1"
  local dt_api_key="$2"
  local project_name="$3"
  local project_version="$4"
  local payload
  payload="$(jq -n --arg name "$project_name" --arg version "$project_version" '{name: $name, version: $version}')"

  local body rc
  set +e
  body="$(api_json PUT "$dt_url/api/v1/project" "$dt_api_key" "$payload")"
  rc=$?
  set -e

  if [[ "$rc" -eq 0 ]]; then
    local project_uuid
    project_uuid="$(jq -r '.uuid // ""' <<<"$body")"
    [[ -n "$project_uuid" ]] || die "Dependency-Track response missing project uuid"
    echo "Project created successfully"
    echo "Project UUID: $project_uuid"
    printf '%s\n' "$project_uuid"
    return 0
  fi

  if [[ "$rc" -ne 9 ]]; then
    die "Unexpected error creating project"
  fi

  local lookup_url
  lookup_url="$dt_url/api/v1/project/lookup?name=$(url_encode "$project_name")&version=$(url_encode "$project_version")"
  body="$(api_json GET "$lookup_url" "$dt_api_key")"
  local project_uuid
  project_uuid="$(jq -r '.uuid // ""' <<<"$body")"
  [[ -n "$project_uuid" ]] || die "Dependency-Track returned 409 but lookup did not return uuid"
  echo "Project already exists, reusing existing project"
  echo "Project UUID: $project_uuid"
  printf '%s\n' "$project_uuid"
}

generate_sbom_from_requirements() {
  local requirements_path="$1"
  local sbom_output_path="$2"

  require_bin cyclonedx-py
  log_event "INFO" "SBOM command: cyclonedx-py requirements $requirements_path --of JSON -o $sbom_output_path"
  cyclonedx-py requirements "$requirements_path" --of JSON -o "$sbom_output_path"
  [[ -f "$sbom_output_path" ]] || die "SBOM file not generated: $sbom_output_path"
}

upload_sbom() {
  local dt_url="$1"
  local dt_api_key="$2"
  local project_uuid="$3"
  local sbom_path="$4"

  local bom_b64
  bom_b64="$(base64 -w0 "$sbom_path")"
  local payload
  payload="$(jq -n --arg project "$project_uuid" --arg bom "$bom_b64" '{project: $project, bom: $bom}')"

  local response
  response="$(api_json PUT "$dt_url/api/v1/bom" "$dt_api_key" "$payload")"

  echo "SBOM uploaded successfully"
  local task_token
  task_token="$(jq -r '.token // ""' <<<"$response")"
  [[ -n "$task_token" ]] && echo "Dependency-Track task token: $task_token"
}

download_export() {
  local dt_url="$1"
  local dt_api_key="$2"
  local project_uuid="$3"
  local output_path="$4"

  local body
  body="$(api_json GET "$dt_url/api/v1/finding/project/$project_uuid/export" "$dt_api_key")"
  printf '%s\n' "$body" | jq . > "$output_path"

  echo "Findings exported successfully"
  echo "Written to: $output_path"
}

run_dependency_track_sca() {
  local dt_url="$1"
  local dt_api_key="$2"
  local project_name="$3"
  local engagement_name="$4"
  local version="$5"
  local requirements_path="$6"
  local sbom_path="$7"
  local findings_output_path="$8"
  local wait_after_sbom_seconds="$9"

  log_step "SCA_DEPENDENCY_TRACK"
  local dt_project_version="${engagement_name}-${version}"
  log_event "INFO" "Dependency-Track project version: $dt_project_version"

  log_call "create_project"
  local project_uuid
  project_uuid="$(create_or_reuse_project "$dt_url" "$dt_api_key" "$project_name" "$dt_project_version" | tail -n1)"

  log_call "generate_sbom_from_requirements"
  generate_sbom_from_requirements "$requirements_path" "$sbom_path"

  log_call "upload_sbom"
  upload_sbom "$dt_url" "$dt_api_key" "$project_uuid" "$sbom_path"

  if [[ "$wait_after_sbom_seconds" -gt 0 ]]; then
    log_event "WAIT" "Waiting ${wait_after_sbom_seconds}s for Dependency-Track analysis"
    sleep "$wait_after_sbom_seconds"
  fi

  log_call "download_export"
  download_export "$dt_url" "$dt_api_key" "$project_uuid" "$findings_output_path"
}
