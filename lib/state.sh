#!/usr/bin/env bash
# Holds state helpers for scan tags and extraction of test/engagement IDs from API responses.
set -euo pipefail

build_scan_tags() {
  local raw="$1"
  [[ -z "${raw// }" ]] && return 0
  awk -v input="$raw" 'BEGIN {
    n=split(input, arr, ",");
    out="";
    for (i=1; i<=n; i++) {
      gsub(/^ +| +$/, "", arr[i]);
      if (arr[i] == "") continue;
      if (!seen[arr[i]]++) {
        if (out == "") out=arr[i]; else out=out "," arr[i];
      }
    }
    print out;
  }'
}

extract_test_id() {
  local payload="$1"
  jq -r '
    if (.test|type) == "number" then .test
    elif (.test_id|type) == "number" then .test_id
    elif (.test|type) == "object" and (.test.id|type) == "number" then .test.id
    elif (.test|type) == "object" and (.test.test_id|type) == "number" then .test.test_id
    else "" end
  ' <<<"$payload"
}

extract_engagement_id() {
  local payload="$1"
  jq -r '
    if (.engagement|type) == "number" then .engagement
    elif (.engagement_id|type) == "number" then .engagement_id
    elif (.test|type) == "object" and (.test.engagement|type) == "number" then .test.engagement
    else "" end
  ' <<<"$payload"
}
