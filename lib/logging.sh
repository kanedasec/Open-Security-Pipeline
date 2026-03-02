#!/usr/bin/env bash
# Provides standardized pipeline logging and common fatal/dependency helper functions.
set -euo pipefail

log_event() {
  local level="$1"
  local message="$2"
  echo "[PIPELINE][$level] $message"
}

log_step() {
  log_event "STEP" "$1"
}

log_call() {
  log_event "CALL" "$1"
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

require_bin() {
  local bin="$1"
  command -v "$bin" >/dev/null 2>&1 || die "Required binary not found in PATH: $bin"
}
