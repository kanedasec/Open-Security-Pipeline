# Security Pipeline Bash POC (DefectDojo as Source of Truth)

This repository should be treated as an autonomous security pipeline project. It runs security scans, imports results into DefectDojo, gates by policy thresholds, and generates local reports for traceability.

DefectDojo is the source of truth and gate authority for this pipeline. Findings are centralized in DefectDojo so triage, deduplication, auditing, and policy decisions happen in one place.

Current implemented scans are SCA (Dependency-Track export import) and SAST (Bandit), and the project is designed to expand with additional suites such as secrets scanning, DAST, and container image scanning.

## Flow

1. Load config from `.env` + CLI args.
2. Use explicit version from `--version` (or `PRODUCT_VERSION` env).
3. Run SCA with Dependency-Track (project/version, SBOM, upload, export).
4. Import SCA findings into DefectDojo.
5. Optionally run SAST (Bandit) and import to DefectDojo.
6. Fetch active findings from DefectDojo and run gate checks.
7. Generate JSON/CSV/Markdown reports.
8. Optionally request DefectDojo engagement report.
9. Optionally cleanup JSON artifacts in `tmp/**`.

## Project Positioning

- The orchestration contract is scanner-agnostic:
  - execute scanner
  - normalize output artifact
  - upload/reimport into DefectDojo
  - evaluate centralized gate from DefectDojo active findings
- New scan types should follow the same contract so governance remains unified in DefectDojo.

## DefectDojo Model: Product, Engagement, Version

How this pipeline treats DefectDojo entities:

- `Product`:
  - Represents the system/application boundary being secured.
  - Should remain stable over time (do not create a new product per run).
- `Engagement`:
  - Represents an operational stream (for example `Release`, `Staging`, `Production`, `Snapshot`).
  - This pipeline uses a stable engagement name and reuses it across runs.
- `Version`:
  - Represents the analyzed delivery state for a run.
  - Passed explicitly via `--version` and sent on each import.

Recommended approach:

- Keep one stable `Product` per app/service.
- Keep a small, intentional set of stable `Engagement` names per workflow (for example `Release`, `DAST`, `Container`).
- Always pass a meaningful `--version` (release tag/build number/commit-derived semantic version) so trends and audits are coherent.
- Avoid creating transient products/engagements per execution; this fragments historical triage and weakens auditability.

## Requirements

- `bash` (4+)
- `curl`
- `jq`
- `cyclonedx-py`
- `bandit` (unless `--skip-sast`)

## File Map

- `run_pipeline.sh`: orchestrator
- `lib/config.sh`: argument/env parsing and validation
- `lib/dt.sh`: Dependency-Track calls and SCA flow
- `lib/dj.sh`: DefectDojo API and imports
- `lib/sast.sh`: SAST execution (Bandit)
- `lib/gate.sh`: gate evaluation logic
- `lib/reporting.sh`: local report generation
- `lib/cleanup.sh`: artifact cleanup
- `lib/state.sh`: tag and ID extraction helpers
- `lib/logging.sh`: common logging and helper functions

## CLI Flags

All flags supported by `run_pipeline.sh`:

- `--dt-url STRING`: Dependency-Track base URL. Default: `DT_URL` env.
- `--dt-api-key STRING`: Dependency-Track API key. Default: `DT_API_KEY` env.
- `--dj-url STRING`: DefectDojo base URL. Default: `DJ_URL` env.
- `--dj-api-key STRING`: DefectDojo API key. Default: `DJ_API_KEY` env.

- `--project-name STRING`: Dependency-Track project name. Default: `PROJECT_NAME` env.
- `--product-name STRING`: DefectDojo product name. Default: `PRODUCT_NAME` env.
- `--product-type-name STRING`: DefectDojo product type. Default: `PRODUCT_TYPE_NAME` env.
- `--engagement-name STRING`: DefectDojo engagement name. Default: `ENGAGEMENT_NAME` env.
- `--engagement-id INT`: Optional fixed engagement ID override. Default: `ENGAGEMENT_ID` env.
- `--version X.Y.Z`: Pipeline version to send to DT/DD. Required if `PRODUCT_VERSION` env is not set.

- `--extra-tags CSV`: Extra tags applied to imports. Default: `EXTRA_SCAN_TAGS` env.

- `--sbom-path PATH`: SBOM output path. Default: `SBOM_PATH` env or `tmp/sbom.json`.
- `--dt-findings-path PATH`: Dependency-Track export output path. Default: `DT_FINDINGS_PATH` env or `tmp/findings.json`.
- `--sast-report-path PATH`: SAST report output path. Alias: `--bandit-report-path`. Default: `SAST_REPORT_PATH`/`SAST_JSON_PATH`/`BANDIT_JSON_PATH` env or `tmp/sast-report.json`.

- `--tests-source-path PATH`: Base path to scan and to locate `requirements.txt`. Alias: `--sast-source-path`. Default: `TESTS_SOURCE_PATH`/`SAST_SOURCE_PATH` env.
- `--sast-tool STRING`: SAST engine key. Current supported value: `bandit`. Default: `SAST_TOOL` env or `bandit`.
- `--sast-exclude CSV`: Exclusion patterns for directory scans. Default: `SAST_EXCLUDE` env or `.venv,.idea,__pycache__`.
- `--skip-sast`: Skip SAST step and import. Alias: `--skip-bandit`.

- `--wait-after-sbom-seconds INT`: Sleep after SBOM upload before DT export. Default: `WAIT_AFTER_SBOM_SECONDS` env or `10`.

- `--max-critical INT`: Gate threshold. Default: `MAX_CRITICAL` env or `0`.
- `--max-high INT`: Gate threshold. Default: `MAX_HIGH` env or `0`.
- `--max-medium INT`: Gate threshold. Default: `MAX_MEDIUM` env or `999999`.
- `--max-low INT`: Gate threshold. Default: `MAX_LOW` env or `999999`.
- `--max-total INT`: Gate threshold. Default: `MAX_TOTAL` env or `999999`.

- `--dj-upload-timeout INT`: SAST upload request timeout (seconds). Default: `DJ_UPLOAD_TIMEOUT` env or `300`.
- `--dj-upload-retries INT`: SAST upload retries. Default: `DJ_UPLOAD_RETRIES` env or `2`.
- `--dj-upload-retry-delay INT`: Delay between SAST upload retries (seconds). Default: `DJ_UPLOAD_RETRY_DELAY` env or `5`.

- `--report-output-dir PATH`: Local report folder. Default: `REPORT_OUTPUT_DIR` env or `tmp/reports`.
- `--report-language STRING`: Preferred language for DefectDojo engagement report. Default: `REPORT_LANGUAGE` env or `pt-BR`.
- `--skip-defectdojo-report`: Skip DefectDojo engagement report request.

- `--bypass`: Return success even when gate fails. Alias: `--by-pass`.
- `--cleanup-json`: Remove `*.json` recursively under `tmp/` at the end.

- `--help` / `-h`: Show help.

## Environment Variables

You can configure via `.env` and override with CLI flags.

Primary env vars:
- `DT_URL`, `DT_API_KEY`
- `DJ_URL`, `DJ_API_KEY`
- `PROJECT_NAME`, `PRODUCT_NAME`, `PRODUCT_TYPE_NAME`, `ENGAGEMENT_NAME`, `ENGAGEMENT_ID`
- `PRODUCT_VERSION`
- `TESTS_SOURCE_PATH`, `SAST_TOOL`, `SAST_EXCLUDE`
- `SBOM_PATH`, `DT_FINDINGS_PATH`, `SAST_REPORT_PATH`, `REPORT_OUTPUT_DIR`
- `MAX_CRITICAL`, `MAX_HIGH`, `MAX_MEDIUM`, `MAX_LOW`, `MAX_TOTAL`

## Example Run

```bash
./run_pipeline.sh \
  --project-name my-service \
  --product-name my-service \
  --product-type-name microservice \
  --engagement-name Release \
  --version 1.0.19 \
  --tests-source-path /path/to/repo \
  --sast-exclude ".venv,.idea,__pycache__" \
  --max-critical 0 --max-high 0 \
  --bypass \
  --cleanup-json
```

## Adding New Test Suites

The pattern is: **scan -> upload to DefectDojo -> include test IDs for gate/report visibility**.

### 1) Add scanner execution logic

You have two options:

- Extend `lib/sast.sh` for another `--sast-tool` value.
- Or add a new module (for example `lib/dast.sh`, `lib/container.sh`) and call it from `run_pipeline.sh`.

Each scanner function should produce:
- local report file path
- compatible DefectDojo `scan_type` name

### 2) Upload results to DefectDojo

Reuse `upload_sast_to_dj` in `lib/dj.sh` (it is generic for parser-based uploads).

You need to pass:
- report path
- `scan_type` exactly matching a DefectDojo parser
- product/product-type/engagement/version
- retries/timeout/tags/test_id if desired

### 3) Include the uploaded test in gate/report scope

In `run_pipeline.sh`, after upload:
- extract returned `test_id` with `extract_test_id`
- append to `current_test_ids`

This ensures `fetch_open_findings` includes findings from that test and gate/report sees them.

### 4) Add CLI flags/config entries (if needed)

In `lib/config.sh`, add flags/env vars such as:
- `--skip-dast`
- `--zap-report-path`
- `--trivy-report-path`
- `--container-image`

Then validate required values in `validate_args`.

## Example: Add DAST (ZAP)

1. Add `execute_dast_zap()` in `lib/dast.sh`:
- run ZAP baseline/full scan
- output report in JSON or SARIF
- return matching `scan_type` (for example parser supported in your DD instance)

2. In `run_pipeline.sh`:
- call `execute_dast_zap`
- call `upload_sast_to_dj` with ZAP report and scan type
- capture `test_id` and add to `current_test_ids`

## Example: Add Container Scans (Trivy / OSV-Scanner / Dive)

### Trivy
- Run: `trivy image --format sarif -o tmp/trivy.sarif <image>`
- Upload with `scan_type` set to parser available in DefectDojo (often `SARIF`).

### OSV-Scanner
- Run in JSON/SARIF mode against code or lockfiles.
- Upload using matching DefectDojo parser.

### Dive
- Dive itself is focused on image layer inspection, not a standard vuln parser format for DefectDojo.
- If used, convert output into a format DefectDojo can parse (or keep as local-only report).

## Important Integration Rule

DefectDojo import succeeds only when `scan_type` exactly matches a parser enabled in your instance. Always verify parser naming in your DefectDojo configuration first.
