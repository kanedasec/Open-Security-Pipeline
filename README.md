# Security Pipeline Bash POC (DefectDojo as Source of Truth)

This repository is an autonomous security pipeline project. It runs enabled security scans, imports results into DefectDojo, gates by policy thresholds, and can generate local pipeline reports.

DefectDojo is the source of truth and gate authority for this pipeline. Findings are centralized in DefectDojo so triage, deduplication, auditing, and policy decisions happen in one place.

Current implemented scans are SCA (Dependency-Track export import), SAST (Bandit), and secrets scanning (Gitleaks).

## Key Behavior

- Scans are opt-in:
  - SCA runs only when `--sca <language>` is passed.
  - SAST runs only when `--sast` is passed.
  - Secrets runs only when `--secrets` is passed.
- Pipeline local report is opt-in:
  - It runs only when `--pipeline-report <formats>` is passed.
- All local outputs use one global directory:
  - `--output-dir` (default: `tmp/reports`)

## Flow

1. Load config from `.env` + CLI args.
2. Use explicit version from `--version` (or `PRODUCT_VERSION` env).
3. Run only scans explicitly enabled by flags.
4. For SCA, resolve language-specific manifest and run Dependency-Track flow.
5. For SAST, run Bandit only when enabled.
6. For secrets, run Gitleaks only when enabled.
7. Import enabled scan results into DefectDojo.
8. Fetch active findings from DefectDojo and run gate checks.
9. Optionally generate local pipeline report (`--pipeline-report`).
10. Optionally request DefectDojo engagement report (`--defectdojo-report`).
11. Optionally cleanup JSON artifacts in `--output-dir` (`--cleanup-json`).

## Requirements

Base:
- `bash` (4+)
- `curl`
- `jq`

SCA tools by language:
- `--sca python`: `cyclonedx-py`
- `--sca java`: `mvn` (CycloneDX Maven plugin invocation)
- `--sca javascript`: `cyclonedx-npm`
- Default DT post-upload wait: `60s`
- DT export stabilization enabled by default (3 equal probes, 10s interval, 180s timeout)

SAST:
- `bandit` (only when `--sast`)

Secrets:
- `gitleaks` (only when `--secrets`)

## CLI Highlights

Core:
- `--dt-url`, `--dt-api-key`
- `--dj-url`, `--dj-api-key`
- `--project-name`, `--product-name`, `--product-type-name`, `--engagement-name`
- `--version`

Enable scans:
- `--sca python|java|javascript`
- `--sast`
- `--secrets [path/to/.gitleaks.toml]`

Paths:
- `--source-path` (aliases: `--tests-source-path`, `--sast-source-path`)
- `--output-dir` (single global local output directory)

Pipeline local report:
- `--pipeline-report json,csv,md` (or `all`)

DefectDojo report:
- `--defectdojo-report` / `--enable-defectdojo-report`
- `--skip-defectdojo-report`
- `--report-language`

Secrets options:
- `--secrets-tool` (current supported: `gitleaks`)
- `--secrets [path/to/.gitleaks.toml]` (optional custom config)
- `--secrets-scan-type` (DefectDojo parser name, default: `Gitleaks Scan`)
- `--secrets-exclude`

Gate thresholds:
- `--max-critical`, `--max-high`, `--max-medium`, `--max-low`, `--max-total`

Other:
- `--bypass`
- `--cleanup-json`
- `--help`
- `--wait-after-sbom-seconds`
- `--dt-export-stability-polls`
- `--dt-export-stability-interval-seconds`
- `--dt-export-stability-timeout-seconds`

## SCA Manifest Resolution

When `--sca` is enabled, default manifest lookup under `--source-path` is:
- `python` -> `requirements.txt`
- `java` -> `pom.xml`
- `javascript` -> `package.json`

Use `--sca-manifest-path` to override.

## Output Files in `--output-dir`

When SCA enabled:
- `sca-sbom.json`
- `sca-findings.json`

When SAST enabled:
- `sast-report.json`

When secrets enabled:
- `secrets-report.json`

When pipeline report enabled (`--pipeline-report`):
- `engagement-...-active-findings.json` (if `json` selected)
- `engagement-...-active-findings.csv` (if `csv` selected)
- `engagement-...-active-findings.md` (if `md` selected)

When DefectDojo report enabled (`--defectdojo-report`):
- `defectdojo-engagement-report-...json` (request/response metadata saved by pipeline)

## Environment Variables

Primary env vars:
- `DT_URL`, `DT_API_KEY`
- `DJ_URL`, `DJ_API_KEY`
- `PROJECT_NAME`, `PRODUCT_NAME`, `PRODUCT_TYPE_NAME`, `ENGAGEMENT_NAME`, `ENGAGEMENT_ID`
- `PRODUCT_VERSION`
- `SCAN_SOURCE_PATH` (or `TESTS_SOURCE_PATH`/`SAST_SOURCE_PATH`)
- `OUTPUT_DIR`
- `ENABLE_SCA`, `SCA_LANGUAGE`, `SCA_MANIFEST_PATH`
- `ENABLE_SAST`, `SAST_TOOL`, `SAST_EXCLUDE`
- `ENABLE_SECRETS`, `SECRETS_TOOL`, `SECRETS_SCAN_TYPE`, `SECRETS_EXCLUDE`
- `SECRETS_CONFIG_PATH` (or `GITLEAKS_CONFIG`)
- `PIPELINE_REPORT_FORMATS`
- `MAX_CRITICAL`, `MAX_HIGH`, `MAX_MEDIUM`, `MAX_LOW`, `MAX_TOTAL`
- `WAIT_AFTER_SBOM_SECONDS`, `DT_EXPORT_STABILITY_POLLS`, `DT_EXPORT_STABILITY_INTERVAL_SECONDS`, `DT_EXPORT_STABILITY_TIMEOUT_SECONDS`
- `SKIP_DEFECTDOJO_REPORT`, `REPORT_LANGUAGE`

## Example Run

```bash
./run_pipeline.sh \
  --project-name my-service \
  --product-name my-service \
  --product-type-name microservice \
  --engagement-name Release \
  --version 1.0.19 \
  --source-path /path/to/repo \
  --output-dir ./tmp/reports \
  --sca python \
  --sast \
  --secrets /path/to/.gitleaks.toml \
  --pipeline-report csv,md \
  --defectdojo-report \
  --max-critical 0 --max-high 0
```

## Important Integration Rule

DefectDojo import succeeds only when `scan_type` exactly matches a parser enabled in your instance. Always verify parser naming in your DefectDojo configuration first.
