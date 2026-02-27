# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SecOps SOAR Migration Toolkit — a Flask web app and CLI toolset for migrating tenants from legacy SIEM to Google SecOps SOAR. Automates service account key generation, SOAR URI configuration, and feature flag management via an internal CLI tool (`cli_main`).

## Running the Application

```bash
# Start the webapp (creates venv, installs deps, runs on port 9443)
./start_webapp.sh

# Or manually:
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python webapp/app.py
```

**Environment variables** (all optional, defaults in `config.py`):
- `CLI_MAIN_PATH` — path to `cli_main` (default: `/usr/local/bin/cli_main`)
- `CERT_DIR`, `SSL_CERT_FILE`, `SSL_KEY_FILE` — SSL cert locations
- `JWT_OUTPUT_DIR` — where generated SA keys are stored (default: `~/.secops_auth_JWTs`)
- `AUTH_DOMAIN` — corporate email domain for auth validation
- `PORT` — webapp port (default: `9443`)
- `FLASK_DEBUG` — set to `true` for debug mode

## CLI Usage

```bash
# Step 1: Generate SA key (single tenant)
python3 step1/create_SA_JWT.py -t <tenant_id> -p <gcp_project_id>

# Step 1: Batch from CSV
python3 step1/create_SA_JWT.py customer_list.csv

# Step 2: Configure SOAR (single tenant)
python3 step2/update_secops.py -t <tenant_id> --soar-fe <frontend>

# Step 2: Dry run with CSV
python3 step2/update_secops.py -i tenants.csv --dry-run

# Step 2: Disable SOAR
python3 step2/update_secops.py -t <tenant_id> --disable
```

## Architecture

### Two-step migration flow

**Step 1** (`step1/create_SA_JWT.py`): Enables SecOps authentication for a tenant via `cli_main`, finds/creates the SecOps service account in the GCP project, and generates a JSON key file. Key files are stored in `~/.secops_auth_JWTs/` and named by `client_email` from the key JSON.

**Step 2** (`step2/update_secops.py`): Configures SOAR platform URIs (`set_customer_response_platform_uri`, `set_customer_soar_api_uri`) and enables/disables the `soar_enabled` feature flag via `cli_main`. Supports enable/disable modes.

### Webapp layer

`webapp/app.py` is a Flask app that wraps the CLI scripts with a web UI. It does **not** import step1/step2 as subprocesses — it imports them as Python modules via `webapp/utils/script_runner.py`, which calls `create_SA_JWT.process_single_customer()` and `update_secops.process_single_tenant()` directly.

Key webapp utilities in `webapp/utils/`:
- **`script_runner.py`** — bridge between Flask routes and step1/step2 modules; also handles partner association management and JWT file discovery
- **`cm_parser.py`** — parses `cli_main customer info` text output into structured dicts; handles `customer_features`, `external_project_info`, and `response_platform_uri` fields
- **`auth_checker.py`** — validates admin_session (process tree walk), gcert, and gcloud auth status; runs at startup (warnings only, non-blocking)
- **`precheck.py`** — pre-flight validation before step1 (gcloud auth, project access, SA existence, key file existence)
- **`secret_manager.py`** — GCP Secret Manager integration for storing SA keys

### Config

`config.py` at the project root is the single source for all configurable paths/settings, driven by env vars. Both step1 and step2 import it via `importlib.import_module("config")` (not a relative import) because they can run as standalone scripts.

### Frontend

Single-page app in `webapp/templates/index.html` (inline JS) with `webapp/static/style.css`. Communicates with Flask via JSON API endpoints (`/api/auth_status`, `/api/precheck_step1`, `/api/run_step1`, `/api/run_step2`, etc.).

## Key Patterns

- All external CLI commands (`gcloud`, `cli_main`) are run via `subprocess.run()` with timeouts. Step1 uses `shell=True`; webapp utilities use list-form commands.
- The webapp manages a `gcloud auth login --no-launch-browser` subprocess lifecycle across two endpoints (`/api/gcloud_auth_login` and `/api/gcloud_auth_code`) using a module-level `_gcloud_auth_process` global.
- CSV batch processing supports three formats: simple (`tenant_id,gcp_project_id`), extended (adds `soar_fe`), and enterprise (adds `customer_id,customer_code,customer_name`).
- Idempotency: step1 checks success logs and existing key files before re-processing; step2 commands are safe to re-run.
- Service account email pattern: `{tla}-secops-auth@{project}.iam.gserviceaccount.com` where TLA is extracted from `malachite-{tla}` in the project ID.

## Prerequisites

- Python 3.8+
- `gcloud` CLI (authenticated with corporate account)
- `cli_main` internal CLI tool (requires `admin_session`)
- Valid gcert (corporate certificate)
- Network access to internal APIs (privileged workstation)

## No Tests

There is currently no test suite in this repository.
