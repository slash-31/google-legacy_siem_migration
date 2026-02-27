# Legacy SIEM to SecOps SOAR Migration Toolkit

A Flask web application and CLI toolset for migrating tenants from legacy SIEM
to Google SecOps SOAR. Automates service account key generation, SOAR URI
configuration, and feature flag management.

## Features

- **Step 1**: Enable SecOps authentication, create/find a GCP service account,
  and generate a JSON key.
- **Step 2**: Configure SOAR platform URIs and enable the `soar_enabled` feature
  flag.
- **Web UI**: Guided single-page application with pre-flight checks, auth status
  monitoring, and partner association management.
- **CLI mode**: Batch processing via CSV or single-tenant flags.

## Prerequisites

| Requirement | Purpose |
|-------------|---------|
| Python 3.8+ | Runtime |
| `gcloud` CLI | GCP project access, IAM, Secret Manager |
| `cli_main` | Customer management operations (set `CLI_MAIN_PATH` env var) |
| Privileged workstation | Network access to internal APIs |
| Valid corporate certificate | Authentication |

## Quick Start

```bash
# Clone the repo
git clone https://github.com/slash-31/google-legacy_siem_migration.git
cd google-legacy_siem_migration

# Start the web application (creates venv, installs deps, runs on port 9443)
./start_webapp.sh
```

The app will be available at `https://127.0.0.1:9443` (HTTPS if certs are
configured) or `http://127.0.0.1:9443`.

## Configuration

All paths and settings are centralized in `config.py` and driven by environment
variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CLI_MAIN_PATH` | `/usr/local/bin/cli_main` | Path to the customer management CLI |
| `CERT_DIR` | `~/.certs` | Directory containing SSL certificates |
| `SSL_CERT_FILE` | `server.crt` | SSL certificate filename |
| `SSL_KEY_FILE` | `server.key` | SSL key filename |
| `JWT_OUTPUT_DIR` | `~/.secops_auth_JWTs` | Where generated SA keys are stored |
| `AUTH_DOMAIN` | `example.com` | Corporate email domain for auth validation |

## CLI Usage

```bash
# Step 1: Generate SA key for a single tenant
python3 step1/create_SA_JWT.py -t <tenant_id> -p <gcp_project_id>

# Step 1: Batch processing from CSV
python3 step1/create_SA_JWT.py customer_list.csv

# Step 2: Configure SOAR for a single tenant
python3 step2/update_secops.py -t <tenant_id> --soar-fe <frontend>

# Step 2: Dry run with CSV
python3 step2/update_secops.py -i tenants.csv --dry-run

# Step 2: Disable SOAR
python3 step2/update_secops.py -t <tenant_id> --disable
```

## Project Structure

```
├── config.py              # Centralized configuration (env-var driven)
├── start_webapp.sh        # Startup script
├── requirements.txt       # Python dependencies
├── webapp/
│   ├── app.py             # Flask routes and API endpoints
│   ├── templates/         # Jinja2 HTML
│   ├── static/            # CSS/JS
│   └── utils/
│       ├── script_runner.py    # Bridge to step1/step2 modules
│       ├── cm_parser.py        # CLI output parser
│       ├── auth_checker.py     # Auth validation
│       ├── precheck.py         # Pre-flight checks
│       └── secret_manager.py   # GCP Secret Manager integration
├── step1/
│   └── create_SA_JWT.py   # SA key generation
└── step2/
    └── update_secops.py   # SOAR configuration
```

## License

Apache 2.0
