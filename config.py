"""
Centralized configuration for the SecOps Migration Toolkit.

All configurable paths and settings are driven by environment variables
with sensible defaults. Override these by setting the corresponding
environment variable before starting the application.
"""

import os

# Path to the customer-management CLI tool
CLI_MAIN_PATH = os.environ.get("CLI_MAIN_PATH", "/google/data/ro/teams/malachite/customermanagement/live/cli_main")

# SSL/TLS certificate paths
CERT_DIR = os.environ.get("CERT_DIR", os.path.expanduser("~/.certs"))
SSL_CERT = os.path.join(CERT_DIR, os.environ.get("SSL_CERT_FILE", "server.crt"))
SSL_KEY = os.path.join(CERT_DIR, os.environ.get("SSL_KEY_FILE", "server.key"))

# Directory for generated SA key files
JWT_OUTPUT_DIR = os.environ.get(
    "JWT_OUTPUT_DIR",
    os.path.join(os.path.expanduser("~"), ".secops_auth_JWTs"),
)

# Domain used for corporate account validation (e.g. gcloud auth checks)
AUTH_DOMAIN = os.environ.get("AUTH_DOMAIN", "google.com")

# Directory for session tracking files (keyed by tenant_id)
SESSION_DIR = os.environ.get(
    "SESSION_DIR",
    os.path.join(os.path.expanduser("~"), ".secops_migration_sessions"),
)
