"""
Session tracker for migration state persistence.

Saves/loads per-tenant session JSON files so users can resume
interrupted migrations without losing progress.
"""

import json
import os
import re
from datetime import datetime, timezone

import importlib
config = importlib.import_module("config")


def _session_path(tenant_id):
    """Return the file path for a tenant's session, sanitizing the ID."""
    # Strip anything that isn't alphanumeric, hyphen, or underscore
    safe_id = re.sub(r'[^a-zA-Z0-9_-]', '', tenant_id)
    if not safe_id:
        raise ValueError("Invalid tenant_id")
    return os.path.join(config.SESSION_DIR, f"{safe_id}.json")


def save_session(tenant_id, data):
    """Create or update a session file for the given tenant.

    Merges *data* into any existing session so callers can send partial
    updates (e.g. just step_results for the latest step).
    """
    os.makedirs(config.SESSION_DIR, exist_ok=True)
    path = _session_path(tenant_id)
    now = datetime.now(timezone.utc).isoformat()

    existing = load_session(tenant_id) or {}

    existing.update(data)
    existing["tenant_id"] = tenant_id
    existing.setdefault("created_at", now)
    existing["updated_at"] = now

    # Deep-merge step_results so individual steps accumulate
    if "step_results" in data and "step_results" in existing:
        merged = dict(existing.get("step_results", {}))
        merged.update(data["step_results"])
        existing["step_results"] = merged

    with open(path, "w") as f:
        json.dump(existing, f, indent=2, default=str)

    return existing


def load_session(tenant_id):
    """Return the session dict for *tenant_id*, or None if not found."""
    path = _session_path(tenant_id)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def delete_session(tenant_id):
    """Remove the session file for *tenant_id*. No-op if missing."""
    path = _session_path(tenant_id)
    try:
        os.remove(path)
        return True
    except FileNotFoundError:
        return False
