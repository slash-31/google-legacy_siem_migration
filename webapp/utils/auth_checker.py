"""
Authentication Checker for SecOps Webapp

Validates gcloud, gcert, and admin_session status before allowing
the webapp to start.
"""

import os
import re
import subprocess
import sys
import logging
from datetime import datetime
from pathlib import Path
from typing import Tuple, Dict


REQUIRED_DOMAIN = "google.com"


def check_admin_session() -> Tuple[bool, str]:
    """
    Check if user is in an admin_session by walking the process tree.

    Returns:
        Tuple[bool, str]: (is_valid, message)
    """
    try:
        pid = os.getpid()
        for _ in range(20):  # safety limit
            result = subprocess.run(
                ['ps', '-o', 'ppid=,command=', '-p', str(pid)],
                capture_output=True,
                text=True,
                timeout=2
            )
            line = result.stdout.strip()
            if not line:
                break

            if 'admin_session' in line.lower():
                match = re.search(r"--reason[= ]*['\"]?([^'\"\\s]+)", line)
                if match:
                    return True, f"Active (Reason: {match.group(1)})"
                return True, "Active (detected in process tree)"

            parts = line.split(None, 1)
            if not parts:
                break
            try:
                parent_pid = int(parts[0])
            except ValueError:
                break
            if parent_pid <= 1 or parent_pid == pid:
                break
            pid = parent_pid

    except Exception:
        pass

    return False, "Not detected. Run: admin_session --reason='YOUR_TICKET_ID'"


def check_gcert() -> Tuple[bool, str]:
    """
    Check if gcert is valid and not expired.

    Uses the gcertstatus command first, falls back to file-based heuristic.

    Returns:
        Tuple[bool, str]: (is_valid, message)
    """
    try:
        result = subprocess.run(
            ['gcertstatus'],
            capture_output=True,
            text=True,
            timeout=5
        )
        output = result.stdout.strip()
        if output:
            expiry_entries = []
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                match = re.search(r'(.+?)\s+expires\s+in\s+(.+)', line)
                if match:
                    cert_type = match.group(1).strip()
                    time_remaining = match.group(2).strip()
                    expiry_entries.append((cert_type, time_remaining))
                elif 'expired' in line.lower() or 'not found' in line.lower() or 'no cert' in line.lower():
                    return False, "gcert expired or not found. Run: gcert"

            if expiry_entries:
                summary = ", ".join(f"{t}: {r}" for t, r in expiry_entries)
                return True, f"Valid ({summary})"

            if result.returncode == 0:
                return True, "Valid (gcertstatus returned OK)"
            return False, "gcert status unclear. Run: gcert"
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    # Fallback: file-based heuristic
    ssh_dir = Path.home() / '.ssh'

    cert_patterns = [
        '*google*cert*',
        '*certificateauthority*',
        '*.pub-cert',
        'id_*-cert.pub'
    ]

    cert_files = []
    if ssh_dir.exists():
        for pattern in cert_patterns:
            found = list(ssh_dir.glob(pattern))
            cert_files.extend(found)

    if not cert_files:
        return False, f"Unable to find gcert files in {ssh_dir}. Run: gcert"

    most_recent = max(cert_files, key=lambda p: p.stat().st_mtime)
    cert_age_seconds = datetime.now().timestamp() - most_recent.stat().st_mtime
    cert_age_hours = cert_age_seconds / 3600

    if cert_age_hours > 20:
        return False, f"Certificate may be expired (age: {cert_age_hours:.1f}h). Run: gcert"

    return True, f"Valid (age: {cert_age_hours:.1f}h, file: {most_recent.name})"


def check_gcloud_auth() -> Tuple[bool, str]:
    """
    Check if gcloud is authenticated with a @google.com account.

    Returns:
        Tuple[bool, str]: (is_valid, message)
    """
    try:
        result = subprocess.run(
            ['gcloud', 'auth', 'list', '--filter=status:ACTIVE', '--format=value(account)'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            account = result.stdout.strip().split('\n')[0]
            if account.endswith(f"@{REQUIRED_DOMAIN}"):
                return True, f"Authenticated as {account}"
            elif '@' in account:
                return False, f"Authenticated as {account} — must use a @{REQUIRED_DOMAIN} account"
            else:
                return False, f"Unexpected account format: {account}"
        return False, "No active gcloud account"
    except FileNotFoundError:
        return False, "gcloud CLI not found"
    except subprocess.TimeoutExpired:
        return False, "gcloud command timed out"
    except Exception as e:
        return False, f"Error checking gcloud auth: {str(e)}"


def get_auth_status() -> Dict[str, any]:
    """
    Get comprehensive authentication status.

    Returns:
        Dict with admin_session, gcert, and gcloud status fields.
    """
    admin_valid, admin_msg = check_admin_session()
    gcert_valid, gcert_msg = check_gcert()
    gcloud_valid, gcloud_msg = check_gcloud_auth()

    return {
        'admin_session_valid': admin_valid,
        'gcert_valid': gcert_valid,
        'gcloud_valid': gcloud_valid,
        'admin_session_message': admin_msg,
        'gcert_message': gcert_msg,
        'gcloud_message': gcloud_msg,
        'all_valid': admin_valid and gcert_valid and gcloud_valid
    }


def validate_startup_requirements():
    """
    Validate authentication at startup.

    Checks gcloud, gcert, and admin_session. If any fail, prints an
    error message and exits. The webapp will not start.
    """
    failures = []

    gcloud_valid, gcloud_msg = check_gcloud_auth()
    if gcloud_valid:
        logging.info(f"gcloud auth: {gcloud_msg}")
    else:
        failures.append(("gcloud", gcloud_msg, "gcloud auth login"))

    gcert_valid, gcert_msg = check_gcert()
    if gcert_valid:
        logging.info(f"gcert: {gcert_msg}")
    else:
        failures.append(("gcert", gcert_msg, "gcert"))

    admin_valid, admin_msg = check_admin_session()
    if admin_valid:
        logging.info(f"admin_session: {admin_msg}")
    else:
        failures.append(("admin_session", admin_msg, "admin_session --reason='YOUR_TICKET_ID'"))

    if failures:
        print()
        print("=" * 60)
        print("ERROR: Authentication requirements not met")
        print("=" * 60)
        for name, msg, fix in failures:
            print(f"  {name}: {msg}")
            print(f"    Fix: {fix}")
            print()
        print(f"  gcloud must use a @{REQUIRED_DOMAIN} account.")
        print("=" * 60)
        print()
        sys.exit(1)
