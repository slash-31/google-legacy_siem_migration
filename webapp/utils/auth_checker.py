"""
Authentication Checker for SecOps Webapp

Validates gcloud authentication with a @google.com account before
allowing the webapp to start.
"""

import subprocess
import sys
import logging
from typing import Tuple, Dict


REQUIRED_DOMAIN = "google.com"


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
    Get gcloud authentication status.

    Returns:
        Dict with gcloud_valid, gcloud_message, and account fields.
    """
    gcloud_valid, gcloud_msg = check_gcloud_auth()

    return {
        'gcloud_valid': gcloud_valid,
        'gcloud_message': gcloud_msg,
    }


def validate_startup_requirements():
    """
    Validate gcloud authentication at startup.

    If the active gcloud account is not @google.com, prints an error
    message and exits. The webapp will not start.
    """
    gcloud_valid, message = check_gcloud_auth()

    if gcloud_valid:
        logging.info(f"gcloud auth: {message}")
    else:
        print()
        print("=" * 60)
        print("ERROR: gcloud authentication required")
        print("=" * 60)
        print(f"  {message}")
        print()
        print("  Please authenticate before running the app:")
        print()
        print("    gcloud auth login")
        print()
        print(f"  You must use a @{REQUIRED_DOMAIN} account.")
        print("=" * 60)
        print()
        sys.exit(1)
