"""
Secret Manager operations for storing service account keys.

Stores generated SA keys in GCP Secret Manager for the GCP project.
"""

import subprocess
import logging
import json
from typing import Tuple, Optional


def get_secret_name(customer_code: str) -> str:
    """
    Generate secret name from customer code.

    Format: {code-lowercase}-secops-auth
    Example: MAGNT -> magnt-secops-auth
    """
    return f"{customer_code.lower()}-secops-auth"


def check_secret_exists(project_id: str, secret_name: str) -> Tuple[bool, str]:
    """
    Check if a secret already exists in Secret Manager.

    Returns:
        Tuple[bool, str]: (exists, message)
    """
    try:
        result = subprocess.run(
            ['gcloud', 'secrets', 'describe', secret_name,
             f'--project={project_id}',
             '--format=value(name)'],
            capture_output=True,
            text=True,
            timeout=15
        )
        if result.returncode == 0 and result.stdout.strip():
            return True, f"Secret {secret_name} exists"
        return False, f"Secret {secret_name} does not exist"
    except subprocess.TimeoutExpired:
        return False, "Secret check timed out"
    except Exception as e:
        return False, f"Error checking secret: {str(e)}"


def create_secret(project_id: str, secret_name: str) -> Tuple[bool, str]:
    """
    Create a new secret in Secret Manager.

    Returns:
        Tuple[bool, str]: (success, message)
    """
    try:
        result = subprocess.run(
            ['gcloud', 'secrets', 'create', secret_name,
             f'--project={project_id}',
             '--replication-policy=automatic'],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return True, f"Created secret {secret_name}"
        return False, f"Failed to create secret: {result.stderr}"
    except subprocess.TimeoutExpired:
        return False, "Secret creation timed out"
    except Exception as e:
        return False, f"Error creating secret: {str(e)}"


def add_secret_version(project_id: str, secret_name: str, key_file_path: str) -> Tuple[bool, str]:
    """
    Add a new version to an existing secret with the contents of the key file.

    Args:
        project_id: GCP project ID
        secret_name: Name of the secret
        key_file_path: Path to the JSON key file

    Returns:
        Tuple[bool, str]: (success, message)
    """
    try:
        result = subprocess.run(
            ['gcloud', 'secrets', 'versions', 'add', secret_name,
             f'--project={project_id}',
             f'--data-file={key_file_path}'],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return True, f"Added new version to secret {secret_name}"
        return False, f"Failed to add secret version: {result.stderr}"
    except subprocess.TimeoutExpired:
        return False, "Adding secret version timed out"
    except Exception as e:
        return False, f"Error adding secret version: {str(e)}"


def store_sa_key_in_secret_manager(
    gcp_project: str,
    customer_code: str,
    key_file_path: str
) -> Tuple[bool, str]:
    """
    Store service account key in Secret Manager.

    Creates the secret if it doesn't exist, then adds the key as a new version.

    Args:
        gcp_project: The GCP project ID
        customer_code: Customer code (e.g., "MAGNT")
        key_file_path: Path to the JSON key file

    Returns:
        Tuple[bool, str]: (success, detailed_message)
    """
    secret_name = get_secret_name(customer_code)

    logging.info(f"Storing SA key in Secret Manager: {secret_name} in project {gcp_project}")

    # Check if secret exists
    exists, check_msg = check_secret_exists(gcp_project, secret_name)

    # Create secret if it doesn't exist
    if not exists:
        logging.info(f"Secret does not exist, creating: {secret_name}")
        success, create_msg = create_secret(gcp_project, secret_name)
        if not success:
            return False, f"Failed to create secret: {create_msg}"
        logging.info(create_msg)
    else:
        logging.info(f"Secret already exists: {secret_name}")

    # Add new version with the key file contents
    success, version_msg = add_secret_version(gcp_project, secret_name, key_file_path)
    if not success:
        return False, f"Failed to add secret version: {version_msg}"

    return True, f"Successfully stored SA key in Secret Manager as {secret_name}"


def get_sa_email_from_key(key_file_path: str) -> Optional[str]:
    """
    Extract the service account email from a JSON key file.

    Returns:
        Optional[str]: Service account email or None if extraction fails
    """
    try:
        with open(key_file_path, 'r') as f:
            key_data = json.load(f)
            return key_data.get('client_email')
    except Exception as e:
        logging.error(f"Failed to read SA email from key file: {e}")
        return None
