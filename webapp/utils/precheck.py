"""
Pre-check validation for migration steps.

Runs all validation checks before executing migration steps to identify
potential issues early.
"""

import os
import re
import glob
import subprocess
import logging
from typing import Dict, List, Tuple


from config import CLI_MAIN_PATH as CLI_MAIN, AUTH_DOMAIN


def check_gcert_status() -> Tuple[bool, str]:
    """
    Check gcert validity using the gcertstatus command.

    Parses output like:
        LOAS2 expires in 16h 48m
        corp/normal expires in 19h 23m

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
        return False, "gcertstatus command not found. Run: gcert"
    except subprocess.TimeoutExpired:
        return False, "gcertstatus timed out"
    except Exception as e:
        return False, f"Error checking gcert: {str(e)}"


def check_admin_session_status() -> Tuple[bool, str]:
    """
    Check if user is in an admin_session by walking the process tree.

    admin_session doesn't export env vars to child processes and PS1 is
    shell-local, so heuristic checks fail. Instead we walk up the process
    tree looking for an 'admin_session' ancestor process.

    Returns:
        Tuple[bool, str]: (is_valid, message)
    """
    try:
        # Walk the process tree from current PID upward
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
                # Try to extract the reason
                match = re.search(r"--reason[= ]*['\"]?([^'\"\\s]+)", line)
                if match:
                    return True, f"Active (Reason: {match.group(1)})"
                return True, "Active (detected in process tree)"

            # Move to parent PID
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

    return False, "Not detected in process tree. Run: admin_session --reason='YOUR_TICKET_ID'"


def check_gcloud_project_context(gcp_project_id: str) -> Tuple[bool, str]:
    """
    Check if the current gcloud default project matches the expected project.

    This is informational only — commands use --project= flags, but having the
    correct default project helps with manual debugging.

    Returns:
        Tuple[bool, str]: (matches, message)
    """
    if not gcp_project_id:
        return False, "No project ID provided"

    try:
        result = subprocess.run(
            ['gcloud', 'config', 'get-value', 'project'],
            capture_output=True,
            text=True,
            timeout=5
        )
        current_project = result.stdout.strip()
        if current_project == gcp_project_id:
            return True, f"gcloud default project matches: {current_project}"
        elif current_project:
            return False, f"gcloud default project is '{current_project}', expected '{gcp_project_id}'. Consider: gcloud config set project {gcp_project_id}"
        else:
            return False, f"No gcloud default project set. Consider: gcloud config set project {gcp_project_id}"
    except FileNotFoundError:
        return False, "gcloud CLI not found"
    except subprocess.TimeoutExpired:
        return False, "gcloud config check timed out"
    except Exception as e:
        return False, f"Error checking gcloud project: {str(e)}"


def check_cm_cli_access() -> Tuple[bool, str]:
    """
    Check if cli_main is accessible AND running inside admin_session.

    Outside admin_session, 'cli_main customer' returns a limited set of
    subcommands (list_for_all_regions, update, impersonate). Inside
    admin_session, it exposes 'info', 'enable_secops_authentication', etc.
    We check for 'info' in the output to confirm admin_session is active.
    """
    try:
        result = subprocess.run(
            [CLI_MAIN, 'customer', '--help'],
            capture_output=True,
            text=True,
            timeout=10
        )
        output = (result.stdout + result.stderr).lower()
        if result.returncode == 0 or 'usage' in output:
            if 'info' in output and 'enable_secops_authentication' in output:
                return True, "cli_main is accessible (admin_session active)"
            else:
                return False, "cli_main found but admin_session not active — limited commands available. Run: admin_session --reason='YOUR_TICKET_ID'"
        return False, f"cli_main returned error: {result.stderr}"
    except FileNotFoundError:
        return False, f"cli_main not found at {CLI_MAIN}"
    except subprocess.TimeoutExpired:
        return False, "cli_main timed out"
    except Exception as e:
        return False, f"Error checking cli_main: {str(e)}"


def check_gcloud_auth() -> Tuple[bool, str]:
    """Check if gcloud is authenticated with a corporate account."""
    try:
        result = subprocess.run(
            ['gcloud', 'auth', 'list', '--filter=status:ACTIVE', '--format=value(account)'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            account = result.stdout.strip().split('\n')[0]

            # Check if it's a corporate account
            domain_suffix = f"@{AUTH_DOMAIN}"
            if domain_suffix in account:
                return True, f"Authenticated as {account} (corporate account)"
            elif '@' in account:
                return False, f"Authenticated as {account} - Please use your {domain_suffix} account. Run: gcloud auth login"
            else:
                return False, f"Unexpected account format: {account}"
        return False, "No active gcloud account. Run: gcloud auth login"
    except FileNotFoundError:
        return False, "gcloud CLI not found. Install Google Cloud SDK"
    except subprocess.TimeoutExpired:
        return False, "gcloud command timed out"
    except Exception as e:
        return False, f"Error checking gcloud auth: {str(e)}"


def check_gcp_project_access(project_id: str) -> Tuple[bool, str]:
    """Check if we can access the GCP project."""
    if not project_id:
        return False, "No project ID provided"

    try:
        result = subprocess.run(
            ['gcloud', 'projects', 'describe', project_id, '--format=value(projectId)'],
            capture_output=True,
            text=True,
            timeout=15
        )
        if result.returncode == 0 and result.stdout.strip() == project_id:
            return True, f"Project {project_id} is accessible"
        return False, f"Cannot access project {project_id}. Check permissions."
    except subprocess.TimeoutExpired:
        return False, "gcloud project check timed out"
    except Exception as e:
        return False, f"Error checking project: {str(e)}"


def check_tenant_exists(tenant_id: str, env: str = "prod", region: str = "US") -> Tuple[bool, str, Dict]:
    """Check if tenant exists in cm_cli."""
    if not tenant_id:
        return False, "No tenant ID provided", {}

    try:
        result = subprocess.run(
            [CLI_MAIN, 'customer', 'info', tenant_id, f'--env={env}', f'--region={region}'],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            # Basic validation - if we get output, tenant exists
            output = result.stdout
            data = {}
            # Try to extract key info
            for line in output.split('\n'):
                if ':' in line:
                    key, val = line.split(':', 1)
                    data[key.strip()] = val.strip()
            return True, f"Tenant found: {data.get('customer_name', tenant_id)}", data
        return False, f"Tenant {tenant_id} not found or inaccessible", {}
    except FileNotFoundError:
        return False, "cli_main not found", {}
    except subprocess.TimeoutExpired:
        return False, "cli_main tenant lookup timed out", {}
    except Exception as e:
        return False, f"Error checking tenant: {str(e)}", {}


def check_secops_auth_enabled(tenant_id: str, env: str = "prod", region: str = "US") -> Tuple[bool, str]:
    """Check if SecOps auth is already enabled for tenant."""
    if not tenant_id:
        return False, "No tenant ID provided"

    # This is a heuristic check - we look for certain indicators
    # The actual enable_secops_auth function would provide more detail
    try:
        result = subprocess.run(
            [CLI_MAIN, 'customer', 'info', tenant_id, f'--env={env}', f'--region={region}'],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            output = result.stdout.lower()
            # Look for indicators of SecOps auth
            if 'secops' in output or 'authentication' in output:
                return True, "SecOps auth appears to be configured"
            return False, "SecOps auth not detected (will be enabled in step1)"
        return False, "Cannot determine auth status"
    except Exception as e:
        return False, f"Error checking auth status: {str(e)}"


def get_expected_sa_email(project_id: str) -> str:
    """
    Construct the expected SecOps SA email from project ID.

    Pattern: {tla}-secops-auth@{project}.iam.gserviceaccount.com
    Example: <project-id> -> <tla>-secops-auth@<project-id>.iam.gserviceaccount.com
    """
    match = re.match(r'malachite-(\w+)', project_id)
    if match:
        tla = match.group(1).lower()
        return f"{tla}-secops-auth@{project_id}.iam.gserviceaccount.com"
    return ""


def check_service_account_exists(project_id: str) -> Tuple[bool, str]:
    """Check if SecOps service account exists in project using direct describe."""
    if not project_id:
        return False, "No project ID provided"

    expected_email = get_expected_sa_email(project_id)
    if not expected_email:
        return False, f"Cannot determine SA email from project: {project_id} (expected malachite-{{TLA}} format)"

    try:
        result = subprocess.run(
            ['gcloud', 'iam', 'service-accounts', 'describe', expected_email,
             f'--project={project_id}',
             '--format=value(email)'],
            capture_output=True,
            text=True,
            timeout=15
        )
        if result.returncode == 0 and result.stdout.strip():
            return True, f"Service account found: {result.stdout.strip()}"
        return False, f"Service account {expected_email} not found (will be created in step1)"
    except subprocess.TimeoutExpired:
        return False, "Service account check timed out"
    except Exception as e:
        return False, f"Error checking service account: {str(e)}"


def check_key_file_exists(project_id: str) -> Tuple[bool, str]:
    """Check if key file already exists in ~/.secops_auth_JWTs."""
    if not project_id:
        return False, "No project ID provided"

    jwt_dir = os.path.join(os.path.expanduser('~'), '.secops_auth_JWTs')

    if not os.path.exists(jwt_dir):
        return False, f"JWT directory does not exist yet: {jwt_dir}"

    # Check for files matching the project
    patterns = [
        os.path.join(jwt_dir, f"*{project_id}*.json"),
        os.path.join(jwt_dir, f"secops-auth*malachite*{project_id.replace('malachite-', '')}*.json"),
    ]
    for pattern in patterns:
        key_files = glob.glob(pattern)
        if key_files:
            return True, f"Key file already exists: {os.path.basename(key_files[0])}"

    # List all files in the directory for context
    all_files = glob.glob(os.path.join(jwt_dir, '*.json'))
    if all_files:
        names = [os.path.basename(f) for f in all_files]
        return False, f"No key for {project_id}, but {len(all_files)} other key(s) found: {', '.join(names)}"

    return False, f"No key files found in {jwt_dir}/"


def set_gcloud_project(project_id: str) -> Tuple[bool, str]:
    """Set the default gcloud project to the one collected in the previous step."""
    try:
        result = subprocess.run(
            ['gcloud', 'config', 'set', 'project', project_id],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return True, f"Default project set to {project_id}"
        return False, f"Failed to set project: {result.stderr.strip()}"
    except FileNotFoundError:
        return False, "gcloud CLI not found"
    except subprocess.TimeoutExpired:
        return False, "gcloud config set project timed out"
    except Exception as e:
        return False, f"Error setting project: {str(e)}"


def run_step1_prechecks(tenant_id: str, gcp_project_id: str, env: str = "prod", region: str = "US") -> Dict:
    """
    Run all pre-checks for step1 migration.

    Returns a dictionary with check results and overall status.
    """
    results = {
        'checks': [],
        'all_passed': True,
        'critical_failures': [],
        'warnings': [],
        'ready_to_proceed': False
    }

    # Set the default gcloud project to the one collected from the user
    set_project_passed, set_project_msg = set_gcloud_project(gcp_project_id)
    results['checks'].append({
        'name': 'Set gcloud Project',
        'passed': set_project_passed,
        'message': set_project_msg,
        'critical': True
    })
    if not set_project_passed:
        results['all_passed'] = False
        results['critical_failures'].append('Set gcloud Project')

    # Critical checks (must pass)
    critical_checks = [
        ("gcloud Authentication", check_gcloud_auth()),
        ("GCP Project Access", check_gcp_project_access(gcp_project_id))
    ]

    for check_name, (passed, message) in critical_checks:
        results['checks'].append({
            'name': check_name,
            'passed': passed,
            'message': message,
            'critical': True
        })
        if not passed:
            results['all_passed'] = False
            results['critical_failures'].append(check_name)

    # Non-critical checks (informational)
    info_checks = [
        ("SecOps Auth Status", check_secops_auth_enabled(tenant_id, env, region)),
        ("Service Account", check_service_account_exists(gcp_project_id)),
        ("Existing Key File", check_key_file_exists(gcp_project_id))
    ]

    for check_name, (passed, message) in info_checks:
        results['checks'].append({
            'name': check_name,
            'passed': passed,
            'message': message,
            'critical': False
        })
        if not passed and check_name != "Existing Key File":
            results['warnings'].append(message)

    # Ready to proceed if all critical checks passed
    results['ready_to_proceed'] = len(results['critical_failures']) == 0

    return results
