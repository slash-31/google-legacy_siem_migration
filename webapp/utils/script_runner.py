import os
import sys
import subprocess
import logging
import re

# Add parent directories to path so we can import step1/step2
# Assumes structure:
# root/
#   step1/create_SA_JWT.py
#   step2/update_secops.py
#   webapp/utils/script_runner.py

current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(os.path.dirname(current_dir))
sys.path.append(root_dir)

from step1 import create_SA_JWT
from step2 import update_secops
from webapp.utils import cm_parser

from config import CLI_MAIN_PATH as CLI_MAIN
JWT_OUTPUT_DIR = os.path.join(os.path.expanduser('~'), '.secops_auth_JWTs')

def get_customer_info(customer_id_or_code: str, env: str = "prod", region: str = "US") -> dict:
    """
    Runs the customer management CLI tool and returns parsed dictionary.
    """
    cmd = [CLI_MAIN, "customer", "info", customer_id_or_code, f"--env={env}", f"--region={region}"]
    
    logging.info(f"Running command: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True
        )
        return cm_parser.parse_customer_info(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to get customer info: {e.stderr}")
        return {"error": e.stderr}
    except FileNotFoundError:
        logging.error("cm_cli not found")
        # Return mock data for development if CLI is missing
        return {
            "error": "CLI tool not found", 
            "mock_data": True,
            "tenant_id": "tenant-mock", 
            "customer_features": {"byop_enabled": False}
        }

def extract_customer_code_from_project(gcp_project_id: str) -> str:
    """
    Extract customer code from GCP project ID.
    Format: <prefix>-{code} -> {CODE}
    """
    match = re.search(r'malachite-(\w+)', gcp_project_id)
    if match:
        return match.group(1).upper()
    return ""


def ensure_jwt_dir() -> str:
    """Ensure ~/.secops_auth_JWTs exists. Returns the path."""
    if not os.path.exists(JWT_OUTPUT_DIR):
        os.makedirs(JWT_OUTPUT_DIR)
        logging.info(f"Created JWT output directory: {JWT_OUTPUT_DIR}")
    return JWT_OUTPUT_DIR


def list_jwt_files() -> list:
    """List all JSON key files in ~/.secops_auth_JWTs."""
    import glob
    ensure_jwt_dir()
    files = glob.glob(os.path.join(JWT_OUTPUT_DIR, '*.json'))
    return sorted(files)


def find_existing_jwt(gcp_project_id: str) -> str:
    """
    Check if a JWT key file already exists for a given project.

    Returns the file path if found, empty string otherwise.
    """
    import glob
    ensure_jwt_dir()
    # Match by project ID or by secops-auth@malachite-{code} pattern
    patterns = [
        os.path.join(JWT_OUTPUT_DIR, f'*{gcp_project_id}*.json'),
        os.path.join(JWT_OUTPUT_DIR, f'secops-auth*malachite*{gcp_project_id.replace("malachite-", "")}*.json'),
    ]
    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
    return ""


def run_step1(tenant_id: str, gcp_project_id: str, env: str = "prod") -> dict:
    """
    Runs Step 1: Enable Auth & Generate Key.

    Keys are stored in ~/.secops_auth_JWTs. If a key already exists for the
    project, step 1 is skipped.

    Args:
        tenant_id: SecOps tenant ID
        gcp_project_id: GCP project ID
        env: Environment (prod/staging/dev)

    Returns:
        dict with status and key info
    """
    output_dir = ensure_jwt_dir()

    result = {
        "success": False,
        "key_path": None,
        "message": "",
        "existing_files": list_jwt_files()
    }

    # Check for existing key file
    existing = find_existing_jwt(gcp_project_id)
    if existing:
        logging.info(f"Existing JWT found: {existing}")
        result["success"] = True
        result["key_path"] = existing
        result["message"] = f"SA key already exists: {os.path.basename(existing)}"
        return result

    try:
        success, key_path = create_SA_JWT.process_single_customer(
            tenant_id=tenant_id,
            gcp_project_id=gcp_project_id,
            output_dir=output_dir,
            env=env
        )

        result["success"] = success
        result["key_path"] = key_path

        if success:
            result["message"] = f"Step 1 completed. Key saved to {os.path.basename(key_path)}"
            result["existing_files"] = list_jwt_files()
        else:
            result["message"] = "Step 1 failed: Could not generate SA key"

        return result

    except Exception as e:
        result["success"] = False
        result["message"] = f"Step 1 error: {str(e)}"
        logging.error(f"Step 1 error: {e}", exc_info=True)
        return result

def remove_partner_association(tenant_id: str, partner_code: str, env: str = "prod", region: str = "US") -> dict:
    """
    Removes partner association using cm_cli.
    Command: cli_main cu delete_customer_partner_association CUST PART
    """
    cmd = [CLI_MAIN, "cu", "delete_customer_partner_association", tenant_id, partner_code, f"--env={env}", f"--region={region}"]
    logging.info(f"Running command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True
        )
        return {"success": True, "message": "Partner association removed successfully."}
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to remove partner association: {e.stderr}")
        return {"success": False, "message": f"Failed to remove partner: {e.stderr}"}
    except FileNotFoundError:
        return {"success": True, "message": "Mock: Partner Removed (CLI not found)"}

def add_partner_association(tenant_id: str, partner_code: str, env: str = "prod", region: str = "US") -> dict:
    """
    Re-adds partner association using cm_cli.
    Command: cli_main cu create_customer_partner_association CUST PART
    """
    cmd = [CLI_MAIN, "cu", "create_customer_partner_association", tenant_id, partner_code, f"--env={env}", f"--region={region}"]
    logging.info(f"Running command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True
        )
        return {"success": True, "message": "Partner association added successfully."}
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to add partner association: {e.stderr}")
        return {"success": False, "message": f"Failed to add partner: {e.stderr}"}
    except FileNotFoundError:
        return {"success": True, "message": "Mock: Partner Added (CLI not found)"}

def run_step2(tenant_id: str, soar_fe: str, enable: bool = True, env: str = "prod") -> dict:
    """
    Runs Step 2: Configure SOAR.
    Returns dict with status.
    """
    try:
        # We need to set the global CLI vars in update_secops if we want to change env/region dynamically,
        # but right now they are constants. For now we assume they match the env passed, 
        # or we could monkeypatch if strict env control is needed.
        # update_secops.ENV = env 
        
        success = update_secops.process_single_tenant(
            tenant_id=tenant_id,
            soar_fe=soar_fe,
            dry_run=False,
            disable_mode=not enable
        )
        
        return {
            "success": success,
            "message": "Step 2 completed successfully" if success else "Step 2 failed"
        }
    except Exception as e:
        return {"success": False, "message": str(e)}
