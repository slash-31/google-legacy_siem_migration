#!/usr/bin/env python3

"""
SecOps Authentication and Key Generation Script

This script automates the process of enabling SecOps authentication for multiple tenants
and generates service account keys for their corresponding GCP projects.

Version: 1.3
Name: create_SA_JWT.py
"""

import csv
import subprocess
import logging
import argparse
from datetime import datetime
import os
import sys
import re
import time
import json
from typing import Optional, Tuple

import importlib
_config = importlib.import_module("config")
CLI_MAIN = _config.CLI_MAIN_PATH
SECOPS_SERVICE_ACCOUNT_PATTERN = "secops-auth@malachite"  # fallback filter for list


def get_expected_sa_email(gcp_project_id: str) -> str:
    """
    Construct the expected SecOps service account email from a project ID.

    Pattern: {tla}-secops-auth@{project}.iam.gserviceaccount.com
    Example: <project-id> -> <tla>-secops-auth@<project-id>.iam.gserviceaccount.com
    """
    match = re.search(r'malachite-(\w+)', gcp_project_id)
    if match:
        tla = match.group(1).lower()
        return f"{tla}-secops-auth@{gcp_project_id}.iam.gserviceaccount.com"
    return ""
DEFAULT_KEY_OUTPUT_DIR = os.path.join(os.path.expanduser('~'), '.secops_auth_JWTs')
DEFAULT_REGION = "US"
DEFAULT_ENV = "prod"
SUCCESS_LOG_FILE = "secops_success_log.txt"
FAILURE_LOG_FILE = "secops_failure_log.txt"

def ensure_output_dir(path: str):
    if not os.path.exists(path):
        os.makedirs(path)

def setup_logging(output_dir: str) -> str:
    ensure_output_dir(output_dir)
    now_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_filename = os.path.join(output_dir, f'secops_script_log_{now_str}.log')
    logging.basicConfig(
        filename=log_filename,
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s %(message)s'
    )
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    logging.getLogger().addHandler(console_handler)
    return log_filename

def run_command(command: str, capture_output: bool=True) -> str:
    logging.debug(f'Executing command: {command}')
    try:
        result = subprocess.run(
            command,
            capture_output=capture_output,
            shell=True,
            text=True,
            check=True
        )
        output = result.stdout.strip()
        log_output = output[:200] + "..." if len(output) > 200 else output
        logging.debug(f'Command succeeded. Output: {log_output}')
        return output
    except subprocess.CalledProcessError as e:
        error_msg = f'Command failed: {command}\nError: {e.stderr}'
        logging.error(error_msg)
        raise

def key_file_path_for_customer(gcp_project_id: str, service_account_email: str, output_dir: str) -> str:
    """Legacy function for temporary key file naming."""
    safe_email = service_account_email.replace('@', '_').replace('.', '_')
    key_filename = f"{gcp_project_id}_{safe_email}_key.json"
    return os.path.join(output_dir, key_filename)

def get_key_file_path_by_client_email(client_email: str, output_dir: str) -> str:
    """
    Get the path for a key file using the client_email naming convention.
    
    Args:
        client_email: Service account email from the JSON key
        output_dir: Directory containing key files
        
    Returns:
        Path to the key file
    """
    safe_client_email = client_email.replace('@', '_').replace('.', '_')
    key_filename = f"{safe_client_email}.json"
    return os.path.join(output_dir, key_filename)

def extract_client_email_from_key(key_file_path: str) -> Optional[str]:
    """
    Extract the client_email field from a service account JSON key file.
    
    Args:
        key_file_path: Path to the JSON key file
        
    Returns:
        The client_email value or None if not found
    """
    try:
        with open(key_file_path, 'r', encoding='utf-8') as f:
            key_data = json.load(f)
            client_email = key_data.get('client_email')
            if client_email:
                logging.debug(f"Extracted client_email: {client_email}")
                return client_email
            else:
                logging.warning(f"No client_email field found in {key_file_path}")
                return None
    except Exception as e:
        logging.error(f"Error reading key file {key_file_path}: {str(e)}")
        return None

def key_file_exists(gcp_project_id: str, service_account_email: str, output_dir: str) -> bool:
    """Check if key file exists using legacy naming or new client_email naming."""
    # Check new naming convention first
    new_path = get_key_file_path_by_client_email(service_account_email, output_dir)
    if os.path.exists(new_path) and os.path.getsize(new_path) > 0:
        return True
    
    # Fall back to legacy naming
    legacy_path = key_file_path_for_customer(gcp_project_id, service_account_email, output_dir)
    return os.path.exists(legacy_path) and os.path.getsize(legacy_path) > 0

def key_file_exists_by_client_email(client_email: str, output_dir: str) -> bool:
    """
    Check if a key file exists using the client_email naming convention.
    
    Args:
        client_email: Service account email
        output_dir: Directory containing key files
        
    Returns:
        True if the key file exists and is non-empty
    """
    path = get_key_file_path_by_client_email(client_email, output_dir)
    return os.path.exists(path) and os.path.getsize(path) > 0

def enable_secops_auth(tenant_id: str, env: str = DEFAULT_ENV, region: str = DEFAULT_REGION) -> str:
    logging.info(f'Enabling SecOps authentication for tenant: {tenant_id}')
    cmd = (
        f"{CLI_MAIN} "
        f"customer enable_secops_authentication {tenant_id} "
        f"--env={env} --region={region}"
    )
    return run_command(cmd)

def find_secops_auth_service_account(gcp_project_id: str, retries: int = 3, delay_sec: int = 5) -> Optional[str]:
    """
    Find the SecOps authentication service account in a GCP project.

    First tries a direct describe using the expected email pattern
    ({tla}-secops-auth@{project}.iam.gserviceaccount.com).
    Falls back to listing all SAs and filtering if describe fails.

    Retries up to 'retries' times with 'delay_sec' between attempts.

    Args:
        gcp_project_id: The Google Cloud Project ID to search in
        retries: Number of attempts before giving up (default 3)
        delay_sec: Seconds to wait between attempts (default 5)

    Returns:
        The service account email if found, None otherwise
    """
    expected_email = get_expected_sa_email(gcp_project_id)

    for attempt in range(1, retries + 1):
        logging.info(f'Attempt {attempt}: Searching for SecOps service account in project: {gcp_project_id}')

        # Try direct describe first (faster, no listing)
        if expected_email:
            describe_cmd = (
                f"gcloud iam service-accounts describe {expected_email} "
                f"--project={gcp_project_id} "
                f"--format='value(email)'"
            )
            try:
                output = run_command(describe_cmd)
                if output.strip():
                    logging.info(f'Found SecOps service account: {output.strip()} (attempt {attempt})')
                    return output.strip()
            except subprocess.CalledProcessError:
                logging.debug(f'Attempt {attempt}: describe failed for {expected_email}, trying list fallback')

        # Fallback: list all SAs and filter
        list_cmd = (
            f"gcloud iam service-accounts list "
            f"--project={gcp_project_id} "
            f"--format='value(email)'"
        )
        try:
            output = run_command(list_cmd)
            for line in output.splitlines():
                if SECOPS_SERVICE_ACCOUNT_PATTERN in line:
                    service_account_email = line.strip()
                    logging.info(f'Found SecOps service account: {service_account_email} (attempt {attempt})')
                    return service_account_email
            logging.warning(f'Attempt {attempt}: No SecOps service account found in project {gcp_project_id}')
        except subprocess.CalledProcessError:
            logging.warning(f'Attempt {attempt}: Failed to list service accounts in project {gcp_project_id}')

        if attempt < retries:
            logging.info(f"Waiting {delay_sec} seconds before retrying service account lookup...")
            time.sleep(delay_sec)

    logging.error(f'No SecOps service account found in project {gcp_project_id} after {retries} attempts.')
    return None

def generate_service_account_key(gcp_project_id: str, service_account_email: str, output_dir: str = DEFAULT_KEY_OUTPUT_DIR) -> str:
    """
    Generate a service account key and rename it using the client_email from the key file.
    
    Args:
        gcp_project_id: GCP project ID
        service_account_email: Service account email
        output_dir: Directory to store the key file
        
    Returns:
        Path to the final renamed key file
    """
    logging.info(f'Generating key for service account: {service_account_email}')
    ensure_output_dir(output_dir)
    
    # Create temporary key file with original naming scheme
    temp_key_path = key_file_path_for_customer(gcp_project_id, service_account_email, output_dir)
    
    cmd = (
        f"gcloud iam service-accounts keys create {temp_key_path} "
        f"--iam-account={service_account_email} "
        f"--project={gcp_project_id}"
    )
    run_command(cmd)
    logging.info(f'Successfully generated key file: {temp_key_path}')
    
    # Extract client_email and rename the file
    client_email = extract_client_email_from_key(temp_key_path)
    
    if client_email:
        # Create new filename using client_email
        new_key_path = get_key_file_path_by_client_email(client_email, output_dir)
        
        # Check if a file with the new name already exists
        if os.path.exists(new_key_path):
            logging.warning(f'Key file {new_key_path} already exists. Removing temp file.')
            os.remove(temp_key_path)
            return new_key_path
        
        # Rename the file
        try:
            os.rename(temp_key_path, new_key_path)
            logging.info(f'Renamed key file to: {new_key_path}')
            return new_key_path
        except Exception as e:
            logging.warning(f'Failed to rename key file: {str(e)}. Using original name.')
            return temp_key_path
    else:
        logging.warning('Could not extract client_email, keeping original filename')
        return temp_key_path

def log_success_attempt(tenant_id: str, gcp_project_id: str, service_account_email: str, key_file_path: str, output_dir: str):
    ensure_output_dir(output_dir)
    success_log_path = os.path.join(output_dir, SUCCESS_LOG_FILE)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(success_log_path, 'a', encoding='utf-8') as f:
        f.write(f"{timestamp}|{tenant_id}|{gcp_project_id}|{service_account_email}|{os.path.basename(key_file_path)}\n")
    logging.info(f"Success logged to: {success_log_path}")

def log_failure_attempt(tenant_id: str, gcp_project_id: str, error_message: str, output_dir: str):
    ensure_output_dir(output_dir)
    failure_log_path = os.path.join(output_dir, FAILURE_LOG_FILE)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(failure_log_path, 'a', encoding='utf-8') as f:
        f.write(f"{timestamp}|{tenant_id}|{gcp_project_id}|{error_message}\n")
    logging.info(f"Failure logged to: {failure_log_path}")

def check_if_already_processed(tenant_id: str, gcp_project_id: str, output_dir: str) -> Tuple[bool, str, Optional[str]]:
    """Check if a tenant/project was already processed; returns (bool, details, service_account_email)."""
    success_log_path = os.path.join(output_dir, SUCCESS_LOG_FILE)
    if not os.path.exists(success_log_path):
        return False, "", None
    try:
        with open(success_log_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                parts = line.split('|')
                if len(parts) >= 4:
                    logged_tenant, logged_project = parts[1], parts[2]
                    if logged_tenant == tenant_id and logged_project == gcp_project_id:
                        timestamp = parts[0]
                        service_account = parts[3] if len(parts) >= 4 else "unknown"
                        key_file = parts[4] if len(parts) >= 5 else "unknown"
                        details = f"Previously processed on {timestamp}, SA: {service_account}, Key: {key_file}"
                        return True, details, service_account
        return False, "", None
    except Exception as e:
        logging.warning(f"Error checking success log: {str(e)}")
        return False, "", None

def verify_existing_key_file(tenant_id: str, gcp_project_id: str, output_dir: str) -> bool:
    is_processed, _, sa_email = check_if_already_processed(tenant_id, gcp_project_id, output_dir)
    if not is_processed or not sa_email:
        return False
    
    # Check both naming conventions
    if key_file_exists_by_client_email(sa_email, output_dir):
        logging.debug(f"Verified existing key file with client_email naming")
        return True
    
    legacy_path = key_file_path_for_customer(gcp_project_id, sa_email, output_dir)
    if os.path.exists(legacy_path) and os.path.isfile(legacy_path) and os.path.getsize(legacy_path) > 0:
        logging.debug(f"Verified existing key file: {legacy_path}")
        return True
    
    return False

def validate_csv_file(csv_file: str) -> str:
    if not os.path.exists(csv_file):
        raise FileNotFoundError(f"CSV file not found: {csv_file}")
    required_columns = {'tenant_id', 'gcp_project_id'}
    with open(csv_file, newline='') as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError("CSV file appears to be empty or invalid")
        available_columns = set(reader.fieldnames)
        missing_columns = required_columns - available_columns
        if missing_columns:
            raise ValueError(f"Missing required columns: {', '.join(missing_columns)}")
        if 'customer_id' in available_columns and 'customer_code' in available_columns:
            return 'enterprise'
        elif 'soar_fe' in available_columns:
            return 'extended'
        else:
            return 'simple'

def process_single_customer(tenant_id: str, gcp_project_id: str, output_dir: str, env: str = DEFAULT_ENV, region: str = DEFAULT_REGION) -> Tuple[bool, Optional[str]]:
    logging.info("=" * 60)
    logging.info("SINGLE CUSTOMER PROCESSING MODE")
    logging.info("=" * 60)
    logging.info(f"Tenant ID: {tenant_id}")
    logging.info(f"GCP Project ID: {gcp_project_id}")
    logging.info(f"Output Directory: {output_dir}")
    logging.info("=" * 60)

    # Skip if key exists and is valid
    is_processed, details, sa_email = check_if_already_processed(tenant_id, gcp_project_id, output_dir)
    if is_processed and sa_email and key_file_exists(gcp_project_id, sa_email, output_dir):
        logging.info(f"Customer already processed successfully: {details}")
        logging.info("=" * 60 + "\nSINGLE CUSTOMER PROCESSING SKIPPED (ALREADY COMPLETED)\n" + "=" * 60)
        # Determine the key path to return
        new_path = get_key_file_path_by_client_email(sa_email, output_dir)
        if os.path.exists(new_path):
            return True, new_path
        else:
            legacy_path = key_file_path_for_customer(gcp_project_id, sa_email, output_dir)
            return True, legacy_path

    try:
        enable_secops_auth(tenant_id, env, region)
        service_account_email = find_secops_auth_service_account(gcp_project_id)
        if not service_account_email:
            error_msg = "SecOps service account not found"
            logging.error(f"{error_msg}")
            log_failure_attempt(tenant_id, gcp_project_id, error_msg, output_dir)
            return False, None
        logging.info("Pausing 5 seconds before generating JSON key to allow IAM propagation...")
        time.sleep(5)
        
        # Check if key file already exists (either naming convention)
        if key_file_exists(gcp_project_id, service_account_email, output_dir):
            logging.info(f"Key already exists for {service_account_email}, skipping key creation.")
            # Get the actual key file path for logging
            new_path = get_key_file_path_by_client_email(service_account_email, output_dir)
            if os.path.exists(new_path):
                key_path = new_path
            else:
                key_path = key_file_path_for_customer(gcp_project_id, service_account_email, output_dir)
            log_success_attempt(tenant_id, gcp_project_id, service_account_email, key_path, output_dir)
            return True, key_path

        key_file_path = generate_service_account_key(gcp_project_id, service_account_email, output_dir)
        log_success_attempt(tenant_id, gcp_project_id, service_account_email, key_file_path, output_dir)
        logging.info("=" * 60 + "\nSINGLE CUSTOMER PROCESSING COMPLETED SUCCESSFULLY\n" + "=" * 60)
        return True, key_file_path

    except Exception as e:
        error_msg = f"Processing exception: {str(e)}"
        logging.error(f"Error processing single customer: {error_msg}")
        log_failure_attempt(tenant_id, gcp_project_id, error_msg, output_dir)
        logging.info("=" * 60 + "\nSINGLE CUSTOMER PROCESSING FAILED\n" + "=" * 60)
        return False, None

def process_csv_file(csv_file: str, output_dir: str, env: str = DEFAULT_ENV, region: str = DEFAULT_REGION) -> Tuple[int, int, int]:
    logging.info(f'Starting to process CSV file: {csv_file}')
    csv_format = validate_csv_file(csv_file)
    logging.info(f'Detected CSV format: {csv_format}')
    success_count = 0
    error_count = 0
    skipped_count = 0

    with open(csv_file, newline='') as f:
        reader = csv.DictReader(f)
        for row_num, row in enumerate(reader, start=1):
            try:
                tenant_id = row['tenant_id'].strip()
                gcp_project_id = row['gcp_project_id'].strip()
                soar_fe = row.get('soar_fe', '').strip() if csv_format in ['extended', 'enterprise'] else ''
                if not tenant_id or not gcp_project_id:
                    logging.warning(f'Skipping row {row_num}: missing tenant_id or gcp_project_id')
                    continue

                log_msg = f'Processing row {row_num}: tenant_id={tenant_id}, gcp_project_id={gcp_project_id}'
                if soar_fe:
                    log_msg += f', soar_fe={soar_fe}'
                logging.info(log_msg)

                # Check existence of key first
                is_processed, details, sa_email = check_if_already_processed(tenant_id, gcp_project_id, output_dir)
                if is_processed and sa_email and key_file_exists(gcp_project_id, sa_email, output_dir):
                    logging.info(f"Row {row_num}: Already processed successfully - {details}")
                    skipped_count += 1
                    continue

                enable_secops_auth(tenant_id, env, region)
                service_account_email = find_secops_auth_service_account(gcp_project_id)
                if not service_account_email:
                    error_msg = f"SecOps service account not found for project {gcp_project_id}"
                    logging.error(f"Row {row_num}: {error_msg}")
                    log_failure_attempt(tenant_id, gcp_project_id, error_msg, output_dir)
                    error_count += 1
                    continue

                if key_file_exists(gcp_project_id, service_account_email, output_dir):
                    logging.info(f"Row {row_num}: Key already exists for {service_account_email}, skipping key creation.")
                    # Get the actual key file path for logging
                    new_path = get_key_file_path_by_client_email(service_account_email, output_dir)
                    if os.path.exists(new_path):
                        key_path = new_path
                    else:
                        key_path = key_file_path_for_customer(gcp_project_id, service_account_email, output_dir)
                    log_success_attempt(tenant_id, gcp_project_id, service_account_email, key_path, output_dir)
                    skipped_count += 1
                    continue

                key_file_path = generate_service_account_key(gcp_project_id, service_account_email, output_dir)
                log_success_attempt(tenant_id, gcp_project_id, service_account_email, key_file_path, output_dir)
                success_count += 1
                logging.info(f'Row {row_num}: Successfully processed {tenant_id}')
            except Exception as e:
                error_msg = f"Error processing row: {str(e)}"
                logging.error(f"Row {row_num}: {error_msg}")
                log_failure_attempt(tenant_id, gcp_project_id, error_msg, output_dir)
                error_count += 1

    logging.info(f'Processing complete. Success: {success_count}, Errors: {error_count}, Skipped: {skipped_count}')
    return success_count, error_count, skipped_count

def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Enable SecOps authentication and generate service account keys.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
# Process CSV file
%(prog)s customer_list.csv
%(prog)s customer_list.csv --output-dir /path/to/keys

# Process single customer (quick mode)
%(prog)s -t tenant-001 -p my-gcp-project-001
%(prog)s --tenant tenant-001 --project my-gcp-project-001 --output-dir ./keys

# Help and information
%(prog)s --help
%(prog)s --simple-help
CSV Format Support:
The script supports multiple CSV formats:
Simple: tenant_id,gcp_project_id
Extended: tenant_id,soar_fe,gcp_project_id
Enterprise: tenant_id,customer_id,customer_code,customer_name,gcp_project_id,gcp_project_id_from_gcp
        """
    )
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('csv_file', nargs='?', help='Path to the CSV file containing tenant and project information')
    input_group.add_argument('-t', '--tenant', help='Process a single tenant ID (requires --project)')
    parser.add_argument('-p', '--project', help='GCP project ID (required when using --tenant)')
    parser.add_argument('-o', '--output-dir', default=DEFAULT_KEY_OUTPUT_DIR, help=f'Directory to store generated key files (default: {DEFAULT_KEY_OUTPUT_DIR})')
    parser.add_argument('--env', default=DEFAULT_ENV, choices=['prod', 'staging', 'dev'], help=f'Environment for cli_main operations (default: {DEFAULT_ENV})')
    parser.add_argument('--region', default=DEFAULT_REGION, help=f'Region for cli_main operations (default: {DEFAULT_REGION})')
    parser.add_argument('--simple-help', action='store_true', help='Show simplified help message')
    parser.add_argument('--version', action='version', version='SecOps Authentication Script v1.3')
    return parser

def show_simple_help():
    help_text = """
SecOps Authentication Script - Quick Help
USAGE:
# Process CSV file
python3 {script_name} customer_list.csv
# Process single customer
python3 {script_name} -t tenant-001 -p my-gcp-project-001
# Custom output directory
python3 {script_name} customer_list.csv --output-dir ./keys
WHAT IT DOES:
1. Enables SecOps authentication for tenant(s)
2. Finds SecOps service account in GCP project(s)
3. Generates JSON key file(s) named using client_email from the key
CSV FORMAT (any of these work):
tenant_id,gcp_project_id
tenant_id,soar_fe,gcp_project_id
tenant_id,customer_id,customer_code,customer_name,gcp_project_id,gcp_project_id_from_gcp
KEY FILE NAMING:
Files are named using the client_email from the JSON key file:
Example: secops-auth_project-example_com.json
REQUIREMENTS:
- gcloud CLI authenticated
- cli_main tool access
- GCP IAM permissions
For full help: python3 {script_name} --help
""".format(script_name=os.path.basename(sys.argv[0]))
    print(help_text)

def main():
    parser = create_argument_parser()
    args = parser.parse_args()
    if args.simple_help:
        show_simple_help()
        sys.exit(0)
    if args.tenant and not args.project:
        print("Error: --project is required when using --tenant")
        print("Try: python3 {} --simple-help".format(os.path.basename(sys.argv[0])))
        sys.exit(1)
    log_filename = setup_logging(args.output_dir)
    try:
        logging.info("=" * 60)
        logging.info("SecOps Authentication and Key Generation Script")
        logging.info("=" * 60)
        if args.tenant:
            logging.info("Processing Mode: Single Customer")
            logging.info(f"Tenant ID: {args.tenant}")
            logging.info(f"GCP Project ID: {args.project}")
            success, _ = process_single_customer(args.tenant, args.project, args.output_dir, args.env, args.region)
            success_count = 1 if success else 0
            error_count = 0 if success else 1
            skipped_count = 0
        else:
            logging.info("Processing Mode: CSV File")
            logging.info(f"CSV file: {args.csv_file}")
            csv_format = validate_csv_file(args.csv_file)
            logging.info(f"CSV format detected: {csv_format}")
            logging.info(f"Output directory: {args.output_dir}")
            logging.info(f"Environment: {args.env}")
            logging.info(f"Region: {args.region}")
            logging.info(f"Log file: {log_filename}")
            success_count, error_count, skipped_count = process_csv_file(args.csv_file, args.output_dir, args.env, args.region)
        print("\n" + "=" * 60)
        print("SCRIPT EXECUTION COMPLETE")
        print("=" * 60)
        if args.tenant:
            print("Single customer processed successfully" if success_count > 0 else "Single customer processing failed")
        else:
            print(f"Successfully processed: {success_count} customers")
            print(f"Failed to process: {error_count} customers")
            print(f"Skipped (already completed): {skipped_count} customers")
            print(f"Generated keys stored in: {args.output_dir}")
            print(f"Success log: {os.path.join(args.output_dir, SUCCESS_LOG_FILE)}")
            print(f"Failure log: {os.path.join(args.output_dir, FAILURE_LOG_FILE)}")
            print(f"Detailed logs written to: {log_filename}")
            print("=" * 60)
        sys.exit(0 if error_count == 0 else 1)
    except KeyboardInterrupt:
        logging.info("Script interrupted by user")
        print("\nScript interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        print(f"\nError: {str(e)}")
        print(f"Check the log file for details: {log_filename}")
        sys.exit(1)

if __name__ == '__main__':
    main()