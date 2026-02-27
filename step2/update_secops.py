#!/usr/bin/env python3
"""
------------------------------------------------------------
Tenant SOAR Configuration Updater
------------------------------------------------------------
Name: update_secops.py
Python: 3.8+
------------------------------------------------------------
Description:
    This script automates updating SOAR (Security Orchestration, 
    Automation, and Response) configurations for multiple tenants 
    by reading tenant details from a CSV file. 

    Each tenant entry requires:
      - tenant_id
      - soar_fe (frontend identifier)

    The script:
      1. Reads tenant details from a CSV.
      2. Generates or executes CLI commands for each tenant.
      3. Logs successes and errors to timestamped log files.
      4. Can perform a dry run without executing commands.
      5. Can enable or disable SOAR configurations.
      6. Supports single tenant processing via command-line.

------------------------------------------------------------
Command-Line Usage Example:
    # Dry run with CSV (no commands executed, just printed)
    python update_soar_configs.py -i tenants.csv --dry-run

    # Execute with logs in custom directory using CSV
    python update_soar_configs.py -i tenants.csv -o ./output_logs

    # Disable SOAR for troubleshooting using CSV
    python update_soar_configs.py -i tenants.csv --disable

    # Enable SOAR explicitly using CSV
    python update_soar_configs.py -i tenants.csv --enable

    # Process single tenant (enable mode - default)
    python update_soar_configs.py -t tenant_123 --soar-fe MyCompany

    # Process single tenant (enable mode - explicit)
    python update_soar_configs.py -t tenant_123 --soar-fe MyCompany --enable

    # Process single tenant (disable mode)
    python update_soar_configs.py -t tenant_123 --soar-fe MyCompany --disable

    # Single tenant dry run
    python update_soar_configs.py -t tenant_123 --soar-fe MyCompany --dry-run
------------------------------------------------------------
"""

import argparse
import csv
import logging
import subprocess
import os
from datetime import datetime


# --- Configuration Constants ---
import importlib
_config = importlib.import_module("config")
CLI_MAIN = _config.CLI_MAIN_PATH
ENV = "prod"      # Execution environment
REGION = "US"     # Target region


# --- Logging Setup ---
def setup_logging(output_dir):
    """Sets up logging for successes and errors."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f'success_{timestamp}.log')
    error_file = os.path.join(output_dir, f'errors_{timestamp}.log')

    # Root logger configuration
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        handlers=[
            logging.FileHandler(output_file, 'w', 'utf-8'),
            logging.StreamHandler()  # Also print to console
        ]
    )

    # Dedicated error handler
    error_handler = logging.FileHandler(error_file, 'w', 'utf-8')
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logging.getLogger('').addHandler(error_handler)

    return output_file, error_file


# --- Core Logic ---
def process_single_tenant(tenant_id, soar_fe, dry_run, disable_mode):
    """Process a single tenant with provided tenant_id and soar_fe. Returns True if all commands succeed."""
    return run_commands_for_tenant(tenant_id, soar_fe, dry_run, disable_mode)


def process_tenants_from_csv(csv_file_path, dry_run, disable_mode):
    """
    Reads tenants from CSV and executes/prints CLI commands.
    Expected CSV columns: tenant_id, soar_fe.
    """
    try:
        with open(csv_file_path, mode='r', newline='') as f:
            reader = csv.DictReader(f)

            # Validate required columns
            if 'tenant_id' not in reader.fieldnames or 'soar_fe' not in reader.fieldnames:
                raise ValueError("CSV must contain 'tenant_id' and 'soar_fe' columns.")
            
            # Process each row (tenant)
            for row in reader:
                tenant_id = row['tenant_id']
                soar_fe = row['soar_fe']
                run_commands_for_tenant(tenant_id, soar_fe, dry_run, disable_mode)

    except FileNotFoundError:
        logging.error(f"CSV file not found: {csv_file_path}")
    except ValueError as e:
        logging.error(f"CSV file format error: {e}")
    except Exception as e:
        logging.error(f"Unexpected error occurred: {e}")


def run_commands_for_tenant(tenant_id, soar_fe, dry_run, disable_mode):
    """Executes or prints CLI commands for a given tenant. Returns True if successful."""
    soar_fe_lower = soar_fe.lower()

    # Determine mode text for logging
    mode_text = "DISABLING" if disable_mode else "ENABLING"
    
    if dry_run:
        print(f"--- DRY RUN: Tenant ID {tenant_id} | SOAR_FE {soar_fe_lower} | {mode_text} SOAR ---")
    else:
        logging.info(f"--- Processing Tenant ID {tenant_id} | SOAR_FE {soar_fe_lower} | {mode_text} SOAR ---")

    # Define the commands to execute based on mode
    if disable_mode:
        # Only run the disable command when in disable mode
        commands_to_run = [
            f'{CLI_MAIN} feature set {tenant_id} soar_enabled=false "Disabling SOAR for troubleshooting" --env={ENV} --region={REGION}'
        ]
    else:
        # Run full setup commands when enabling
        commands_to_run = [
            f'{CLI_MAIN} customer set_customer_response_platform_uri {tenant_id} RESPONSE_PLATFORM_TYPE_SIEMPLIFY https://{soar_fe_lower}.siemplify-soar.com:443 --env={ENV} --region={REGION}',
            f'{CLI_MAIN} customer set_customer_soar_api_uri {tenant_id} https://{soar_fe_lower}.siemplify-soar.com --env={ENV} --region={REGION}',
            f'{CLI_MAIN} feature set {tenant_id} soar_enabled=true "Enabling SIEM SOAR connection" --env={ENV} --region={REGION}'
        ]

    # Execute each command
    all_success = True
    for i, cmd in enumerate(commands_to_run, 1):
        if dry_run:
            print(f"  Command {i}: {cmd}")
        else:
            logging.info(f"  Executing Command {i}...")

            # Inject 'Y' for confirmation required by feature enabling/disabling
            input_val = 'Y\n' if 'soar_enabled=' in cmd else None

            try:
                result = subprocess.run(
                    cmd, 
                    shell=True, 
                    check=True, 
                    capture_output=True, 
                    text=True,
                    input=input_val
                )
                logging.info(f"  ✅ Command {i} successful.")
                if result.stdout:
                    logging.info(f"  Output:\n{result.stdout}")
            except subprocess.CalledProcessError as e:
                logging.error(f"  ❌ Command {i} failed | Tenant {tenant_id}")
                logging.error(f"  Command: {cmd}")
                logging.error(f"  Stderr:\n{e.stderr}")
                all_success = False
            except Exception as e:
                logging.error(f"  ❌ Error executing Command {i} | Tenant {tenant_id}: {e}")
                all_success = False
    
    return all_success


# --- Main Execution ---
def main():
    """Entry point: Parse arguments, setup logging, and process tenants."""
    parser = argparse.ArgumentParser(
        description="Update SOAR configurations for tenants via CLI tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Create mutually exclusive group for input methods
    input_group = parser.add_mutually_exclusive_group(required=True)
    
    # CSV input option
    input_group.add_argument(
        '-i', '--input',
        type=str,
        help="Path to input CSV (must have 'tenant_id' and 'soar_fe' columns)."
    )
    
    # Single tenant option
    input_group.add_argument(
        '-t', '--tenant',
        type=str,
        help="Single tenant ID to process (must be used with --soar-fe)."
    )

    # SOAR FE for single tenant (required when using -t)
    parser.add_argument(
        '--soar-fe',
        type=str,
        help="SOAR frontend identifier (required when using -t/--tenant)."
    )

    # Optional logs directory
    parser.add_argument(
        '-o', '--output_dir',
        type=str,
        default='logs',
        help="Path to log directory (default: ./logs)."
    )

    # Dry run flag
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help="Dry run mode: Commands are printed but not executed."
    )

    # Create mutually exclusive group for enable/disable modes
    mode_group = parser.add_mutually_exclusive_group()
    
    # Enable flag
    mode_group.add_argument(
        '--enable',
        action='store_true',
        help="Enable mode: Set soar_enabled=true and configure SOAR URIs (default behavior)."
    )
    
    # Disable flag
    mode_group.add_argument(
        '--disable',
        action='store_true',
        help="Disable mode: Set soar_enabled=false for troubleshooting (skips URI configuration)."
    )

    args = parser.parse_args()

    # Validate single tenant arguments
    if args.tenant and not args.soar_fe:
        parser.error("--soar-fe is required when using -t/--tenant")
    if args.soar_fe and not args.tenant:
        parser.error("--soar-fe can only be used with -t/--tenant")

    # Setup logging only if we're running for real
    if not args.dry_run:
        output_log, error_log = setup_logging(args.output_dir)
        # Determine mode - default to enable if neither flag is specified
        if args.disable:
            mode_text = "DISABLE"
        else:
            mode_text = "ENABLE"
        logging.info(f"Script started in {mode_text} mode. Logs at: {output_log}, {error_log}")
    else:
        # Determine mode for dry run output
        if args.disable:
            mode_text = "DISABLE"
        else:
            mode_text = "ENABLE"
        print(f"--- DRY RUN INITIATED ({mode_text} MODE) ---")

    # Process tenants based on input method
    if args.tenant:
        # Process single tenant
        process_single_tenant(args.tenant, args.soar_fe, args.dry_run, args.disable)
    else:
        # Process tenants from CSV
        process_tenants_from_csv(args.input, args.dry_run, args.disable)

    # Wrap up
    if not args.dry_run:
        logging.info("Script finished successfully.")
    else:
        print("--- DRY RUN COMPLETE ---")


if __name__ == "__main__":
    main()