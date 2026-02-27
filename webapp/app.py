from flask import Flask, render_template, request, jsonify, session
import secrets
import os
import re
import sys
import subprocess
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from webapp.utils import script_runner, cm_parser, auth_checker, precheck

app = Flask(__name__)
# Generate a secret key for session storage
app.secret_key = secrets.token_hex(16)

# Configure logging
logging.basicConfig(level=logging.INFO)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/auth_status', methods=['GET'])
def auth_status():
    """Get current authentication status."""
    status = auth_checker.get_auth_status()
    return jsonify(status)

@app.route('/api/precheck_step1', methods=['POST'])
def precheck_step1():
    """Run pre-checks for step1 migration (gcloud, cli_main, project access)."""
    data = request.json
    tenant_id = data.get('tenant_id')
    gcp_project_id = data.get('gcp_project_id')
    env = data.get('env', 'prod')
    region = data.get('region', 'US')

    if not tenant_id or not gcp_project_id:
        return jsonify({"error": "tenant_id and gcp_project_id are required"}), 400

    results = precheck.run_step1_prechecks(tenant_id, gcp_project_id, env, region)
    return jsonify(results)

@app.route('/api/check_customer', methods=['POST'])
def check_customer():
    data = request.json
    tenant_id = data.get('tenant_id')
    # Use tenant_id or customer_code if provided?
    # User prompt said "Collect information... Use information to pull tenant information"
    # Usually tenant_id works for customer info lookup if it is the UUID,
    # or we might need a separate field. The CLI supports both.

    if not tenant_id:
        return jsonify({"error": "Tenant ID is required"}), 400

    info = script_runner.get_customer_info(tenant_id)
    if "error" in info:
        return jsonify(info), 500

    # Analyze for BYOP/Pre-reqs
    byop_status = cm_parser.check_byop_status(info)

    return jsonify({
        "customer_info": info,
        "byop_status": byop_status
    })

@app.route('/api/run_step1', methods=['POST'])
def run_step1():
    data = request.json
    tenant_id = data.get('tenant_id')
    gcp_project_id = data.get('gcp_project_id')
    env = data.get('env', 'prod')

    if not tenant_id or not gcp_project_id:
        return jsonify({"error": "Missing required fields"}), 400

    result = script_runner.run_step1(tenant_id, gcp_project_id, env=env)

    if result.get('success'):
        key_path = result.get('key_path')
        client_email = None
        key_content = None

        if key_path and os.path.exists(key_path):
            try:
                with open(key_path, 'r') as f:
                    key_content = f.read()
                    import json
                    key_json = json.loads(key_content)
                    client_email = key_json.get('client_email')
            except Exception as e:
                logging.error(f"Failed to read key file: {e}")

        return jsonify({
            "success": True,
            "message": result.get('message'),
            "client_email": client_email,
            "key_content": key_content,
            "key_path": key_path
        })
    else:
        return jsonify(result), 500

@app.route('/api/run_step2', methods=['POST'])
def run_step2():
    data = request.json
    tenant_id = data.get('tenant_id')
    soar_fe = data.get('soar_fe')

    if not tenant_id or not soar_fe:
        return jsonify({"error": "Missing required fields"}), 400

    result = script_runner.run_step2(tenant_id, soar_fe)
    return jsonify(result)

@app.route('/api/remove_partner', methods=['POST'])
def remove_partner():
    data = request.json
    tenant_id = data.get('tenant_id')
    partner_code = data.get('partner_code')
    env = data.get('env', 'prod')

    if not tenant_id or not partner_code:
        return jsonify({"success": False, "message": "Missing tenant_id or partner_code"}), 400

    result = script_runner.remove_partner_association(tenant_id, partner_code, env=env)
    return jsonify(result)

@app.route('/api/add_partner', methods=['POST'])
def add_partner():
    data = request.json
    tenant_id = data.get('tenant_id')
    partner_code = data.get('partner_code')
    env = data.get('env', 'prod')

    if not tenant_id or not partner_code:
        return jsonify({"success": False, "message": "Missing tenant_id or partner_code"}), 400

    result = script_runner.add_partner_association(tenant_id, partner_code, env=env)
    return jsonify(result)


@app.route('/api/set_gcloud_project', methods=['POST'])
def set_gcloud_project():
    """Set the default gcloud project."""
    data = request.json
    project_id = data.get('project_id', '').strip()

    if not project_id:
        return jsonify({"success": False, "message": "project_id is required"}), 400

    # Basic validation: only allow alphanumeric, hyphens, and colons
    if not re.match(r'^[a-zA-Z0-9:._-]+$', project_id):
        return jsonify({"success": False, "message": "Invalid project ID format"}), 400

    try:
        result = subprocess.run(
            ['gcloud', 'config', 'set', 'project', project_id],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return jsonify({"success": True, "message": f"Default project set to {project_id}"})
        else:
            return jsonify({
                "success": False,
                "message": f"Failed to set project: {result.stderr.strip()}"
            }), 500
    except FileNotFoundError:
        return jsonify({"success": False, "message": "gcloud CLI not found"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "gcloud command timed out"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


if __name__ == '__main__':
    import ssl
    import socket

    # Check gcloud authentication — exits if not authenticated with @google.com
    auth_checker.validate_startup_requirements()

    # SSL/TLS Configuration
    from config import SSL_CERT, SSL_KEY
    cert_path = SSL_CERT
    key_path = SSL_KEY

    ssl_context = None
    protocol = 'https' if os.path.exists(cert_path) and os.path.exists(key_path) else 'http'

    if os.path.exists(cert_path) and os.path.exists(key_path):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_path, key_path)
        logging.info("SSL/TLS enabled with wildcard certificate")
    else:
        logging.warning(f"SSL certificates not found at {cert_path} and {key_path}. Running without SSL.")

    port = int(os.environ.get('PORT', 9443))

    # Get hostname and display accessible URLs
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
        logging.info(f"SecOps Migration Web App starting on port {port}")
        logging.info(f"  Localhost:    {protocol}://127.0.0.1:{port}")
        logging.info(f"  Network IP:   {protocol}://{local_ip}:{port}")
        logging.info(f"  Hostname:     {protocol}://{hostname}:{port}")
    except:
        logging.info(f"SecOps Migration Web App starting on {protocol}://0.0.0.0:{port}")

    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug, host='0.0.0.0', port=port, ssl_context=ssl_context)
