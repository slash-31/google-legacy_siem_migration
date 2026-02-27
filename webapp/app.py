from flask import Flask, render_template, request, jsonify, session
import secrets
import os
import re
import select
import sys
import subprocess
import time
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
    """Get current authentication and authorization status."""
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
        # Store key content in session or return it to be stored in frontend state?
        # Returning it to frontend is easier for "Reveal Variables" button on SPA.
        # But for security, maybe keep in session? 
        # Requirement: "Step 1 has been completed... pull client_email... store as a variable... create a button that when clicked will expose the value"
        
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
    # User wants to perform SAML trace FIRST. 
    # Step 2 in script is "configure SOAR".
    # The requirement says: "In step 2 we want to have the customer perform a SAML trace... we do not want to enable SOAR... until we know SAML is passing"
    # So this endpoint should probably cover the actual "Update SecOps" part, 
    # and the frontend handles the "Wait for SAML" manual check.
    
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

# Store the running gcloud auth process so we can feed it the auth code later
_gcloud_auth_process = None


@app.route('/api/gcloud_auth_login', methods=['POST'])
def gcloud_auth_login():
    """Start gcloud auth login --no-launch-browser and return the auth URL."""
    global _gcloud_auth_process

    # Kill any previous auth process
    if _gcloud_auth_process and _gcloud_auth_process.poll() is None:
        _gcloud_auth_process.terminate()
        _gcloud_auth_process = None

    try:
        proc = subprocess.Popen(
            ['gcloud', 'auth', 'login', '--no-launch-browser'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Read stderr until we find the URL (gcloud prints the prompt to stderr)
        url = None
        lines_read = []
        deadline = time.time() + 15  # 15s timeout
        while time.time() < deadline:
            # Check both stdout and stderr for the URL
            ready, _, _ = select.select(
                [proc.stdout, proc.stderr], [], [], 1.0
            )
            for stream in ready:
                line = stream.readline()
                if line:
                    lines_read.append(line.strip())
                    # gcloud outputs: "Go to the following link in your browser:\n\n    https://..."
                    url_match = re.search(r'(https://accounts\.google\.com/\S+)', line)
                    if url_match:
                        url = url_match.group(1)
            if url:
                break

        if url:
            _gcloud_auth_process = proc
            return jsonify({"success": True, "auth_url": url})
        else:
            proc.terminate()
            return jsonify({
                "success": False,
                "message": "Could not extract auth URL from gcloud output",
                "output": lines_read
            }), 500

    except FileNotFoundError:
        return jsonify({"success": False, "message": "gcloud CLI not found"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/gcloud_auth_code', methods=['POST'])
def gcloud_auth_code():
    """Submit the authorization code to complete gcloud auth login."""
    global _gcloud_auth_process

    data = request.json
    auth_code = data.get('auth_code', '').strip()

    if not auth_code:
        return jsonify({"success": False, "message": "Authorization code is required"}), 400

    if not _gcloud_auth_process or _gcloud_auth_process.poll() is not None:
        return jsonify({"success": False, "message": "No active auth session. Start login first."}), 400

    try:
        # Send the auth code to the waiting gcloud process
        _gcloud_auth_process.stdin.write(auth_code + '\n')
        _gcloud_auth_process.stdin.flush()

        # Wait for the process to complete
        stdout, stderr = _gcloud_auth_process.communicate(timeout=30)
        rc = _gcloud_auth_process.returncode
        _gcloud_auth_process = None

        combined = (stdout or '') + (stderr or '')
        if rc == 0 or 'You are now logged in' in combined:
            return jsonify({"success": True, "message": "gcloud authentication successful"})
        else:
            return jsonify({"success": False, "message": f"Auth failed: {combined[-300:]}"}), 500

    except subprocess.TimeoutExpired:
        _gcloud_auth_process.terminate()
        _gcloud_auth_process = None
        return jsonify({"success": False, "message": "Auth code submission timed out"}), 500
    except Exception as e:
        _gcloud_auth_process = None
        return jsonify({"success": False, "message": str(e)}), 500


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

    # Check authentication status (warnings only, does not block startup)
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
