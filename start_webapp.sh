#!/bin/bash
set -e

VENV_DIR="venv"

# Check if venv exists, if not create it
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating Python virtual environment in $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
fi

# Activate venv
source "$VENV_DIR/bin/activate"

# Install dependencies
echo "Installing/Updating dependencies..."
pip install -r requirements.txt

# Run the Flask App
echo "Starting SecOps Migration Web App..."
echo ""
echo "The application will be accessible from:"
echo "  - Localhost: https://127.0.0.1:9443"
echo "  - Network:   https://<your-ip>:9443"
echo ""
python webapp/app.py
