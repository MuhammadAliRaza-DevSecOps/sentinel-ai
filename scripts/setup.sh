#!/bin/bash
# scripts/setup.sh
# Ek command mein pura project setup kar deta hai
# Chalane ka tarika: chmod +x scripts/setup.sh && ./scripts/setup.sh

set -e  # Agar koi command fail ho to script band kar do

echo "=============================================="
echo "  DevSecOps Pipeline Orchestrator Setup"
echo "=============================================="

# Python version check
echo ""
echo "1. Python check..."
python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
echo "   Python: $python_version"

# Virtual environment
echo ""
echo "2. Virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "   venv banaya"
else
    echo "   venv pehle se hai"
fi

# Activate venv
source venv/bin/activate

# Install Python packages
echo ""
echo "3. Python packages install ho rahe hain..."
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo "   Done!"

# Security tools install
echo ""
echo "4. Security tools install ho rahe hain..."

# Semgrep
if ! command -v semgrep &> /dev/null; then
    echo "   Semgrep install ho raha hai..."
    pip install -q semgrep
fi
echo "   Semgrep: OK"

# Bandit
if ! command -v bandit &> /dev/null; then
    pip install -q bandit
fi
echo "   Bandit: OK"

# Safety
if ! command -v safety &> /dev/null; then
    pip install -q safety
fi
echo "   Safety: OK"

# pip-audit
if ! command -v pip-audit &> /dev/null; then
    pip install -q pip-audit
fi
echo "   pip-audit: OK"

# Trivy (Linux only)
if ! command -v trivy &> /dev/null; then
    echo "   Trivy install ho raha hai..."
    wget -q -O /tmp/trivy_install.sh https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh
    sh /tmp/trivy_install.sh -b /usr/local/bin 2>/dev/null || echo "   Trivy: manual install karein — https://aquasecurity.github.io/trivy"
fi

# .env file
echo ""
echo "5. Environment file..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "   .env create kiya — please fill karein"
else
    echo "   .env pehle se hai"
fi

# Output directory
mkdir -p reports/output

echo ""
echo "=============================================="
echo "  Setup Complete!"
echo "=============================================="
echo ""
echo "Agla step:"
echo "  1. .env file mein values fill karein"
echo "  2. docker-compose up -d --build"
echo "  3. http://localhost:8501 kholo"
echo ""