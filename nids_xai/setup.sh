#!/bin/bash
# =============================================================================
# NIDS with XAI - Setup Script (Linux/Mac)
# =============================================================================
# This script sets up the virtual environment and installs dependencies.
# Run with: chmod +x setup.sh && ./setup.sh
# =============================================================================

set -e  # Exit on error

echo "========================================"
echo "  NIDS with XAI - Setup Script"
echo "========================================"
echo ""

# Check Python version
PYTHON_CMD=""
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo "Error: Python not found. Please install Python 3.8 or higher."
    exit 1
fi

# Check Python version is 3.8+
PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Found Python $PYTHON_VERSION"

# Create virtual environment
echo ""
echo "Creating virtual environment..."
$PYTHON_CMD -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo ""
echo "Installing dependencies..."
pip install -r requirements.txt

# Create necessary directories
echo ""
echo "Creating directories..."
mkdir -p data/raw data/processed models outputs logs

# Success message
echo ""
echo "========================================"
echo "  Setup Complete!"
echo "========================================"
echo ""
echo "To activate the virtual environment:"
echo "  source venv/bin/activate"
echo ""
echo "To run the application:"
echo "  python main.py"
echo ""
echo "To deactivate the virtual environment:"
echo "  deactivate"
echo ""
echo "Don't forget to place your dataset files in:"
echo "  data/raw/"
echo ""
