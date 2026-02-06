#!/bin/bash
# Quick Start Script for SecOps Toolkit

echo "========================================="
echo "  SecOps Automation Toolkit - Demo"
echo "========================================="
echo ""

# Check Python version
echo "[*] Checking Python version..."
python3 --version

echo ""
echo "[*] Installing dependencies..."
pip3 install -q requests pandas matplotlib 2>/dev/null || echo "[!] Some dependencies may need manual installation"

echo ""
echo "========================================="
echo "  Demo 1: Log Analyzer"
echo "========================================="
echo ""
echo "[*] Analyzing sample auth.log for threats..."
python3 src/log_analyzer.py --file examples/sample_logs/auth.log --alert

echo ""
echo "========================================="
echo "  Demo 2: Log Analyzer with JSON Output"
echo "========================================="
echo ""
echo "[*] Generating JSON report..."
python3 src/log_analyzer.py --file examples/sample_logs/auth.log --output demo_report.json
echo "[+] Report saved to demo_report.json"

echo ""
echo "========================================="
echo "  Setup Complete!"
echo "========================================="
echo ""
echo "Try these commands:"
echo ""
echo "  # Analyze your own logs"
echo "  python3 src/log_analyzer.py --file /var/log/auth.log --alert"
echo ""
echo "  # Monitor logs in real-time"
echo "  python3 src/log_analyzer.py --file /var/log/auth.log --follow --alert"
echo ""
echo "  # Scan your network (requires sudo)"
echo "  python3 src/network_monitor.py --scan --baseline"
echo ""
