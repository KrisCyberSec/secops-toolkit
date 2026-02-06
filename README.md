# SecOps Automation Toolkit 🔧

> A comprehensive collection of security automation scripts for SOC analysts and security engineers

![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey.svg)

## 📋 Overview

**SecOps Automation Toolkit** is a modular collection of Python-based security automation tools designed to streamline common Security Operations Center (SOC) workflows. Each module addresses a specific security need, from log analysis to incident response.

## ✨ Features

### 🔍 Log Analyzer (`log_analyzer.py`)
Automated security log analysis with threat detection capabilities.

**Features:**
- ✅ SSH brute force detection
- ✅ Failed login pattern analysis
- ✅ Port scan detection
- ✅ Suspicious IP tracking
- ✅ Automated alert generation
- ✅ Support for multiple log formats (auth.log, syslog, Apache, Nginx)

**Detection Rules:**
- Multiple failed SSH attempts (configurable threshold)
- Rapid connection attempts from single IP
- Access to sensitive files/directories
- Privilege escalation attempts
- Unusual sudo usage patterns

### 🌐 Network Change Monitor (`network_monitor.py`)
Continuous network monitoring with change detection and alerting.

**Features:**
- ✅ Periodic network scanning (ARP sweep)
- ✅ Device fingerprinting (MAC, hostname, open ports)
- ✅ Change detection (new devices, missing devices, port changes)
- ✅ Historical tracking database
- ✅ Alert on anomalies
- ✅ Export reports (JSON, CSV, HTML)

**Use Cases:**
- Detect rogue devices on network
- Track unauthorized services
- Monitor network topology changes
- Identify shadow IT

### 📊 Security Report Generator (`report_generator.py`)
Automated security reporting and metrics dashboard.

**Features:**
- ✅ Daily/weekly/monthly security summaries
- ✅ Threat statistics and trends
- ✅ Top attackers and targets
- ✅ Geographic threat mapping
- ✅ Executive-friendly visualizations
- ✅ Export to PDF, HTML, or email

**Report Sections:**
- Executive summary
- Threat landscape overview
- Top security events
- Remediation recommendations
- Compliance metrics

### 🚨 Incident Response Helper (`ir_helper.py`)
Quick incident response commands and automation.

**Features:**
- ✅ Rapid triage commands
- ✅ Evidence collection automation
- ✅ Network isolation scripts
- ✅ Forensic data gathering
- ✅ Incident timeline builder
- ✅ IR playbook templates

**Capabilities:**
- System snapshot (running processes, connections, users)
- Memory dump collection
- Log preservation
- Network traffic capture
- Hash calculation for files
- Indicator of Compromise (IOC) extraction

## 🛠️ Tech Stack

- **Language**: Python 3.9+
- **Libraries**: 
  - `scapy` - Network packet manipulation
  - `pandas` - Data analysis and reporting
  - `matplotlib` / `plotly` - Visualization
  - `sqlite3` - Local database
  - `requests` - API integration
  - `jinja2` - Report templating
  - `psutil` - System monitoring

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.9+ required
python3 --version

# Install system dependencies (Linux)
sudo apt-get install python3-pip libpcap-dev

# Install system dependencies (macOS)
brew install libpcap
```

### Installation

```bash
# Clone the repository
git clone https://github.com/KrisCyberSec/secops-toolkit.git
cd secops-toolkit

# Install Python dependencies
pip install -r requirements.txt

# (Optional) Install as a package
pip install -e .
```

### Usage Examples

#### 1. Analyze Security Logs

```bash
# Analyze auth.log for threats
python log_analyzer.py --file /var/log/auth.log --output report.json

# Monitor logs in real-time
python log_analyzer.py --file /var/log/auth.log --follow --alert

# Custom detection threshold
python log_analyzer.py --file /var/log/auth.log --threshold 5 --timewindow 300
```

#### 2. Monitor Network Changes

```bash
# Initial network baseline
python network_monitor.py --scan --baseline

# Monitor for changes
python network_monitor.py --scan --detect-changes

# Continuous monitoring (every 5 minutes)
python network_monitor.py --monitor --interval 300

# Generate network inventory report
python network_monitor.py --report --format html
```

#### 3. Generate Security Reports

```bash
# Daily security summary
python report_generator.py --period daily --output daily_report.pdf

# Weekly executive report
python report_generator.py --period weekly --format pdf --email security-team@company.com

# Custom date range
python report_generator.py --start 2026-01-01 --end 2026-01-31 --format html
```

#### 4. Incident Response

```bash
# Quick system triage
python ir_helper.py --triage --output triage_report.json

# Collect forensic evidence
python ir_helper.py --collect-evidence --case-id INC-2026-001

# Network isolation (requires root)
sudo python ir_helper.py --isolate --host 192.168.1.100

# Extract IOCs from logs
python ir_helper.py --extract-iocs --file /var/log/syslog
```

## 📁 Project Structure

```
secops-toolkit/
├── README.md
├── requirements.txt
├── setup.py
├── .gitignore
├── config/
│   ├── config.yaml           # Main configuration
│   ├── detection_rules.yaml  # Custom detection rules
│   └── alert_templates.yaml  # Alert message templates
├── src/
│   ├── __init__.py
│   ├── log_analyzer.py       # Log analysis module
│   ├── network_monitor.py    # Network monitoring module
│   ├── report_generator.py   # Report generation module
│   ├── ir_helper.py          # Incident response module
│   └── utils/
│       ├── __init__.py
│       ├── database.py       # Database operations
│       ├── alerts.py         # Alert handling
│       ├── parsers.py        # Log parsers
│       └── enrichment.py     # Threat intel enrichment
├── templates/
│   ├── report_template.html  # HTML report template
│   └── email_template.html   # Email alert template
├── tests/
│   ├── test_log_analyzer.py
│   ├── test_network_monitor.py
│   └── test_report_generator.py
└── examples/
    ├── sample_logs/          # Sample log files
    ├── detection_rules/      # Example detection rules
    └── playbooks/            # IR playbook examples
```

## 🎓 Skills Demonstrated

This toolkit showcases:

- ✅ **Security Automation** - Building tools to automate SOC workflows
- ✅ **Threat Detection** - Implementing detection logic and rules
- ✅ **Log Analysis** - Parsing and analyzing security logs
- ✅ **Network Security** - Network monitoring and change detection
- ✅ **Incident Response** - IR automation and evidence collection
- ✅ **Python Development** - Clean, modular, maintainable code
- ✅ **Data Analysis** - Processing and visualizing security data
- ✅ **Reporting** - Creating actionable security reports

## 🔒 Security Considerations

- **Permissions**: Some modules require elevated privileges (root/sudo)
- **Data Privacy**: Logs may contain sensitive information - handle appropriately
- **Network Impact**: Network scanning can trigger IDS/IPS alerts
- **Testing**: Always test in a controlled environment first

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Guide](docs/configuration.md)
- [Detection Rules](docs/detection_rules.md)
- [API Reference](docs/api_reference.md)
- [Contributing Guide](CONTRIBUTING.md)

## 🔮 Roadmap

- [ ] Add support for Windows Event Logs
- [ ] Integrate with SIEM platforms (Splunk, ELK)
- [ ] Machine learning-based anomaly detection
- [ ] Web-based dashboard for all modules
- [ ] Slack/Teams/Discord integration for alerts
- [ ] MITRE ATT&CK framework mapping
- [ ] Automated threat hunting queries
- [ ] Cloud security monitoring (AWS, Azure, GCP)

## 🤝 Contributing

Contributions are welcome! Please read the [Contributing Guide](CONTRIBUTING.md) first.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by real-world SOC operations and challenges
- Built with feedback from security professionals
- Designed for learning and practical application

---

**Built by [KrisCyberSec](https://github.com/KrisCyberSec)** | Aspiring SOC Analyst

*⚠️ Disclaimer: This toolkit is for educational and authorized security testing only. Always obtain proper authorization before using these tools on any network or system.*
