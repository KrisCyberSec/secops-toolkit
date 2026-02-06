#!/usr/bin/env python3
"""
Log Analyzer - Automated security log analysis with threat detection

This module analyzes security logs for suspicious patterns and generates alerts.
"""

import re
import json
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
import sys

class LogAnalyzer:
    """Analyzes security logs for threats and suspicious patterns"""
    
    def __init__(self, threshold=5, time_window=300):
        """
        Initialize the log analyzer
        
        Args:
            threshold: Number of failed attempts before alerting
            time_window: Time window in seconds for pattern detection
        """
        self.threshold = threshold
        self.time_window = time_window
        self.failed_logins = defaultdict(list)
        self.port_scans = defaultdict(list)
        self.sudo_attempts = defaultdict(list)
        self.alerts = []
        
        # Regex patterns for common log formats
        self.patterns = {
            'ssh_failed': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(\w+) from ([\d.]+)'
            ),
            'ssh_success': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password for (\w+) from ([\d.]+)'
            ),
            'sudo_command': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*sudo.*USER=(\w+).*COMMAND=(.*)'
            ),
            'port_scan': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*Connection from ([\d.]+) port \d+'
            ),
        }
    
    def parse_timestamp(self, timestamp_str):
        """Parse log timestamp to datetime object"""
        try:
            # Handle common syslog format (e.g., "Feb  5 20:30:15")
            current_year = datetime.now().year
            dt = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            return dt
        except ValueError:
            return datetime.now()
    
    def analyze_line(self, line):
        """Analyze a single log line for threats"""
        
        # Check for failed SSH attempts
        match = self.patterns['ssh_failed'].search(line)
        if match:
            timestamp_str, username, ip = match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            self.failed_logins[ip].append({
                'timestamp': timestamp,
                'username': username,
                'line': line.strip()
            })
            return 'ssh_failed'
        
        # Check for successful SSH logins
        match = self.patterns['ssh_success'].search(line)
        if match:
            timestamp_str, username, ip = match.groups()
            return 'ssh_success'
        
        # Check for sudo commands
        match = self.patterns['sudo_command'].search(line)
        if match:
            timestamp_str, user, command = match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            self.sudo_attempts[user].append({
                'timestamp': timestamp,
                'command': command,
                'line': line.strip()
            })
            return 'sudo_command'
        
        # Check for potential port scans
        match = self.patterns['port_scan'].search(line)
        if match:
            timestamp_str, ip = match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            self.port_scans[ip].append({
                'timestamp': timestamp,
                'line': line.strip()
            })
            return 'port_scan'
        
        return None
    
    def detect_brute_force(self):
        """Detect SSH brute force attempts"""
        
        for ip, attempts in self.failed_logins.items():
            if not attempts:
                continue
            
            # Use the latest timestamp from attempts instead of current time
            latest_time = max(a['timestamp'] for a in attempts)
            
            # Filter attempts within time window from the latest attempt
            recent_attempts = [
                a for a in attempts 
                if (latest_time - a['timestamp']).total_seconds() <= self.time_window
            ]
            
            if len(recent_attempts) >= self.threshold:
                usernames = [a['username'] for a in recent_attempts]
                alert = {
                    'type': 'SSH_BRUTE_FORCE',
                    'severity': 'HIGH',
                    'source_ip': ip,
                    'attempt_count': len(recent_attempts),
                    'usernames': list(set(usernames)),
                    'first_seen': min(a['timestamp'] for a in recent_attempts).isoformat(),
                    'last_seen': max(a['timestamp'] for a in recent_attempts).isoformat(),
                    'description': f'SSH brute force detected from {ip}: {len(recent_attempts)} failed attempts'
                }
                self.alerts.append(alert)

    
    def detect_port_scan(self):
        """Detect potential port scanning activity"""
        
        for ip, connections in self.port_scans.items():
            if not connections:
                continue
            
            # Use the latest timestamp from connections
            latest_time = max(c['timestamp'] for c in connections)
            
            # Filter connections within time window from the latest connection
            recent_connections = [
                c for c in connections 
                if (latest_time - c['timestamp']).total_seconds() <= self.time_window
            ]
            
            # If many connections in short time, likely a port scan
            if len(recent_connections) >= 10:
                alert = {
                    'type': 'PORT_SCAN',
                    'severity': 'MEDIUM',
                    'source_ip': ip,
                    'connection_count': len(recent_connections),
                    'first_seen': min(c['timestamp'] for c in recent_connections).isoformat(),
                    'last_seen': max(c['timestamp'] for c in recent_connections).isoformat(),
                    'description': f'Potential port scan from {ip}: {len(recent_connections)} connections'
                }
                self.alerts.append(alert)

    
    def analyze_file(self, filepath, follow=False):
        """
        Analyze a log file
        
        Args:
            filepath: Path to log file
            follow: If True, continuously monitor the file (like tail -f)
        """
        try:
            with open(filepath, 'r') as f:
                if follow:
                    # Move to end of file
                    f.seek(0, 2)
                    print(f"[*] Monitoring {filepath} for threats...")
                    
                    while True:
                        line = f.readline()
                        if line:
                            self.analyze_line(line)
                            self.detect_brute_force()
                            self.detect_port_scan()
                        else:
                            import time
                            time.sleep(0.1)
                else:
                    print(f"[*] Analyzing {filepath}...")
                    line_count = 0
                    for line in f:
                        self.analyze_line(line)
                        line_count += 1
                    
                    print(f"[+] Analyzed {line_count} log lines")
                    
                    # Run detections
                    self.detect_brute_force()
                    self.detect_port_scan()
                    
        except FileNotFoundError:
            print(f"[!] Error: File not found: {filepath}")
            sys.exit(1)
        except PermissionError:
            print(f"[!] Error: Permission denied: {filepath}")
            sys.exit(1)
    
    def generate_report(self):
        """Generate analysis report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_alerts': len(self.alerts),
                'unique_ips': len(set(a['source_ip'] for a in self.alerts)),
                'severity_breakdown': Counter(a['severity'] for a in self.alerts)
            },
            'alerts': self.alerts,
            'statistics': {
                'failed_login_ips': len(self.failed_logins),
                'total_failed_logins': sum(len(v) for v in self.failed_logins.values()),
                'port_scan_ips': len(self.port_scans),
                'sudo_users': len(self.sudo_attempts)
            }
        }
        return report
    
    def print_alerts(self):
        """Print alerts to console"""
        if not self.alerts:
            print("\n[✓] No threats detected")
            return
        
        print(f"\n[!] {len(self.alerts)} ALERT(S) DETECTED\n")
        print("=" * 80)
        
        for i, alert in enumerate(self.alerts, 1):
            print(f"\nAlert #{i}")
            print(f"Type: {alert['type']}")
            print(f"Severity: {alert['severity']}")
            print(f"Source IP: {alert['source_ip']}")
            print(f"Description: {alert['description']}")
            
            if 'attempt_count' in alert:
                print(f"Attempt Count: {alert['attempt_count']}")
            if 'usernames' in alert:
                print(f"Targeted Usernames: {', '.join(alert['usernames'])}")
            
            print(f"First Seen: {alert['first_seen']}")
            print(f"Last Seen: {alert['last_seen']}")
            print("-" * 80)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Automated security log analysis with threat detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a log file
  python log_analyzer.py --file /var/log/auth.log
  
  # Monitor logs in real-time
  python log_analyzer.py --file /var/log/auth.log --follow
  
  # Custom threshold and time window
  python log_analyzer.py --file /var/log/auth.log --threshold 3 --timewindow 60
  
  # Save report to JSON
  python log_analyzer.py --file /var/log/auth.log --output report.json
        """
    )
    
    parser.add_argument(
        '--file', '-f',
        required=True,
        help='Path to log file to analyze'
    )
    parser.add_argument(
        '--follow',
        action='store_true',
        help='Monitor log file in real-time (like tail -f)'
    )
    parser.add_argument(
        '--threshold', '-t',
        type=int,
        default=5,
        help='Number of failed attempts before alerting (default: 5)'
    )
    parser.add_argument(
        '--timewindow', '-w',
        type=int,
        default=300,
        help='Time window in seconds for pattern detection (default: 300)'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output file for JSON report'
    )
    parser.add_argument(
        '--alert',
        action='store_true',
        help='Print alerts to console'
    )
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = LogAnalyzer(
        threshold=args.threshold,
        time_window=args.timewindow
    )
    
    # Analyze file
    try:
        analyzer.analyze_file(args.file, follow=args.follow)
        
        # Generate report
        if not args.follow:
            report = analyzer.generate_report()
            
            # Print alerts
            if args.alert or not args.output:
                analyzer.print_alerts()
            
            # Save to file
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
                print(f"\n[+] Report saved to {args.output}")
    
    except KeyboardInterrupt:
        print("\n\n[*] Monitoring stopped by user")
        if args.follow:
            report = analyzer.generate_report()
            analyzer.print_alerts()
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
                print(f"\n[+] Report saved to {args.output}")


if __name__ == '__main__':
    main()
