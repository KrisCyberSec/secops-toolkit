#!/usr/bin/env python3
"""
Network Monitor - Continuous network monitoring with change detection

This module scans the network, tracks devices, and alerts on changes.
"""

import argparse
import json
import sqlite3
import subprocess
import re
from datetime import datetime
from pathlib import Path
import socket
import sys

class NetworkMonitor:
    """Monitors network for devices and detects changes"""
    
    def __init__(self, db_path='network_inventory.db'):
        """Initialize network monitor with database"""
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for tracking"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                mac_address TEXT,
                hostname TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                devices_found INTEGER,
                changes_detected INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                change_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                change_type TEXT,
                ip_address TEXT,
                mac_address TEXT,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def get_local_network(self):
        """Detect local network subnet"""
        try:
            # Get default gateway
            result = subprocess.run(
                ['netstat', '-rn'],
                capture_output=True,
                text=True
            )
            
            # Parse for default route
            for line in result.stdout.split('\n'):
                if 'default' in line or '0.0.0.0' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        gateway = parts[1]
                        # Assume /24 network
                        network = '.'.join(gateway.split('.')[:-1]) + '.0/24'
                        return network
            
            # Fallback to common private networks
            return '192.168.1.0/24'
        
        except Exception as e:
            print(f"[!] Error detecting network: {e}")
            return '192.168.1.0/24'
    
    def scan_network(self, network=None):
        """
        Scan network for active devices
        
        Args:
            network: Network to scan (e.g., '192.168.1.0/24')
        
        Returns:
            List of discovered devices
        """
        if network is None:
            network = self.get_local_network()
        
        print(f"[*] Scanning network: {network}")
        devices = []
        
        try:
            # Use arp-scan if available (requires sudo)
            result = subprocess.run(
                ['sudo', 'arp-scan', '--localnet'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse arp-scan output
            for line in result.stdout.split('\n'):
                # Match IP and MAC address
                match = re.match(r'([\d.]+)\s+([0-9a-f:]+)\s+(.*)', line, re.IGNORECASE)
                if match:
                    ip, mac, vendor = match.groups()
                    
                    # Try to get hostname
                    hostname = self.get_hostname(ip)
                    
                    devices.append({
                        'ip': ip,
                        'mac': mac.upper(),
                        'hostname': hostname,
                        'vendor': vendor.strip()
                    })
            
        except FileNotFoundError:
            print("[!] arp-scan not found, using fallback method")
            devices = self.scan_network_fallback(network)
        
        except subprocess.TimeoutExpired:
            print("[!] Scan timeout, using fallback method")
            devices = self.scan_network_fallback(network)
        
        except Exception as e:
            print(f"[!] Scan error: {e}")
            devices = self.scan_network_fallback(network)
        
        print(f"[+] Found {len(devices)} active device(s)")
        return devices
    
    def scan_network_fallback(self, network):
        """Fallback network scan using ping sweep"""
        print("[*] Using ping sweep (slower)...")
        devices = []
        
        # Extract network base
        base = '.'.join(network.split('/')[0].split('.')[:-1])
        
        # Ping sweep (only first 20 hosts for demo)
        for i in range(1, 21):
            ip = f"{base}.{i}"
            
            try:
                # Ping host
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    capture_output=True,
                    timeout=2
                )
                
                if result.returncode == 0:
                    hostname = self.get_hostname(ip)
                    mac = self.get_mac_address(ip)
                    
                    devices.append({
                        'ip': ip,
                        'mac': mac,
                        'hostname': hostname,
                        'vendor': 'Unknown'
                    })
            
            except Exception:
                continue
        
        return devices
    
    def get_hostname(self, ip):
        """Get hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return 'Unknown'
    
    def get_mac_address(self, ip):
        """Get MAC address for IP (from ARP cache)"""
        try:
            result = subprocess.run(
                ['arp', '-n', ip],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.split('\n'):
                match = re.search(r'([0-9a-f:]{17})', line, re.IGNORECASE)
                if match:
                    return match.group(1).upper()
            
            return 'Unknown'
        
        except Exception:
            return 'Unknown'
    
    def save_devices(self, devices):
        """Save discovered devices to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for device in devices:
            # Check if device exists
            cursor.execute(
                'SELECT id FROM devices WHERE mac_address = ?',
                (device['mac'],)
            )
            
            existing = cursor.fetchone()
            
            if existing:
                # Update last seen
                cursor.execute(
                    'UPDATE devices SET last_seen = ?, ip_address = ?, hostname = ?, status = ? WHERE id = ?',
                    (datetime.now(), device['ip'], device['hostname'], 'active', existing[0])
                )
            else:
                # Insert new device
                cursor.execute(
                    'INSERT INTO devices (ip_address, mac_address, hostname) VALUES (?, ?, ?)',
                    (device['ip'], device['mac'], device['hostname'])
                )
        
        # Record scan
        cursor.execute(
            'INSERT INTO scans (devices_found) VALUES (?)',
            (len(devices),)
        )
        
        conn.commit()
        conn.close()
    
    def detect_changes(self, current_devices):
        """Detect changes from baseline"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        changes = []
        current_macs = {d['mac'] for d in current_devices}
        
        # Get previously known devices
        cursor.execute('SELECT ip_address, mac_address, hostname FROM devices WHERE status = "active"')
        known_devices = cursor.fetchall()
        known_macs = {mac for _, mac, _ in known_devices}
        
        # Detect new devices
        new_macs = current_macs - known_macs
        for device in current_devices:
            if device['mac'] in new_macs:
                change = {
                    'type': 'NEW_DEVICE',
                    'ip': device['ip'],
                    'mac': device['mac'],
                    'hostname': device['hostname'],
                    'details': f"New device detected: {device['hostname']} ({device['ip']})"
                }
                changes.append(change)
                
                # Log to database
                cursor.execute(
                    'INSERT INTO changes (change_type, ip_address, mac_address, details) VALUES (?, ?, ?, ?)',
                    (change['type'], change['ip'], change['mac'], change['details'])
                )
        
        # Detect missing devices
        missing_macs = known_macs - current_macs
        for ip, mac, hostname in known_devices:
            if mac in missing_macs:
                change = {
                    'type': 'DEVICE_OFFLINE',
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname,
                    'details': f"Device went offline: {hostname} ({ip})"
                }
                changes.append(change)
                
                # Update status
                cursor.execute(
                    'UPDATE devices SET status = ? WHERE mac_address = ?',
                    ('offline', mac)
                )
                
                # Log to database
                cursor.execute(
                    'INSERT INTO changes (change_type, ip_address, mac_address, details) VALUES (?, ?, ?, ?)',
                    (change['type'], change['ip'], change['mac'], change['details'])
                )
        
        conn.commit()
        conn.close()
        
        return changes
    
    def print_devices(self, devices):
        """Print device list to console"""
        print("\n" + "=" * 80)
        print(f"{'IP Address':<15} {'MAC Address':<18} {'Hostname':<30} {'Vendor'}")
        print("=" * 80)
        
        for device in devices:
            print(f"{device['ip']:<15} {device['mac']:<18} {device['hostname']:<30} {device.get('vendor', 'N/A')}")
        
        print("=" * 80)
    
    def print_changes(self, changes):
        """Print detected changes"""
        if not changes:
            print("\n[✓] No changes detected")
            return
        
        print(f"\n[!] {len(changes)} CHANGE(S) DETECTED\n")
        print("=" * 80)
        
        for i, change in enumerate(changes, 1):
            print(f"\nChange #{i}")
            print(f"Type: {change['type']}")
            print(f"IP: {change['ip']}")
            print(f"MAC: {change['mac']}")
            print(f"Hostname: {change['hostname']}")
            print(f"Details: {change['details']}")
            print("-" * 80)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Network monitoring with change detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initial network scan and baseline
  python network_monitor.py --scan --baseline
  
  # Scan and detect changes
  python network_monitor.py --scan --detect-changes
  
  # Scan specific network
  python network_monitor.py --scan --network 192.168.1.0/24
        """
    )
    
    parser.add_argument(
        '--scan', '-s',
        action='store_true',
        help='Perform network scan'
    )
    parser.add_argument(
        '--network', '-n',
        help='Network to scan (e.g., 192.168.1.0/24)'
    )
    parser.add_argument(
        '--baseline', '-b',
        action='store_true',
        help='Create baseline (save current state)'
    )
    parser.add_argument(
        '--detect-changes', '-d',
        action='store_true',
        help='Detect changes from baseline'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output file for JSON report'
    )
    
    args = parser.parse_args()
    
    if not args.scan:
        parser.print_help()
        sys.exit(0)
    
    # Initialize monitor
    monitor = NetworkMonitor()
    
    # Scan network
    devices = monitor.scan_network(args.network)
    monitor.print_devices(devices)
    
    # Save baseline
    if args.baseline:
        monitor.save_devices(devices)
        print("\n[+] Baseline saved")
    
    # Detect changes
    if args.detect_changes:
        changes = monitor.detect_changes(devices)
        monitor.save_devices(devices)
        monitor.print_changes(changes)
        
        if args.output:
            report = {
                'timestamp': datetime.now().isoformat(),
                'devices': devices,
                'changes': changes
            }
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Report saved to {args.output}")


if __name__ == '__main__':
    main()
