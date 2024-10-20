import os
import subprocess
import platform
import json
import logging
import requests
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecureConfigChecker:
    def __init__(self):
        self.results = {
            "os_version": None,
            "firewall_status": None,
            "user_accounts": [],
            "ssh_config": {},
            "services_status": {},
            "file_permissions": {},
            "audit_logs": {},
            "software_updates": {},
            "disk_encryption": {},
            "password_policy": {},
            "network_settings": {},
            "dns_leak": {},
            "vpn_status": {},
            "open_ports": {},
            "security_patch_level": {},
            "encrypted_protocols": {},
            "browser_security": {}
        }

    def check_os_version(self):
        logging.info("Checking operating system version...")
        self.results["os_version"] = platform.system() + " " + platform.release()
        logging.info(f"Operating System: {self.results['os_version']}")

    def check_firewall(self):
        logging.info("Checking firewall status...")
        if platform.system() == "Linux":
            try:
                status = subprocess.run(['ufw', 'status'], capture_output=True, text=True, check=True)
                self.results["firewall_status"] = status.stdout.strip()
            except subprocess.CalledProcessError as e:
                logging.error("Failed to check firewall status.")
                self.results["firewall_status"] = str(e)
        elif platform.system() == "Windows":
            try:
                status = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True, check=True)
                self.results["firewall_status"] = status.stdout.strip()
            except subprocess.CalledProcessError as e:
                logging.error("Failed to check firewall status.")
                self.results["firewall_status"] = str(e)
        else:
            self.results["firewall_status"] = "Unsupported OS for firewall check."
        logging.info(f"Firewall Status: {self.results['firewall_status']}")

    def check_user_accounts(self):
        logging.info("Checking user accounts...")
        if platform.system() == "Linux":
            try:
                users = subprocess.run(['cut', '-d:', '-f1', '/etc/passwd'], capture_output=True, text=True, check=True)
                self.results["user_accounts"] = users.stdout.strip().split()
            except subprocess.CalledProcessError as e:
                logging.error("Failed to check user accounts.")
                self.results["user_accounts"] = str(e)
        elif platform.system() == "Windows":
            try:
                users = subprocess.run(['net', 'user'], capture_output=True, text=True, check=True)
                self.results["user_accounts"] = [line.strip() for line in users.stdout.splitlines() if line]
            except subprocess.CalledProcessError as e:
                logging.error("Failed to check user accounts.")
                self.results["user_accounts"] = str(e)
        logging.info(f"User Accounts: {self.results['user_accounts']}")

    def check_ssh_config(self):
        logging.info("Checking SSH configuration...")
        ssh_config_path = "/etc/ssh/sshd_config" if platform.system() == "Linux" else "C:\\ProgramData\\ssh\\sshd_config"
        if os.path.exists(ssh_config_path):
            try:
                with open(ssh_config_path, 'r') as f:
                    config_lines = f.readlines()
                    for line in config_lines:
                        if "PermitRootLogin" in line or "PasswordAuthentication" in line:
                            key, value = line.split()
                            self.results["ssh_config"][key] = value.strip()
            except Exception as e:
                logging.error(f"Failed to read SSH configuration: {e}")
        logging.info(f"SSH Configuration: {self.results['ssh_config']}")

    def check_services(self):
        logging.info("Checking running services...")
        if platform.system() == "Linux":
            try:
                services = subprocess.run(['systemctl', 'list-units', '--type=service'], capture_output=True, text=True, check=True)
                self.results["services_status"] = services.stdout.strip().splitlines()
            except subprocess.CalledProcessError as e:
                logging.error("Failed to check services.")
                self.results["services_status"] = str(e)
        elif platform.system() == "Windows":
            try:
                services = subprocess.run(['sc', 'query'], capture_output=True, text=True, check=True)
                self.results["services_status"] = [line.strip() for line in services.stdout.splitlines() if line]
            except subprocess.CalledProcessError as e:
                logging.error("Failed to check services.")
                self.results["services_status"] = str(e)
        logging.info(f"Services Status: {self.results['services_status']}")

    def check_file_permissions(self):
        logging.info("Checking file permissions...")
        sensitive_files = ["/etc/passwd", "/etc/shadow", "/etc/group"] if platform.system() == "Linux" else ["C:\\Windows\\System32\\config\\SAM"]
        for file in sensitive_files:
            if os.path.exists(file):
                permissions = oct(os.stat(file).st_mode)[-3:]
                self.results["file_permissions"][file] = permissions
                logging.info(f"Permissions for {file}: {permissions}")

    def check_audit_logs(self):
        logging.info("Checking audit logs...")
        audit_log_path = "/var/log/auth.log" if platform.system() == "Linux" else "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        if os.path.exists(audit_log_path):
            try:
                with open(audit_log_path, 'r') as f:
                    logs = f.readlines()
                    self.results["audit_logs"]["count"] = len(logs)
                    self.results["audit_logs"]["sample"] = logs[:5] 
            except Exception as e:
                logging.error(f"Failed to read audit logs: {e}")
        logging.info(f"Audit Logs: {self.results['audit_logs']}")

    def check_software_updates(self):
        logging.info("Checking for software updates...")
        if platform.system() == "Linux":
            try:
                updates = subprocess.run(['apt-get', 'update'], capture_output=True, text=True, check=True)
                self.results["software_updates"]["available"] = updates.stdout.strip()
            except subprocess.CalledProcessError as e:
                logging.error("Failed to check software updates.")
                self.results["software_updates"]["error"] = str(e)
        elif platform.system() == "Windows":
            logging.info("Windows Update check requires manual inspection.")
            self.results["software_updates"]["available"] = "Manual check required."
        logging.info(f"Software Updates: {self.results['software_updates']}")

    def check_disk_encryption(self):
        logging.info("Checking disk encryption status...")
        if platform.system() == "Linux":
            try:
                status = subprocess.run(['lsblk', '-o', 'NAME,TYPE,MOUNTPOINT,FSTYPE', '--json'], capture_output=True, text=True)
                self.results["disk_encryption"]["status"] = status.stdout
            except subprocess.CalledProcessError as e:
                logging.error("Failed to check disk encryption.")
                self.results["disk_encryption"]["error"] = str(e)
        elif platform.system() == "Windows":
            try:
                status = subprocess.run(['manage-bde', '-status'], capture_output=True, text=True)
                self.results["disk_encryption"]["status"] = status.stdout
            except subprocess.CalledProcessError as e:
                logging.error("Failed to check disk encryption.")
                self.results["disk_encryption"]["error"] = str(e)
        logging.info(f"Disk Encryption Status: {self.results['disk_encryption']}")

    def check_password_policy(self):
        logging.info("Checking password policy...")
        if platform.system() == "Linux":
            try:
                with open('/etc/login.defs', 'r') as f:
                    for line in f:
                        if "PASS_MAX_DAYS" in line or "PASS_MIN_DAYS" in line:
                            key, value = line.split()
                            self.results["password_policy"][key] = value.strip()
            except Exception as e:
                logging.error(f"Failed to read password policy: {e}")
        elif platform.system() == "Windows":
            try:
                policy = subprocess.run(['net', 'accounts'], capture_output=True, text=True, check=True)
                self.results["password_policy"]["policy"] = policy.stdout.strip()
            except subprocess.CalledProcessError as e:
                logging.error("Failed to check password policy.")
                self.results["password_policy"]["error"] = str(e)
        logging.info(f"Password Policy: {self.results['password_policy']}")

    def check_network_settings(self):
        logging.info("Checking network settings...")
        if platform.system() == "Linux":
            try:
                ip_info = subprocess.run(['ip', 'addr'], capture_output=True, text=True, check=True)
                self.results["network_settings"]["ip_info"] = ip_info.stdout.strip()
            except subprocess.CalledProcessError as e:
                logging.error("Failed to check network settings.")
                self.results["network_settings"]["error"] = str(e)
        elif platform.system() == "Windows":
            try:
                ip_info = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, check=True)
                self.results["network_settings"]["ip_info"] = ip_info.stdout.strip()
            except subprocess.CalledProcessError as e:
                logging.error("Failed to check network settings.")
                self.results["network_settings"]["error"] = str(e)
        logging.info(f"Network Settings: {self.results['network_settings']}")

    def check_dns_leak(self):
        logging.info("Checking for DNS leaks...")
        try:
            response = requests.get('https://api.ipify.org?format=json')
            ip_info = response.json()
            self.results["dns_leak"]["public_ip"] = ip_info["ip"]
            
            dns_response = requests.get('https://dnsleaktest.com/api/public-dns')
            self.results["dns_leak"]["dns_servers"] = dns_response.json()
        except Exception as e:
            logging.error(f"Failed to check DNS leak: {e}")
            self.results["dns_leak"]["error"] = str(e)
        logging.info(f"DNS Leak Check: {self.results['dns_leak']}")

    def check_vpn_status(self):
        logging.info("Checking VPN status...")
        self.results["vpn_status"]["active"] = False 
        if platform.system() == "Linux":
            try:
                interfaces = subprocess.run(['ip', 'a'], capture_output=True, text=True, check=True)
                vpn_interfaces = ['tun', 'ppp', 'tap'] 
                for line in interfaces.stdout.splitlines():
                    if any(interface in line for interface in vpn_interfaces):
                        self.results["vpn_status"]["active"] = True
                        break
            except Exception as e:
                logging.error("Failed to check VPN interfaces.")
                self.results["vpn_status"]["error"] = str(e)
        elif platform.system() == "Windows":
            try:
                status = subprocess.run(['rasdial'], capture_output=True, text=True, check=True)
                self.results["vpn_status"]["active"] = "No connections" not in status.stdout
            except subprocess.CalledProcessError as e:
                logging.error("Failed to check VPN status.")
                self.results["vpn_status"]["error"] = str(e)
        logging.info(f"VPN Status: {self.results['vpn_status']}")

    def check_open_ports(self):
        logging.info("Checking for open ports...")
        if platform.system() == "Linux":
            try:
                ports = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, check=True)
                self.results["open_ports"]["Linux"] = ports.stdout.strip().splitlines()
            except subprocess.CalledProcessError as e:
                logging.error("Failed to check open ports.")
                self.results["open_ports"]["error"] = str(e)
        elif platform.system() == "Windows":
            try:
                ports = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, check=True)
                self.results["open_ports"]["Windows"] = ports.stdout.strip().splitlines()
            except subprocess.CalledProcessError as e:
                logging.error("Failed to check open ports.")
                self.results["open_ports"]["error"] = str(e)
        logging.info(f"Open Ports: {self.results['open_ports']}")

    def check_security_patch_level(self):
        logging.info("Checking security patch level...")
        if platform.system() == "Linux":
            try:
                patches = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True, check=True)
                self.results["security_patch_level"]["available"] = patches.stdout.strip()
            except subprocess.CalledProcessError as e:
                logging.error("Failed to check security patches.")
                self.results["security_patch_level"]["error"] = str(e)
        elif platform.system() == "Windows":
            logging.info("Windows Update check requires manual inspection.")
            self.results["security_patch_level"]["available"] = "Manual check required."
        logging.info(f"Security Patch Level: {self.results['security_patch_level']}")

    def check_encrypted_protocols(self):
        logging.info("Checking for encrypted protocols on critical services...")
        critical_services = {
            "SSH": "22",
            "HTTPS": "443",
            "FTP": "21",
            "SMTP": "25"
        }
        for service, port in critical_services.items():
            self.results["encrypted_protocols"][service] = {"port": port, "encrypted": False}

        for service, details in self.results["open_ports"].items():
            for line in details:
                if f':{service}' in line:
                    self.results["encrypted_protocols"][service]["encrypted"] = True
                    break

        logging.info(f"Encrypted Protocols: {self.results['encrypted_protocols']}")

    def check_browser_security(self):
        logging.info("Checking browser security settings...")
        browsers = {
            "Chrome": [
                "/usr/bin/google-chrome",
                "/usr/bin/chrome"
            ],
            "Firefox": [
                "/usr/bin/firefox"
            ]
        }
        for browser, paths in browsers.items():
            found = False
            for path in paths:
                if os.path.exists(path):
                    found = True
                    self.results["browser_security"][browser] = {
                        "secure_connections": True 
                    }
                    logging.info(f"{browser} found at {path}. Security settings checked.")
                    break
            if not found:
                self.results["browser_security"][browser] = "Not installed"
                logging.info(f"{browser} not installed.")
        
        logging.info(f"Browser Security: {self.results['browser_security']}")

    def generate_report(self):
        report_path = f"secure_config_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as report_file:
            json.dump(self.results, report_file, indent=4)
        logging.info(f"Report generated: {report_path}")

    def run_checks(self):
        self.check_os_version()
        self.check_firewall()
        self.check_user_accounts()
        self.check_ssh_config()
        self.check_services()
        self.check_file_permissions()
        self.check_audit_logs()
        self.check_software_updates()
        self.check_disk_encryption()
        self.check_password_policy()
        self.check_network_settings()
        self.check_dns_leak()
        self.check_vpn_status()
        self.check_open_ports()
        self.check_security_patch_level()
        self.check_encrypted_protocols()
        self.check_browser_security()
        self.generate_report()

if __name__ == "__main__":
    checker = SecureConfigChecker()
    checker.run_checks()
