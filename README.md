# SecScan

**SecScan** is a OS configuration checker which evaluates and enhances the security of your system. It performs a series of checks, providing a .json report to help you identify potential vulnerabilities.

## Features

- **Operating System Version Check**: Determines the OS and its version.
- **Firewall Status**: Checks the status of the firewall.
- **User Accounts**: Lists user accounts and their privileges.
- **SSH Configuration**: Analyzes SSH settings.
- **Services Status**: Monitors running services.
- **File Permissions**: Evaluates permissions of sensitive files.
- **Audit Logs**: Reviews security-related logs.
- **Software Updates**: Checks for available updates.
- **Disk Encryption**: Checks status of disk encryption.
- **Password Policy**: Evaluates password strength and policies.
- **Network Settings**: Inspects network configurations.
- **DNS Leak Test**: Identifies potential DNS leaks.
- **VPN Status**: Checks if a VPN is active.
- **Open Ports**: Lists open ports and their statuses.
- **Security Patch Level**: Security patch level check.
- **Encrypted Protocols**: Verifies the use of secure protocols.
- **Browser Security**: Checks for security settings in Firefox/Chrome.
- **Report Generation**: Creates a detailed JSON report of the findings.

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/secscan.git
cd secscan
```

## Usage
```bash
python3 secscan.py
```

Every check will generate a report in JSON format.
