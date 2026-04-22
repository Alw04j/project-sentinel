"""
scanner.py
──────────
Network scanning service using python-nmap.
Also provides fix_smb_vulnerability() for blocking SMB port 445 via netsh.

Install dependency:  pip install python-nmap
Nmap binary:         https://nmap.org/download.html  (must be in system PATH)
"""

import subprocess
import platform

# ─── Risk Classification ──────────────────────────────────────────────────────
HIGH_RISK_PORTS = {
    21:   'FTP',
    22:   'SSH',
    23:   'Telnet',
    25:   'SMTP',
    53:   'DNS',
    80:   'HTTP',
    110:  'POP3',
    135:  'RPC',
    139:  'NetBIOS',
    143:  'IMAP',
    389:  'LDAP',
    443:  'HTTPS',
    445:  'SMB',
    1433: 'MSSQL',
    1521: 'Oracle DB',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    27017:'MongoDB',
}


def _classify_severity(port: int, service: str) -> str:
    """Return 'High' for sensitive/dangerous ports, 'Low' otherwise."""
    high_risk_set = {21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5900, 6379, 27017}
    return 'High' if port in high_risk_set else 'Low'


# ─── Network Scanner ──────────────────────────────────────────────────────────
def scan_network(target: str) -> list | dict:
    """
    Scan a target IP or subnet using Nmap via python-nmap.

    Returns:
        list of dicts on success:
            [
              {
                'address': '192.168.1.1',
                'status':  'up',
                'ports': [
                    {'port': 80, 'service': 'http', 'state': 'open', 'severity': 'Low'},
                    ...
                ]
              },
              ...
            ]
        dict with 'error' key on failure:
            {'error': 'reason string'}
    """
    try:
        import nmap
    except ImportError:
        return {'error': "python-nmap not installed. Run: pip install python-nmap"}

    try:
        nm = nmap.PortScanner()
        # -sV: service detection  -T4: fast timing  --open: only open ports
        nm.scan(hosts=target, arguments='-sV -T4 --open')
    except nmap.PortScannerError as e:
        return {'error': f"Nmap error: {str(e)}. Make sure Nmap is installed and in PATH."}
    except Exception as e:
        return {'error': f"Scan failed: {str(e)}"}

    if not nm.all_hosts():
        return {'error': f"No hosts found for target: {target}. Host may be down or unreachable."}

    results = []
    for host in nm.all_hosts():
        host_data = {
            'address': host,
            'status':  nm[host].state(),
            'ports':   [],
        }

        for proto in nm[host].all_protocols():
            port_list = sorted(nm[host][proto].keys())
            for port in port_list:
                port_info = nm[host][proto][port]
                if port_info['state'] != 'open':
                    continue

                service  = port_info.get('name', 'unknown')
                # Prefer our label, fall back to nmap's
                service  = HIGH_RISK_PORTS.get(port, service)
                severity = _classify_severity(port, service)

                host_data['ports'].append({
                    'port':     port,
                    'service':  service,
                    'state':    port_info['state'],
                    'severity': severity,
                })

        results.append(host_data)

    return results


# ─── SMB Remediation ──────────────────────────────────────────────────────────
def fix_smb_vulnerability() -> str:
    """
    Block SMB port 445 using Windows netsh firewall rules.
    Returns a status string containing 'SUCCESS' or 'ERROR'.
    """
    if platform.system() != 'Windows':
        return "ERROR: SMB remediation is only supported on Windows."

    rule_name = "Sentinel_Block_SMB_445"

    # Check if rule already exists
    check_cmd = ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name}']
    check = subprocess.run(check_cmd, capture_output=True, text=True)

    if 'No rules match' not in check.stdout and rule_name in check.stdout:
        return f"SUCCESS: Firewall rule '{rule_name}' already exists. Port 445 is blocked."

    # Add inbound block rule
    inbound_cmd = [
        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
        f'name={rule_name}',
        'protocol=TCP',
        'dir=in',
        'localport=445',
        'action=block',
    ]
    # Add outbound block rule
    outbound_cmd = [
        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
        f'name={rule_name}',
        'protocol=TCP',
        'dir=out',
        'localport=445',
        'action=block',
    ]

    try:
        r1 = subprocess.run(inbound_cmd,  capture_output=True, text=True, timeout=15)
        r2 = subprocess.run(outbound_cmd, capture_output=True, text=True, timeout=15)

        if r1.returncode == 0 and r2.returncode == 0:
            return (
                f"SUCCESS: SMB Port 445 has been BLOCKED by Sentinel. "
                f"Firewall rule '{rule_name}' created (inbound + outbound)."
            )
        else:
            err = r1.stderr or r2.stderr or "Unknown netsh error."
            return (
                f"ERROR: Failed to create firewall rule. "
                f"Details: {err.strip()} — Try running the server as Administrator."
            )

    except subprocess.TimeoutExpired:
        return "ERROR: netsh command timed out. Try running as Administrator."
    except FileNotFoundError:
        return "ERROR: netsh not found. This command requires Windows."
    except Exception as e:
        return f"ERROR: Unexpected error during remediation: {str(e)}"
