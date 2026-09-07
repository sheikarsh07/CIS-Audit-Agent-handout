"""
Prioritizer Module: Takes structured rule findings, ranks failures by severity,
and attaches grounded, exact remediation commands.

Enforces zero-drift / strict reproducibility across identical audit runs.
"""

# Deterministic remediation template map
REMEDIATION_MAP = {
    "CIS-5.2.10": {
        "category": "SSH Hardening",
        "finding": "Root login over SSH is permitted.",
        "why_it_matters": "A leaked or brute-forced root credential grants full remote access with no separate privilege escalation step.",
        "fix_command": "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload sshd"
    },
    "CIS-5.2.11": {
        "category": "SSH Hardening",
        "finding": "SSH password authentication is enabled.",
        "why_it_matters": "Allows password brute-force attacks against SSH service. Key-based authentication should be enforced.",
        "fix_command": "sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload sshd"
    },
    "CIS-6.1.2": {
        "category": "File Permissions",
        "finding": "Permissions or ownership on /etc/shadow are insecure.",
        "why_it_matters": "/etc/shadow contains encrypted user password hashes. Excessive permissions allow local password hash cracking.",
        "fix_command": "sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow"
    },
    "CIS-6.1.1": {
        "category": "File Permissions",
        "finding": "Permissions or ownership on /etc/passwd are insecure.",
        "why_it_matters": "Unrestricted write access to /etc/passwd allows unauthorized account creation or privilege escalation.",
        "fix_command": "sudo chown root:root /etc/passwd && sudo chmod 644 /etc/passwd"
    },
    "CIS-6.2.1": {
        "category": "Account Security",
        "finding": "Accounts with empty password fields detected.",
        "why_it_matters": "Allows unauthenticated users to gain shell access without entering a password.",
        "fix_command": "sudo passwd -l <username>"
    },
    "CIS-3.5.1": {
        "category": "Network Security",
        "finding": "Host firewall is disabled or inactive.",
        "why_it_matters": "Exposes unneeded listening network services directly to unauthorized remote traffic.",
        "fix_command": "sudo ufw enable || sudo systemctl enable --now firewalld"
    },
    "CIS-5.3.4": {
        "category": "Privilege Escalation",
        "finding": "Wildcard NOPASSWD found in sudoers configuration.",
        "why_it_matters": "Allows users or compromised processes to run administrative commands as root without authentication.",
        "fix_command": "sudo visudo  # Remove NOPASSWD directives from /etc/sudoers and /etc/sudoers.d/"
    },
    "CIS-6.1.10": {
        "category": "File System Integrity",
        "finding": "World-writable files present in system directories.",
        "why_it_matters": "Any local user can modify or corrupt critical system configuration or executable scripts.",
        "fix_command": "sudo chmod o-w <file_path>"
    },
    "CIS-5.3.1": {
        "category": "Password Policy",
        "finding": "Password complexity / length policy is insufficient.",
        "why_it_matters": "Short or simple passwords are vulnerable to dictionary and brute-force attacks.",
        "fix_command": "sudo apt-get install -y libpam-pwquality && sudo sed -i 's/# minlen =.*/minlen = 14/' /etc/security/pwquality.conf"
    },
    "CIS-1.9": {
        "category": "System Maintenance",
        "finding": "Automatic security updates are disabled.",
        "why_it_matters": "Leaves system unpatched against publicly known security vulnerabilities (CVEs).",
        "fix_command": "sudo apt-get install -y unattended-upgrades && sudo dpkg-reconfigure --priority=low unattended-upgrades"
    }
}

SEVERITY_ORDER = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4
}

class Prioritizer:
    def prioritize(self, findings: list[dict]) -> list[dict]:
        """
        Ranks FAIL findings by severity and attaches exact remediation commands.
        Guarantees 100% reproducible ordering across runs.
        """
        # Filter strictly for FAIL status
        failed_findings = [f for f in findings if f["status"] == "FAIL"]

        # Deterministic sorting: Primary by severity rank, Secondary by rule_id string
        failed_findings.sort(key=lambda x: (SEVERITY_ORDER.get(x.get("severity_hint", "low"), 99), x["rule_id"]))

        fix_list = []
        for index, item in enumerate(failed_findings, start=1):
            rule_id = item["rule_id"]
            meta = REMEDIATION_MAP.get(rule_id, {
                "category": "Security Hardening",
                "finding": f"Rule {rule_id} check failed.",
                "why_it_matters": "Violates system security benchmark guidelines.",
                "fix_command": f"# Review configuration for rule {rule_id}"
            })

            fix_list.append({
                "priority": index,
                "rule_id": rule_id,
                "category": meta["category"],
                "finding": f"{meta['finding']} (Observed: '{item['evidence']}')",
                "why_it_matters": meta["why_it_matters"],
                "fix_command": meta["fix_command"],
                "evidence_ref": rule_id
            })

        return fix_list
