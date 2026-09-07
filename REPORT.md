# CIS Audit Agent - Host Security Report

**Target:** `demo-misconfigured` | **Transport:** `demo` | **Allowlist Version:** `1.0.0`

## Executive Summary
- 🟢 **PASS:** 2
- 🔴 **FAIL:** 8
- 🟡 **UNKNOWN:** 0

## Prioritized Fix List (Remediation Plan)

### Priority 1: File Permissions (`CIS-6.1.2`)
- **Finding:** Permissions or ownership on /etc/shadow are insecure. (Observed: 'Insecure permissions: 666 owner root:root (expected 640 root:shadow or root:root)')
- **Why It Matters:** /etc/shadow contains encrypted user password hashes. Excessive permissions allow local password hash cracking.
- **Exact Fix Command:**
```bash
sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow
```

### Priority 2: Account Security (`CIS-6.2.1`)
- **Finding:** Accounts with empty password fields detected. (Observed: 'Account(s) with empty password: testuser')
- **Why It Matters:** Allows unauthenticated users to gain shell access without entering a password.
- **Exact Fix Command:**
```bash
sudo passwd -l <username>
```

### Priority 3: SSH Hardening (`CIS-5.2.10`)
- **Finding:** Root login over SSH is permitted. (Observed: 'PermitRootLogin is set to 'yes' (expected 'no')')
- **Why It Matters:** A leaked or brute-forced root credential grants full remote access with no separate privilege escalation step.
- **Exact Fix Command:**
```bash
sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload sshd
```

### Priority 4: Privilege Escalation (`CIS-5.3.4`)
- **Finding:** Wildcard NOPASSWD found in sudoers configuration. (Observed: 'NOPASSWD entry found: %sudo ALL=(ALL:ALL) NOPASSWD: ALL')
- **Why It Matters:** Allows users or compromised processes to run administrative commands as root without authentication.
- **Exact Fix Command:**
```bash
sudo visudo  # Remove NOPASSWD directives from /etc/sudoers and /etc/sudoers.d/
```

### Priority 5: SSH Hardening (`CIS-5.2.11`)
- **Finding:** SSH password authentication is enabled. (Observed: 'PasswordAuthentication is set to 'yes' (expected 'no')')
- **Why It Matters:** Allows password brute-force attacks against SSH service. Key-based authentication should be enforced.
- **Exact Fix Command:**
```bash
sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload sshd
```

### Priority 6: File System Integrity (`CIS-6.1.10`)
- **Finding:** World-writable files present in system directories. (Observed: 'World-writable files detected: /etc/config_backup.tmp')
- **Why It Matters:** Any local user can modify or corrupt critical system configuration or executable scripts.
- **Exact Fix Command:**
```bash
sudo chmod o-w <file_path>
```

### Priority 7: System Maintenance (`CIS-1.9`)
- **Finding:** Automatic security updates are disabled. (Observed: 'Automatic security updates disabled')
- **Why It Matters:** Leaves system unpatched against publicly known security vulnerabilities (CVEs).
- **Exact Fix Command:**
```bash
sudo apt-get install -y unattended-upgrades && sudo dpkg-reconfigure --priority=low unattended-upgrades
```

### Priority 8: Password Policy (`CIS-5.3.1`)
- **Finding:** Password complexity / length policy is insufficient. (Observed: 'Minimum password length is 6 (expected >= 14)')
- **Why It Matters:** Short or simple passwords are vulnerable to dictionary and brute-force attacks.
- **Exact Fix Command:**
```bash
sudo apt-get install -y libpam-pwquality && sudo sed -i 's/# minlen =.*/minlen = 14/' /etc/security/pwquality.conf
```

## Detailed Rule Evaluation

| Rule ID | Title | Status | Evidence Excerpt |
| :--- | :--- | :--- | :--- |
| `CIS-5.2.10` | Disable SSH Root Login | **🔴 FAIL** | `PermitRootLogin is set to 'yes' (expected 'no')` |
| `CIS-5.2.11` | Disable SSH Password Authentication | **🔴 FAIL** | `PasswordAuthentication is set to 'yes' (expected 'no')` |
| `CIS-6.1.2` | Ensure permissions on /etc/shadow are configured | **🔴 FAIL** | `Insecure permissions: 666 owner root:root (expected 640 root:shadow or root:root` |
| `CIS-6.1.1` | Ensure permissions on /etc/passwd are configured | **🟢 PASS** | `Permissions are 644 owner root` |
| `CIS-6.2.1` | Ensure no accounts have empty password fields | **🔴 FAIL** | `Account(s) with empty password: testuser` |
| `CIS-3.5.1` | Ensure firewall is active | **🟢 PASS** | `Active firewall detected` |
| `CIS-5.3.4` | Ensure sudoers contains no NOPASSWD wildcard | **🔴 FAIL** | `NOPASSWD entry found: %sudo ALL=(ALL:ALL) NOPASSWD: ALL` |
| `CIS-6.1.10` | Ensure no world-writable files exist in system paths | **🔴 FAIL** | `World-writable files detected: /etc/config_backup.tmp` |
| `CIS-5.3.1` | Ensure password complexity / length policy is set | **🔴 FAIL** | `Minimum password length is 6 (expected >= 14)` |
| `CIS-1.9` | Ensure automatic security updates are enabled | **🔴 FAIL** | `Automatic security updates disabled` |

---
*Report generated automatically by CIS Audit Agent (strictly read-only).* 
