"""
Deterministic Rule Engine: Evaluates raw evidence against ~10 CIS-Benchmark-style rules.
Outputs structured findings with status (PASS / FAIL / UNKNOWN) and evidence.
"""

import re

class RuleEngine:
    def __init__(self, raw_evidence: dict):
        self.evidence = raw_evidence

    def evaluate_all(self) -> list[dict]:
        """Runs all rule checks and returns a list of findings."""
        findings = [
            self._check_ssh_root_login(),
            self._check_ssh_password_auth(),
            self._check_shadow_permissions(),
            self._check_passwd_permissions(),
            self._check_empty_passwords(),
            self._check_firewall_active(),
            self._check_sudoers_nopasswd(),
            self._check_world_writable_files(),
            self._check_password_quality(),
            self._check_auto_updates()
        ]
        return findings

    def _check_ssh_root_login(self) -> dict:
        data = self.evidence.get("ssh_root_login", {})
        if not data.get("available") or (data.get("exit_code") != 0 and not data.get("stdout")):
            return self._build_finding(
                rule_id="CIS-5.2.10",
                title="Disable SSH Root Login",
                command=data.get("command", ""),
                status="UNKNOWN",
                evidence=f"SSH config unreadable or sshd service unavailable (stderr: {data.get('stderr', 'N/A')})",
                severity_hint="high"
            )
        
        stdout = data.get("stdout", "").strip()
        match = re.search(r"permitrootlogin\s+(yes|no|prohibit-password|without-password)", stdout, re.IGNORECASE)
        if match:
            val = match.group(1).lower()
            if val == "no":
                return self._build_finding("CIS-5.2.10", "Disable SSH Root Login", data["command"], "PASS", f"PermitRootLogin set to '{val}'", "high")
            else:
                return self._build_finding("CIS-5.2.10", "Disable SSH Root Login", data["command"], "FAIL", f"PermitRootLogin is set to '{val}' (expected 'no')", "high")
        
        return self._build_finding("CIS-5.2.10", "Disable SSH Root Login", data["command"], "FAIL", f"PermitRootLogin not explicitly set to 'no' (found: '{stdout}')", "high")

    def _check_ssh_password_auth(self) -> dict:
        data = self.evidence.get("ssh_password_auth", {})
        if not data.get("available") or (data.get("exit_code") != 0 and not data.get("stdout")):
            return self._build_finding("CIS-5.2.11", "Disable SSH Password Authentication", data.get("command", ""), "UNKNOWN", "SSH config unreadable", "medium")
        
        stdout = data.get("stdout", "").strip()
        match = re.search(r"passwordauthentication\s+(yes|no)", stdout, re.IGNORECASE)
        if match:
            val = match.group(1).lower()
            if val == "no":
                return self._build_finding("CIS-5.2.11", "Disable SSH Password Authentication", data["command"], "PASS", f"PasswordAuthentication set to '{val}'", "medium")
            else:
                return self._build_finding("CIS-5.2.11", "Disable SSH Password Authentication", data["command"], "FAIL", f"PasswordAuthentication is set to '{val}' (expected 'no')", "medium")
        
        return self._build_finding("CIS-5.2.11", "Disable SSH Password Authentication", data["command"], "FAIL", f"PasswordAuthentication not explicitly set to 'no' (found: '{stdout}')", "medium")

    def _check_shadow_permissions(self) -> dict:
        data = self.evidence.get("shadow_perms", {})
        stdout = data.get("stdout", "").strip()
        if not data.get("available") or not stdout or data.get("exit_code") != 0:
            return self._build_finding("CIS-6.1.2", "Ensure permissions on /etc/shadow are configured", data.get("command", ""), "UNKNOWN", f"Permission denied or file unreadable: {data.get('stderr', '')}", "critical")
        
        parts = stdout.split()
        if len(parts) >= 3:
            perms, owner, group = parts[0], parts[1], parts[2]
            # Valid perms: 640, 600, 000 with owner root
            if perms in ["640", "600", "000"] and owner == "root":
                return self._build_finding("CIS-6.1.2", "Ensure permissions on /etc/shadow are configured", data["command"], "PASS", f"Permissions are {perms} owner {owner}:{group}", "critical")
            else:
                return self._build_finding("CIS-6.1.2", "Ensure permissions on /etc/shadow are configured", data["command"], "FAIL", f"Insecure permissions: {perms} owner {owner}:{group} (expected 640 root:shadow or root:root)", "critical")
        
        return self._build_finding("CIS-6.1.2", "Ensure permissions on /etc/shadow are configured", data["command"], "UNKNOWN", f"Unexpected stat output: '{stdout}'", "critical")

    def _check_passwd_permissions(self) -> dict:
        data = self.evidence.get("passwd_perms", {})
        stdout = data.get("stdout", "").strip()
        if not data.get("available") or not stdout or data.get("exit_code") != 0:
            return self._build_finding("CIS-6.1.1", "Ensure permissions on /etc/passwd are configured", data.get("command", ""), "UNKNOWN", "File unreadable", "medium")
        
        parts = stdout.split()
        if len(parts) >= 3:
            perms, owner = parts[0], parts[1]
            if perms in ["644", "600"] and owner == "root":
                return self._build_finding("CIS-6.1.1", "Ensure permissions on /etc/passwd are configured", data["command"], "PASS", f"Permissions are {perms} owner {owner}", "medium")
            else:
                return self._build_finding("CIS-6.1.1", "Ensure permissions on /etc/passwd are configured", data["command"], "FAIL", f"Insecure permissions: {perms} owner {owner}", "medium")
        return self._build_finding("CIS-6.1.1", "Ensure permissions on /etc/passwd are configured", data["command"], "UNKNOWN", f"Stat output: '{stdout}'", "medium")

    def _check_empty_passwords(self) -> dict:
        data = self.evidence.get("empty_passwords", {})
        if not data.get("available") or data.get("exit_code") != 0:
            return self._build_finding("CIS-6.2.1", "Ensure no accounts have empty password fields", data.get("command", ""), "UNKNOWN", f"Unable to read shadow database: {data.get('stderr', '')}", "critical")
        
        stdout = data.get("stdout", "").strip()
        if stdout:
            accounts = ", ".join(stdout.splitlines())
            return self._build_finding("CIS-6.2.1", "Ensure no accounts have empty password fields", data["command"], "FAIL", f"Account(s) with empty password: {accounts}", "critical")
        
        return self._build_finding("CIS-6.2.1", "Ensure no accounts have empty password fields", data["command"], "PASS", "No accounts with empty passwords found", "critical")

    def _check_firewall_active(self) -> dict:
        data = self.evidence.get("firewall_status", {})
        stdout = data.get("stdout", "").lower()
        if "status: active" in stdout or "active (running)" in stdout or "chain input" in stdout or "active" in stdout:
            return self._build_finding("CIS-3.5.1", "Ensure firewall is active", data.get("command", ""), "PASS", "Active firewall detected", "high")
        elif "inactive" in stdout or "disabled" in stdout or data.get("exit_code") != 0:
            return self._build_finding("CIS-3.5.1", "Ensure firewall is active", data.get("command", ""), "FAIL", f"Firewall disabled or inactive (output: '{data.get('stdout', '')}')", "high")
        
        return self._build_finding("CIS-3.5.1", "Ensure firewall is active", data.get("command", ""), "UNKNOWN", "Firewall utility output unparseable", "high")

    def _check_sudoers_nopasswd(self) -> dict:
        data = self.evidence.get("sudoers_nopasswd", {})
        if not data.get("available"):
            return self._build_finding("CIS-5.3.4", "Ensure sudoers contains no NOPASSWD wildcard", data.get("command", ""), "UNKNOWN", "Unable to inspect sudoers files", "high")
        
        stdout = data.get("stdout", "").strip()
        if stdout:
            return self._build_finding("CIS-5.3.4", "Ensure sudoers contains no NOPASSWD wildcard", data["command"], "FAIL", f"NOPASSWD entry found: {stdout[:120]}", "high")
        
        return self._build_finding("CIS-5.3.4", "Ensure sudoers contains no NOPASSWD wildcard", data["command"], "PASS", "No NOPASSWD wildcard entries found", "high")

    def _check_world_writable_files(self) -> dict:
        data = self.evidence.get("world_writable", {})
        if not data.get("available") or data.get("exit_code") != 0:
            return self._build_finding("CIS-6.1.10", "Ensure no world-writable files exist in system paths", data.get("command", ""), "UNKNOWN", "Find command execution restricted", "medium")
        
        stdout = data.get("stdout", "").strip()
        if stdout:
            files = ", ".join(stdout.splitlines()[:5])
            return self._build_finding("CIS-6.1.10", "Ensure no world-writable files exist in system paths", data["command"], "FAIL", f"World-writable files detected: {files}", "medium")
        
        return self._build_finding("CIS-6.1.10", "Ensure no world-writable files exist in system paths", data["command"], "PASS", "No world-writable files detected in system paths", "medium")

    def _check_password_quality(self) -> dict:
        data = self.evidence.get("pw_quality", {})
        stdout = data.get("stdout", "")
        match = re.search(r"minlen\s*=\s*(\d+)", stdout)
        if match:
            minlen = int(match.group(1))
            if minlen >= 14:
                return self._build_finding("CIS-5.3.1", "Ensure password complexity / length policy is set", data["command"], "PASS", f"Minimum password length is set to {minlen}", "low")
            else:
                return self._build_finding("CIS-5.3.1", "Ensure password complexity / length policy is set", data["command"], "FAIL", f"Minimum password length is {minlen} (expected >= 14)", "low")
        
        if data.get("available") and stdout:
            return self._build_finding("CIS-5.3.1", "Ensure password complexity / length policy is set", data["command"], "FAIL", "Minimum password length minlen not configured", "low")
        
        return self._build_finding("CIS-5.3.1", "Ensure password complexity / length policy is set", data.get("command", ""), "UNKNOWN", "pwquality config unreadable", "low")

    def _check_auto_updates(self) -> dict:
        data = self.evidence.get("auto_updates", {})
        stdout = data.get("stdout", "").lower()
        if "periodic::update-package-lists \"1\"" in stdout or "enabled" in stdout or "active" in stdout:
            return self._build_finding("CIS-1.9", "Ensure automatic security updates are enabled", data.get("command", ""), "PASS", "Automatic updates enabled", "low")
        elif "periodic::update-package-lists \"0\"" in stdout or "disabled" in stdout or "inactive" in stdout:
            return self._build_finding("CIS-1.9", "Ensure automatic security updates are enabled", data.get("command", ""), "FAIL", "Automatic security updates disabled", "low")
        
        return self._build_finding("CIS-1.9", "Ensure automatic security updates are enabled", data.get("command", ""), "UNKNOWN", "Automatic update config unreadable", "low")

    def _build_finding(self, rule_id: str, title: str, command: str, status: str, evidence: str, severity_hint: str) -> dict:
        return {
            "rule_id": rule_id,
            "title": title,
            "command": command,
            "status": status,
            "evidence": evidence,
            "severity_hint": severity_hint
        }
