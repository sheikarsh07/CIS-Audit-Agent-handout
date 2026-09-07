"""
Versioned, fixed allowlist of strictly read-only commands.
Rule: Never build a command dynamically from user input or LLM generation.
"""

ALLOWLIST_VERSION = "1.0.0"

# Explicit allowlist mapping query keys to strictly read-only shell commands
ALLOWLIST = {
    "ssh_root_login": "sshd -T 2>/dev/null | grep -i permitrootlogin || grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null",
    "ssh_password_auth": "sshd -T 2>/dev/null | grep -i passwordauthentication || grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null",
    "shadow_perms": "stat -c '%a %U %G' /etc/shadow 2>/dev/null",
    "passwd_perms": "stat -c '%a %U %G' /etc/passwd 2>/dev/null",
    "empty_passwords": "awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null",
    "firewall_status": "ufw status 2>/dev/null || systemctl is-active firewalld 2>/dev/null || iptables -L -n 2>/dev/null",
    "sudoers_nopasswd": "grep -r -i 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null",
    "world_writable": "find /etc /var /usr -maxdepth 3 -type f -perm -0002 2>/dev/null | head -n 20",
    "pw_quality": "cat /etc/security/pwquality.conf /etc/pam.d/common-password 2>/dev/null",
    "auto_updates": "cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || systemctl is-enabled unattended-upgrades 2>/dev/null"
}
