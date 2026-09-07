"""
Connector Module: Opens read-only sessions to target hosts via Docker, SSH, or Local Shell.
Also includes a built-in Demo mode for instant testing without infrastructure.
"""

import subprocess
import shutil

class TargetConnector:
    def __init__(self, target: str, transport: str = "docker", ssh_user: str = "ubuntu", ssh_key: str = None, ssh_port: int = 22):
        self.target = target
        self.transport = transport.lower()
        self.ssh_user = ssh_user
        self.ssh_key = ssh_key
        self.ssh_port = ssh_port
        
        # Verify connection availability on setup
        self._verify_connection()

    def _verify_connection(self):
        """Ensures target is reachable before collecting evidence."""
        if self.transport == "demo":
            return  # Demo mode always available
        elif self.transport == "docker":
            if not shutil.which("docker"):
                raise ConnectionError("Docker executable not found in PATH.")
            res = subprocess.run(["docker", "inspect", self.target], capture_output=True, text=True)
            if res.returncode != 0:
                raise ConnectionError(f"Docker container '{self.target}' is not running or unreachable.")
        elif self.transport == "ssh":
            if not shutil.which("ssh"):
                try:
                    import paramiko
                except ImportError:
                    raise ConnectionError("Neither OpenSSH client nor 'paramiko' package is installed.")
        elif self.transport == "local":
            pass  # Local system checks
        else:
            raise ValueError(f"Unknown transport: '{self.transport}'")

    def execute_read_only(self, command_key: str, command_str: str) -> tuple[int, str, str]:
        """
        Executes a single allowlisted command strictly read-only.
        Returns: (exit_code, stdout, stderr)
        """
        if self.transport == "demo":
            return self._demo_response(command_key)

        elif self.transport == "docker":
            cmd = ["docker", "exec", self.target, "sh", "-c", command_str]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return res.returncode, res.stdout.strip(), res.stderr.strip()

        elif self.transport == "local":
            res = subprocess.run(command_str, shell=True, capture_output=True, text=True, timeout=15)
            return res.returncode, res.stdout.strip(), res.stderr.strip()

        elif self.transport == "ssh":
            try:
                import paramiko
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                kwargs = {"hostname": self.target, "username": self.ssh_user, "port": self.ssh_port, "timeout": 10}
                if self.ssh_key:
                    kwargs["key_filename"] = self.ssh_key
                ssh.connect(**kwargs)
                _, stdout, stderr = ssh.exec_command(command_str, timeout=15)
                exit_code = stdout.channel.recv_exit_status()
                out_str = stdout.read().decode("utf-8", errors="ignore").strip()
                err_str = stderr.read().decode("utf-8", errors="ignore").strip()
                ssh.close()
                return exit_code, out_str, err_str
            except ImportError:
                # Fallback to shelled-out ssh client
                ssh_cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
                if self.ssh_key:
                    ssh_cmd.extend(["-i", self.ssh_key])
                ssh_cmd.append(f"{self.ssh_user}@{self.target}")
                ssh_cmd.append(command_str)
                res = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=20)
                return res.returncode, res.stdout.strip(), res.stderr.strip()

        else:
            raise ValueError(f"Unsupported transport '{self.transport}'")

    def _demo_response(self, command_key: str) -> tuple[int, str, str]:
        """Provides realistic mock responses for testing clean, misconfigured, and broken targets."""
        target_type = self.target.lower()

        if "broken" in target_type:
            if command_key == "shadow_perms":
                return 1, "", "stat: cannot stat '/etc/shadow': Permission denied"
            elif command_key == "firewall_status":
                return 127, "", "ufw: command not found"
            # Return partial fails and errors for broken target testing
            return 0, "", ""

        elif "clean" in target_type or "hardened" in target_type:
            responses = {
                "ssh_root_login": (0, "permitrootlogin no", ""),
                "ssh_password_auth": (0, "passwordauthentication no", ""),
                "shadow_perms": (0, "640 root shadow", ""),
                "passwd_perms": (0, "644 root root", ""),
                "empty_passwords": (0, "", ""),
                "firewall_status": (0, "Status: active", ""),
                "sudoers_nopasswd": (0, "", ""),
                "world_writable": (0, "", ""),
                "pw_quality": (0, "minlen = 14\ndcredit = -1", ""),
                "auto_updates": (0, "APT::Periodic::Update-Package-Lists \"1\";", "")
            }
            return responses.get(command_key, (0, "", ""))

        else:
            # Default misconfigured target demo (has security vulnerabilities)
            responses = {
                "ssh_root_login": (0, "permitrootlogin yes", ""),
                "ssh_password_auth": (0, "passwordauthentication yes", ""),
                "shadow_perms": (0, "666 root root", ""),
                "passwd_perms": (0, "644 root root", ""),
                "empty_passwords": (0, "testuser", ""),
                "firewall_status": (0, "Status: inactive", ""),
                "sudoers_nopasswd": (0, "%sudo ALL=(ALL:ALL) NOPASSWD: ALL", ""),
                "world_writable": (0, "/etc/config_backup.tmp", ""),
                "pw_quality": (0, "minlen = 6", ""),
                "auto_updates": (0, "APT::Periodic::Update-Package-Lists \"0\";", "")
            }
            return responses.get(command_key, (0, "", ""))
