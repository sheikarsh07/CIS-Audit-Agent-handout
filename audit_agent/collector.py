"""
Collector Module: Runs all versioned allowlist commands against target host,
capturing stdout, stderr, and exit codes cleanly.
"""

from audit_agent.allowlist import ALLOWLIST
from audit_agent.connector import TargetConnector

class Collector:
    def __init__(self, connector: TargetConnector):
        self.connector = connector

    def collect_all(self) -> dict:
        """
        Executes all allowlisted commands and returns structured raw evidence.
        """
        evidence = {}
        for key, cmd in ALLOWLIST.items():
            try:
                code, stdout, stderr = self.connector.execute_read_only(key, cmd)
                evidence[key] = {
                    "command_key": key,
                    "command": cmd,
                    "exit_code": code,
                    "stdout": stdout,
                    "stderr": stderr,
                    "available": True
                }
            except Exception as exc:
                evidence[key] = {
                    "command_key": key,
                    "command": cmd,
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": str(exc),
                    "available": False
                }
        return evidence
