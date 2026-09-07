"""
Lightweight API & Web Server for CIS Audit Agent Dashboard.
Serves web assets from web/ and provides endpoints:
  - POST /api/audit : Runs audit pipeline against target
  - GET  /api/report: Returns latest audit report JSON
  - POST /api/chat  : AI Security Assistant Chatbot endpoint
"""

import http.server
import socketserver
import json
import os
import urllib.parse
import sys
from datetime import datetime

# Add root directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from audit_agent.allowlist import ALLOWLIST_VERSION, ALLOWLIST
from audit_agent.connector import TargetConnector
from audit_agent.collector import Collector
from audit_agent.rules import RuleEngine
from audit_agent.prioritizer import Prioritizer, REMEDIATION_MAP
from audit_agent.reporter import ReportGenerator

PORT = 8000
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

class AuditServerHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/report":
            self._handle_get_report()
        else:
            # Default static file handling from web/
            if parsed.path == "/":
                self.path = "/index.html"
            super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        content_length = int(self.headers.get('Content-Length', 0))
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b"{}"
        
        try:
            body = json.loads(body_bytes.decode('utf-8'))
        except Exception:
            body = {}

        if parsed.path == "/api/audit":
            self._handle_post_audit(body)
        elif parsed.path == "/api/chat":
            self._handle_post_chat(body)
        else:
            self._send_json({"error": "Endpoint not found"}, status=404)

    def _handle_get_report(self):
        report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report.json")
        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._send_json(data)
        else:
            self._send_json({"error": "No report generated yet. Run an audit first."}, status=404)

    def _handle_post_audit(self, body: dict):
        target = body.get("target", "demo-misconfigured")
        transport = body.get("transport", "demo")
        ssh_user = body.get("ssh_user", "ubuntu")
        ssh_key = body.get("ssh_key", None)

        try:
            connector = TargetConnector(target=target, transport=transport, ssh_user=ssh_user, ssh_key=ssh_key)
            collector = Collector(connector)
            raw_evidence = collector.collect_all()

            rule_engine = RuleEngine(raw_evidence)
            findings = rule_engine.evaluate_all()

            prioritizer = Prioritizer()
            fix_list = prioritizer.prioritize(findings)

            reporter = ReportGenerator(target=target, transport=transport, allowlist_version=ALLOWLIST_VERSION)
            json_output = reporter.build_json_report(findings, fix_list, raw_evidence)
            md_output = reporter.build_markdown_report(findings, fix_list)

            root_dir = os.path.dirname(os.path.abspath(__file__))
            with open(os.path.join(root_dir, "report.json"), "w", encoding="utf-8") as f:
                f.write(json_output)
            with open(os.path.join(root_dir, "REPORT.md"), "w", encoding="utf-8") as f:
                f.write(md_output)

            report_data = json.loads(json_output)
            self._send_json(report_data)

        except Exception as exc:
            self._send_json({"error": f"Audit execution failed: {str(exc)}"}, status=500)

    def _handle_post_chat(self, body: dict):
        user_msg = body.get("message", "").strip().lower()
        
        # Load current report data for context
        report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report.json")
        current_report = None
        if os.path.exists(report_path):
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    current_report = json.load(f)
            except Exception:
                pass

        reply = self._generate_chatbot_reply(user_msg, current_report)
        self._send_json({"reply": reply})

    def _generate_chatbot_reply(self, query: str, report: dict) -> str:
        """Contextual AI Assistant logic for security rules and current host audit report."""
        if not query:
            return "Hello! I am **AuditBot AI**, your CIS Security Assistant. Ask me anything about your host audit, security rules, or how to fix vulnerabilities!"

        # Query parsing & contextual responses
        if "summary" in query or "overview" in query or "status" in query or "score" in query:
            if not report:
                return "No audit report found yet. Please run an audit using the controls above!"
            s = report.get("summary", {})
            meta = report.get("metadata", {})
            return (
                f"📊 **Audit Summary for `{meta.get('target', 'Unknown')}`**:\n\n"
                f"- 🟢 **PASS:** {s.get('pass_count', 0)}\n"
                f"- 🔴 **FAIL:** {s.get('fail_count', 0)}\n"
                f"- 🟡 **UNKNOWN:** {s.get('unknown_count', 0)}\n\n"
                f"There are **{s.get('fail_count', 0)} critical/high risk items** requiring remediation."
            )

        if "fix" in query or "remediat" in query or "how to" in query or "command" in query:
            if not report or not report.get("fix_list"):
                return "🎉 No fix items needed! All checks are currently passing or no audit has been run."
            
            lines = ["🛠️ **Recommended Fix Commands (Ranked by Severity):**\n"]
            for item in report["fix_list"]:
                lines.append(f"**Priority {item['priority']} - {item['rule_id']} ({item['category']}):**")
                lines.append(f"`{item['fix_command']}`\n")
            return "\n".join(lines)

        if "ssh" in query or "root" in query:
            return (
                "🔒 **SSH Security Benchmark (CIS-5.2.10 & CIS-5.2.11):**\n\n"
                "1. **Disable Root Login:** Root logins over SSH bypass privilege escalation logs. Fix with:\n"
                "   `sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config`\n"
                "2. **Disable Password Authentication:** Enforce key-based authentication:\n"
                "   `sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config`"
            )

        if "shadow" in query or "permission" in query or "etc/shadow" in query:
            return (
                "🔑 **`/etc/shadow` Permissions (CIS-6.1.2):**\n\n"
                "The `/etc/shadow` file contains encrypted user password hashes. Insecure permissions allow local users to extract and crack hashes offline.\n\n"
                "**Exact Fix:**\n"
                "`sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow`"
            )

        if "firewall" in query or "ufw" in query or "port" in query:
            return (
                "🛡️ **Host Firewall (CIS-3.5.1):**\n\n"
                "An inactive firewall leaves internal services directly exposed to port scans and unauthorized network traffic.\n\n"
                "**Exact Fix:**\n"
                "`sudo ufw enable` or `sudo systemctl enable --now firewalld`"
            )

        if "read-only" in query or "safety" in query or "secure" in query:
            return (
                "🛡️ **Safety Model:**\n\n"
                "Our agent connects strictly in **read-only mode**. All commands are locked in an immutable allowlist (`allowlist.py`). "
                "The agent **never** mutates target system state, installs packages, or edits files automatically."
            )

        # Fallback intelligent answer
        return (
            f"🤖 I analyzed your query regarding **'{query}'**.\n\n"
            "Here is what you can do:\n"
            "- Ask me to **'summarize risks'** for an executive breakdown.\n"
            "- Ask **'how to fix SSH'** or **'how to fix shadow permissions'** for step-by-step remediation steps.\n"
            "- Select a target above and click **'Run Live Audit'** to analyze a fresh target!"
        )

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

def run_server(port: int = PORT):
    os.makedirs(WEB_DIR, exist_ok=True)
    with socketserver.TCPServer(("", port), AuditServerHandler) as httpd:
        print(f"[+] CIS Audit Dashboard Server running at: http://localhost:{port}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Stopping server...")

if __name__ == "__main__":
    run_server()
