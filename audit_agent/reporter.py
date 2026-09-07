"""
Reporter Module: Formats audit findings into report.json and human-readable REPORT.md.
"""

import json
from datetime import datetime

class ReportGenerator:
    def __init__(self, target: str, transport: str, allowlist_version: str):
        self.target = target
        self.transport = transport
        self.allowlist_version = allowlist_version

    def build_json_report(self, findings: list[dict], fix_list: list[dict], raw_evidence: dict) -> str:
        """Constructs the complete structured JSON audit report."""
        summary = {
            "total_checks": len(findings),
            "pass_count": sum(1 for f in findings if f["status"] == "PASS"),
            "fail_count": sum(1 for f in findings if f["status"] == "FAIL"),
            "unknown_count": sum(1 for f in findings if f["status"] == "UNKNOWN")
        }
        
        report = {
            "metadata": {
                "target": self.target,
                "transport": self.transport,
                "allowlist_version": self.allowlist_version,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            },
            "summary": summary,
            "findings": findings,
            "fix_list": fix_list,
            "raw_evidence": raw_evidence
        }
        return json.dumps(report, indent=2)

    def build_markdown_report(self, findings: list[dict], fix_list: list[dict]) -> str:
        """Constructs human-readable REPORT.md markdown document."""
        pass_cnt = sum(1 for f in findings if f["status"] == "PASS")
        fail_cnt = sum(1 for f in findings if f["status"] == "FAIL")
        unk_cnt = sum(1 for f in findings if f["status"] == "UNKNOWN")

        md = f"# CIS Audit Agent - Host Security Report\n\n"
        md += f"**Target:** `{self.target}` | **Transport:** `{self.transport}` | **Allowlist Version:** `{self.allowlist_version}`\n\n"
        
        md += f"## Executive Summary\n"
        md += f"- 🟢 **PASS:** {pass_cnt}\n"
        md += f"- 🔴 **FAIL:** {fail_cnt}\n"
        md += f"- 🟡 **UNKNOWN:** {unk_cnt}\n\n"
        
        md += f"## Prioritized Fix List (Remediation Plan)\n\n"
        if not fix_list:
            md += "🎉 **No security failures detected.** System complies with evaluated CIS Benchmark rules.\n\n"
        else:
            for item in fix_list:
                md += f"### Priority {item['priority']}: {item['category']} (`{item['rule_id']}`)\n"
                md += f"- **Finding:** {item['finding']}\n"
                md += f"- **Why It Matters:** {item['why_it_matters']}\n"
                md += f"- **Exact Fix Command:**\n```bash\n{item['fix_command']}\n```\n\n"
        
        md += f"## Detailed Rule Evaluation\n\n"
        md += f"| Rule ID | Title | Status | Evidence Excerpt |\n"
        md += f"| :--- | :--- | :--- | :--- |\n"
        for f in findings:
            status_icon = "🟢 PASS" if f['status'] == "PASS" else ("🔴 FAIL" if f['status'] == "FAIL" else "🟡 UNKNOWN")
            evidence_clean = f['evidence'].replace("\n", " ")[:80]
            md += f"| `{f['rule_id']}` | {f['title']} | **{status_icon}** | `{evidence_clean}` |\n"
        
        md += "\n---\n*Report generated automatically by CIS Audit Agent (strictly read-only).* \n"
        return md
