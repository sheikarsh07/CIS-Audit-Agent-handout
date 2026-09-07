"""
CIS Audit Agent CLI Entrypoint
Usage:
  python main.py --target <host-or-container> [--transport docker|ssh|local|demo] [--ssh-user ubuntu] [--ssh-key path]
"""

import argparse
import sys
import os
from audit_agent.allowlist import ALLOWLIST_VERSION
from audit_agent.connector import TargetConnector
from audit_agent.collector import Collector
from audit_agent.rules import RuleEngine
from audit_agent.prioritizer import Prioritizer
from audit_agent.reporter import ReportGenerator

def print_banner():
    print("=" * 65)
    print("           CIS AUDIT AGENT v1.0 (Strictly Read-Only)")
    print("  COMMANDS -> RULES -> PRIORITIZER -> REPRODUCIBLE FIX LIST")
    print("=" * 65)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Audits Linux hosts against CIS-style rules safely.")
    parser.add_argument("--target", help="Target host, container name, or 'demo'/'demo-clean'/'demo-broken'")
    parser.add_argument("--transport", choices=["docker", "ssh", "local", "demo"], default="demo", help="Transport mode (default: demo)")
    parser.add_argument("--ssh-user", default="ubuntu", help="SSH username (default: ubuntu)")
    parser.add_argument("--ssh-key", help="Path to SSH private key")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--out-dir", default=".", help="Output directory for reports (default: current directory)")
    parser.add_argument("--web", action="store_true", help="Launch interactive Web Dashboard & AI Chatbot Server")

    args = parser.parse_args()

    if args.web:
        from server import run_server
        run_server()
        return

    if not args.target:
        parser.error("the following arguments are required: --target (or specify --web to launch web interface)")

    # Step 1: Initialize Connector (Must fail loudly if connection impossible)
    print(f"\n[*] Connecting to target '{args.target}' via transport '{args.transport}'...")
    try:
        connector = TargetConnector(
            target=args.target,
            transport=args.transport,
            ssh_user=args.ssh_user,
            ssh_key=args.ssh_key,
            ssh_port=args.ssh_port
        )
    except Exception as exc:
        print(f"\n[!] CRITICAL CONNECTION ERROR: {exc}", file=sys.stderr)
        print(f"[!] Unable to establish read-only session with target host. Exiting with non-zero status.\n", file=sys.stderr)
        sys.exit(1)

    # Step 2: Run Collector against allowlisted commands
    print("[*] Collecting raw evidence using fixed versioned allowlist...")
    collector = Collector(connector)
    raw_evidence = collector.collect_all()
    print(f"    [+] Captured evidence for {len(raw_evidence)} allowlisted commands.")

    # Step 3: Run Deterministic Rule Engine
    print("[*] Evaluating rules in Rule Engine...")
    rule_engine = RuleEngine(raw_evidence)
    findings = rule_engine.evaluate_all()
    
    pass_cnt = sum(1 for f in findings if f["status"] == "PASS")
    fail_cnt = sum(1 for f in findings if f["status"] == "FAIL")
    unk_cnt = sum(1 for f in findings if f["status"] == "UNKNOWN")
    print(f"    [+] Evaluation complete: {pass_cnt} PASS | {fail_cnt} FAIL | {unk_cnt} UNKNOWN")

    # Step 4: Prioritize Failures
    print("[*] Ranking failures and generating grounded fix list...")
    prioritizer = Prioritizer()
    fix_list = prioritizer.prioritize(findings)
    print(f"    [+] Generated {len(fix_list)} prioritized action items.")

    # Step 5: Write Output Reports
    print("[*] Writing audit reports...")
    reporter = ReportGenerator(target=args.target, transport=args.transport, allowlist_version=ALLOWLIST_VERSION)
    
    json_output = reporter.build_json_report(findings, fix_list, raw_evidence)
    md_output = reporter.build_markdown_report(findings, fix_list)

    json_path = os.path.join(args.out_dir, "report.json")
    md_path = os.path.join(args.out_dir, "REPORT.md")

    with open(json_path, "w", encoding="utf-8") as f:
        f.write(json_output)
        
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_output)

    print(f"\n[+] SUCCESS! Reports saved to:")
    print(f"    - JSON Report:     {os.path.abspath(json_path)}")
    print(f"    - Markdown Report: {os.path.abspath(md_path)}")
    print("=" * 65)

if __name__ == "__main__":
    main()
