"""
Unit & Reproducibility Test Suite for CIS Audit Agent.
Validates Requirements 1-10 from the handout.
"""

import sys
import os
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    import pytest
except ImportError:
    pytest = None

from audit_agent.connector import TargetConnector
from audit_agent.collector import Collector
from audit_agent.rules import RuleEngine
from audit_agent.prioritizer import Prioritizer
from audit_agent.allowlist import ALLOWLIST

def run_pipeline(target: str, transport: str = "demo"):
    connector = TargetConnector(target=target, transport=transport)
    collector = Collector(connector)
    raw_evidence = collector.collect_all()
    rule_engine = RuleEngine(raw_evidence)
    findings = rule_engine.evaluate_all()
    prioritizer = Prioritizer()
    fix_list = prioritizer.prioritize(findings)
    return findings, fix_list, raw_evidence

def test_no_drift_reproducibility():
    """Requirement 6 & 10: Two runs against unchanged target must produce identical findings & fix-list ordering."""
    findings_run1, fix_list_run1, _ = run_pipeline("demo-target")
    findings_run2, fix_list_run2, _ = run_pipeline("demo-target")

    # Assert findings are identical
    assert findings_run1 == findings_run2, "Findings drifted between runs!"

    # Assert fix list order and contents are identical
    assert fix_list_run1 == fix_list_run2, "Fix list ordering drifted between runs!"

def test_allowlist_commands_only():
    """Requirement 2: Every command must come from fixed allowlist."""
    _, _, raw_evidence = run_pipeline("demo-target")
    for key, data in raw_evidence.items():
        assert key in ALLOWLIST, f"Command key {key} not in allowlist!"
        assert data["command"] == ALLOWLIST[key], f"Command string modified at runtime!"

def test_graceful_degradation_on_broken_target():
    """Requirement 7: Missing/broken command is skipped with UNKNOWN status, never crashes."""
    findings, fix_list, _ = run_pipeline("demo-broken-target")
    assert len(findings) == 10, "Should evaluate all 10 rules even on broken target"
    unknown_count = sum(1 for f in findings if f["status"] == "UNKNOWN")
    assert unknown_count > 0, "Broken target should yield UNKNOWN verdicts for missing tools"

def test_grounding_evidence_traceability():
    """Requirement 5: Every fix item traces to one rule_id and captured evidence."""
    findings, fix_list, _ = run_pipeline("demo-target")
    rule_map = {f["rule_id"]: f for f in findings}
    
    for fix_item in fix_list:
        rule_id = fix_item["rule_id"]
        assert rule_id in rule_map, f"Fix item rule {rule_id} not found in findings!"
        assert rule_map[rule_id]["status"] == "FAIL", f"Fix item generated for non-failing rule {rule_id}!"
        assert fix_item["evidence_ref"] == rule_id

if __name__ == "__main__":
    print("[*] Running unit and reproducibility test suite...")
    test_no_drift_reproducibility()
    print("    [+] Test 1 PASSED: Reproducibility & Zero-Drift verified.")
    test_allowlist_commands_only()
    print("    [+] Test 2 PASSED: Allowlist compliance verified.")
    test_graceful_degradation_on_broken_target()
    print("    [+] Test 3 PASSED: Graceful error degradation verified.")
    test_grounding_evidence_traceability()
    print("    [+] Test 4 PASSED: Grounding & evidence traceability verified.")
    print("\n[+] ALL TESTS PASSED SUCCESSFULLY!")
