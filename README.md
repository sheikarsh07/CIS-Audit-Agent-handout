# CIS Audit Agent

> A hardened, read-only Linux host security auditing CLI tool that evaluates hosts against CIS-Benchmark-style rules and generates a reproducible, grounded remediation plan.

---

## 🚀 Overview

The **CIS Audit Agent** connects to target Linux hosts (via Docker `exec`, SSH, or local execution), executes a versioned allowlist of strictly read-only commands, evaluates raw evidence against ~10 CIS benchmark rules deterministically, and produces a ranked, grounded fix list.

### 🛡️ Safety & Architecture Principles
1. **Zero State Mutation**: Operates strictly read-only (`cat`, `stat`, `sshd -T`). Never runs mutating commands (`sed -i`, `apt install`, `systemctl restart`).
2. **Fixed Command Allowlist**: Commands are hardcoded and versioned (`allowlist.py`). No arbitrary commands constructed from runtime input or LLM generation.
3. **Deterministic Verdicts**: Verdicts (`PASS`, `FAIL`, `UNKNOWN`) are decided by rule regex parsers—never guessed by an LLM.
4. **100% Groundability**: Every fix-list item links back to a specific `rule_id` and raw stdout evidence snippet.
5. **No-Drift Guarantee**: Two consecutive runs against an unchanged host yield identical findings in identical order.

---

## 🛠️ Installation & Requirements

- Python 3.8+
- (Optional) `paramiko` for SSH connections (`pip install paramiko`)

```bash
# Clone or navigate to the repository
cd CIS-Audit-Agent

# Install dependencies (optional for SSH)
pip install -r requirements.txt
```

---

## 💻 How to Run

### 1. Instant Demo Mode (No Setup Required)
Run the auditor against built-in mock targets (misconfigured, clean, or broken):

```bash
# Audit a misconfigured target
py -3 main.py --target demo-misconfigured --transport demo

# Audit a clean target
py -3 main.py --target demo-clean --transport demo

# Audit a broken/partially unreachable target
py -3 main.py --target demo-broken --transport demo
```

### 2. Audit a Local Docker Container
```bash
py -3 main.py --target my-ubuntu-container --transport docker
```

### 3. Audit a Remote Host via SSH
```bash
py -3 main.py --target 192.168.1.100 --transport ssh --ssh-user ubuntu --ssh-key ~/.ssh/id_rsa
```

---

## 📊 Output Files

After each run, two report files are generated in the working directory:
- `report.json`: Structured JSON containing metadata, summary, findings, and fix list.
- `REPORT.md`: Human-readable markdown audit report with priority fix commands.

---

## 🧪 Testing & Verification

Run the built-in test suite to verify reproducibility, allowlist compliance, error handling, and evidence grounding:

```bash
py -3 tests/test_agent.py
```

### Passing Requirements Checklist:
- [x] Connects strictly read-only.
- [x] Command allowlist enforcement.
- [x] 10 CIS-style benchmark rules evaluated.
- [x] Grounded fix list with exact remediation commands.
- [x] Zero-drift / reproducible ordering.
- [x] Graceful degradation on missing tools / permission errors (`UNKNOWN`).
- [x] Non-zero exit code on connection failure.
