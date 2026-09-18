import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

from app.core.registry import execute_tool, TOOL_TO_SUITE
from app.core.ledger import verify_ledger_integrity, get_ledger_entries

def run_tests():
    print(f"Total tools mapped in catalog: {len(TOOL_TO_SUITE)}")
    assert len(TOOL_TO_SUITE) >= 80, f"Expected at least 80 tools, got {len(TOOL_TO_SUITE)}"

    # Test Tool 1: Deep URL Analyzer
    res1 = execute_tool("url_analyzer", "http://xn--pypal-4ve.com/login/secure", {})
    print(f"[Tool 1] URL Analyzer -> Verdict: {res1.verdict}, Risk: {res1.risk_score}, Evidence items: {len(res1.technical_evidence)}")
    assert res1.verdict.value in ["SUSPICIOUS", "MALICIOUS", "CRITICAL"]
    assert len(res1.remediation_playbook) > 0
    assert len(res1.standards_and_references) > 0

    # Test Tool 12: Web Attack Signature Scanner
    res12 = execute_tool("web_attack_scanner", "GET /search.php?id=1' UNION SELECT null, username, password FROM users-- HTTP/1.1", {})
    print(f"[Tool 12] Web Attack Scanner -> Verdict: {res12.verdict}, Risk: {res12.risk_score}")
    assert res12.verdict.value in ["SUSPICIOUS", "MALICIOUS", "CRITICAL"]

    # Test Tool 24: Firewall Rule Synthesizer
    res24 = execute_tool("firewall_synthesizer", "203.0.113.55", {})
    print(f"[Tool 24] Firewall Rule Synthesizer -> Commands generated: {len(res24.remediation_playbook)}")
    assert len(res24.remediation_playbook) >= 3

    # Test Tool 35: Secret Leak Scanner
    res35 = execute_tool("secret_leak_scanner", "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", {})
    print(f"[Tool 35] Secret Leak Scanner -> Verdict: {res35.verdict}, Score: {res35.risk_score}")
    assert res35.verdict.value == "CRITICAL"

    # Test Tool 55: Port Risk Catalog
    res55 = execute_tool("port_risk_catalog", "445", {})
    print(f"[Tool 55] Port 445 -> Service: {res55.verdict}, Score: {res55.risk_score}")
    assert res55.risk_score >= 80

    # Test Tool 77: CISA KEV Checker
    res77 = execute_tool("cisa_kev_checker", "CVE-2021-44228", {})
    print(f"[Tool 77] CISA KEV -> Verdict: {res77.verdict}, Score: {res77.risk_score}")
    assert res77.verdict.value == "CRITICAL"

    # Test Cryptographic Hash-Chained Audit Ledger
    entries = get_ledger_entries(10)
    print(f"Total audit ledger entries recorded: {len(entries)}")
    assert len(entries) >= 6

    # Verify chain integrity
    verification = verify_ledger_integrity()
    print(f"Audit Ledger Chain Integrity Valid: {verification.is_valid}, Total: {verification.total_records}, Tampered: {verification.tampered_records}")
    assert verification.is_valid is True
    assert len(verification.tampered_records) == 0

    print("\n>>> ALL BACKEND & CRYPTOGRAPHIC LEDGER TESTS PASSED SUCCESSFULLY! <<<\n")

if __name__ == "__main__":
    run_tests()
