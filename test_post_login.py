import sys
sys.path.append('backend')
from app.suites.suite2_telemetry import run_suite2_tool

line = "POST /login.php HTTP/1.1, Host: bank.com, Body: username=admin'--&password=x, User-Agent: python-requests/2.28.0"
res = run_suite2_tool('access_log_parser', line, {})

print("Verdict:", res.verdict)
print("Risk Score:", res.risk_score)
print("Summary:", res.summary)
print("Payload:\n", res.generated_payload)

assert res.verdict.value == 'SUSPICIOUS', f"Expected SUSPICIOUS, got {res.verdict}"
assert res.risk_score >= 80, f"Expected score >= 80, got {res.risk_score}"
print("\nTEST PASSED 100%!")
