import sys
sys.path.append('backend')
from app.suites.suite2_telemetry import run_suite2_tool

tc1 = '192.168.1.50 - - [19/Sep/2026:10:15:32 +0530] "GET /index.html HTTP/1.1" 200 1234'
res1 = run_suite2_tool('access_log_parser', tc1, {})
print('TC1 Clean -> Verdict:', res1.verdict, '| Score:', res1.risk_score)
assert res1.verdict.value == 'CLEAN' and res1.risk_score == 0

tc2 = "45.142.213.88 - - [19/Sep/2026:10:15:32 +0530] \"GET /admin.php?id=1' OR '1'='1 HTTP/1.1\" 500 0"
res2 = run_suite2_tool('access_log_parser', tc2, {})
print('TC2 SQLi -> Verdict:', res2.verdict, '| Score:', res2.risk_score)
print('Summary:', res2.summary)
assert res2.verdict.value == 'SUSPICIOUS' and res2.risk_score >= 80

tc3 = '103.75.201.2 - - [19/Sep/2026:10:15:32 +0530] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 5678'
res3 = run_suite2_tool('access_log_parser', tc3, {})
print('TC3 XSS -> Verdict:', res3.verdict, '| Score:', res3.risk_score)
print('Summary:', res3.summary)
assert res3.verdict.value == 'SUSPICIOUS' and res3.risk_score >= 50

print('\nALL ACCESS LOG PARSER TESTS PASSED 100%!')
