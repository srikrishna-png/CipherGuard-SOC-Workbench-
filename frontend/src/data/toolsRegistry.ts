import { SuiteMetadata } from '../types';

export const SUITES_CATALOG: SuiteMetadata[] = [
  // Suite 1
  {
    id: 'suite1_artifacts',
    name: '1. Identification & Artifact Analysis',
    badge: '10 Tools',
    iconName: 'Search',
    description: 'Inspect URLs, headers, email auth, strings, and entropy.',
    tools: [
      {
        id: 'url_analyzer',
        name: 'Deep URL & Phishing Link Analyzer',
        suiteId: 'suite1_artifacts',
        description: 'Evaluates IDN homographs, punycode, brand squatting, and open redirects.',
        inputPlaceholder: 'Enter target URL to analyze (e.g. http://xn--pypal-4ve.com/login)',
        sampleInputs: [
          { label: 'Punycode PayPal Lure', description: 'IDN homoglyph spoofing PayPal', payload: 'http://xn--pypal-4ve.com/signin/verify-account' },
          { label: 'Subdomain Brand Squat', description: 'Brand keyword in subdomain', payload: 'https://microsoft.online-verification-support.cfd/auth' },
          { label: 'Raw IP Redirection', description: 'Raw IP host with redirect parameter', payload: 'http://185.220.101.5/login.php?redirect=https://legit.com' }
        ]
      },
      {
        id: 'email_header_tracer',
        name: 'Email Header & Hop Tracer',
        suiteId: 'suite1_artifacts',
        description: 'Parses RFC 822/5322 headers, chronological MTA relays, and delay points.',
        inputPlaceholder: 'Paste raw email RFC 822 headers (Received, From, Return-Path, etc.)',
        sampleInputs: [
          { label: 'Spoofed Return-Path', description: 'Discrepancy between From and Return-Path', payload: 'From: "CEO Office" <ceo@corporation.com>\nReturn-Path: <malicious@compromised-relay.net>\nReceived: from relay.badhost.org by mail.target.com with ESMTP;' }
        ]
      },
      {
        id: 'spf_dkim_validator',
        name: 'SPF / DKIM / DMARC Validator',
        suiteId: 'suite1_artifacts',
        description: 'Evaluates sender domain policies and flags email spoofing indicators.',
        inputPlaceholder: 'Paste Authentication-Results header or DNS SPF/DMARC evaluation string',
        sampleInputs: [
          { label: 'DMARC Failure', description: 'Failed SPF & DMARC alignment', payload: 'Authentication-Results: mx.google.com;\n  spf=fail (google.com: domain of evil.com does not designate 198.51.100.1);\n  dkim=fail header.i=@trusted.com;\n  dmarc=fail (p=REJECT sp=REJECT)' }
        ]
      },
      {
        id: 'phishing_lure_scorer',
        name: 'Phishing Lure & Psychology Scorer',
        suiteId: 'suite1_artifacts',
        description: 'NLP heuristic scoring for urgency, credential harvesting forms, and coercion.',
        inputPlaceholder: 'Paste suspicious email body or text lure message',
        sampleInputs: [
          { label: 'Urgent Wire Transfer', description: 'Executive urgency & financial coercion', payload: 'URGENT: Immediate action required! Your account has been suspended due to unauthorized access. Please sign in within 24 hours to verify password and confirm wire transfer or face legal action.' }
        ]
      },
      {
        id: 'ioc_extractor',
        name: 'IOC Extractor',
        suiteId: 'suite1_artifacts',
        description: 'Regex extraction of IPv4, IPv6, domains, URLs, hashes, and CVE identifiers.',
        inputPlaceholder: 'Paste raw threat intel report, notes, or log dump',
        sampleInputs: [
          { label: 'Multi-Indicator Incident Report', description: 'Mixed IPs, hashes, domains, and CVE', payload: 'Adversary connected from 198.51.100.45 and 203.0.113.12 targeting CVE-2021-44228. Dropped backdoor with SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 and contacted c2.threat-actor.org.' }
        ]
      },
      {
        id: 'defanger_refanger',
        name: 'Defanger / Refanger',
        suiteId: 'suite1_artifacts',
        description: 'Converts active URLs to safe non-clickable format (hxxps[://]...[.]com) and back.',
        inputPlaceholder: 'Enter active URL or defanged indicator',
        sampleInputs: [
          { label: 'Active Malicious URL', description: 'Convert to defanged format', payload: 'https://malware-drop.evil-site.com/payload.exe' },
          { label: 'Defanged Indicator', description: 'Refang into active format', payload: 'hxxps[://]c2[.]evil[.]com[:]8443/beacon' }
        ]
      },
      {
        id: 'file_hash_calculator',
        name: 'Static File Hash Calculator',
        suiteId: 'suite1_artifacts',
        description: 'Computes cryptographic digests (MD5, SHA-1, SHA-256, SHA-512).',
        inputPlaceholder: 'Upload any file/binary or paste file hash manifest (e.g. Algorithm: SHA-256, File: notepad.exe, Hash: ...)',
        sampleInputs: [
          { label: '🟢 Notepad (Clean Baseline)', description: 'Known OS binary', payload: 'Algorithm: SHA-256, File: notepad.exe, Hash: 5ed140a8f59a010f7fccf307027e99246dfd1e557a882e5a3c4769e0f0aee5e4' },
          { label: '🔴 Mimikatz (Suspicious Malware)', description: 'Known credential dumping hacktool', payload: 'Algorithm: SHA-256, File: mimikatz.exe, Hash: 84d885875f86357aa77d31b6f3a80e5f0ab30f700a2a6b9d2a8c6e1f3b4d5e6f' },
          { label: '⚠️ Empty File MD5 (Edge Case)', description: '0-byte empty file fingerprint with weak MD5', payload: 'Algorithm: MD5, File: legacy_app.dll, Hash: d41d8cd98f00b204e9800998ecf8427e (weak hash, empty file)' }
        ]
      },
      {
        id: 'entropy_calculator',
        name: 'Shannon Entropy Calculator',
        suiteId: 'suite1_artifacts',
        description: 'Calculates informational entropy (0.0 - 8.0 bits/byte) to detect packed payloads.',
        inputPlaceholder: 'Paste hex or binary-like string to measure randomness',
        sampleInputs: [
          { label: 'Packed High-Entropy Buffer', description: 'Simulated high-entropy ransomware header', payload: '\x9a\xf2\x1c\x8b\x4e\x02\x7d\xaa\xc4\x59\xee\x12\x84\x9f\xbc\xde\x67\x43\x21\x90\xaa\xbb\xcc\xdd\xee\xff\x12\x34\x56\x78\x9a\xbc\xde\xf0\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa' },
          { label: 'Plaintext Low-Entropy Script', description: 'Low entropy repetitive text', payload: 'AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDDEEEEEEEEEE' }
        ]
      },
      {
        id: 'embedded_string_carver',
        name: 'Embedded String Carver',
        suiteId: 'suite1_artifacts',
        description: 'Extracts ASCII/Unicode strings and flags suspicious memory injection APIs.',
        inputPlaceholder: 'Paste raw disassembled binary snippet or memory dump strings',
        sampleInputs: [
          { label: 'Process Injection Imports', description: 'APIs used in DLL injection & hollowing', payload: 'KERNEL32.DLL VirtualAlloc WriteProcessMemory CreateRemoteThread ntdll.dll NtUnmapViewOfSection cmd.exe /c whoami' }
        ]
      },
      {
        id: 'multi_layer_decoder',
        name: 'Multi-Layer Obfuscation Decoder',
        suiteId: 'suite1_artifacts',
        description: 'Recursively unwraps Base64, Hexadecimal, URL percent-encoding, and ROT13.',
        inputPlaceholder: 'Paste nested obfuscated string payload',
        sampleInputs: [
          { label: 'URL + Base64 PowerShell', description: 'Percent-encoded base64 payload', payload: 'cG93ZXJzaGVsbC5leGUgLWMgIklFWCAoTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnYTIucHMxJyki' }
        ]
      }
    ]
  },

  // Suite 2
  {
    id: 'suite2_telemetry',
    name: '2. Detection & Telemetry Engine',
    badge: '10 Tools',
    iconName: 'Activity',
    description: 'Ingest web logs, scan attack signatures, detect bursts, and evaluate Sigma.',
    tools: [
      {
        id: 'access_log_parser',
        name: 'Web Access Log Parser',
        suiteId: 'suite2_telemetry',
        description: 'Ingests and normalizes Apache, Nginx, and IIS combined access logs.',
        inputPlaceholder: 'Paste web access log lines',
        sampleInputs: [
          { label: '🟢 Clean Web Traffic', description: 'Standard benign web access', payload: '192.168.1.50 - - [19/Sep/2026:10:15:32 +0530] "GET /index.html HTTP/1.1" 200 1234' },
          { label: '🔴 SQLi Exploit Probe', description: 'Admin SQL injection trigger resulting in HTTP 500', payload: '45.142.213.88 - - [19/Sep/2026:10:15:32 +0530] "GET /admin.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 500 0' },
          { label: '⚠️ XSS Script Reflection', description: 'Cross-site scripting search query attempt', payload: '103.75.201.2 - - [19/Sep/2026:10:15:32 +0530] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 5678' }
        ]
      },
      {
        id: 'web_attack_scanner',
        name: 'Web Attack Signature Scanner',
        suiteId: 'suite2_telemetry',
        description: 'Scans for SQL injection, Path Traversal, Command Injection, and XSS patterns.',
        inputPlaceholder: 'Paste HTTP requests or server access logs to audit for exploits',
        sampleInputs: [
          { label: 'SQLi & Traversal Injections', description: 'Classic SQL injection and path traversal attempts', payload: '198.51.100.99 - - [18/Sep/2026:12:00:01] "GET /item.php?id=1\' UNION SELECT null, username, password FROM users-- HTTP/1.1" 200 4912\n198.51.100.99 - - [18/Sep/2026:12:00:03] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 200 1820' }
        ]
      },
      {
        id: 'brute_force_detector',
        name: 'Brute Force & Burst Detector',
        suiteId: 'suite2_telemetry',
        description: 'Flags rapid-fire authentication failure bursts (HTTP 401/403) and credential stuffing.',
        inputPlaceholder: 'Paste authentication log stream (SSH, Web, or Active Directory)',
        sampleInputs: [
          { label: 'Rapid Password Spray Burst', description: 'Cluster of 401 Unauthorized responses', payload: '198.51.100.40 - - "POST /api/v1/auth HTTP/1.1" 401 84\n198.51.100.40 - - "POST /api/v1/auth HTTP/1.1" 401 84\n198.51.100.40 - - "POST /api/v1/auth HTTP/1.1" 401 84\n198.51.100.40 - - "POST /api/v1/auth HTTP/1.1" 401 84\n198.51.100.40 - - "POST /api/v1/auth HTTP/1.1" 401 84\n198.51.100.40 - - "POST /api/v1/auth HTTP/1.1" 401 84' }
        ]
      },
      {
        id: 'bot_fingerprinter',
        name: 'Scanner & Bot Fingerprinter',
        suiteId: 'suite2_telemetry',
        description: 'Identifies automated recon scanners (sqlmap, nikto, gobuster, nmap) by signature.',
        inputPlaceholder: 'Paste log lines with User-Agents and query syntax',
        sampleInputs: [
          { label: 'Sqlmap & Gobuster Probe', description: 'Automated vulnerability scanner User-Agents', payload: '198.51.100.12 - - "GET /admin HTTP/1.1" 404 - "gobuster/3.1.0"\n198.51.100.12 - - "GET /vuln.php?id=1 HTTP/1.1" 200 - "sqlmap/1.6#stable"' }
        ]
      },
      {
        id: 'windows_event_analyzer',
        name: 'Windows Event Log Analyzer',
        suiteId: 'suite2_telemetry',
        description: 'Parses Windows Security Event IDs (4624, 4625, 4688, 7045, 1102).',
        inputPlaceholder: 'Paste Windows Event XML or text snippet',
        sampleInputs: [
          { label: 'Event ID 1102 & 7045', description: 'Audit log cleared and persistence service created', payload: 'EventID 1102: The audit log was cleared by Administrator\nEventID 7045: A new service was installed. Service Name: RansomBackup Target: C:\\Windows\\Temp\\svc.exe' }
        ]
      },
      {
        id: 'sigma_evaluator',
        name: 'Sigma Rule Evaluator',
        suiteId: 'suite2_telemetry',
        description: 'Validates and evaluates Sigma YAML rules against telemetry streams.',
        inputPlaceholder: 'Paste Sigma rule YAML block',
        sampleInputs: [
          { label: 'PowerShell Download Cradle Sigma Rule', description: 'Sigma rule targeting WebClient download strings', payload: 'title: Suspicious PowerShell Download Cradle\nid: 2f7c001a-8891-4c12-b912-000000000001\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains:\n      - "Net.WebClient"\n      - "DownloadString"\n  condition: selection\nlevel: high' }
        ]
      },
      {
        id: 'statistical_anomaly',
        name: 'Statistical Anomaly Detector',
        suiteId: 'suite2_telemetry',
        description: 'Calculates standard deviation Z-scores on traffic volume, arrival jitter, and endpoint error rates.',
        inputPlaceholder: 'Paste log stream lines or numeric traffic volume sequence',
        sampleInputs: [
          {
            label: '🟢 Non-Suspicious: Human Browsing',
            description: 'Standard multi-minute intervals, 200 OK responses, normal static pages',
            payload: '192.168.1.50 - - [18/Sep/2026:12:00:01] "GET /index.html HTTP/1.1" 200 5432\n192.168.1.50 - - [18/Sep/2026:12:05:01] "GET /about.html HTTP/1.1" 200 3210\n192.168.1.50 - - [18/Sep/2026:12:10:01] "GET /contact.html HTTP/1.1" 200 2156'
          },
          {
            label: '🔴 Suspicious: Rapid Recon & 404 Burst',
            description: '1 req/sec rapid scanning targeting sensitive paths with 100% 404 errors',
            payload: '45.142.213.88 - - [18/Sep/2026:12:00:01] "GET /admin.php HTTP/1.1" 404 0\n45.142.213.88 - - [18/Sep/2026:12:00:02] "GET /wp-admin HTTP/1.1" 404 0\n45.142.213.88 - - [18/Sep/2026:12:00:03] "GET /phpmyadmin HTTP/1.1" 404 0\n45.142.213.88 - - [18/Sep/2026:12:00:04] "GET /.git/config HTTP/1.1" 404 0\n45.142.213.88 - - [18/Sep/2026:12:00:05] "GET /.env HTTP/1.1" 404 0'
          },
          {
            label: '⚠️ Edge: Zero-Jitter API Polling / Beacon',
            description: 'Zero-jitter 30s periodic intervals on /api/users with uniform byte size',
            payload: '203.0.113.45 - - [18/Sep/2026:12:00:01] "GET /api/users HTTP/1.1" 200 1234\n203.0.113.45 - - [18/Sep/2026:12:00:30] "GET /api/users HTTP/1.1" 200 1234\n203.0.113.45 - - [18/Sep/2026:12:01:00] "GET /api/users HTTP/1.1" 200 1234\n203.0.113.45 - - [18/Sep/2026:12:01:30] "GET /api/users HTTP/1.1" 200 1234'
          },
          {
            label: 'Surge Traffic Sample (Numeric)',
            description: 'High spike numerical batch exceeding normal Gaussian distribution',
            payload: '102, 115, 98, 105, 110, 95, 108, 120, 115, 1420, 1890, 2100'
          }
        ]
      },
      {
        id: 'useragent_inspector',
        name: 'User-Agent Anomaly Inspector',
        suiteId: 'suite2_telemetry',
        description: 'Flags missing, spoofed, empty, or default library HTTP User-Agent fingerprints.',
        inputPlaceholder: 'Paste User-Agent header string',
        sampleInputs: [
          { label: 'Python Scripting Client', description: 'Un-spoofed python-requests client', payload: 'python-requests/2.28.1' },
          { label: 'Curl Command Line Client', description: 'Standard curl client', payload: 'curl/7.88.1' }
        ]
      },
      {
        id: 'log_timeline_merger',
        name: 'Log Timeline Merger',
        suiteId: 'suite2_telemetry',
        description: 'Merges heterogeneous logs from multiple sources into a chronological event sequence.',
        inputPlaceholder: 'Paste multiple timestamped log lines from different servers',
        sampleInputs: [
          { 
            label: 'Cross-Server Event Sequence', 
            description: 'Mixed firewall, web, and SSH log entries out of chronological order', 
            payload: '2026-09-18T14:02:11Z NGINX Accepted 198.51.100.1\n2026-09-18T14:01:45Z FIREWALL DROP 198.51.100.1:22\n2026-09-18T14:02:50Z SSHD Failed password for root from 198.51.100.1' 
          },
          { 
            label: 'Mixed Heterogeneous Log Stream', 
            description: 'ISO 8601, Apache Combined, and BSD Syslog formats interleaved', 
            payload: 'Sep 18 14:05:02 web01 sudo: session opened for user root\n198.51.100.1 - - [18/Sep/2026:14:03:15 +0000] "POST /api/login HTTP/1.1" 200 452\n2026-09-18T14:01:00Z auth01 sshd: Accepted publickey for admin' 
          }
        ]
      },
      {
        id: 'beaconing_analyzer',
        name: 'Beaconing & Heartbeat Analyzer',
        suiteId: 'suite2_telemetry',
        description: 'Detects repetitive periodic connections characteristic of C2 beacon callbacks.',
        inputPlaceholder: 'Paste timestamped connection intervals',
        sampleInputs: [
          {
            label: '🟢 Non-Suspicious: Irregular Browsing',
            description: 'User-driven browsing with irregular intervals and varying response sizes',
            payload: '14:00:00 -> 198.51.100.22:443 (128 bytes)\n14:07:32 -> 198.51.100.22:443 (2048 bytes)\n14:15:18 -> 198.51.100.22:443 (512 bytes)\n14:31:45 -> 198.51.100.22:443 (1024 bytes)'
          },
          {
            label: '🔴 Suspicious: 60s Fixed C2 Beacon',
            description: 'Periodic outbound HTTPS traffic with exact 60s interval and 128 byte uniform payload',
            payload: '14:00:00 -> 198.51.100.22:443 (128 bytes)\n14:01:00 -> 198.51.100.22:443 (128 bytes)\n14:02:00 -> 198.51.100.22:443 (128 bytes)\n14:03:00 -> 198.51.100.22:443 (128 bytes)\n14:04:00 -> 198.51.100.22:443 (128 bytes)\n14:05:00 -> 198.51.100.22:443 (128 bytes)'
          },
          {
            label: '⚠️ Edge: Jittered ~60s Beaconing',
            description: 'Requests every 55-65 seconds randomized with +/-7% jitter to evade threshold detection',
            payload: '14:00:00 -> 198.51.100.22:443 (128 bytes)\n14:00:57 -> 198.51.100.22:443 (128 bytes)\n14:02:03 -> 198.51.100.22:443 (128 bytes)\n14:02:58 -> 198.51.100.22:443 (128 bytes)\n14:04:01 -> 198.51.100.22:443 (128 bytes)'
          }
        ]
      }
    ]
  },

  // Suite 3
  {
    id: 'suite3_defense',
    name: '3. Defense, Hardening & Mitigation',
    badge: '10 Tools',
    iconName: 'ShieldAlert',
    description: 'Synthesize YARA, Sigma, Suricata, iptables, and security headers.',
    tools: [
      {
        id: 'yara_generator',
        name: 'YARA Rule Generator',
        suiteId: 'suite3_defense',
        description: 'Automatically constructs syntax-valid YARA rules from strings, byte patterns, or metadata.',
        inputPlaceholder: 'Paste suspicious strings or command lines to include in rule',
        sampleInputs: [
          { 
            label: 'Mimikatz Credential Dumper Strings', 
            description: 'Generate rule for LSASS memory credential dumper indicators', 
            payload: 'sekurlsa::logonpasswords\nwdigest.dll\nlsass.exe' 
          },
          { 
            label: 'Ransomware Shadow Deletion Commands', 
            description: 'Generate rule targeting volume shadow copy destruction commands', 
            payload: 'vssadmin.exe delete shadows /all /quiet\nwbadmin delete catalog -quiet\nbcdedit /set {default} recoveryenabled No' 
          },
          { 
            label: 'Shellcode Hex Byte Pattern', 
            description: 'Generate rule with raw machine code hex bytes and API symbols', 
            payload: '{ 6A 40 68 00 30 00 00 6A 14 8D 95 }\nVirtualAlloc\nCreateRemoteThread' 
          },
          { 
            label: 'Existing YARA Rule (Audit & Verify)', 
            description: 'Analyze an existing YARA rule for syntax, false-positive risks, and performance', 
            payload: 'rule Suspicious_Rule {\n    meta:\n        author = "Security Team"\n    strings:\n        $s1 = "cmd"\n        $s2 = "net"\n    condition:\n        any of them\n}' 
          }
        ]
      },
      {
        id: 'sigma_synthesizer',
        name: 'Sigma Rule Synthesizer',
        suiteId: 'suite3_defense',
        description: 'Generates YAML-formatted Sigma detection rules from log query findings.',
        inputPlaceholder: 'Enter command line pattern to detect',
        sampleInputs: [
          { label: 'Certutil Base64 Download Rule', description: 'Generate Sigma rule for certutil living-off-the-land', payload: 'certutil.exe -urlcache -split -f http' }
        ]
      },
      {
        id: 'suricata_builder',
        name: 'Suricata / Snort Rule Builder',
        suiteId: 'suite3_defense',
        description: 'Produces NIDS network signatures for detected payloads and URI parameters.',
        inputPlaceholder: 'Enter payload content or URI string',
        sampleInputs: [
          { 
            label: 'Log4Shell JNDI Exploit String', 
            description: 'NIDS rule for Apache Log4j JNDI injection (CVE-2021-44228)', 
            payload: '${jndi:ldap://' 
          },
          { 
            label: 'C2 Domain DNS Query', 
            description: 'NIDS rule for suspicious C2 threat domain resolution', 
            payload: 'dns query c2.evil.com' 
          },
          { 
            label: 'Web Exploit URI Path', 
            description: 'NIDS HTTP buffer rule for administrative backdoor traversal', 
            payload: '/wp-admin/install.php' 
          },
          { 
            label: 'Automated Recon User-Agent', 
            description: 'NIDS HTTP header rule detecting sqlmap scanner client', 
            payload: 'User-Agent: sqlmap/1.6.12#stable' 
          },
          { 
            label: 'Malicious C2 Host Drop', 
            description: 'NIDS perimeter IP drop rule for high-confidence malicious host', 
            payload: '185.234.72.19' 
          },
          { 
            label: 'Existing Rule Audit', 
            description: 'Analyze an existing Suricata rule for flow tracking and performance', 
            payload: 'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 80 (msg:"Custom Rule"; content:"cmd"; sid:1000001; rev:1;)' 
          }
        ]
      },
      {
        id: 'firewall_synthesizer',
        name: 'Firewall Rule Synthesizer',
        suiteId: 'suite3_defense',
        description: 'Generates one-click blocking commands for Linux iptables, Windows Defender, and AWS SGs.',
        inputPlaceholder: 'Enter target malicious IP or CIDR (e.g. 198.51.100.24)',
        sampleInputs: [
          { 
            label: 'Malicious Attacker Host Block', 
            description: 'Generate multi-platform blocking commands for individual threat actor IP', 
            payload: '198.51.100.24' 
          },
          { 
            label: 'Subnet CIDR with Port Scope', 
            description: 'Block entire adversary subnet targeting specific port service', 
            payload: '198.51.100.0/24 port 22 tcp' 
          },
          { 
            label: 'Outbound C2 Egress Containment', 
            description: 'Block host outbound traffic to malicious C2 IP and port', 
            payload: 'outbound 203.0.113.50 port 443' 
          },
          { 
            label: 'Existing Directive Audit', 
            description: 'Audit an existing firewall rule for insecure 0.0.0.0/0 exposure', 
            payload: 'iptables -A INPUT -p tcp --dport 22 -s 0.0.0.0/0 -j ACCEPT' 
          }
        ]
      },
      {
        id: 'security_headers_auditor',
        name: 'Web Security Header Auditor',
        suiteId: 'suite3_defense',
        description: 'Evaluates HTTP response headers (CSP, HSTS, X-Frame-Options, CORS).',
        inputPlaceholder: 'Paste HTTP response headers from target web server',
        sampleInputs: [
          { label: 'Insecure Header Dump', description: 'Headers missing CSP, HSTS, and XFO', payload: 'HTTP/1.1 200 OK\nServer: Apache/2.4.41\nContent-Type: text/html; charset=UTF-8\nConnection: keep-alive' }
        ]
      },
      {
        id: 'server_hardener',
        name: 'Nginx / Apache Hardener',
        suiteId: 'suite3_defense',
        description: 'Generates secure server configuration blocks with rate limiting and disabled methods.',
        inputPlaceholder: 'Enter target domain or web server requirements',
        sampleInputs: [
          { label: 'Production Web App Hardening', description: 'Generate CIS-compliant Nginx server block', payload: 'app.example.com' }
        ]
      },
      {
        id: 'password_validator',
        name: 'Password Policy & Entropy Validator',
        suiteId: 'suite3_defense',
        description: 'Tests organizational password complexity, character diversity, and entropy bits.',
        inputPlaceholder: 'Enter test password to evaluate entropy and dictionary resistance',
        sampleInputs: [
          { label: 'Weak Corporate Password', description: 'Common seasonal password with low entropy', payload: 'Winter2026!' },
          { label: 'High-Entropy Passphrase', description: 'Multi-word randomized passphrase', payload: 'correct-horse-battery-staple-7791' }
        ]
      },
      {
        id: 'cors_checker',
        name: 'CORS Misconfiguration Checker',
        suiteId: 'suite3_defense',
        description: 'Analyzes Access-Control headers to detect wildcard origins with credentials allowed.',
        inputPlaceholder: 'Paste HTTP response CORS headers',
        sampleInputs: [
          { label: 'Critical CORS Misconfiguration', description: 'Wildcard origin paired with allow-credentials', payload: 'Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true' }
        ]
      },
      {
        id: 'security_txt_gen',
        name: 'Security.txt Generator',
        suiteId: 'suite3_defense',
        description: 'Generates RFC 9116 compliant /.well-known/security.txt vulnerability disclosure files.',
        inputPlaceholder: 'Enter company security contact email and policy URL',
        sampleInputs: [
          { label: 'Enterprise Disclosure Policy', description: 'RFC 9116 template with PGP key reference', payload: 'security@mycompany.com' }
        ]
      },
      {
        id: 'cis_checklist_gen',
        name: 'CIS Benchmark Checklist',
        suiteId: 'suite3_defense',
        description: 'Generates OS hardening checklists based on CIS benchmark guidelines.',
        inputPlaceholder: 'Enter target OS (e.g. Ubuntu 22.04 LTS or Windows Server 2022)',
        sampleInputs: [
          { label: 'Ubuntu Linux CIS Benchmark L1', description: 'Hardening checklist for SSH, UFW, and Auditd', payload: 'Ubuntu Linux' }
        ]
      }
    ]
  },

  // Suite 4
  {
    id: 'suite4_crypto',
    name: '4. Encryption & Cryptographic Utilities',
    badge: '10 Tools',
    iconName: 'Lock',
    description: 'FIM integrity monitor, AES-256-GCM, RSA signatures, and leak scanner.',
    tools: [
      {
        id: 'fim_engine',
        name: 'File Integrity Monitor (FIM)',
        suiteId: 'suite4_crypto',
        description: 'Creates cryptographic baselines of directories and flags modified or added files.',
        inputPlaceholder: 'Paste file checksum baseline and current hashes',
        sampleInputs: [
          { label: 'Tampered Binary Alert', description: 'Changed SHA256 checksum on system binary', payload: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /bin/login\na1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0 /bin/login' }
        ]
      },
      {
        id: 'aes_gcm_suite',
        name: 'AES-256-GCM Encryptor / Decryptor',
        suiteId: 'suite4_crypto',
        description: 'Authenticated symmetric encryption for secure incident evidence storage.',
        inputPlaceholder: 'Enter text or evidence data to encrypt with AES-256-GCM',
        sampleInputs: [
          { label: 'Confidential Incident Notes', description: 'Encrypt sensitive forensic report', payload: 'Forensic Report: Extracted root password hash from memory dump.' }
        ]
      },
      {
        id: 'rsa_signature_suite',
        name: 'RSA Key Pair & Signature Suite',
        suiteId: 'suite4_crypto',
        description: 'Generates 2048-bit RSA key pairs, signs data, and verifies digital signatures.',
        inputPlaceholder: 'Enter data to digitally sign with RSA-PSS',
        sampleInputs: [
          { label: 'Evidence Manifest Signature', description: 'Cryptographic non-repudiation signature', payload: 'Chain of Custody Manifest #8912 - Verified by Analyst 01' }
        ]
      },
      {
        id: 'crypto_benchmark',
        name: 'Crypto Hasher & Speed Benchmark',
        suiteId: 'suite4_crypto',
        description: 'High-speed cryptographic hashing (SHA-256, SHA-3, BLAKE2b) with speed benchmarking and algorithm safety audits.',
        inputPlaceholder: 'Enter text, algorithm specification (e.g. Algorithm: SHA-256, Input: "test data"), or "benchmark"',
        sampleInputs: [
          { label: 'SHA-256 Digest (NIST Approved)', description: 'Cryptographically secure 256-bit hash of test data', payload: 'Algorithm: SHA-256, Input: "test data", Output: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08' },
          { label: 'MD5 Hash (Weak / Insecure)', description: 'Flag broken MD5 algorithm used for credentials', payload: 'Algorithm: MD5, Input: password list, Output: 5f4dcc3b5aa765d61d8327deb882cf99 (weak hash for credentials)' },
          { label: 'SHA-1 Digest (Deprecated)', description: 'Flag deprecated SHA-1 certificate signature', payload: 'Algorithm: SHA-1, Input: certificate data, Output: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d (deprecated but still in use)' },
          { label: 'Run Throughput Benchmark', description: 'Compute MB/sec throughput for SHA-256 vs BLAKE2b', payload: 'benchmark' }
        ]
      },
      {
        id: 'secret_leak_scanner',
        name: 'Secret & API Key Leak Scanner',
        suiteId: 'suite4_crypto',
        description: 'Scans source code and documents for AWS, GitHub, Stripe, and private keys.',
        inputPlaceholder: 'Paste code snippet or configuration file to audit for credentials',
        sampleInputs: [
          { label: 'Hardcoded AWS Access Key', description: 'Leaked AWS IAM credentials in script', payload: 'const awsConfig = {\n  accessKeyId: "AKIAIOSFODNN7EXAMPLE",\n  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n};' }
        ]
      },
      {
        id: 'hmac_authenticator',
        name: 'HMAC Message Authenticator',
        suiteId: 'suite4_crypto',
        description: 'Calculates and verifies Hash-based Message Authentication Codes for data integrity.',
        inputPlaceholder: 'Enter message payload to authenticate',
        sampleInputs: [
          { label: 'API Webhook Payload', description: 'Compute HMAC-SHA256 signature tag', payload: 'action=isolate_host&hostname=HOST-01&timestamp=1726671000' }
        ]
      },
      {
        id: 'x509_decoder',
        name: 'X.509 Certificate Decoder',
        suiteId: 'suite4_crypto',
        description: 'Decodes and inspects X.509 certificates, checking expiration dates and SANs.',
        inputPlaceholder: 'Paste PEM certificate (-----BEGIN CERTIFICATE-----)',
        sampleInputs: [
          { label: 'Inspect X.509 Certificate', description: 'Decode certificate hierarchy and validity', payload: '-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIETV... (Paste certificate)\n-----END CERTIFICATE-----' }
        ]
      },
      {
        id: 'stego_detector',
        name: 'Steganography & Trailing Byte Detector',
        suiteId: 'suite4_crypto',
        description: 'Scans image headers and trailing bytes for appended hidden data payloads and polyglots.',
        inputPlaceholder: 'Upload an image file (PNG/JPEG/GIF/BMP) or paste base64 data URL / hex stream',
        sampleInputs: [
          { label: 'Stego PNG (Carved ZIP Payload)', description: 'Image with embedded ZIP archive appended past IEND', payload: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJgglBLAwQUAAAACABzZWNyZXQudHh0X09WRVJMQVlfQllURVNfMTQyODA=' },
          { label: 'Clean PNG (0 Trailing Bytes)', description: 'Sanitized image container ending strictly at EOF', payload: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==' },
          { label: 'Stego PNG (Web Shell)', description: 'Image with embedded PHP web shell appended past EOF', payload: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggjw/cGhwIHN5c3RlbShcWyJjbWQiXSk7ID8+' },
          { label: 'Legacy Hex Stream', description: 'Detect data hidden past IEND marker', payload: '49 45 4E 44 AE 42 60 82 [TRAILING OVERLAY: 14280 BYTES]' }
        ]
      },
      {
        id: 'hash_identifier',
        name: 'Password Hash Identifier',
        suiteId: 'suite4_crypto',
        description: 'Detects hash formats (Bcrypt, Argon2, PBKDF2, NTLM, MD5-crypt).',
        inputPlaceholder: 'Enter hash string to identify algorithm and Hashcat mode',
        sampleInputs: [
          { label: 'Bcrypt Hash', description: 'Key-stretched Blowfish password hash', payload: '$2a$12$e8Mcq8eO/u/K3oVvXf893e4Z4xQ5Zg1v7a8b9c0d1e2f3g4h5i6j7' },
          { label: 'NTLM Digest', description: 'Windows NTLM 32-character hex hash', payload: '31d6cfe0d16ae931b73c59d7e0c089c0' }
        ]
      },
      {
        id: 'diffie_hellman_sim',
        name: 'Diffie-Hellman Key Exchange Visualizer',
        suiteId: 'suite4_crypto',
        description: 'Demonstrates cryptographic key agreement math and parameter safety.',
        inputPlaceholder: 'Click Run to simulate discrete logarithm key exchange',
        sampleInputs: [
          { label: 'Simulate DH Agreement', description: 'Calculate shared secret over public parameters', payload: 'prime=23, generator=5' }
        ]
      }
    ]
  },

  // Suite 5
  {
    id: 'suite5_alerting',
    name: '5. Alerting & Incident Triage',
    badge: '10 Tools',
    iconName: 'Bell',
    description: 'Prioritization scoring, deduplication, webhooks, timelines, and playbooks.',
    tools: [
      {
        id: 'alert_scorer',
        name: 'Alert Prioritization & Severity Scorer',
        suiteId: 'suite5_alerting',
        description: 'Calculates CVSS-style priority scores based on asset criticality and threat impact.',
        inputPlaceholder: 'Enter incident parameters (asset role, threat vector)',
        sampleInputs: [
          { label: 'Domain Controller RCE Alert', description: 'Tier-0 asset with unauthenticated code execution', payload: 'Asset: Production Domain Controller (DC01)\nThreat: Unauthenticated Remote Code Execution\nExposure: Internet-Facing' }
        ]
      },
      {
        id: 'dedup_flapping_filter',
        name: 'Deduplication & Flapping Filter',
        suiteId: 'suite5_alerting',
        description: 'Suppresses repeated alerts within a sliding time window to prevent alert fatigue.',
        inputPlaceholder: 'Paste repeating raw alert stream',
        sampleInputs: [
          { label: 'Flapping Port Scan Alerts', description: '5 duplicate alerts within 60 seconds', payload: 'Alert 1: Port Scan from 198.51.100.22\nAlert 2: Port Scan from 198.51.100.22\nAlert 3: Port Scan from 198.51.100.22\nAlert 4: Port Scan from 198.51.100.22\nAlert 5: Port Scan from 198.51.100.22' }
        ]
      },
      {
        id: 'webhook_dispatcher',
        name: 'Webhook Dispatcher',
        suiteId: 'suite5_alerting',
        description: 'Sends formatted alert payloads to Slack, Discord, Microsoft Teams, or custom APIs.',
        inputPlaceholder: 'Enter incident summary to format as JSON webhook',
        sampleInputs: [
          { label: 'Critical Incident Dispatch', description: 'Slack-formatted alert card', payload: 'INC-2026-9042: Ransomware beacon detected on workstation FIN-04' }
        ]
      },
      {
        id: 'email_dispatcher',
        name: 'Email Alert Dispatcher',
        suiteId: 'suite5_alerting',
        description: 'Dispatches SMTP incident notifications with formatted HTML summaries.',
        inputPlaceholder: 'Enter incident notification text',
        sampleInputs: [
          { label: 'Executive Email Notification', description: 'Synthesize dark-theme HTML escalation email', payload: 'High severity alert: Unauthorized admin credential login from unusual geolocation.' }
        ]
      },
      {
        id: 'mitre_tagger',
        name: 'MITRE ATT&CK Matrix Tagger',
        suiteId: 'suite5_alerting',
        description: 'Automatically tags alerts with ATT&CK Tactics and Technique IDs.',
        inputPlaceholder: 'Paste alert description or observed behavior',
        sampleInputs: [
          { label: 'PowerShell Beacon Execution', description: 'Map execution and C2 tactics', payload: 'Malicious process WINWORD.EXE spawned powershell.exe connecting to external web service.' }
        ]
      },
      {
        id: 'case_timeline_builder',
        name: 'Incident Case Timeline Builder',
        suiteId: 'suite5_alerting',
        description: 'Compiles alerts, log snippets, and analyst notes into an interactive timeline.',
        inputPlaceholder: 'Paste event milestones to organize into a timeline',
        sampleInputs: [
          { 
            label: 'Phishing to Ransomware Timeline', 
            description: 'Chronological progression of rapid enterprise breach', 
            payload: '10:02 - User clicked phishing link\n10:04 - Macro executed powershell payload\n10:15 - Internal port scan initiated\n10:28 - Domain Controller compromised' 
          },
          { 
            label: 'Out-of-Order Multi-Source Telemetry', 
            description: 'Unsorted events from SIEM/EDR/Firewall auto-restructured chronologically', 
            payload: '14:22:10 - Cobalt Strike beacon established to evil.com\n14:05:00 - Malicious attachment invoice.xlsm opened\n14:48:30 - Data exfiltration to Mega.nz over HTTPS\n14:12:45 - Mimikatz lsass credential dump executed\n14:35:00 - Lateral movement via PsExec to DB-01' 
          },
          { 
            label: 'ISO 8601 APT Campaign Reconstruction', 
            description: 'Standardized timestamps tracking persistent adversary intrusion', 
            payload: '2026-09-18T08:15:00Z - Spearphishing email with payload delivered to CFO\n2026-09-18T08:19:30Z - Scheduled task persistence created via schtasks.exe\n2026-09-18T09:45:00Z - Network service discovery sweep across 10.0.0.0/16\n2026-09-18T10:30:15Z - Sensitive customer database archive staged into backup.zip\n2026-09-18T11:00:00Z - Endpoint isolated by SOC incident response team' 
          },
          { 
            label: 'Benign Administrative Workflow', 
            description: 'Authorized baseline IT maintenance activities', 
            payload: '02:00 - Scheduled database backup started\n02:15 - OS security patch update applied\n02:30 - Scheduled server reboot completed\n02:35 - Clean service healthcheck verified' 
          }
        ]
      },
      {
        id: 'runbook_selector',
        name: 'SOC Runbook & Playbook Selector',
        suiteId: 'suite5_alerting',
        description: 'Suggests step-by-step incident response procedures based on alert category.',
        inputPlaceholder: 'Enter incident category (e.g. Ransomware, Phishing, Data Leak)',
        sampleInputs: [
          { label: 'Ransomware Containment Playbook', description: 'Match SOP-IR-04 for active ransomware', payload: 'Ransomware outbreak on internal subnet' }
        ]
      },
      {
        id: 'evidence_locker',
        name: 'Evidence Locker & Hash Custody Tracker',
        suiteId: 'suite5_alerting',
        description: 'Tracks Chain of Custody for collected digital evidence with tamper-proof checksums.',
        inputPlaceholder: 'Enter evidence description or memory dump reference',
        sampleInputs: [
          { label: 'Host Memory Dump Artifact', description: 'Generate cryptographic custody stamp', payload: 'HOST-01-MEMORY-SNAPSHOT-20260918.raw' }
        ]
      },
      {
        id: 'report_generator',
        name: 'Executive Incident Report Generator',
        suiteId: 'suite5_alerting',
        description: 'Exports complete, professional incident triage reports to Markdown and printable formats.',
        inputPlaceholder: 'Enter incident summary notes for executive report generation',
        sampleInputs: [
          { 
            label: 'Web Exploit Breach Contained (Zero Exfil)', 
            description: 'Leadership report on successfully contained external exploit with no data loss', 
            payload: 'Incident INC-8812: External web exploit targeting PROD-WEB-01 contained within 14 minutes by SOC; egress logs confirm 0 customer data leaked. Impacted host isolated.' 
          },
          { 
            label: 'LockBit Ransomware Enterprise Outbreak', 
            description: 'Critical executive escalation detailing host encryption and regulatory impacts', 
            payload: 'INC-2026-9042: LockBit 3.0 ransomware outbreak detected on internal subnet VLAN 10. 12 finance servers (FIN-SRV-01 through 12) encrypted with vssadmin shadow copies deleted. Subnet isolated; air-gapped backups intact.' 
          },
          { 
            label: 'Cloud Customer PII Data Exfiltration', 
            description: 'Board and Legal Counsel briefing on suspected data breach and statutory disclosure', 
            payload: 'CASE-4401: Unauthorized data exfiltration to Mega.nz detected via compromised AWS API keys. 45,000 customer PII records accessed from DB-CUSTOMER-01. Egress rules blocked and credentials revoked.' 
          },
          { 
            label: 'Business Email Compromise (BEC) Fraud Attempt', 
            description: 'Executive briefing on halted executive impersonation and wire diversion', 
            payload: 'INC-2026-7731: Spearphishing email compromised CFO mailbox via credential harvest. Attacker attempted $240,000 fraudulent wire transfer to offshore account. Transaction halted by bank; mailbox sessions revoked.' 
          }
        ]
      },
      {
        id: 'shift_handover_gen',
        name: 'Shift Handover & Briefing Generator',
        suiteId: 'suite5_alerting',
        description: 'Generates concise SOC shift-change briefing notes of active and resolved incidents.',
        inputPlaceholder: 'Enter shift notes or active tickets',
        sampleInputs: [
          { label: 'EMEA to US Shift Handover', description: 'Structure active and watch items for incoming shift', payload: 'Active: INC-8812 memory dump analysis pending. Closed: 14 brute force tickets.' }
        ]
      }
    ]
  },

  // Suite 6
  {
    id: 'suite6_network',
    name: '6. Network & Protocol Analysis',
    badge: '10 Tools',
    iconName: 'Network',
    description: 'PCAP inspection, DNS tunneling, HTTP dissector, CIDR, and TLS auditor.',
    tools: [
      {
        id: 'pcap_inspector',
        name: 'PCAP Packet Header Inspector',
        suiteId: 'suite6_network',
        description: 'Extracts IP conversations, packet counts, protocol distribution, and port usage.',
        inputPlaceholder: 'Paste PCAP summary text or packet stream header',
        sampleInputs: [
          { label: 'SMB Outbound Over WAN', description: 'Inspect packet header conversations', payload: 'Frame 1: 10.0.0.45 -> 198.51.100.22 TCP 49812 > 445 [SYN]' }
        ]
      },
      {
        id: 'dns_inspector',
        name: 'DNS Record & Query Inspector',
        suiteId: 'suite6_network',
        description: 'Diagnoses A, AAAA, MX, TXT records and flags high-entropy DNS tunneling.',
        inputPlaceholder: 'Enter queried domain or suspicious hostname',
        sampleInputs: [
          { label: 'High-Entropy DNS Tunneling Query', description: 'Suspicious DNS query label typical of dnscat2', payload: 'a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4.c2.malicious-domain.org' }
        ]
      },
      {
        id: 'http_dissector',
        name: 'HTTP/HTTPS Traffic Dissector',
        suiteId: 'suite6_network',
        description: 'Decodes raw HTTP requests and responses, breaking down headers and payloads.',
        inputPlaceholder: 'Paste raw HTTP request stream',
        sampleInputs: [
          { label: 'Raw HTTP POST with Auth Token', description: 'Dissect headers, method, and payload', payload: 'POST /api/v1/auth HTTP/1.1\nHost: target.com\nAuthorization: Bearer eyJhbGciOiJIUzI1Ni...\nContent-Type: application/json\n\n{"command":"exec"}' }
        ]
      },
      {
        id: 'subnet_calculator',
        name: 'Subnet & CIDR Calculator',
        suiteId: 'suite6_network',
        description: 'Calculates network ranges, broadcast addresses, usable hosts, and wildcard masks.',
        inputPlaceholder: 'Enter CIDR notation (e.g. 192.168.10.0/24 or 10.0.0.0/16)',
        sampleInputs: [
          { label: 'Labeled Subnet CIDR', description: 'Handles descriptive prefixes like Network:', payload: 'Network: 192.168.10.0/24' },
          { label: 'Standard /24 Subnet', description: 'Compute usable hosts and broadcast', payload: '192.168.1.0/24' },
          { label: 'Corporate /20 VLAN', description: 'Calculate 4,094 host allocation', payload: '10.200.0.0/20' },
          { label: 'Point-to-Point /31 Link', description: 'RFC 3021 router interconnect subnet', payload: '172.16.0.0/31' }
        ]
      },
      {
        id: 'port_risk_catalog',
        name: 'Port & Service Risk Catalog',
        suiteId: 'suite6_network',
        description: 'Searchable catalog of standard and registered TCP/UDP ports with associated risks.',
        inputPlaceholder: 'Enter port number (e.g. 445, 3389, 23, 22)',
        sampleInputs: [
          { label: 'Port 445 (SMB)', description: 'Critical lateral movement and worm port', payload: '445' },
          { label: 'Port 3389 (RDP)', description: 'Remote Desktop Protocol security vector', payload: '3389' },
          { label: 'Port 23 (Telnet)', description: 'Cleartext legacy protocol risk', payload: '23' }
        ]
      },
      {
        id: 'tcp_flag_analyzer',
        name: 'TCP Flag Analyzer',
        suiteId: 'suite6_network',
        description: 'Explains SYN, ACK, FIN, RST states and anomalous flag combinations (Xmas, Null).',
        inputPlaceholder: 'Enter TCP flags (e.g. FIN+URG+PSH or SYN+ACK)',
        sampleInputs: [
          { label: 'Xmas Tree Scan Flags', description: 'Anomalous FIN, URG, PSH combination', payload: 'FIN, URG, PSH' },
          { label: 'Null Scan Flags', description: 'Zero flags set', payload: 'NULL' }
        ]
      },
      {
        id: 'tls_cipher_auditor',
        name: 'SSL/TLS Cipher Suite Auditor',
        suiteId: 'suite6_network',
        description: 'Evaluates server cipher suites, flagging weak protocols (SSLv3, TLS 1.0) and ciphers.',
        inputPlaceholder: 'Enter supported cipher suite names or server SSL audit dump',
        sampleInputs: [
          { label: 'Modern Cipher Configuration', description: 'Verify TLS 1.2 / 1.3 and Perfect Forward Secrecy', payload: 'TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES128-GCM-SHA256' }
        ]
      },
      {
        id: 'mac_oui_resolver',
        name: 'MAC Address OUI Vendor Resolver',
        suiteId: 'suite6_network',
        description: 'Identifies device hardware manufacturers from MAC OUI prefixes.',
        inputPlaceholder: 'Enter MAC address (e.g. 00:50:56:AB:CD:EF)',
        sampleInputs: [
          { label: 'VMware Virtual NIC', description: 'Resolve VMware OUI prefix', payload: '00:50:56:11:22:33' },
          { label: 'Raspberry Pi NIC', description: 'Resolve Raspberry Pi Foundation OUI', payload: 'B8:27:EB:AA:BB:CC' }
        ]
      },
      {
        id: 'bandwidth_estimator',
        name: 'Bandwidth & Volumetric Flow Estimator',
        suiteId: 'suite6_network',
        description: 'Calculates packet-per-second (PPS) and bandwidth rates to model traffic surges.',
        inputPlaceholder: 'Enter flow data or click Run for volumetric DDoS simulation',
        sampleInputs: [
          { label: 'Standard 10k PPS Flow', description: '10,000 PPS with standard 1500-byte MTU frames (120 Mbps)', payload: 'PPS: 10,000 packets/sec\navg_packet_size: 1500 bytes' },
          { label: 'Volumetric Multi-Gigabit Flood', description: 'Model 150k PPS attack flow exceeding Gigabit uplinks', payload: 'PPS=150000, avg_packet_size=1024' },
          { label: 'High-Rate 1 Gbps SYN Flood', description: 'Model 1.95M PPS minimal 64-byte TCP packets', payload: 'bandwidth: 1 Gbps, packet_size: 64' },
          { label: 'DNS Amplification Surge', description: 'Model high-payload amplified reflection stream', payload: 'PPS: 40000, packet_size: 1400 bytes' }
        ]
      },
      {
        id: 'proxy_header_validator',
        name: 'Reverse Proxy & Header Forwarding Validator',
        suiteId: 'suite6_network',
        description: 'Checks X-Forwarded-For, X-Real-IP, and proxy protocol preservation.',
        inputPlaceholder: 'Paste proxy forwarding headers',
        sampleInputs: [
          { label: 'Forwarded Header Chain', description: 'Audit client IP preservation', payload: 'X-Forwarded-For: 203.0.113.195, 10.0.0.1\nX-Real-IP: 203.0.113.195' }
        ]
      }
    ]
  },

  // Suite 7
  {
    id: 'suite7_forensics',
    name: '7. Digital Forensics & Host Artifacts',
    badge: '10 Tools',
    iconName: 'Cpu',
    description: 'Prefetch, ShimCache, browser carving, USB audit, and magic bytes.',
    tools: [
      {
        id: 'prefetch_parser',
        name: 'Windows Prefetch File Parser',
        suiteId: 'suite7_forensics',
        description: 'Analyzes program execution history, run counts, and timestamps from .pf files.',
        inputPlaceholder: 'Enter prefetch file name or execution trace',
        sampleInputs: [
          { label: 'Mimikatz Execution Prefetch', description: 'Proof of malicious binary execution', payload: 'MIMIKATZ.EXE-B8A91234.pf' }
        ]
      },
      {
        id: 'shimcache_inspector',
        name: 'ShimCache & Amcache Inspector',
        suiteId: 'suite7_forensics',
        description: 'Audits application execution metadata and persistence tracks.',
        inputPlaceholder: 'Paste ShimCache or Amcache entry path',
        sampleInputs: [
          { label: 'Public Directory Execution', description: 'Executable run from C:\\Users\\Public', payload: 'C:\\Users\\Public\\Downloads\\backdoor_update.exe' }
        ]
      },
      {
        id: 'browser_carver',
        name: 'Browser History & Cache Carve',
        suiteId: 'suite7_forensics',
        description: 'Extracts visited URLs, download history, and search terms from browser databases.',
        inputPlaceholder: 'Paste browser history record or navigation string',
        sampleInputs: [
          { label: 'Phishing Landing Visit', description: 'Navigation to credential harvest page', payload: 'https://secure-login-update.cfd/auth/verify.php' }
        ]
      },
      {
        id: 'usb_auditor',
        name: 'USB Device Auditor',
        suiteId: 'suite7_forensics',
        description: 'Inspects registry traces of mounted USB storage devices and serial numbers.',
        inputPlaceholder: 'Enter USBSTOR registry key or device serial',
        sampleInputs: [
          { label: 'SanDisk Removable Storage', description: 'Identify unauthorized connected flash drive', payload: 'USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\4C530001230415116032&0' }
        ]
      },
      {
        id: 'task_cron_inspector',
        name: 'Scheduled Tasks & Cron Job Inspector',
        suiteId: 'suite7_forensics',
        description: 'Scans configured system tasks for suspicious commands and unusual triggers.',
        inputPlaceholder: 'Paste scheduled task command or crontab line',
        sampleInputs: [
          { label: 'Hidden PowerShell Cron Persistence', description: 'Hidden window recurrent trigger', payload: 'schtasks /create /sc minute /mo 15 /tn "Updater" /tr "powershell.exe -w hidden -enc JABzAD0..."' }
        ]
      },
      {
        id: 'autorun_analyzer',
        name: 'Autorun & Startup Entry Analyzer',
        suiteId: 'suite7_forensics',
        description: 'Audits registry run keys and startup folders for unauthorized persistence.',
        inputPlaceholder: 'Paste registry Run key entry',
        sampleInputs: [
          { label: 'AppData Run Key Persistence', description: 'Executable masquerading as sync client', payload: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -> "OneDriveSyncHelper"="C:\\Users\\Victim\\AppData\\Roaming\\sync_agent.exe"' }
        ]
      },
      {
        id: 'metadata_exif_extractor',
        name: 'File Metadata & EXIF Data Extractor',
        suiteId: 'suite7_forensics',
        description: 'Extracts creation/modification timestamps, author metadata, and camera/GPS tags.',
        inputPlaceholder: 'Enter metadata fields or document author info',
        sampleInputs: [
          { label: 'Document Author & GPS Tags', description: 'Unstripped author and location coordinates', payload: 'Author: Johnathan Doe\nProducer: Word 2016\nGPS: 38.8977° N, 77.0365° W' }
        ]
      },
      {
        id: 'magic_byte_identifier',
        name: 'Magic Byte File Identifier',
        suiteId: 'suite7_forensics',
        description: 'Identifies true file types by magic byte signatures, flagging extension spoofing.',
        inputPlaceholder: 'Enter hex header or file signature string',
        sampleInputs: [
          { label: 'Spoofed PE Binary Masquerading as PDF', description: 'MZ executable header with .pdf filename', payload: '4D 5A 90 00 (invoice_statement.pdf)' },
          { label: 'Valid ELF Binary Header', description: 'Linux executable 7F 45 4C 46', payload: '7F 45 4C 46 02 01 01 00' }
        ]
      },
      {
        id: 'lnk_parser',
        name: 'LNK Shortcut File Parser',
        suiteId: 'suite7_forensics',
        description: 'Extracts target paths, drive serial numbers, and machine IDs from .lnk files.',
        inputPlaceholder: 'Paste LNK target path and arguments',
        sampleInputs: [
          { label: 'Weaponized LNK Phishing Shortcut', description: 'cmd.exe spawning powershell payload download', payload: 'Target: C:\\Windows\\System32\\cmd.exe /c powershell.exe -w hidden -c "IEX ..."' }
        ]
      },
      {
        id: 'process_tree_detector',
        name: 'Process Tree Anomaly Detector',
        suiteId: 'suite7_forensics',
        description: 'Flags suspicious parent-child process pairs (e.g. winword.exe spawning powershell.exe).',
        inputPlaceholder: 'Paste process tree hierarchy (Parent -> Child)',
        sampleInputs: [
          { label: 'Word Spawning PowerShell', description: 'Weaponized macro document execution hierarchy', payload: 'WINWORD.EXE (PID: 4120) -> POWERSHELL.EXE (PID: 6788) -> WHOAMI.EXE' }
        ]
      }
    ]
  },

  // Suite 8
  {
    id: 'suite8_threatintel',
    name: '8. Threat Intelligence & OSINT',
    badge: '10 Tools',
    iconName: 'Globe',
    description: 'CVE lookups, MITRE navigator, ASN resolver, WHOIS, CISA KEV, and APT profiles.',
    tools: [
      {
        id: 'cve_search',
        name: 'CVE & NVD Vulnerability Search',
        suiteId: 'suite8_threatintel',
        description: 'Looks up CVE details, CVSS scores, affected versions, and official patch advisories.',
        inputPlaceholder: 'Enter CVE identifier (e.g. CVE-2021-44228 or CVE-2023-34362)',
        sampleInputs: [
          { label: 'Log4Shell (CVE-2021-44228)', description: 'Apache Log4j2 JNDI RCE', payload: 'CVE-2021-44228' },
          { label: 'MOVEit SQLi (CVE-2023-34362)', description: 'MOVEit Transfer critical vulnerability', payload: 'CVE-2023-34362' },
          { label: 'EternalBlue (CVE-2017-0144)', description: 'SMBv1 remote code execution exploit', payload: 'CVE-2017-0144' }
        ]
      },
      {
        id: 'mitre_navigator',
        name: 'MITRE ATT&CK Navigator',
        suiteId: 'suite8_threatintel',
        description: 'Interactive navigator for browsing Tactics, Techniques, Sub-techniques, and Mitigations.',
        inputPlaceholder: 'Enter Technique ID (e.g. T1059, T1190, T1078, T1071)',
        sampleInputs: [
          { label: 'T1059: Command & Scripting Interpreter', description: 'Execution tactic details and mitigations', payload: 'T1059' },
          { label: 'T1190: Exploit Public-Facing Application', description: 'Initial access tactic details', payload: 'T1190' },
          { label: 'T1078: Valid Accounts', description: 'Credential abuse technique overview', payload: 'T1078' }
        ]
      },
      {
        id: 'asn_resolver',
        name: 'ASN & IP Geolocation Resolver',
        suiteId: 'suite8_threatintel',
        description: 'Resolves autonomous system numbers, BGP routing origins, ISP info, and country.',
        inputPlaceholder: 'Enter IP address to resolve BGP ASN routing details',
        sampleInputs: [
          { label: 'Cloud Datacenter IP', description: 'Resolve AWS AS16509 prefix', payload: '198.51.100.24' }
        ]
      },
      {
        id: 'whois_auditor',
        name: 'WHOIS & Domain Age Auditor',
        suiteId: 'suite8_threatintel',
        description: 'Retrieves domain registration dates, registrar details, and flags Newly Registered Domains (NRDs).',
        inputPlaceholder: 'Enter domain name to audit age and registrar',
        sampleInputs: [
          { label: 'Suspicious Newly Registered Domain', description: 'Recently registered lookalike domain', payload: 'secure-login-portal-update.cfd' }
        ]
      },
      {
        id: 'ct_log_search',
        name: 'Certificate Transparency Log Search',
        suiteId: 'suite8_threatintel',
        description: 'Queries CT logs to discover newly issued subdomains and certificates.',
        inputPlaceholder: 'Enter target root domain (e.g. example.com)',
        sampleInputs: [
          { label: 'Discover Subdomains via CT', description: 'Search public certificate logs for shadow IT', payload: 'example.com' }
        ]
      },
      {
        id: 'apt_profile_viewer',
        name: 'Threat Actor & APT Profile Viewer',
        suiteId: 'suite8_threatintel',
        description: 'Curated encyclopedia of recognized threat groups (APT28, APT29, Lazarus, Volt Typhoon).',
        inputPlaceholder: 'Enter threat actor name (e.g. APT28, APT29, Lazarus, Volt Typhoon)',
        sampleInputs: [
          { label: 'APT28 (Fancy Bear)', description: 'Russian GRU state-sponsored threat group', payload: 'APT28' },
          { label: 'APT29 (Cozy Bear)', description: 'Russian SVR cyber espionage actor', payload: 'APT29' },
          { label: 'Lazarus Group', description: 'North Korean RGB financial and destructive threat actor', payload: 'Lazarus' },
          { label: 'Volt Typhoon', description: 'China-nexus critical infrastructure pre-positioning', payload: 'Volt Typhoon' }
        ]
      },
      {
        id: 'cisa_kev_checker',
        name: 'CISA Known Exploited Vulnerabilities (KEV) Checker',
        suiteId: 'suite8_threatintel',
        description: 'Cross-references CVEs against the official CISA KEV catalog (offline bundled).',
        inputPlaceholder: 'Enter CVE identifier to check against CISA KEV list',
        sampleInputs: [
          { label: 'Citrix Bleed (CVE-2023-4966)', description: 'Check CISA KEV listing and required action', payload: 'CVE-2023-4966' },
          { label: 'Ivanti Command Injection (CVE-2024-21887)', description: 'Check KEV mandatory remediation status', payload: 'CVE-2024-21887' }
        ]
      },
      {
        id: 'dnsbl_checker',
        name: 'DNS Blacklist (DNSBL) Checker',
        suiteId: 'suite8_threatintel',
        description: 'Checks IP/domain reputation against public spam and malware DNSBL lists.',
        inputPlaceholder: 'Enter IP address to query against reputation blacklists',
        sampleInputs: [
          { label: 'Spamhaus Listed IP', description: 'Check reputation across ZEN and Barracuda lists', payload: '198.51.100.99' }
        ]
      },
      {
        id: 'advisory_library',
        name: 'Security Advisory Reference Library',
        suiteId: 'suite8_threatintel',
        description: 'Cross-references vulnerability IDs against known public disclosure advisories.',
        inputPlaceholder: 'Enter advisory or vulnerability identifier',
        sampleInputs: [
          { label: 'CISA Alert AA23-347A', description: 'Query official government vulnerability alert', payload: 'AA23-347A' }
        ]
      },
      {
        id: 'stix_feed_parser',
        name: 'Threat Intelligence Feed Parser (STIX/TAXII)',
        suiteId: 'suite8_threatintel',
        description: 'Ingests, normalizes, and filters external threat intelligence bundles (STIX 2.1).',
        inputPlaceholder: 'Paste STIX 2.1 JSON bundle',
        sampleInputs: [
          { label: 'Sample STIX 2.1 Indicator Bundle', description: 'Parse machine-readable threat intelligence', payload: '{"type":"bundle","id":"bundle--example","objects":[{"type":"indicator","pattern":"[file:hashes.\'SHA-256\' = \'...\']"}]}' }
        ]
      }
    ]
  }
];

export function findToolById(toolId: string) {
  for (const suite of SUITES_CATALOG) {
    const found = suite.tools.find(t => t.id === toolId);
    if (found) return { tool: found, suite };
  }
  return { tool: SUITES_CATALOG[0].tools[0], suite: SUITES_CATALOG[0] };
}
