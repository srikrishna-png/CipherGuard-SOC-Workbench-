# CipherGuard: SOC Defensive Operations & Triage Workbench

> A practical, production-grade cybersecurity analysis platform featuring **8 Suites, 80 Operational Tools**, a structured **5-Layer Threat Explanation Engine**, and a **Cryptographic SHA-256 Tamper-Evident Audit Ledger**.

Modeled directly after the **CipherAcademy (`my-crypto-app`)** design language:
- **Theme**: Deep zinc background (`#09090b`), hacker emerald green (`#10b981`), cyber cyan (`#06b6d4`), and crisp zinc borders (`#27272a`).
- **Desktop**: Top navigation with search, sticky collapsible sidebar organizing suites/tools, and split-screen analysis workbench.
- **Mobile**: Responsive layout with a floating glassmorphic bottom navigation dock (`BottomNav`) and slide-out drawer (`MobileSidebar`).
- **Global Command Palette**: `Ctrl+K` / `Cmd+K` keyboard-driven search across all 80 tools, MITRE ATT&CK technique IDs, and artifact extensions.

---

## 8 Analysis Suites & 80 Tools

### Suite 1: Identification & Artifact Analysis (10 Tools)
1. **Deep URL & Phishing Link Analyzer**: IDN homographs, punycode, brand squatting, open redirects.
2. **Email Header & Hop Tracer**: Parses RFC 822/5322 headers, chronological MTA relays, delay points.
3. **SPF / DKIM / DMARC Validator**: Authenticates sender domain policies and flags email spoofing.
4. **Phishing Lure & Psychology Scorer**: Heuristic NLP scoring for urgency, credential lures, financial pretexts.
5. **IOC Extractor**: Regex extraction of IPv4, IPv6, domains, URLs, hashes, and CVE identifiers.
6. **Defanger / Refanger**: Converts active links to safe format (`hxxps[://]...[.]com`) and back.
7. **Static File Hash Calculator**: Computes MD5, SHA-1, SHA-256, and SHA-512 digests.
8. **Shannon Entropy Calculator**: Calculates informational entropy (0.0 to 8.0 bits/byte) to detect packed payloads.
9. **Embedded String Carver**: Extracts ASCII/Unicode strings, flagging suspicious memory injection APIs.
10. **Multi-Layer Obfuscation Decoder**: Recursively decodes Base64, Hex, URL percent-encoding, and ROT13.

### Suite 2: Detection & Telemetry Engine (10 Tools)
11. **Web Access Log Parser**: Ingests and normalizes Nginx, Apache, and IIS access logs into structured fields.
12. **Web Attack Signature Scanner**: Detects SQL injection, Path Traversal (`../`), Command Injection, and XSS patterns in logs.
13. **Brute Force & Burst Detector**: Flags rapid-fire authentication failure bursts (HTTP 401/403) and credential stuffing.
14. **Scanner & Bot Fingerprinter**: Identifies automated recon tools (`sqlmap`, `nikto`, `gobuster`, `nmap`) by signature.
15. **Windows Event Log Analyzer**: Parses Windows Security Event IDs (4624, 4625, 4688, 7045, 1102).
16. **Sigma Rule Evaluator**: Validates and evaluates Sigma YAML rules against incoming log lines.
17. **Statistical Anomaly Detector**: Calculates standard deviation Z-scores on traffic volume, error rates, and unusual endpoints.
18. **User-Agent Anomaly Inspector**: Flags missing, spoofed, empty, or outdated browser fingerprints.
19. **Log Timeline Merger**: Merges heterogeneous logs from multiple sources into a chronological event sequence.
20. **Beaconing & Heartbeat Analyzer**: Detects repetitive, periodic outbound connections characteristic of C2 callbacks.

### Suite 3: Defense, Hardening & Mitigation (10 Tools)
21. **YARA Rule Generator**: Automatically constructs syntax-valid YARA rules from identified strings or byte patterns.
22. **Sigma Rule Synthesizer**: Generates YAML-formatted Sigma detection rules from log query findings.
23. **Suricata / Snort Rule Builder**: Produces network intrusion detection system (NIDS) signatures for detected payloads.
24. **Firewall Rule Synthesizer**: Generates one-click blocking commands for Linux `iptables`, Windows Defender Firewall, and AWS Security Groups.
25. **Web Security Header Auditor**: Evaluates HTTP response headers (`CSP`, `HSTS`, `X-Frame-Options`, `CORS`, `Permissions-Policy`).
26. **Nginx / Apache Hardener**: Generates secure server blocks with rate limiting and disabled methods.
27. **Password Policy & Entropy Validator**: Tests organizational password complexity, dictionary resilience, and zxcvbn strength.
28. **CORS Misconfiguration Checker**: Analyzes Access-Control headers to detect wildcard origins with credentials allowed.
29. **Security.txt Generator**: Generates RFC 9116 compliant `/.well-known/security.txt` vulnerability disclosure files.
30. **CIS Benchmark Checklist**: Generates OS hardening checklists based on CIS benchmark guidelines.

### Suite 4: Encryption & Cryptographic Utilities (10 Tools)
31. **File Integrity Monitor (FIM)**: Creates cryptographic baselines of directories and flags modified, added, or deleted files.
32. **AES-256-GCM Encryptor / Decryptor**: Authenticated symmetric encryption for secure incident evidence storage.
33. **RSA Key Pair & Signature Suite**: Generates 2048/4096-bit key pairs, signs data, and verifies digital signatures.
34. **Crypto Hasher & Speed Benchmark**: High-speed cryptographic hashing (SHA-256, SHA-3, BLAKE2b) with speed benchmarking.
35. **Secret & API Key Leak Scanner**: Scans source code and documents for regex patterns matching AWS, GitHub, Stripe, and private keys.
36. **HMAC Message Authenticator**: Calculates and verifies Hash-based Message Authentication Codes for data integrity.
37. **X.509 Certificate Decoder**: Decodes and inspects X.509 certificates, checking expiration dates, SANs, and issuer chains.
38. **Steganography & Trailing Byte Detector**: Scans image headers and trailing bytes for appended hidden data payloads.
39. **Password Hash Identifier**: Detects hash formats (Bcrypt, Argon2, PBKDF2, NTLM, MD5-crypt).
40. **Diffie-Hellman Key Exchange Visualizer**: Demonstrates cryptographic key agreement math and parameter safety.

### Suite 5: Alerting & Incident Triage (10 Tools)
41. **Alert Prioritization & Severity Scorer**: Calculates CVSS-style priority scores based on asset criticality and threat impact.
42. **Deduplication & Flapping Filter**: Suppresses repeated alerts within a sliding time window to prevent alert fatigue.
43. **Webhook Dispatcher**: Sends formatted alert payloads to Slack, Discord, Microsoft Teams, or custom API endpoints.
44. **Email Alert Dispatcher**: Dispatches SMTP incident notifications with formatted HTML summaries.
45. **MITRE ATT&CK Matrix Tagger**: Automatically tags alerts with ATT&CK Tactics and Technique IDs.
46. **Incident Case Timeline Builder**: Compiles alerts, log snippets, and analyst notes into an interactive chronological timeline.
47. **SOC Runbook & Playbook Selector**: Suggests step-by-step incident response procedures based on alert category.
48. **Evidence Locker & Hash Custody Tracker**: Tracks Chain of Custody for collected digital evidence with tamper-proof checksums.
49. **Executive Incident Report Generator**: Exports complete, professional incident triage reports to Markdown and PDF.
50. **Shift Handover & Briefing Generator**: Generates concise SOC shift-change briefing notes of active and resolved incidents.

### Suite 6: Network & Protocol Analysis (10 Tools)
51. **PCAP Packet Header Inspector**: Extracts IP conversations, packet counts, protocol distribution, and port usage.
52. **DNS Record & Query Inspector**: Diagnoses A, AAAA, MX, TXT, NS, and CAA records, flagging DNS tunneling anomalies.
53. **HTTP/HTTPS Traffic Dissector**: Decodes raw HTTP requests and responses, breaking down headers, cookies, and payloads.
54. **Subnet & CIDR Calculator**: Calculates network ranges, broadcast addresses, usable hosts, and wildcard masks.
55. **Port & Service Risk Catalog**: Searchable catalog of standard and registered TCP/UDP ports with associated security risks.
56. **TCP Flag Analyzer**: Explains SYN, ACK, FIN, RST states and anomalous flag combinations (Xmas, Null, SYN flood).
57. **SSL/TLS Cipher Suite Auditor**: Evaluates server cipher suites, flagging weak protocols (SSLv3, TLS 1.0) and ciphers.
58. **MAC Address OUI Vendor Resolver**: Identifies device hardware manufacturers from MAC OUI prefixes.
59. **Bandwidth & Volumetric Flow Estimator**: Calculates packet-per-second (PPS) and bandwidth rates to model traffic.
60. **Reverse Proxy & Header Forwarding Validator**: Checks `X-Forwarded-For`, `X-Real-IP`, and proxy protocol preservation.

### Suite 7: Digital Forensics & Host Artifacts (10 Tools)
61. **Windows Prefetch File Parser**: Analyzes program execution history, run counts, and timestamps.
62. **ShimCache & Amcache Inspector**: Audits application execution metadata and persistence tracks.
63. **Browser History & Cache Carve**: Extracts visited URLs, download history, and search terms.
64. **USB Device Auditor**: Inspects registry traces of mounted USB storage devices and serial numbers.
65. **Scheduled Tasks & Cron Job Inspector**: Scans configured system tasks for suspicious commands and unusual triggers.
66. **Autorun & Startup Entry Analyzer**: Audits registry run keys and startup folders for unauthorized persistence.
67. **File Metadata & EXIF Data Extractor**: Extracts creation/modification timestamps, author metadata, and camera/GPS tags.
68. **Magic Byte File Identifier**: Identifies true file types by magic byte signatures, flagging extension spoofing.
69. **LNK Shortcut File Parser**: Extracts target paths, drive serial numbers, and machine IDs from `.lnk` files.
70. **Process Tree Anomaly Detector**: Flags suspicious parent-child process pairs (e.g. `winword.exe` spawning `powershell.exe`).

### Suite 8: Threat Intelligence & OSINT (10 Tools)
71. **CVE & NVD Vulnerability Search**: Looks up CVE details, CVSS scores, affected versions, and official patch advisories.
72. **MITRE ATT&CK Navigator**: Interactive navigator for browsing Tactics, Techniques, Sub-techniques, and Mitigations.
73. **ASN & IP Geolocation Resolver**: Resolves autonomous system numbers, BGP routing origins, ISP info, and country.
74. **WHOIS & Domain Age Auditor**: Retrieves domain registration dates, registrar details, and flags Newly Registered Domains (NRDs).
75. **Certificate Transparency Log Search**: Queries CT logs to discover newly issued subdomains and certificates.
76. **Threat Actor & APT Profile Viewer**: Curated encyclopedia of recognized threat groups (APT28, APT29, Lazarus, Volt Typhoon) and typical TTPs.
77. **CISA Known Exploited Vulnerabilities (KEV) Checker**: Cross-references CVEs against the official CISA KEV catalog (offline bundled).
78. **DNS Blacklist (DNSBL) Checker**: Checks IP/domain reputation against public spam and malware DNSBL lists.
79. **Security Advisory Reference Library**: Cross-references vulnerability IDs against known public disclosure advisories.
80. **Threat Intelligence Feed Parser (STIX/TAXII)**: Ingests, normalizes, and filters external threat intelligence bundles.

---

## The 5-Layer Structured Output Engine

Every analysis output renders through a standardized, consistent 5-layer hierarchy:
1. 🛡️ **Executive Verdict & Severity**: Clean, Low, Suspicious, Malicious, or Critical rating with an animated radial 0-100 risk score meter.
2. 🔍 **Technical Evidence Breakdown**: Structured inspection table documenting exact byte matches, RFC flags, entropy scores, or syntax hits.
3. ⚠️ **Threat Impact ("Why It Matters")**: Plain-language explanation of attacker objectives and business risk.
4. 🛠️ **Actionable Remediation Playbook**: Ready-to-execute copy-paste commands (Linux `iptables`, Windows PowerShell, YARA signatures, Nginx configurations).
5. 📚 **Educational Deep Dive & Standards**: Direct citations and hyperlinked references to RFCs, NIST SP 800, OWASP, and MITRE ATT&CK technique IDs.

---

## Cryptographic Tamper-Evident Audit Ledger

- **Database**: Local SQLite database at `backend/data/cyber_suite.db` (zero external configuration required).
- **Hash-Chained Ledger**: Every analysis event generates a SHA-256 hash chaining:
  $$\text{Hash}_n = \text{SHA256}(\text{ID}_n + \text{Timestamp}_n + \text{ToolID}_n + \text{Actor}_n + \text{InputHash}_n + \text{Verdict}_n + \text{RiskScore}_n + \text{Hash}_{n-1})$$
- **Live Integrity Verification**: Built-in **"Verify Audit Log Integrity"** feature that recalculates the entire hash chain on demand to guarantee 100% untampered forensic custody.

---

## Quick Start

### 1. Launch Backend (FastAPI + Python 3.14)
```bash
cd backend
py -3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive Swagger documentation is available at `http://127.0.0.1:8000/docs`.

### 2. Launch Frontend (React + Vite + Tailwind)
```bash
cd frontend
npm run dev
```
Open `http://localhost:5173` in your browser.

### 3. One-Click Launcher (PowerShell)
```powershell
.\start.ps1
```
