"""
Curated offline datasets for CipherGuard ensuring 100% zero-leak, air-gap operational reliability.
"""

CISA_KEV_CATALOG = [
    {
        "cve_id": "CVE-2021-44228",
        "vendor": "Apache",
        "product": "Log4j2",
        "vulnerability_name": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "date_added": "2021-12-10",
        "short_description": "Apache Log4j2 versions 2.0-beta9 to 2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints.",
        "required_action": "Apply updates per vendor instructions.",
        "cvss": 10.0,
        "mitre_technique": "T1190"
    },
    {
        "cve_id": "CVE-2023-34362",
        "vendor": "Progress Software",
        "product": "MOVEit Transfer",
        "vulnerability_name": "MOVEit Transfer SQL Injection Vulnerability",
        "date_added": "2023-06-02",
        "short_description": "SQL injection vulnerability in MOVEit Transfer web application that could allow an unauthenticated attacker to gain unauthorized access to MOVEit Transfer database.",
        "required_action": "Apply mitigations and patch to supported version.",
        "cvss": 9.8,
        "mitre_technique": "T1190"
    },
    {
        "cve_id": "CVE-2017-0144",
        "vendor": "Microsoft",
        "product": "Windows SMBv1",
        "vulnerability_name": "Windows SMBv1 Remote Code Execution (EternalBlue)",
        "date_added": "2022-02-10",
        "short_description": "Remote code execution vulnerability in Microsoft Server Message Block 1.0 (SMBv1) protocol handling specially crafted packets.",
        "required_action": "Disable SMBv1 and apply MS17-010 patch.",
        "cvss": 9.8,
        "mitre_technique": "T1210"
    },
    {
        "cve_id": "CVE-2023-4966",
        "vendor": "Citrix",
        "product": "NetScaler ADC and NetScaler Gateway",
        "vulnerability_name": "Citrix Bleed Sensitive Information Disclosure",
        "date_added": "2023-10-18",
        "short_description": "Sensitive information disclosure vulnerability in Citrix NetScaler ADC and NetScaler Gateway when configured as a Gateway or AAA virtual server.",
        "required_action": "Apply vendor patches and terminate active sessions.",
        "cvss": 9.4,
        "mitre_technique": "T1190"
    },
    {
        "cve_id": "CVE-2021-34527",
        "vendor": "Microsoft",
        "product": "Windows Print Spooler",
        "vulnerability_name": "Windows Print Spooler Remote Code Execution (PrintNightmare)",
        "date_added": "2021-11-03",
        "short_description": "Remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations.",
        "required_action": "Apply security updates or disable Print Spooler service on domain controllers.",
        "cvss": 8.8,
        "mitre_technique": "T1068"
    },
    {
        "cve_id": "CVE-2024-21887",
        "vendor": "Ivanti",
        "product": "Connect Secure and Policy Secure",
        "vulnerability_name": "Ivanti Connect Secure Command Injection",
        "date_added": "2024-01-11",
        "short_description": "A command injection vulnerability in web components of Ivanti Connect Secure allows an authenticated administrator to execute arbitrary commands.",
        "required_action": "Apply vendor mitigation and factory reset.",
        "cvss": 9.1,
        "mitre_technique": "T1059"
    }
]

MITRE_ATTACK_MATRIX = {
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "subtechniques": ["T1059.001 (PowerShell)", "T1059.003 (Windows Command Shell)", "T1059.004 (Unix Shell)"],
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "mitigations": ["M1042 (Disable or Remove Feature or Program)", "M1038 (Execution Prevention)", "M1026 (Privileged Account Management)"]
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "subtechniques": [],
        "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended behavior.",
        "mitigations": ["M1050 (Exploit Protection)", "M1051 (Update Software)", "M1030 (Network Segmentation)"]
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "subtechniques": ["T1078.001 (Default Accounts)", "T1078.002 (Domain Accounts)", "T1078.003 (Local Accounts)", "T1078.004 (Cloud Accounts)"],
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "mitigations": ["M1032 (Multi-factor Authentication)", "M1027 (Password Policies)", "M1018 (User Account Management)"]
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "subtechniques": ["T1071.001 (Web Protocols: HTTP/S)", "T1071.002 (File Transfer)", "T1071.004 (DNS C2)"],
        "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
        "mitigations": ["M1031 (Network Intrusion Prevention)", "M1037 (Filter Network Traffic)"]
    },
    "T1566": {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "subtechniques": ["T1566.001 (Spearphishing Attachment)", "T1566.002 (Spearphishing Link)", "T1566.003 (Spearphishing via Service)"],
        "description": "Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering targeted at individuals.",
        "mitigations": ["M1054 (Software Configuration)", "M1049 (Antivirus/Antimalware)", "M1017 (User Training)"]
    },
    "T1003": {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "subtechniques": ["T1003.001 (LSASS Memory)", "T1003.002 (Security Account Manager)", "T1003.003 (NTDS.dit)"],
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password.",
        "mitigations": ["M1043 (Credential Access Protection - Credential Guard)", "M1026 (Privileged Account Management)"]
    }
}

PORT_RISK_CATALOG = {
    21: {"service": "FTP", "transport": "TCP", "risk": "HIGH", "notes": "Cleartext authentication; anonymous FTP abuse; legacy exploit target."},
    22: {"service": "SSH", "transport": "TCP", "risk": "MEDIUM", "notes": "Target for brute-force attacks and credential stuffing if exposed to WAN."},
    23: {"service": "Telnet", "transport": "TCP", "risk": "CRITICAL", "notes": "Cleartext credentials and commands; highly vulnerable to packet sniffing and MitM."},
    25: {"service": "SMTP", "transport": "TCP", "risk": "MEDIUM", "notes": "Open relay abuse; spam dispatch; header spoofing."},
    53: {"service": "DNS", "transport": "UDP/TCP", "risk": "MEDIUM", "notes": "DNS tunneling C2; cache poisoning; DNS amplification DDoS."},
    80: {"service": "HTTP", "transport": "TCP", "risk": "MEDIUM", "notes": "Unencrypted web traffic; injection attacks (SQLi, XSS, SSRF)."},
    88: {"service": "Kerberos", "transport": "TCP/UDP", "risk": "HIGH", "notes": "Domain controller target: AS-REP roasting, Kerberoasting, Golden/Silver tickets."},
    135: {"service": "MSRPC", "transport": "TCP", "risk": "HIGH", "notes": "Remote procedure call endpoint; lateral movement target."},
    139: {"service": "NetBIOS", "transport": "TCP", "risk": "HIGH", "notes": "Legacy file sharing; SMB reconnaissance."},
    389: {"service": "LDAP", "transport": "TCP", "risk": "HIGH", "notes": "Active Directory queries; cleartext credentials if not LDAPS (636)."},
    443: {"service": "HTTPS", "transport": "TCP", "risk": "LOW", "notes": "Encrypted web service; inspect certificates and TLS cipher suites."},
    445: {"service": "SMB", "transport": "TCP", "risk": "CRITICAL", "notes": "Worm propagation vector (WannaCry, EternalBlue); lateral movement, credential relaying."},
    1433: {"service": "MS-SQL", "transport": "TCP", "risk": "HIGH", "notes": "Direct database exposure; `xp_cmdshell` execution if compromised."},
    3306: {"service": "MySQL", "transport": "TCP", "risk": "HIGH", "notes": "Database port; should never be exposed to public Internet."},
    3389: {"service": "RDP", "transport": "TCP", "risk": "CRITICAL", "notes": "Remote Desktop; primary initial access vector for ransomware actors (BlueKeep, brute-force)."},
    5985: {"service": "WinRM HTTP", "transport": "TCP", "risk": "HIGH", "notes": "PowerShell remoting lateral movement target."},
    8080: {"service": "HTTP-Proxy/Alt", "transport": "TCP", "risk": "MEDIUM", "notes": "Alternative web port often hosting admin interfaces, Jenkins, or Tomcat."}
}

MAC_OUI_CATALOG = {
    "00:50:56": "VMware, Inc.",
    "00:0C:29": "VMware, Inc.",
    "00:15:5D": "Microsoft Corporation (Hyper-V)",
    "08:00:27": "Oracle Corporation (VirtualBox)",
    "52:54:00": "QEMU / KVM Virtual NIC",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading Ltd",
    "00:1A:11": "Google, Inc.",
    "3C:D9:2B": "Hewlett Packard",
    "00:1E:67": "Intel Corporate",
    "F0:18:98": "Apple, Inc.",
    "AC:DE:48": "Private / Randomized MAC"
}

THREAT_ACTOR_PROFILES = {
    "APT28": {
        "aliases": ["Fancy Bear", "Sofacy", "Sednit", "Strontium"],
        "origin": "Russia (GRU)",
        "motivation": "Espionage, Information Operations",
        "primary_targets": "Government, Military, Defense Contractors, Think Tanks",
        "common_ttps": ["Spearphishing with malicious LNK/DOCX", "OAuth credential phishing", "Zero-day exploitation (CVE-2023-23397)", "X-Agent and Zebrocy malware"],
        "mitre_id": "G0007"
    },
    "APT29": {
        "aliases": ["Cozy Bear", "Nobelium", "Midnight Blizzard", "The Dukes"],
        "origin": "Russia (SVR)",
        "motivation": "High-stealth Intelligence Collection",
        "primary_targets": "Government, Foreign Policy Institutes, Cloud Service Providers",
        "common_ttps": ["Supply chain compromise (SolarWinds SUNBURST)", "Token theft & SAML forgery (Golden SAML)", "Password spraying on cloud tenants", "Residential proxy networks"],
        "mitre_id": "G0016"
    },
    "Lazarus Group": {
        "aliases": ["Hidden Cobra", "Zinc", "Diamond Sleet"],
        "origin": "North Korea (RGB)",
        "motivation": "Financial Theft (Crypto), Destructive Attacks, Cyber Espionage",
        "primary_targets": "Cryptocurrency exchanges, Financial institutions, Aerospace, Defense",
        "common_ttps": ["Trojanized open-source software (npm, GitHub)", "LinkedIn fake recruiter lures", "WannaCry ransomware", "Custom remote access trojans (AppleJeus, Fallchill)"],
        "mitre_id": "G0032"
    },
    "Volt Typhoon": {
        "aliases": ["Bronze Silhouette", "Vanguard Panda"],
        "origin": "China",
        "motivation": "Pre-positioning against Critical Infrastructure",
        "primary_targets": "Communications, Energy, Transportation, Water systems (US & allies)",
        "common_ttps": ["Living off the Land (LotL) - using native Windows binaries", "Compromising SOHO routers for proxying", "Stealthy credential theft (NTDS.dit dumping)", "Avoiding custom malware"],
        "mitre_id": "G1017"
    }
}
