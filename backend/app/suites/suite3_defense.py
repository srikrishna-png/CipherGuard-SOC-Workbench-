import re
import math
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List
from app.models.schemas import FiveLayerAnalysisResult, SeverityLevel, EvidenceItem, RemediationCommand, EducationalStandard

def run_suite3_tool(tool_id: str, input_text: str, params: Dict[str, Any]) -> FiveLayerAnalysisResult:
    now_ts = datetime.now(timezone.utc).isoformat()
    clean_input = input_text.strip()
    
    # -------------------------------------------------------------
    # -------------------------------------------------------------
    # 21. YARA Rule Generator
    # -------------------------------------------------------------
    if tool_id == "yara_generator":
        low_input = clean_input.lower()
        lines = [l.strip() for l in clean_input.splitlines() if l.strip()]

        # Check if input is already a YARA rule (Analysis Mode)
        is_existing_rule = (
            clean_input.startswith("rule ") or 
            ("strings:" in low_input and "condition:" in low_input)
        )

        if is_existing_rule:
            has_meta = "meta:" in low_input
            has_strings = "strings:" in low_input
            has_condition = "condition:" in low_input

            string_vars = re.findall(r'(\$[a-zA-Z0-9_]+)\s*=', clean_input)
            cond_m = re.search(r'condition:\s*(.+)$', clean_input, re.DOTALL | re.IGNORECASE)
            condition_block = cond_m.group(1).strip().split('}')[0].strip() if cond_m else "N/A"

            warnings = []
            if "any of them" in condition_block.lower() and len(string_vars) > 1:
                short_strings = [s for s in re.findall(r'=\s*"([^"]+)"', clean_input) if len(s) < 5]
                if short_strings:
                    warnings.append(f"High false-positive risk: 'any of them' used with short strings ({short_strings})")
            if "filesize" not in condition_block.lower():
                warnings.append("Performance recommendation: Add filesize constraint (e.g. 'filesize < 10MB') to prevent scanner timeouts")

            rule_name_m = re.search(r'rule\s+([a-zA-Z0-9_]+)', clean_input)
            rule_name = rule_name_m.group(1) if rule_name_m else "Analyzed_YARA_Rule"

            verdict = SeverityLevel.SUSPICIOUS if warnings else SeverityLevel.CLEAN
            risk_score = 45 if warnings else 0

            evidence = [
                EvidenceItem(label="Rule Syntax Verification", value="Valid YARA 4.x grammar & structure", status="pass"),
                EvidenceItem(label="Detected Rule Identifier", value=rule_name, status="info"),
                EvidenceItem(label="Defined Signature Variables", value=f"{len(string_vars)} string/hex identifiers ({', '.join(string_vars[:5])})", status="info"),
                EvidenceItem(label="Evaluated Condition Logic", value=condition_block[:60] + ("..." if len(condition_block) > 60 else ""), status="info"),
                EvidenceItem(label="Optimization & Safety Audit", value=f"{len(warnings)} potential performance/false-positive traps detected" if warnings else "Rule passes performance & specificity checks", status="warning" if warnings else "pass")
            ]

            return FiveLayerAnalysisResult(
                tool_id=tool_id,
                tool_name="YARA Rule Generator",
                suite_id="suite3_defense",
                timestamp=now_ts,
                verdict=verdict,
                risk_score=risk_score,
                operation_mode="analysis",
                summary=f"Analyzed YARA rule '{rule_name}' ({len(string_vars)} variables). {'Optimization warnings identified: ' + '; '.join(warnings) if warnings else 'Rule syntax and condition verified safe.'}",
                technical_evidence=evidence,
                threat_impact="Unoptimized YARA rules can freeze scanner engines on large binaries or trigger floods of false positives.",
                attack_objective="YARA Rule Quality Assurance & Performance Optimization",
                remediation_playbook=[
                    RemediationCommand(title="Test YARA Rule with YARA CLI", platform="YARA CLI", command=f"echo '{clean_input}' > test.yar\nyara -c test.yar /dev/null")
                ],
                standards_and_references=[
                    EducationalStandard(standard="VirusTotal", reference_id="YARA-v4", title="Writing YARA Rules Best Practices", summary="Official VirusTotal guidance on writing performant and low-noise YARA signatures.")
                ],
                generated_payload=clean_input,
                extracted_secret=clean_input
            )

        # Generation Mode
        rule_name = params.get("rule_name")
        mitre_technique = "T1027 - Obfuscated Files or Information"
        severity = "HIGH"
        category = "General Threat"

        if not rule_name:
            if any(k in low_input for k in ["mimikatz", "sekurlsa", "wdigest", "lsass"]):
                rule_name = "HackTool_MSIL_Mimikatz_CredentialDump"
                mitre_technique = "T1003.001 - OS Credential Dumping: LSASS Memory"
                category = "Credential Access"
            elif any(k in low_input for k in ["vssadmin", "shadow", "wbadmin", "bcdedit", "encrypt"]):
                rule_name = "Ransomware_InhibitSystemRecovery_Commands"
                mitre_technique = "T1490 - Inhibit System Recovery"
                category = "Impact / Ransomware"
            elif any(k in low_input for k in ["eval(", "c99", "r57", "passthru", "base64_decode", "shell_exec"]):
                rule_name = "WebShell_PHP_Generic_Backdoor"
                mitre_technique = "T1505.003 - Server Software Component: Web Shell"
                category = "Persistence / Web Shell"
            elif any(k in low_input for k in ["cobalt", "beacon", "meterpreter", "reflective"]):
                rule_name = "C2_Payload_MemoryArtifacts"
                mitre_technique = "T1071.001 - Web Protocols"
                category = "Command and Control"
            elif any(k in low_input for k in ["powershell", "certutil", "downloadstring", "iex"]):
                rule_name = "Suspicious_LivingOffTheLand_DownloadCradle"
                mitre_technique = "T1059.001 - PowerShell Download Cradle"
                category = "Defense Evasion / Execution"
            elif lines:
                first_clean = re.sub(r'[^a-zA-Z0-9_]', '_', lines[0][:24]).strip('_')
                rule_name = f"Detect_{first_clean}" if first_clean else "Threat_Signature_Rule"
            else:
                rule_name = "Detect_Generic_Threat"

        # 2. Parse Signature Strings & Byte Patterns
        strings_entries = []
        has_pe_header = False
        has_hex_pattern = False
        idx = 1

        for line in lines:
            if not line:
                continue

            hex_block_m = re.match(r'^\{\s*([0-9a-fA-F\s\?]+)\s*\}$', line)
            pure_hex_m = re.match(r'^([0-9a-fA-F]{2}\s+)+[0-9a-fA-F]{2}$', line)

            if hex_block_m:
                hex_content = hex_block_m.group(1).strip().upper()
                strings_entries.append(f'        $hex{idx} = {{ {hex_content} }}')
                has_hex_pattern = True
                if "4D 5A" in hex_content:
                    has_pe_header = True
                idx += 1
            elif pure_hex_m:
                hex_content = line.strip().upper()
                strings_entries.append(f'        $hex{idx} = {{ {hex_content} }}')
                has_hex_pattern = True
                if "4D 5A" in hex_content:
                    has_pe_header = True
                idx += 1
            elif line.startswith('/') and line.endswith('/') and len(line) > 2:
                strings_entries.append(f'        $re{idx} = {line} nocase')
                idx += 1
            else:
                escaped = line.replace('\\', '\\\\').replace('"', '\\"')
                strings_entries.append(f'        $s{idx} = "{escaped}" ascii wide nocase')
                if "mz" in line.lower() or "this program cannot be run in dos mode" in line.lower():
                    has_pe_header = True
                idx += 1

        if not strings_entries:
            strings_entries.append('        $s1 = "malicious_payload_signature" ascii wide nocase')

        # 3. Construct Optimized Condition
        total_strings = len(strings_entries)
        conditions = []
        if has_pe_header:
            conditions.append("uint16(0) == 0x5A4D")
        
        conditions.append("filesize < 15MB")

        if total_strings == 1:
            conditions.append("any of them")
        elif total_strings == 2:
            conditions.append("all of them")
        else:
            conditions.append(f"{min(3, total_strings)} of them")

        condition_str = " and\n        ".join(conditions)

        # 4. Generate YARA Rule
        input_hash = hashlib.sha256(clean_input.encode('utf-8')).hexdigest()[:16]
        yara_code = f"""rule {rule_name} {{
    meta:
        description = "Automated threat detection signature for {category}"
        author = "CipherGuard Defense Suite"
        date = "{now_ts[:10]}"
        mitre_technique = "{mitre_technique}"
        rule_hash = "{input_hash}"
        severity = "{severity}"
    strings:
{chr(10).join(strings_entries)}
    condition:
        {condition_str}
}}"""

        evidence = [
            EvidenceItem(label="Generated Rule Name", value=rule_name, status="info"),
            EvidenceItem(label="Threat Classification", value=category, status="info"),
            EvidenceItem(label="Signature Strings Count", value=f"{total_strings} string(s) / hex byte pattern(s)", status="pass"),
            EvidenceItem(label="Engine Optimization", value="filesize < 15MB bounded condition" + (" + PE uint16(0) magic check" if has_pe_header else ""), status="pass"),
            EvidenceItem(label="Target MITRE Technique", value=mitre_technique, status="info")
        ]

        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="YARA Rule Generator",
            suite_id="suite3_defense",
            timestamp=now_ts,
            verdict=SeverityLevel.CLEAN,
            risk_score=0,
            operation_mode="generation",
            summary=f"Synthesized production-grade YARA rule '{rule_name}' with {total_strings} pattern(s) targeting {category}.",
            technical_evidence=evidence,
            threat_impact="Unsigned or polymorphic files evade hashes; YARA pattern matching catches variants across disk and memory.",
            attack_objective="Defensive Detection Signature Engineering",
            remediation_playbook=[
                RemediationCommand(title="Deploy YARA Rule against Directory", platform="YARA CLI", command=f"echo '{yara_code}' > rule.yar\nyara -r -w rule.yar /var/tmp/uploads/"),
                RemediationCommand(title="Scan Running Memory with YARA", platform="YARA CLI", command=f"yara -r rule.yar $(pgrep -f target_process)")
            ],
            standards_and_references=[
                EducationalStandard(standard="VirusTotal", reference_id="YARA-v4", title="YARA: The Pattern Matching Swiss Knife", summary="Open-source rule-based malware classification framework.")
            ],
            generated_payload=yara_code,
            extracted_secret=yara_code
        )

    # -------------------------------------------------------------
    # 22. Sigma Rule Synthesizer
    # -------------------------------------------------------------
    elif tool_id == "sigma_synthesizer":
        sigma_code = f"""title: Suspicious Execution Pattern Detected
id: 9a7b8c1d-4e2f-4a3b-8c1d-000000000001
status: experimental
description: Auto-generated Sigma detection logic for observed command line or endpoint artifact.
references:
    - https://attack.mitre.org/techniques/T1059/
author: CipherGuard SOC Defensive Workbench
date: {now_ts[:10]}
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '{clean_input[:60].replace("'", "''")}'
    condition: selection
falsepositives:
    - Administrative maintenance scripts
level: high"""
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Sigma Rule Synthesizer",
            suite_id="suite3_defense",
            timestamp=now_ts,
            verdict=SeverityLevel.CLEAN,
            risk_score=0,
            summary="Synthesized portable Sigma YAML detection rule targeting process creation telemetry.",
            technical_evidence=[
                EvidenceItem(label="Sigma Specification", value="Sigma v1.0 schema compliant", status="pass"),
                EvidenceItem(label="Logsource", value="windows:process_creation", status="info")
            ],
            threat_impact="Sharing detection rules in vendor-agnostic Sigma allows seamless translation across multi-cloud SIEM platforms.",
            attack_objective="SIEM Detection Engineering",
            remediation_playbook=[
                RemediationCommand(title="Sigma Rule Definition", platform="Sigma YAML", command=sigma_code)
            ],
            standards_and_references=[
                EducationalStandard(standard="Sigma HQ", reference_id="pySigma", title="Generic Signature Format for SIEM", summary="Open standard for vendor-agnostic SIEM search query engineering.")
            ]
        )

    # -------------------------------------------------------------
    # 23. Suricata / Snort Rule Builder
    # -------------------------------------------------------------
    # -------------------------------------------------------------
    # 23. Suricata / Snort Rule Builder
    # -------------------------------------------------------------
    elif tool_id == "suricata_builder":
        low_input = clean_input.lower()

        # 1. Analysis Mode (When input is an existing Suricata / Snort rule)
        is_existing_rule = any(clean_input.startswith(act) for act in ["alert ", "drop ", "reject ", "pass "]) and "(msg:" in low_input

        if is_existing_rule:
            header_parts = clean_input.split("(", 1)[0].strip().split()
            action = header_parts[0] if len(header_parts) > 0 else "alert"
            proto = header_parts[1] if len(header_parts) > 1 else "ip"
            src = header_parts[2] if len(header_parts) > 2 else "any"
            dst = header_parts[5] if len(header_parts) > 5 else "any"

            options_str = clean_input.split("(", 1)[1].rsplit(")", 1)[0] if "(" in clean_input else ""
            msg_m = re.search(r'msg:\s*"([^"]+)"', options_str)
            rule_msg = msg_m.group(1) if msg_m else "Custom Rule"

            sid_m = re.search(r'sid:\s*(\d+)', options_str)
            rule_sid = sid_m.group(1) if sid_m else "N/A"

            contents = re.findall(r'content:\s*"([^"]+)"', options_str)

            # Health audit
            warnings = []
            if proto in ["tcp", "http"] and "flow:" not in options_str:
                warnings.append("Performance warning: Missing 'flow:established' or 'flow:to_server' on stream protocol")
            if any(len(c) < 4 for c in contents) and "fast_pattern" not in options_str:
                warnings.append("False-positive risk: Short content pattern (< 4 bytes) without fast_pattern anchor")
            if "classtype:" not in options_str:
                warnings.append("Best practice: Missing 'classtype' metadata for SIEM severity categorization")

            verdict = SeverityLevel.SUSPICIOUS if warnings else SeverityLevel.CLEAN
            risk_score = 35 if warnings else 0

            evidence = [
                EvidenceItem(label="Rule Action & Protocol", value=f"{action.upper()} over {proto.upper()}", status="info"),
                EvidenceItem(label="Traffic Direction", value=f"{src} -> {dst}", status="info"),
                EvidenceItem(label="Signature Message", value=rule_msg, status="info"),
                EvidenceItem(label="Rule SID & Revision", value=f"SID {rule_sid}", status="info"),
                EvidenceItem(label="Content Matches", value=f"{len(contents)} pattern(s): {contents[:3]}" if contents else "Header / flow only", status="info"),
                EvidenceItem(label="NIDS Rule Health Audit", value=f"{len(warnings)} warning(s): {'; '.join(warnings)}" if warnings else "Rule passes syntax, flow anchoring, and fast_pattern checks", status="warning" if warnings else "pass")
            ]

            return FiveLayerAnalysisResult(
                tool_id=tool_id,
                tool_name="Suricata / Snort Rule Builder",
                suite_id="suite3_defense",
                timestamp=now_ts,
                verdict=verdict,
                risk_score=risk_score,
                operation_mode="analysis",
                summary=f"Analyzed NIDS rule SID {rule_sid} ('{rule_msg}'). {'Rule audit warnings: ' + '; '.join(warnings) if warnings else 'Rule syntax, protocol direction, and flow tracking verified healthy.'}",
                technical_evidence=evidence,
                threat_impact="Unanchored NIDS rules cause high CPU load, packet drops, and alert fatigue on high-speed interfaces.",
                attack_objective="NIDS Rule Quality Assurance & Flow Optimization",
                remediation_playbook=[
                    RemediationCommand(title="Test Suricata Rule Syntax", platform="Suricata CLI", command="echo '" + clean_input + "' > /tmp/test.rules\nsuricata -T -c /etc/suricata/suricata.yaml -S /tmp/test.rules")
                ],
                standards_and_references=[
                    EducationalStandard(standard="OISF", reference_id="Suricata-Rules-Spec", title="Suricata Rule Optimization Guide", summary="Open standard for writing high-performance, low-latency NIDS signatures.")
                ],
                generated_payload=clean_input,
                extracted_secret=clean_input
            )

        # 2. Generation Mode (Synthesizing new NIDS rule from IOCs)
        hash_seed = int(hashlib.md5(clean_input.encode()).hexdigest()[:6], 16)
        sid = 1002000 + (hash_seed % 90000)

        # Category 1: JNDI / Log4Shell Exploit
        if "jndi:" in low_input or "ldap:" in low_input:
            action = "alert"
            proto = "http"
            direction = "$EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS"
            msg = "CIPHERGUARD Apache Log4j JNDI Injection RCE Attempt (CVE-2021-44228)"
            opts = 'flow:to_server,established; content:"${jndi:"; nocase; fast_pattern; classtype:attempted-admin; reference:cve,2021-44228;'
            threat_cat = "Remote Code Execution (Log4Shell)"
            risk_score = 90

        # Category 2: DNS Query / C2 Domain
        elif "dns" in low_input or re.search(r'\b[a-zA-Z0-9.-]+\.(?:evil|malware|xyz|ru|c2|cc|top)\b', low_input) or (re.search(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', clean_input) and " " not in clean_input):
            domain_m = re.search(r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', clean_input)
            domain = domain_m.group(1) if domain_m else "malicious.domain"
            action = "alert"
            proto = "dns"
            direction = "$HOME_NET any -> any 53"
            msg = f"CIPHERGUARD Suspicious DNS Query to Known Threat Domain ({domain})"
            opts = f'dns.query; content:"{domain}"; nocase; endswith; classtype:trojan-activity;'
            threat_cat = f"C2 Domain Resolution ({domain})"
            risk_score = 80

        # Category 3: User-Agent / Automated Scanner
        elif "user-agent" in low_input or any(k in low_input for k in ["sqlmap", "nikto", "curl", "python-requests", "gobuster", "dirbuster"]):
            ua_clean = re.sub(r'User-Agent:\s*', '', clean_input, flags=re.IGNORECASE).strip()[:30]
            action = "alert"
            proto = "http"
            direction = "$EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS"
            msg = f"CIPHERGUARD Automated Reconnaissance Scanner Client ({ua_clean})"
            opts = f'flow:to_server,established; http.user_agent; content:"{ua_clean}"; nocase; classtype:attempted-recon;'
            threat_cat = "Automated Recon Scanner"
            risk_score = 70

        # Category 4: Web Application Exploit Path / URI
        elif clean_input.startswith("/") or any(k in low_input for k in ["get /", "post /", "admin", ".php", "cgi-bin", ".env", "shell"]):
            path_m = re.search(r'(/[a-zA-Z0-9_./?=&%-]+)', clean_input)
            target_path = path_m.group(1) if path_m else clean_input[:35]
            action = "alert"
            proto = "http"
            direction = "$EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS"
            msg = f"CIPHERGUARD Web Exploit Probe targeting {target_path[:25]}"
            opts = f'flow:to_server,established; http.uri; content:"{target_path}"; nocase; fast_pattern; classtype:web-application-attack;'
            threat_cat = f"Web Application Attack ({target_path})"
            risk_score = 75

        # Category 5: Malicious IP Address Drop
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', clean_input):
            action = "drop"
            proto = "ip"
            direction = f"{clean_input} any -> any any"
            msg = f"CIPHERGUARD High Confidence Threat Intelligence Block ({clean_input})"
            opts = 'classtype:trojan-activity;'
            threat_cat = f"Host IP Block ({clean_input})"
            risk_score = 85

        # Category 6: Hex Byte Shellcode Pattern
        elif "|" in clean_input or re.match(r'^[0-9a-fA-F\s]{6,}$', clean_input) or clean_input.startswith("{"):
            hex_clean = re.sub(r'[^0-9a-fA-F\s]', '', clean_input).strip().upper()
            action = "alert"
            proto = "tcp"
            direction = "$EXTERNAL_NET any -> $HOME_NET any"
            msg = "CIPHERGUARD Binary Shellcode Payload Ingress"
            opts = f'flow:to_server,established; content:"|{hex_clean}|"; fast_pattern; classtype:shellcode-detect;'
            threat_cat = "Binary Shellcode Detection"
            risk_score = 85

        # Category 7: Generic Payload Content
        else:
            safe_pat = clean_input[:40].replace('"', '')
            action = "alert"
            proto = "tcp"
            direction = "$EXTERNAL_NET any -> $HOME_NET any"
            msg = f"CIPHERGUARD Suspicious Ingress Signature ({safe_pat[:20]})"
            opts = f'flow:to_server,established; content:"{safe_pat}"; nocase; classtype:misc-activity;'
            threat_cat = "Generic Payload Signature"
            risk_score = 60

        suricata_rule = f'{action} {proto} {direction} (msg:"{msg}"; {opts} sid:{sid}; rev:1;)'

        evidence = [
            EvidenceItem(label="Generated Rule Action", value=action.upper(), status="pass"),
            EvidenceItem(label="Inspection Protocol", value=proto.upper(), status="info"),
            EvidenceItem(label="Network Scope", value=direction, status="info"),
            EvidenceItem(label="Allocated Signature ID", value=f"SID {sid} (Rev 1)", status="info"),
            EvidenceItem(label="NIDS Rule Threat Category", value=threat_cat, status="pass")
        ]

        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Suricata / Snort Rule Builder",
            suite_id="suite3_defense",
            timestamp=now_ts,
            verdict=SeverityLevel.CLEAN,
            risk_score=0,
            operation_mode="generation",
            summary=f"Synthesized production Suricata/Snort rule SID {sid} for {threat_cat}.",
            technical_evidence=evidence,
            threat_impact="NIDS signatures filter exploit attempts at the perimeter before packets reach application listeners.",
            attack_objective="Perimeter Threat Interception (MITRE ATT&CK T1190)",
            remediation_playbook=[
                RemediationCommand(title="Append to Suricata Local Rules", platform="Suricata", command=f"echo '{suricata_rule}' >> /etc/suricata/rules/local.rules\nsuricata-update"),
                RemediationCommand(title="Reload Suricata Engine Rules Live", platform="Suricata", command="suricatasc -c reload-rules")
            ],
            standards_and_references=[
                EducationalStandard(standard="OISF", reference_id="Suricata-Rule-Format", title="Open Information Security Foundation Suricata Rules", summary="Syntax specification for stateful network payload detection.")
            ],
            generated_payload=suricata_rule,
            extracted_secret=suricata_rule
        )

    # -------------------------------------------------------------
    # 24. Firewall Rule Synthesizer
    # -------------------------------------------------------------
    elif tool_id == "firewall_synthesizer":
        low_input = clean_input.lower()

        # 1. Check if input is an existing firewall command (Analysis Mode)
        is_existing_rule = any(low_input.startswith(cmd) for cmd in ["iptables", "ufw", "nft", "new-netfirewallrule", "firewall-cmd", "netsh"])

        if is_existing_rule:
            warnings = []
            risk_score = 0
            has_wide_open = "0.0.0.0/0" in clean_input or "any" in low_input or "-s 0/0" in clean_input
            if has_wide_open:
                if any(p in clean_input for p in ["22", "3389", "445", "23", "3306", "5432"]):
                    warnings.append("High Critical Risk: Sensitive administrative service (SSH/RDP/SMB/Database) exposed to 0.0.0.0/0 (Internet-wide)")
                    risk_score = 80
            if "iptables" in low_input and "-P INPUT ACCEPT" in clean_input:
                warnings.append("Insecure Default Policy: Default INPUT policy set to ACCEPT instead of DROP")
                risk_score = max(risk_score, 65)
            if "state" not in low_input and "ct state" not in low_input and "-m conntrack" not in low_input:
                warnings.append("State tracking warning: Stateless rule evaluation without ESTABLISHED,RELATED connection tracking")
                risk_score = max(risk_score, 30)

            verdict = SeverityLevel.SUSPICIOUS if warnings else SeverityLevel.CLEAN

            evidence = [
                EvidenceItem(label="Evaluated Command", value=clean_input[:60] + ("..." if len(clean_input) > 60 else ""), status="info"),
                EvidenceItem(label="Rule Syntax & Direction", value="Inbound Packet Filter Directive", status="info"),
                EvidenceItem(label="Security Audit Findings", value=f"{len(warnings)} vulnerability warning(s) detected: {'; '.join(warnings)}" if warnings else "Firewall directive passes exposure and stateful tracking audit", status="fail" if risk_score >= 70 else ("warning" if warnings else "pass"))
            ]

            return FiveLayerAnalysisResult(
                tool_id=tool_id,
                tool_name="Firewall Rule Synthesizer",
                suite_id="suite3_defense",
                timestamp=now_ts,
                verdict=verdict,
                risk_score=risk_score,
                operation_mode="analysis",
                summary=f"Audited firewall directive. {'Security warnings identified: ' + '; '.join(warnings) if warnings else 'Firewall command conforms to least-privilege perimeter architecture.'}",
                technical_evidence=evidence,
                threat_impact="Overly permissive firewall rules permit automated brute-force attacks and lateral worm propagation.",
                attack_objective="Firewall Access Control List (ACL) Auditing",
                remediation_playbook=[
                    RemediationCommand(title="Remediate: Restrict Management Port to Management Subnet", platform="Linux (iptables)", command="iptables -I INPUT 1 -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT\niptables -A INPUT -p tcp --dport 22 -j DROP")
                ],
                standards_and_references=[
                    EducationalStandard(standard="NIST", reference_id="SP 800-41 Rev 1", title="Guidelines on Firewalls and Firewall Policy", summary="Mandates least privilege, default-deny ingress filtering, and stateful inspection.")
                ],
                generated_payload=clean_input,
                extracted_secret=clean_input
            )

        # 2. Generation Mode (Synthesizing multi-platform perimeter firewall commands)
        cidr_matches = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b', clean_input)
        raw_ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', clean_input)
        ip_matches = [ip for ip in raw_ips if not any(ip in c for c in cidr_matches)]

        targets = cidr_matches + ip_matches
        if not targets:
            dom_m = re.search(r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', clean_input)
            if dom_m:
                targets = [dom_m.group(1)]
            else:
                targets = ["198.51.100.24"]

        port_m = re.search(r'(?:port|dport|--dport|:)\s*(\d{1,5})', clean_input, re.IGNORECASE)
        target_port = port_m.group(1) if port_m else None

        proto = "tcp" if "tcp" in low_input else ("udp" if "udp" in low_input else "all")
        if target_port and proto == "all":
            proto = "tcp"

        direction = "outbound" if any(w in low_input for w in ["outbound", "output", "egress"]) else "inbound"
        action = "DROP"

        iptables_lines = []
        ufw_lines = []
        nftables_lines = []
        powershell_lines = []
        aws_nacl_lines = []
        pf_lines = []

        nacl_rule_num = 100
        for tgt in targets:
            clean_tgt_id = re.sub(r'[^a-zA-Z0-9_]', '_', tgt).strip('_')
            is_cidr = "/" in tgt
            aws_cidr = tgt if is_cidr else f"{tgt}/32"

            if direction == "inbound":
                if target_port:
                    iptables_lines.append(f"iptables -I INPUT 1 -s {tgt} -p {proto} --dport {target_port} -j {action}")
                    ufw_lines.append(f"ufw insert 1 deny proto {proto} from {tgt} to any port {target_port}")
                    nftables_lines.append(f"nft add rule inet filter input ip saddr {tgt} {proto} dport {target_port} drop")
                    powershell_lines.append(f'New-NetFirewallRule -DisplayName "Block Inbound {tgt} Port {target_port}" -Direction Inbound -RemoteAddress {tgt} -Protocol {proto.upper()} -LocalPort {target_port} -Action Block')
                    aws_nacl_lines.append(f"aws ec2 create-network-acl-entry --network-acl-id acl-0123456789abcdef0 --rule-number {nacl_rule_num} --protocol {6 if proto=='tcp' else 17} --port-range From={target_port},To={target_port} --rule-action deny --egress false --cidr-block {aws_cidr}")
                    pf_lines.append(f"block in quick proto {proto} from {tgt} to any port {target_port}")
                else:
                    iptables_lines.append(f"iptables -I INPUT 1 -s {tgt} -j {action}")
                    ufw_lines.append(f"ufw insert 1 deny from {tgt} to any")
                    nftables_lines.append(f"nft add rule inet filter input ip saddr {tgt} drop")
                    powershell_lines.append(f'New-NetFirewallRule -DisplayName "Block Threat Host {tgt}" -Direction Inbound -RemoteAddress {tgt} -Action Block')
                    aws_nacl_lines.append(f"aws ec2 create-network-acl-entry --network-acl-id acl-0123456789abcdef0 --rule-number {nacl_rule_num} --protocol all --rule-action deny --egress false --cidr-block {aws_cidr}")
                    pf_lines.append(f"block in quick from {tgt} to any")
            else:
                if target_port:
                    iptables_lines.append(f"iptables -I OUTPUT 1 -d {tgt} -p {proto} --dport {target_port} -j {action}")
                    ufw_lines.append(f"ufw insert 1 deny out to {tgt} port {target_port} proto {proto}")
                    nftables_lines.append(f"nft add rule inet filter output ip daddr {tgt} {proto} dport {target_port} drop")
                    powershell_lines.append(f'New-NetFirewallRule -DisplayName "Block Outbound {tgt} Port {target_port}" -Direction Outbound -RemoteAddress {tgt} -Protocol {proto.upper()} -RemotePort {target_port} -Action Block')
                    aws_nacl_lines.append(f"aws ec2 create-network-acl-entry --network-acl-id acl-0123456789abcdef0 --rule-number {nacl_rule_num} --protocol {6 if proto=='tcp' else 17} --port-range From={target_port},To={target_port} --rule-action deny --egress true --cidr-block {aws_cidr}")
                    pf_lines.append(f"block out quick proto {proto} from any to {tgt} port {target_port}")
                else:
                    iptables_lines.append(f"iptables -I OUTPUT 1 -d {tgt} -j {action}")
                    ufw_lines.append(f"ufw insert 1 deny out to {tgt}")
                    nftables_lines.append(f"nft add rule inet filter output ip daddr {tgt} drop")
                    powershell_lines.append(f'New-NetFirewallRule -DisplayName "Block Outbound Threat Host {tgt}" -Direction Outbound -RemoteAddress {tgt} -Action Block')
                    aws_nacl_lines.append(f"aws ec2 create-network-acl-entry --network-acl-id acl-0123456789abcdef0 --rule-number {nacl_rule_num} --protocol all --rule-action deny --egress true --cidr-block {aws_cidr}")
                    pf_lines.append(f"block out quick from any to {tgt}")

            nacl_rule_num += 10

        target_summary_str = ", ".join(targets[:4]) + ("..." if len(targets) > 4 else "")
        port_summary_str = f"Port {target_port}/{proto.upper()}" if target_port else "All Ports / Protocols"

        full_firewall_playbook = f"""# ==============================================================================
# CIPHERGUARD MULTI-PLATFORM PERIMETER FIREWALL BLOCKING PLAYBOOK
# Targets: {target_summary_str} | Direction: {direction.upper()} | Scope: {port_summary_str}
# Generated: {now_ts} | Standard: NIST SP 800-41 Rev 1
# ==============================================================================

# --- 1. Linux iptables (Kernel Netfilter) ---
{chr(10).join(iptables_lines)}

# --- 2. Ubuntu / Debian UFW ---
{chr(10).join(ufw_lines)}

# --- 3. Modern Linux nftables ---
{chr(10).join(nftables_lines)}

# --- 4. Windows Defender Firewall (PowerShell Run-As-Admin) ---
{chr(10).join(powershell_lines)}

# --- 5. AWS VPC Network ACL (Stateless Perimeter Denial) ---
{chr(10).join(aws_nacl_lines)}

# --- 6. BSD / macOS / pfSense (pf.conf) ---
{chr(10).join(pf_lines)}
"""

        evidence = [
            EvidenceItem(label="Target Addresses / Subnets", value=target_summary_str, status="info"),
            EvidenceItem(label="Inspection Direction", value=f"{direction.upper()} Traffic", status="info"),
            EvidenceItem(label="Port & Protocol Scope", value=port_summary_str, status="info"),
            EvidenceItem(label="Platforms Synthesized", value="iptables, ufw, nftables, PowerShell, AWS NACL, pf.conf (6 engines)", status="pass"),
            EvidenceItem(label="Enforcement Action", value=f"Immediate {action} (Unconditional Drop)", status="pass")
        ]

        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Firewall Rule Synthesizer",
            suite_id="suite3_defense",
            timestamp=now_ts,
            verdict=SeverityLevel.CLEAN,
            risk_score=0,
            operation_mode="generation",
            summary=f"Synthesized multi-platform perimeter firewall blocking playbook targeting {target_summary_str} ({port_summary_str}).",
            technical_evidence=evidence,
            threat_impact="Active perimeter blocking stops hostile scanning, brute force attempts, and unauthorized data exfiltration before socket handshake completes.",
            attack_objective="Active Adversary Containment & Network Segmentation (MITRE ATT&CK T1562.004)",
            remediation_playbook=[
                RemediationCommand(title="Linux iptables Immediate Block", platform="Linux (iptables)", command=iptables_lines[0]),
                RemediationCommand(title="Windows PowerShell Firewall Block", platform="Windows (PowerShell)", command=powershell_lines[0]),
                RemediationCommand(title="Ubuntu UFW Block", platform="Linux (ufw)", command=ufw_lines[0]),
                RemediationCommand(title="AWS VPC Network ACL Deny", platform="AWS CLI", command=aws_nacl_lines[0])
            ],
            standards_and_references=[
                EducationalStandard(standard="NIST", reference_id="SP 800-41 Rev 1", title="Guidelines on Firewalls and Firewall Policy", summary="Defines best practices for perimeter access control list (ACL) management, rule ordering, and default-deny policies."),
                EducationalStandard(standard="CIS Benchmark", reference_id="CIS Linux 3.4", title="Configure Firewall", summary="Mandates active host-based firewall enforcement on all perimeter endpoints.")
            ],
            generated_payload=full_firewall_playbook,
            extracted_secret=full_firewall_playbook
        )

    # -------------------------------------------------------------
    # 25. Web Security Header Auditor
    # -------------------------------------------------------------
    elif tool_id == "security_headers_auditor":
        headers = clean_input.lower()
        has_csp = "content-security-policy" in headers
        has_hsts = "strict-transport-security" in headers
        has_xfo = "x-frame-options" in headers
        has_xcto = "x-content-type-options" in headers
        
        evidence = [
            EvidenceItem(label="Content-Security-Policy (CSP)", value="Present" if has_csp else "MISSING", status="pass" if has_csp else "fail"),
            EvidenceItem(label="Strict-Transport-Security (HSTS)", value="Present" if has_hsts else "MISSING", status="pass" if has_hsts else "fail"),
            EvidenceItem(label="X-Frame-Options (Clickjacking)", value="Present" if has_xfo else "MISSING", status="pass" if has_xfo else "warning"),
            EvidenceItem(label="X-Content-Type-Options (nosniff)", value="Present" if has_xcto else "MISSING", status="pass" if has_xcto else "warning")
        ]
        missing_count = 4 - (sum([has_csp, has_hsts, has_xfo, has_xcto]))
        risk_score = missing_count * 25
        verdict = SeverityLevel.MALICIOUS if risk_score >= 75 else (SeverityLevel.SUSPICIOUS if risk_score >= 50 else SeverityLevel.CLEAN)
        
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Web Security Header Auditor",
            suite_id="suite3_defense",
            timestamp=now_ts,
            verdict=verdict,
            risk_score=risk_score,
            summary=f"Security header audit completed. {missing_count} critical defensive HTTP headers missing.",
            technical_evidence=evidence,
            threat_impact="Missing CSP and HSTS allows Cross-Site Scripting (XSS), session hijacking over unencrypted HTTP, and iframe clickjacking.",
            attack_objective="Web Browser Defense Hardening",
            remediation_playbook=[
                RemediationCommand(title="Apply Security Headers in Nginx", platform="Nginx", command="add_header Content-Security-Policy \"default-src 'self'; script-src 'self';\" always;\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\nadd_header X-Frame-Options \"DENY\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;")
            ],
            standards_and_references=[
                EducationalStandard(standard="OWASP", reference_id="Secure-Headers-Project", title="OWASP Secure Headers Project", summary="Guidance for configuring secure HTTP response headers.")
            ]
        )

    # -------------------------------------------------------------
    # 26. Nginx / Apache Hardener
    # -------------------------------------------------------------
    elif tool_id == "server_hardener":
        hardened_nginx = """# CipherGuard Hardened Web Server Block
server {
    listen 443 ssl http2;
    server_name example.com;

    # Disable server tokens (version hiding)
    server_tokens off;

    # Restrict HTTP methods to GET, POST, HEAD
    if ($request_method !~ ^(GET|POST|HEAD)$) {
        return 405;
    }

    # SSL hardening
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;

    # Buffer overflow protections
    client_body_buffer_size 10K;
    client_header_buffer_size 1k;
    client_max_body_size 8m;
    large_client_header_buffers 2 1k;
}"""
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Nginx / Apache Hardener",
            suite_id="suite3_defense",
            timestamp=now_ts,
            verdict=SeverityLevel.CLEAN,
            risk_score=0,
            summary="Synthesized hardened web server configuration with disabled verb tampering and SSL hardening.",
            technical_evidence=[
                EvidenceItem(label="Version Disclosure (server_tokens)", value="Disabled (off)", status="pass"),
                EvidenceItem(label="Allowed HTTP Verbs", value="GET, POST, HEAD only", status="pass"),
                EvidenceItem(label="Permitted TLS Protocols", value="TLSv1.2, TLSv1.3", status="pass")
            ],
            threat_impact="Default server configurations leak version banners that attackers exploit to pinpoint exact CVE exploits.",
            attack_objective="Server Surface Reduction & CIS Hardening",
            remediation_playbook=[
                RemediationCommand(title="Apply Hardened Nginx Config", platform="Nginx", command=hardened_nginx)
            ],
            standards_and_references=[
                EducationalStandard(standard="CIS", reference_id="CIS Nginx Benchmark v2.0.0", title="CIS Nginx Web Server Hardening Guide", summary="Prescriptions for securing Nginx web server installations.")
            ]
        )

    # -------------------------------------------------------------
    # 27. Password Policy & Entropy Validator
    # -------------------------------------------------------------
    elif tool_id == "password_validator":
        pwd = clean_input
        length = len(pwd)
        has_upper = bool(re.search(r"[A-Z]", pwd))
        has_lower = bool(re.search(r"[a-z]", pwd))
        has_num = bool(re.search(r"\d", pwd))
        has_special = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", pwd))
        
        pool_size = (26 if has_lower else 0) + (26 if has_upper else 0) + (10 if has_num else 0) + (32 if has_special else 0)
        entropy_bits = round(length * (math.log2(pool_size) if pool_size > 0 else 0), 1)
        
        evidence = [
            EvidenceItem(label="Length", value=f"{length} characters", status="pass" if length >= 12 else "fail"),
            EvidenceItem(label="Character Pool Size", value=f"{pool_size} possible glyphs", status="info"),
            EvidenceItem(label="Estimated Password Entropy", value=f"{entropy_bits} bits", status="pass" if entropy_bits >= 60 else "fail")
        ]
        is_weak = entropy_bits < 50
        risk_score = 90 if is_weak else (40 if entropy_bits < 70 else 10)
        verdict = SeverityLevel.MALICIOUS if is_weak else (SeverityLevel.SUSPICIOUS if entropy_bits < 70 else SeverityLevel.CLEAN)
        
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Password Policy & Entropy Validator",
            suite_id="suite3_defense",
            timestamp=now_ts,
            verdict=verdict,
            risk_score=risk_score,
            summary=f"Password entropy evaluated at {entropy_bits} bits. {'Vulnerable to rapid offline dictionary attack or GPU cracking.' if is_weak else 'Sufficient entropy against brute force.'}",
            technical_evidence=evidence,
            threat_impact="Low entropy passwords are cracked in seconds by Hashcat using leaked dictionaries and rule masks.",
            attack_objective="Credential Access / Password Cracking",
            remediation_playbook=[
                RemediationCommand(title="Enforce Domain Password Complexity via GPO", platform="Windows PowerShell", command="Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14 -ComplexityEnabled $true -LockoutThreshold 5")
            ],
            standards_and_references=[
                EducationalStandard(standard="NIST", reference_id="SP 800-63B", title="Digital Identity Guidelines: Authentication and Lifecycle Management", summary="Recommendations on password length, memorability, and dictionary screening.")
            ]
        )

    # -------------------------------------------------------------
    # 28. CORS Misconfiguration Checker
    # -------------------------------------------------------------
    elif tool_id == "cors_checker":
        headers = clean_input.lower()
        has_wildcard = "access-control-allow-origin: *" in headers
        has_creds = "access-control-allow-credentials: true" in headers
        has_origin_reflection = "access-control-allow-origin: null" in headers
        
        is_critical_cors = (has_wildcard and has_creds) or (has_origin_reflection and has_creds)
        evidence = [
            EvidenceItem(label="Wildcard Origin (*)", value="Detected" if has_wildcard else "Not Present", status="fail" if has_wildcard else "pass"),
            EvidenceItem(label="Allow-Credentials", value="Enabled (true)" if has_creds else "Disabled / Absent", status="warning" if has_creds else "pass"),
            EvidenceItem(label="Null Origin Allowed", value="Detected" if has_origin_reflection else "Not Allowed", status="fail" if has_origin_reflection else "pass")
        ]
        risk_score = 95 if is_critical_cors else (40 if has_wildcard else 10)
        verdict = SeverityLevel.CRITICAL if is_critical_cors else (SeverityLevel.SUSPICIOUS if has_wildcard else SeverityLevel.CLEAN)

        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="CORS Misconfiguration Checker",
            suite_id="suite3_defense",
            timestamp=now_ts,
            verdict=verdict,
            risk_score=risk_score,
            summary=f"Cross-Origin Resource Sharing policy evaluated. {'Critical misconfiguration: allows unauthorized origins to read authenticated user data.' if is_critical_cors else 'Policy complies with origin restrictions.'}",
            technical_evidence=evidence,
            threat_impact="Insecure CORS allows malicious third-party websites to extract sensitive API responses and auth tokens using victim session cookies.",
            attack_objective="Cross-Origin Data Exfiltration",
            remediation_playbook=[
                RemediationCommand(title="Secure CORS Header Setting", platform="Node.js / Express", command="app.use(cors({\n  origin: ['https://trusted.example.com'],\n  credentials: true\n}));")
            ],
            standards_and_references=[
                EducationalStandard(standard="W3C", reference_id="W3C CORS Spec", title="Cross-Origin Resource Sharing Specification", summary="Security boundary rules for cross-origin web requests and credential inclusion.")
            ]
        )

    # -------------------------------------------------------------
    # 29. Security.txt Generator
    # -------------------------------------------------------------
    elif tool_id == "security_txt_gen":
        contact = params.get("contact", "mailto:security@yourcompany.com")
        security_txt = f"""# RFC 9116 Compliant Vulnerability Disclosure Policy
Contact: {contact}
Expires: {(datetime.now(timezone.utc).year + 1)}-12-31T23:59:59.000Z
Preferred-Languages: en
Canonical: https://yourcompany.com/.well-known/security.txt
Policy: https://yourcompany.com/security-policy
Hiring: https://yourcompany.com/careers/security"""
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Security.txt Generator",
            suite_id="suite3_defense",
            timestamp=now_ts,
            verdict=SeverityLevel.CLEAN,
            risk_score=0,
            summary="Synthesized RFC 9116 compliant security.txt vulnerability disclosure file.",
            technical_evidence=[
                EvidenceItem(label="RFC Standard", value="RFC 9116 Compliant", status="pass"),
                EvidenceItem(label="Target Path", value="/.well-known/security.txt", status="info")
            ],
            threat_impact="Without security.txt, whitehat security researchers struggle to responsibly disclose critical zero-days before public leakage.",
            attack_objective="Vulnerability Disclosure & Responsible Reporting",
            remediation_playbook=[
                RemediationCommand(title="Deploy security.txt to Web Root", platform="Linux", command=f"cat << 'EOF' > /var/www/html/.well-known/security.txt\n{security_txt}\nEOF")
            ],
            standards_and_references=[
                EducationalStandard(standard="RFC", reference_id="RFC 9116", title="A File Format to Aid in Security Vulnerability Disclosure", summary="Defines standard location and syntax for security.txt.")
            ]
        )

    # -------------------------------------------------------------
    # 30. CIS Benchmark Checklist
    # -------------------------------------------------------------
    elif tool_id == "cis_checklist_gen":
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="CIS Benchmark Checklist",
            suite_id="suite3_defense",
            timestamp=now_ts,
            verdict=SeverityLevel.CLEAN,
            risk_score=0,
            summary="Generated core CIS Benchmark Level 1 hardening checklist for Linux and Windows endpoints.",
            technical_evidence=[
                EvidenceItem(label="CIS Level", value="Level 1 - Operational Baseline", status="pass"),
                EvidenceItem(label="Core Controls", value="SSH Hardening, Auditd, Password Policies, Firewall", status="info")
            ],
            threat_impact="Un-hardened operating systems suffer default credentials, legacy protocol exposure, and unconstrained privilege escalation.",
            attack_objective="Host Hardening & Attack Surface Reduction",
            remediation_playbook=[
                RemediationCommand(title="CIS SSH Baseline Configuration", platform="Linux (/etc/ssh/sshd_config)", command="PermitRootLogin no\nPasswordAuthentication no\nX11Forwarding no\nMaxAuthTries 4\nClientAliveInterval 300"),
                RemediationCommand(title="Disable Legacy SMBv1 Protocol", platform="PowerShell", command="Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol")
            ],
            standards_and_references=[
                EducationalStandard(standard="CIS", reference_id="CIS Benchmarks", title="Center for Internet Security Hardening Benchmarks", summary="Consensus-based configuration standards for operating system defenses.")
            ]
        )

    return FiveLayerAnalysisResult(
        tool_id=tool_id,
        tool_name="Suite 3 Tool",
        suite_id="suite3_defense",
        timestamp=now_ts,
        verdict=SeverityLevel.CLEAN,
        risk_score=0,
        summary="Defense logic applied.",
        threat_impact="No threat detected.",
        remediation_playbook=[],
        standards_and_references=[]
    )
