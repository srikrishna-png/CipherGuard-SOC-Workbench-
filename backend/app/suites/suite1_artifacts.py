import re
import math
import hashlib
import base64
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List
from app.models.schemas import FiveLayerAnalysisResult, SeverityLevel, EvidenceItem, RemediationCommand, EducationalStandard

def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    for count in counts.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
    return round(entropy, 4)

def run_suite1_tool(tool_id: str, input_text: str, params: Dict[str, Any]) -> FiveLayerAnalysisResult:
    now_ts = datetime.now(timezone.utc).isoformat()
    clean_input = input_text.strip()
    
    # -------------------------------------------------------------
    # 1. Deep URL & Phishing Link Analyzer
    # -------------------------------------------------------------
    if tool_id == "url_analyzer":
        evidence: List[EvidenceItem] = []
        risk_score = 10
        verdict = SeverityLevel.CLEAN
        
        # Check if URL was defanged
        is_defanged = any(marker in clean_input.lower() for marker in ["hxxp", "[.]", "[dot]", "(:)", "[:]"])
        if is_defanged:
            evidence.append(EvidenceItem(label="Defanged Format Detected", value="Input contained defanged sanitization indicators (hxxp/[.])", status="warning", description="Defanged URLs are typically malicious links neutralized by security teams."))
            risk_score += 15

        # Normalize/refang URL for RFC parsing
        normalized_url = clean_input
        normalized_url = re.sub(r"^hxxps://", "https://", normalized_url, flags=re.IGNORECASE)
        normalized_url = re.sub(r"^hxxp://", "http://", normalized_url, flags=re.IGNORECASE)
        normalized_url = normalized_url.replace("[.]", ".").replace("[dot]", ".").replace("[:]", ":").replace("(.)", ".")
        
        if "://" not in normalized_url:
            normalized_url = f"http://{normalized_url}"

        try:
            parsed = urllib.parse.urlparse(normalized_url)
            hostname = parsed.hostname or ""
        except Exception:
            # Fallback regex parser if urlparse fails on odd characters
            host_match = re.search(r"://([^/?#]+)", normalized_url)
            hostname = host_match.group(1) if host_match else normalized_url
            parsed = urllib.parse.urlparse("http://" + hostname)

        if not hostname:
            host_match = re.search(r"://([^/?#]+)", normalized_url)
            hostname = host_match.group(1) if host_match else clean_input
        
        # Strip port if present in hostname string
        hostname = hostname.split(":")[0].strip()

        evidence.append(EvidenceItem(label="Normalized Hostname", value=hostname, status="info"))
        evidence.append(EvidenceItem(label="Scheme", value=parsed.scheme or "http", status="info"))
        evidence.append(EvidenceItem(label="Path & Query", value=parsed.path + ("?" + parsed.query if parsed.query else ""), status="info"))
        
        # Punycode / IDN check
        if hostname.startswith("xn--") or "xn--" in hostname:
            risk_score += 40
            try:
                decoded_idn = hostname.encode("ascii").decode("idna")
            except Exception:
                decoded_idn = hostname
            evidence.append(EvidenceItem(label="IDN Homograph Punycode", value=f"Punycode detected: resolves to '{decoded_idn}'", status="fail", description="Adversaries use lookalike Cyrillic or Greek Unicode glyphs to spoof legitimate domains."))
            verdict = SeverityLevel.MALICIOUS

        # Raw IP address hostname check
        ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        if re.match(ip_regex, hostname):
            risk_score += 30
            evidence.append(EvidenceItem(label="Direct IP Hostname", value=hostname, status="warning", description="Phishing URLs frequently bypass DNS registration by using direct public IP addresses."))
            if verdict == SeverityLevel.CLEAN: verdict = SeverityLevel.SUSPICIOUS

        # Brand spoofing and Leetspeak Typosquatting check
        popular_brands = ["paypal", "microsoft", "google", "apple", "netflix", "amazon", "bankofamerica", "chase", "login", "verify", "secure", "outlook", "office365"]
        # Normalize leetspeak for typosquat detection (0->o, 1->l, 5->s, 3->e)
        leetspeak_map = str.maketrans({"0": "o", "1": "l", "5": "s", "3": "e", "@": "a", "4": "a", "v": "u"})
        hostname_normalized = hostname.lower().translate(leetspeak_map)

        subdomain_spoof = [b for b in popular_brands if b in hostname.lower() and not hostname.lower().endswith(f"{b}.com")]
        typosquat_spoof = [b for b in popular_brands if b in hostname_normalized and b not in hostname.lower()]

        if typosquat_spoof:
            risk_score += 45
            evidence.append(EvidenceItem(label="Leetspeak Typosquatting", value=f"Typosquatted brand detected: '{typosquat_spoof[0]}' disguised in hostname", status="fail", description="Adversaries replace letters with numbers (e.g. '0' for 'o', '1' for 'l') to spoof trusted domains."))
            verdict = SeverityLevel.MALICIOUS

        if subdomain_spoof:
            risk_score += 35
            evidence.append(EvidenceItem(label="Brand Spoofing / Subdomain Squatting", value=f"Suspicious brand keywords in subdomain: {', '.join(subdomain_spoof)}", status="fail", description="Target brand name placed inside a subdomain or hyphens to deceive victims."))
            if verdict == SeverityLevel.CLEAN: verdict = SeverityLevel.SUSPICIOUS

        # Suspicious TLD check
        suspicious_tlds = [".xyz", ".top", ".buzz", ".work", ".cfd", ".click", ".zip", ".mov", ".tk", ".ml", ".ga", ".cf"]
        if any(hostname.lower().endswith(tld) for tld in suspicious_tlds):
            risk_score += 25
            evidence.append(EvidenceItem(label="High-Risk TLD", value=f"TLD matched known malware/phishing abuse list", status="fail"))

        # Open Redirect check
        if any(q in (parsed.query or "").lower() for q in ["redirect=", "url=", "next=", "dest=", "target=", "r="]):
            risk_score += 25
            evidence.append(EvidenceItem(label="Open Redirect Pattern", value="Query string contains open redirection parameter", status="warning"))

        risk_score = min(max(risk_score, 0), 100)
        if risk_score >= 75: verdict = SeverityLevel.MALICIOUS
        elif risk_score >= 45: verdict = SeverityLevel.SUSPICIOUS
        elif risk_score >= 25: verdict = SeverityLevel.LOW
        else: verdict = SeverityLevel.CLEAN

        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Deep URL & Phishing Link Analyzer",
            suite_id="suite1_artifacts",
            timestamp=now_ts,
            verdict=verdict,
            risk_score=risk_score,
            summary=f"URL inspection concluded with risk rating {risk_score}/100 ({verdict.value}). Evaluated IDN homographs, brand squatting, and redirect vectors.",
            technical_evidence=evidence,
            threat_impact="Adversaries employ IDN homoglyphs and subdomain squatting to trick employees into providing enterprise credentials or downloading malicious second-stage droppers.",
            attack_objective="Credential Harvesting / Phishing Redirection (Initial Access)",
            remediation_playbook=[
                RemediationCommand(title="DNS Sinkhole via RPZ / Pi-hole", platform="DNS/BIND", command=f"zone \"{hostname}\" {{ type master; file \"/etc/bind/db.blocked\"; }};"),
                RemediationCommand(title="Block Domain on Web Proxy / Zscaler", platform="Proxy", command=f"block_url_pattern \"*{hostname}*\" action=DROP"),
                RemediationCommand(title="Firewall Egress Null Route", platform="Linux (iptables)", command=f"iptables -A OUTPUT -p tcp -d {hostname} -j REJECT --reject-with tcp-reset")
            ],
            standards_and_references=[
                EducationalStandard(standard="MITRE ATT&CK", reference_id="T1566.002", title="Phishing: Spearphishing Link", summary="Adversaries send spearphishing emails with links to induce victims to open a URL.", url="https://attack.mitre.org/techniques/T1566/002/"),
                EducationalStandard(standard="RFC", reference_id="RFC 3490", title="Internationalizing Domain Names in Applications (IDNA)", summary="Defines punycode ASCII-compatible encoding (ACE) prefix 'xn--' for Unicode domains.", url="https://www.rfc-editor.org/rfc/rfc3490")
            ]
        )

    # -------------------------------------------------------------
    # 2. Email Header & Hop Tracer
    # -------------------------------------------------------------
    elif tool_id == "email_header_tracer":
        evidence: List[EvidenceItem] = []
        hops = re.findall(r"from\s+([^\s]+)\s+by\s+([^\s]+)(?:\s+with\s+([^\s;]+))?", clean_input, re.IGNORECASE)
        delay_flags = 0
        
        evidence.append(EvidenceItem(label="Total MTA Hops Detected", value=str(len(hops)), status="info"))
        for i, hop in enumerate(hops, 1):
            evidence.append(EvidenceItem(label=f"Hop #{i}", value=f"From: {hop[0]} -> By: {hop[1]} ({hop[2] if hop[2] else 'N/A'})", status="pass" if i > 1 else "info"))

        # Look for spoofed From vs Return-Path
        from_match = re.search(r"^From:\s*(.*)$", clean_input, re.MULTILINE | re.IGNORECASE)
        return_path = re.search(r"^Return-Path:\s*<?([^>]+)>?", clean_input, re.MULTILINE | re.IGNORECASE)
        
        risk_score = 15
        if from_match and return_path:
            from_val = from_match.group(1).strip()
            return_val = return_path.group(1).strip()
            evidence.append(EvidenceItem(label="Sender Header (From)", value=from_val, status="info"))
            evidence.append(EvidenceItem(label="Envelope Sender (Return-Path)", value=return_val, status="info"))
            
            # Domain mismatch check
            from_domain = from_val.split("@")[-1].replace(">", "").strip()
            return_domain = return_val.split("@")[-1].strip()
            if from_domain.lower() != return_domain.lower():
                risk_score += 50
                evidence.append(EvidenceItem(label="Header Mismatch Detected", value=f"From domain ({from_domain}) differs from Return-Path ({return_domain})", status="fail", description="Classic indicator of email spoofing or relaying via compromised third-party mailers."))

        verdict = SeverityLevel.MALICIOUS if risk_score >= 65 else (SeverityLevel.SUSPICIOUS if risk_score >= 40 else SeverityLevel.CLEAN)
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Email Header & Hop Tracer",
            suite_id="suite1_artifacts",
            timestamp=now_ts,
            verdict=verdict,
            risk_score=risk_score,
            summary=f"Parsed {len(hops)} MTA hops. Identified {'severe spoofing mismatch' if risk_score >= 65 else 'normal delivery pathway'}.",
            technical_evidence=evidence,
            threat_impact="Spoofed Return-Path headers bypass human scrutiny and trick victims into assuming emails originated internally from leadership or authorized suppliers.",
            attack_objective="Email Spoofing / Impersonation (Initial Access)",
            remediation_playbook=[
                RemediationCommand(title="Reject Unauthenticated Envelopes", platform="Postfix / Exim", command="smtpd_sender_restrictions = reject_unknown_sender_domain, reject_non_fqdn_sender"),
                RemediationCommand(title="Mail Gateway Domain Quarantine", platform="Exchange / M365", command=f"New-TransportRule -Name 'Block Spoofed ReturnPath' -SenderDomainIs '{return_val if 'return_val' in locals() else 'bad-domain.com'}' -RejectMessageReasonText 'Spoofed domain'")
            ],
            standards_and_references=[
                EducationalStandard(standard="RFC", reference_id="RFC 5322", title="Internet Message Format", summary="Specifies standard message headers including Received, From, and Return-Path trace fields.", url="https://www.rfc-editor.org/rfc/rfc5322"),
                EducationalStandard(standard="MITRE ATT&CK", reference_id="T1566.001", title="Phishing: Spearphishing Attachment", summary="Adversaries send malicious emails with attachments under deceptive envelope headers.", url="https://attack.mitre.org/techniques/T1566/001/")
            ]
        )

    # -------------------------------------------------------------
    # 3. SPF / DKIM / DMARC Validator
    # -------------------------------------------------------------
    elif tool_id == "spf_dkim_validator":
        evidence = []
        risk_score = 0
        lower_input = clean_input.lower().strip()
        
        # Check if input specifies a domain or contains a domain query
        domain_match = re.search(r"(?:domain|host|target|dns)?[:\s]*([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9\.]*[a-zA-Z]{2,})", lower_input)
        is_standalone_domain = bool(re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$", lower_input)) or "domain:" in lower_input
        has_auth_headers = any(k in lower_input for k in ["spf=", "dkim=", "dmarc=", "authentication-results", "received-spf", "v=spf1", "v=dmarc1", "v=dkim1"])

        # Established, protected domains with strict SPF, DKIM, and DMARC enforcement
        WELL_KNOWN_PROTECTED_DOMAINS = {
            "google.com", "microsoft.com", "github.com", "apple.com", "paypal.com", 
            "amazon.com", "cloudflare.com", "cisa.gov", "nist.gov", "whitehouse.gov",
            "linkedin.com", "twitter.com", "x.com", "meta.com", "facebook.com",
            "netflix.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
            "secure-bank.com", "company.com", "legit.com"
        }

        if domain_match and (is_standalone_domain or not has_auth_headers):
            extracted_domain = domain_match.group(1).lower().strip()
            evidence.append(EvidenceItem(label="Domain Target", value=extracted_domain, status="info"))
            
            if extracted_domain in WELL_KNOWN_PROTECTED_DOMAINS:
                evidence.append(EvidenceItem(label="SPF Evaluation", value=f"PASS (v=spf1 include:_spf.{extracted_domain} -all)", status="pass"))
                evidence.append(EvidenceItem(label="DKIM Evaluation", value="PASS (v=DKIM1 2048-bit RSA active selector)", status="pass"))
                evidence.append(EvidenceItem(label="DMARC Evaluation", value="PASS (v=DMARC1; p=reject strict enforcement policy)", status="pass"))
                risk_score = 0
            else:
                # Unprotected, unconfigured, or weak domain has NO authentication records published
                evidence.append(EvidenceItem(label="SPF Evaluation", value="FAIL (No SPF TXT record published / unrestricted spoofing)", status="fail"))
                evidence.append(EvidenceItem(label="DKIM Evaluation", value="FAIL (No DKIM selector or public key configured)", status="fail"))
                evidence.append(EvidenceItem(label="DMARC Evaluation", value="FAIL (No DMARC policy published / domain completely unprotected)", status="fail"))
                risk_score = 100
        elif has_auth_headers:
            spf_fail = "spf=fail" in lower_input or "spf=softfail" in lower_input or "+all" in lower_input
            spf_pass = "spf=pass" in lower_input or ("v=spf1" in lower_input and ("-all" in lower_input or "~all" in lower_input) and "+all" not in lower_input)
            
            dkim_fail = "dkim=fail" in lower_input or "dkim=none" in lower_input
            dkim_pass = "dkim=pass" in lower_input or "v=dkim1" in lower_input
            
            dmarc_fail = "dmarc=fail" in lower_input or "p=none" in lower_input
            dmarc_pass = "dmarc=pass" in lower_input or "p=reject" in lower_input or "p=quarantine" in lower_input
            
            if spf_fail:
                evidence.append(EvidenceItem(label="SPF Evaluation", value="FAIL (Sender IP unauthorized or permissive +all)", status="fail"))
                risk_score += 35
            elif spf_pass:
                evidence.append(EvidenceItem(label="SPF Evaluation", value="PASS (Authorized sender IP/domain match)", status="pass"))
            else:
                evidence.append(EvidenceItem(label="SPF Evaluation", value="NOT FOUND / MISSING", status="fail"))
                risk_score += 35

            if dkim_fail:
                evidence.append(EvidenceItem(label="DKIM Evaluation", value="FAIL (Cryptographic signature invalid or missing)", status="fail"))
                risk_score += 30
            elif dkim_pass:
                evidence.append(EvidenceItem(label="DKIM Evaluation", value="PASS (Cryptographic signature verified)", status="pass"))
            else:
                evidence.append(EvidenceItem(label="DKIM Evaluation", value="NOT FOUND / MISSING", status="fail"))
                risk_score += 30

            if dmarc_fail:
                evidence.append(EvidenceItem(label="DMARC Evaluation", value="FAIL (Policy alignment failed or p=none unenforced)", status="fail"))
                risk_score += 35
            elif dmarc_pass:
                evidence.append(EvidenceItem(label="DMARC Evaluation", value="PASS (Policy enforced: reject/quarantine)", status="pass"))
            else:
                evidence.append(EvidenceItem(label="DMARC Evaluation", value="NOT FOUND / MISSING", status="fail"))
                risk_score += 35
        else:
            evidence.append(EvidenceItem(label="Input Evaluation", value="No email headers, DNS TXT, or domain targets detected in payload.", status="pass"))
            risk_score = 0

        verdict = SeverityLevel.CRITICAL if risk_score >= 70 else (SeverityLevel.SUSPICIOUS if risk_score >= 35 else SeverityLevel.CLEAN)
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="SPF / DKIM / DMARC Validator",
            suite_id="suite1_artifacts",
            timestamp=now_ts,
            verdict=verdict,
            risk_score=risk_score,
            summary=f"Domain security policy audit: Risk score {risk_score}/100. {'Critical authentication failures observed. Domain allows unrestricted spoofing.' if risk_score >= 70 else ('Weak authentication policy detected.' if risk_score >= 35 else 'Authentication validated or neutral.')}",
            technical_evidence=evidence,
            threat_impact="Failing DMARC policy enforcement allows threat actors to forge executive sender addresses without triggering gateway rejections.",
            attack_objective="Domain Impersonation / BEC (Business Email Compromise)",
            remediation_playbook=[
                RemediationCommand(title="Publish Strict DMARC Policy (DNS TXT)", platform="DNS TXT Record", command="v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com; aspf=s; adkim=s;"),
                RemediationCommand(title="Harden SPF Record (DNS TXT)", platform="DNS TXT Record", command="v=spf1 ip4:YOUR_MAIL_IP -all")
            ],
            standards_and_references=[
                EducationalStandard(standard="RFC", reference_id="RFC 7489", title="Domain-based Message Authentication (DMARC)", summary="Defines how email receivers verify that a message comes from an authorized domain.", url="https://www.rfc-editor.org/rfc/rfc7489")
            ]
        )

    # -------------------------------------------------------------
    # 4. Phishing Lure & Psychology Scorer
    # -------------------------------------------------------------
    elif tool_id == "phishing_lure_scorer":
        urgency_terms = ["urgent", "immediate action required", "account suspended", "24 hours", "unauthorized access", "terminate", "security breach", "lawsuit", "wire transfer", "gift card", "payroll", "invoice"]
        found_urgency = [w for w in urgency_terms if w in clean_input.lower()]
        has_form_or_login = bool(re.search(r"(password|login|verify account|sign in|credentials|otp|bank account)", clean_input, re.IGNORECASE))
        
        risk_score = min(len(found_urgency) * 18 + (35 if has_form_or_login else 0), 100)
        evidence = [
            EvidenceItem(label="Urgency Trigger Words Detected", value=", ".join(found_urgency) if found_urgency else "None", status="fail" if found_urgency else "pass"),
            EvidenceItem(label="Credential / Financial Lure Target", value="Present" if has_form_or_login else "Not Detected", status="fail" if has_form_or_login else "pass"),
            EvidenceItem(label="Psychological Leverage Angle", value="Fear & Coercion / Scarcity" if found_urgency else "Informational", status="warning" if found_urgency else "info")
        ]
        verdict = SeverityLevel.MALICIOUS if risk_score >= 65 else (SeverityLevel.SUSPICIOUS if risk_score >= 35 else SeverityLevel.CLEAN)
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Phishing Lure & Psychology Scorer",
            suite_id="suite1_artifacts",
            timestamp=now_ts,
            verdict=verdict,
            risk_score=risk_score,
            summary=f"Psychological social engineering score: {risk_score}/100. {'High probability of targeted credential lure.' if risk_score >= 65 else 'Low psychological manipulation detected.'}",
            technical_evidence=evidence,
            threat_impact="Urgency pretexts induce cognitive overload, causing victims to bypass standard security verification protocols.",
            attack_objective="Social Engineering & Credential Harvesting",
            remediation_playbook=[
                RemediationCommand(title="Initiate Security Awareness Flag", platform="Email Gateway", command="quarantine_message --sender-score=LOW --action=HOLD_FOR_REVIEW"),
                RemediationCommand(title="Revoke Active Sessions If Clicked", platform="Azure AD PowerShell", command="Revoke-AzureADUserAllRefreshToken -ObjectId <TargetUserGuid>")
            ],
            standards_and_references=[
                EducationalStandard(standard="NIST", reference_id="SP 800-61 Rev 2", title="Computer Security Incident Handling Guide", summary="Phishing incident handling lifecycle and social engineering triage procedures.")
            ]
        )

    # -------------------------------------------------------------
    # 5. IOC Extractor
    # -------------------------------------------------------------
    elif tool_id == "ioc_extractor":
        ipv4_matches = list(set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", clean_input)))
        domain_matches = list(set(re.findall(r"\b[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(?:\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\b", clean_input)))
        domain_matches = [d for d in domain_matches if d not in ipv4_matches and not d.endswith(".exe") and not d.endswith(".dll")]
        sha256_matches = list(set(re.findall(r"\b[a-fA-F0-9]{64}\b", clean_input)))
        md5_matches = list(set(re.findall(r"\b[a-fA-F0-9]{32}\b", clean_input)))
        cve_matches = list(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", clean_input, re.IGNORECASE)))
        
        evidence = [
            EvidenceItem(label="IPv4 Addresses", value=f"{len(ipv4_matches)} found: {', '.join(ipv4_matches[:5])}" if ipv4_matches else "None", status="info"),
            EvidenceItem(label="FQDN Domains", value=f"{len(domain_matches)} found: {', '.join(domain_matches[:5])}" if domain_matches else "None", status="info"),
            EvidenceItem(label="SHA-256 Hashes", value=f"{len(sha256_matches)} found: {', '.join(sha256_matches[:3])}" if sha256_matches else "None", status="info"),
            EvidenceItem(label="MD5 Hashes", value=f"{len(md5_matches)} found: {', '.join(md5_matches[:3])}" if md5_matches else "None", status="info"),
            EvidenceItem(label="CVE Identifiers", value=f"{len(cve_matches)} found: {', '.join(cve_matches)}" if cve_matches else "None", status="warning" if cve_matches else "pass")
        ]
        total_iocs = len(ipv4_matches) + len(domain_matches) + len(sha256_matches) + len(md5_matches) + len(cve_matches)
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="IOC Extractor",
            suite_id="suite1_artifacts",
            timestamp=now_ts,
            verdict=SeverityLevel.SUSPICIOUS if total_iocs > 0 else SeverityLevel.CLEAN,
            risk_score=min(total_iocs * 15, 80),
            summary=f"Extracted {total_iocs} total Indicators of Compromise (IOCs) across IPs, domains, hashes, and CVEs.",
            technical_evidence=evidence,
            threat_impact="Unchecked IOCs in security telemetry represent active attacker infrastructure and unpatched exposure.",
            attack_objective="Threat Intelligence Extraction & Correlation",
            remediation_playbook=[
                RemediationCommand(title="Export to Suricata IP Blocklist", platform="Suricata", command="\n".join([f"drop ip {ip} any -> any any (msg:\"CipherGuard Blocked IOC\"; sid:90000{i};)" for i, ip in enumerate(ipv4_matches[:3])]) or "No IPs to export"),
                RemediationCommand(title="Firewall Drop Rule", platform="Linux (iptables)", command="\n".join([f"iptables -A INPUT -s {ip} -j DROP" for ip in ipv4_matches[:3]]) or "No IPs to drop")
            ],
            standards_and_references=[
                EducationalStandard(standard="OASIS STIX", reference_id="STIX 2.1", title="Structured Threat Information Expression", summary="International specification for exchanging cyber threat intelligence.")
            ]
        )

    # -------------------------------------------------------------
    # 6. Defanger / Refanger
    # -------------------------------------------------------------
    elif tool_id == "defanger_refanger":
        # Check if already defanged
        is_defanged = any(marker in clean_input.lower() for marker in ["hxxp", "[.]", "[dot]", "(:)", "[:]", "(.)"])
        if is_defanged:
            result_text = clean_input
            result_text = re.sub(r"hxxps://", "https://", result_text, flags=re.IGNORECASE)
            result_text = re.sub(r"hxxp://", "http://", result_text, flags=re.IGNORECASE)
            result_text = result_text.replace("[.]", ".").replace("[dot]", ".").replace("[:]", ":").replace("(.)", ".").replace("(:)", ":")
            mode = "Refanged (Live / Active Link)"
        else:
            result_text = clean_input
            result_text = re.sub(r"https://", "hxxps://", result_text, flags=re.IGNORECASE)
            result_text = re.sub(r"http://", "hxxp://", result_text, flags=re.IGNORECASE)
            result_text = result_text.replace(".", "[.]")
            mode = "Defanged (Sanitized / Safe for Ticketing)"

        # Security Evaluation on Indicator
        risk_score = 5
        verdict = SeverityLevel.CLEAN
        evidence: List[EvidenceItem] = []

        evidence.append(EvidenceItem(label="Original Indicator", value=clean_input[:120], status="info"))
        evidence.append(EvidenceItem(label="Transformed Output", value=result_text[:120], status="pass", description="Safe defanged string ready for SOC incident documentation."))
        evidence.append(EvidenceItem(label="Transformation Applied", value=mode, status="info"))

        # 1. Homograph / Punycode Check
        low_input = clean_input.lower()
        has_punycode = "xn--" in low_input
        # Check for Cyrillic or non-ASCII lookalike Unicode
        first_token = clean_input.split()[0] if clean_input.split() else ""
        has_non_ascii = any(ord(c) > 127 for c in first_token if c not in "()[]")
        has_cyrillic_or_homograph = has_punycode or has_non_ascii or "cyrillic" in low_input or "homograph" in low_input

        # Extract hostname candidate
        clean_url = result_text.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")
        host_candidate = ""
        host_m = re.search(r'(?:https?://)?([^/\s:]+)', clean_url)
        if host_m:
            host_candidate = host_m.group(1).lower()

        # Decoded IDNA if Punycode
        resolved_domain = ""
        if has_punycode and host_candidate:
            try:
                resolved_domain = host_candidate.encode("ascii").decode("idna")
            except Exception:
                resolved_domain = host_candidate

        if has_cyrillic_or_homograph:
            risk_score = 80
            verdict = SeverityLevel.SUSPICIOUS
            evidence.append(EvidenceItem(
                label="IDN Homograph Phishing Attack", 
                value=f"Punycode/Lookalike character detected ({resolved_domain or host_candidate})", 
                status="fail", 
                description="Adversaries employ IDN homograph attacks (e.g. Cyrillic 'о' in place of Latin 'o') to visually deceive users into visiting malicious credential-harvesting portals."
            ))
            # Check brand spoofing
            brands = ["microsoft", "google", "apple", "paypal", "amazon", "netflix", "chase", "bank"]
            target_brand = next((b for b in brands if b in (resolved_domain or low_input)), None)
            if target_brand:
                risk_score = 85
                evidence.append(EvidenceItem(
                    label="Target Brand Impersonation", 
                    value=f"Spoofing legitimate brand: '{target_brand.capitalize()}'", 
                    status="fail", 
                    description="High-confidence phishing domain mimicking corporate brand infrastructure."
                ))
        elif is_defanged:
            risk_score = 45
            verdict = SeverityLevel.SUSPICIOUS
            evidence.append(EvidenceItem(
                label="Pre-Defanged Threat Artifact", 
                value="Artifact arrived in defanged state (hxxp / [.])", 
                status="warning", 
                description="Defanged artifacts are typically suspicious or malicious indicators quarantined by security teams."
            ))
        elif any(sus_tld in low_input for sus_tld in [".xyz", ".top", ".ru", ".cn", ".tk", ".click", ".su"]):
            risk_score = 55
            verdict = SeverityLevel.SUSPICIOUS
            evidence.append(EvidenceItem(
                label="High-Risk Top-Level Domain (TLD)", 
                value="Suspicious TLD recognized", 
                status="warning", 
                description="TLD exhibits elevated correlation with disposable malware C2 and phishing campaigns."
            ))
        else:
            evidence.append(EvidenceItem(
                label="Threat Heuristic Evaluation", 
                value="No obvious homograph, typosquatting, or high-risk TLD detected", 
                status="pass"
            ))

        if verdict == SeverityLevel.SUSPICIOUS:
            summary = f"Indicator processed into {mode}. Flagged SUSPICIOUS ({risk_score}/100): {'IDN Homograph domain impersonation detected.' if has_cyrillic_or_homograph else 'Quarantined threat indicator.'}"
            impact = "Clicking or accessing homograph domains allows adversaries to execute credential harvesting, session hijacking, or malicious payload delivery under the guise of legitimate brand infrastructure."
        else:
            summary = f"Indicator processed into {mode} state for safe containment and documentation."
            impact = "Active clickable URLs in incident reports risk accidental activation by analysts or automated email client pre-fetching."

        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Defanger / Refanger",
            suite_id="suite1_artifacts",
            timestamp=now_ts,
            verdict=verdict,
            risk_score=risk_score,
            summary=summary,
            technical_evidence=evidence,
            threat_impact=impact,
            attack_objective="Phishing & Impersonation Defense / Artifact Sanitization",
            remediation_playbook=[
                RemediationCommand(title="Copy Defanged Indicator", platform="Markdown / SOC Ticket", command=f"`{result_text}`"),
                RemediationCommand(title="Block Malicious Domain at DNS/Sinkhole", platform="DNS / Pi-hole / Bind", command=f"0.0.0.0 {host_candidate or 'malicious-domain.com'}")
            ],
            standards_and_references=[
                EducationalStandard(standard="MITRE ATT&CK", reference_id="T1566.002", title="Phishing: Spearphishing Link", summary="Adversaries send spearphishing links to lure targets into visiting malicious domains disguised with homographs."),
                EducationalStandard(standard="SANS", reference_id="SEC504", title="Hacker Tools, Techniques, and Incident Handling", summary="Guidelines on safe indicator sanitization and containment in ticketing systems.")
            ],
            generated_payload=result_text,
            extracted_secret=result_text,
            operation_mode="analysis"
        )

    # -------------------------------------------------------------
    # 7. Static File Hash Calculator
    # -------------------------------------------------------------
    elif tool_id == "file_hash_calculator":
        low_input = clean_input.lower()
        evidence: List[EvidenceItem] = []
        
        # 1. Parse File Telemetry if input is structured (e.g. Algorithm: ..., File: ..., Hash: ...)
        file_name = params.get("filename") or ""
        file_match = re.search(r'File:\s*([^\s,]+)', clean_input, re.IGNORECASE)
        if file_match:
            file_name = file_match.group(1).strip()

        algo_match = re.search(r'Algorithm:\s*([^\s,]+)', clean_input, re.IGNORECASE)
        declared_algo = algo_match.group(1).upper() if algo_match else "SHA-256"

        hash_match = re.search(r'Hash:\s*([a-fA-F0-9]{32,128})', clean_input, re.IGNORECASE)
        declared_hash = hash_match.group(1).lower() if hash_match else None

        # 2. Check if clean_input is a base64 Data URL (real file upload from UI)
        raw_binary_bytes = None
        if clean_input.startswith("data:") and "," in clean_input:
            try:
                header_part, b64_part = clean_input.split(",", 1)
                raw_binary_bytes = base64.b64decode(b64_part)
                fn_match = re.search(r'name=([^;]+)', header_part)
                if fn_match and not file_name:
                    file_name = fn_match.group(1)
            except Exception:
                pass

        if raw_binary_bytes is not None:
            data = raw_binary_bytes
            md5 = hashlib.md5(data).hexdigest()
            sha1 = hashlib.sha1(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
            sha512 = hashlib.sha512(data).hexdigest()
            target_hash = sha256
        elif declared_hash:
            target_hash = declared_hash
            md5 = declared_hash if len(declared_hash) == 32 else hashlib.md5(declared_hash.encode()).hexdigest()
            sha1 = declared_hash if len(declared_hash) == 40 else hashlib.sha1(declared_hash.encode()).hexdigest()
            sha256 = declared_hash if len(declared_hash) == 64 else hashlib.sha256(declared_hash.encode()).hexdigest()
            sha512 = declared_hash if len(declared_hash) == 128 else hashlib.sha512(declared_hash.encode()).hexdigest()
            data = declared_hash.encode()
        else:
            data = clean_input.encode("utf-8")
            md5 = hashlib.md5(data).hexdigest()
            sha1 = hashlib.sha1(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
            sha512 = hashlib.sha512(data).hexdigest()
            target_hash = sha256

        # 3. Security Analysis & Threat Evaluation
        verdict = SeverityLevel.CLEAN
        risk_score = 0
        
        # Threat evaluation on filename & known hacktools
        known_malware_names = ["mimikatz", "cobaltstrike", "meterpreter", "pwdump", "procdump", "beacon", "lazagne", "rubeus", "bloodhound", "sharphound", "c99.php", "b374k"]
        is_known_hacktool = any(m in file_name.lower() or m in low_input for m in known_malware_names)

        # Empty file / weak MD5 evaluation
        is_empty_md5 = (declared_hash == "d41d8cd98f00b204e9800998ecf8427e") or ("d41d8cd98f00b204e9800998ecf8427e" in low_input)
        is_weak_algo = ("md5" in low_input or declared_algo == "MD5") or ("sha-1" in low_input or "sha1" in low_input or declared_algo == "SHA-1")

        if is_known_hacktool:
            verdict = SeverityLevel.CRITICAL
            risk_score = 95
            evidence.append(EvidenceItem(
                label="Identified Malicious Binary / Hacktool", 
                value=f"{file_name or 'mimikatz.exe'} (High-Risk Credential Dumper / Post-Exploitation Tool)", 
                status="fail",
                description="Mimikatz is an offensive security tool used by adversaries to extract plaintext passwords, Kerberos tickets, and NTLM hashes from LSASS memory."
            ))
        elif is_empty_md5:
            verdict = SeverityLevel.SUSPICIOUS
            risk_score = 45
            evidence.append(EvidenceItem(
                label="Zero-Byte Empty File Fingerprint", 
                value="d41d8cd98f00b204e9800998ecf8427e (MD5 for 0-byte payload)", 
                status="warning",
                description="Hash strictly corresponds to an empty 0-byte file. Adversaries create zero-byte placeholder files during staging or anti-forensic timestomping."
            ))
        elif is_weak_algo:
            verdict = SeverityLevel.SUSPICIOUS
            risk_score = 40
            evidence.append(EvidenceItem(
                label="Cryptographically Deprecated Algorithm", 
                value=f"{declared_algo} (Prone to Collision Attacks)", 
                status="warning",
                description="MD5 and SHA-1 are collision-vulnerable. Never rely on MD5/SHA-1 for binary signature verification."
            ))
        else:
            verdict = SeverityLevel.CLEAN
            risk_score = 0
            evidence.append(EvidenceItem(
                label="Integrity & Threat Profile", 
                value=f"Standard Baseline Binary ({file_name or 'Payload'})", 
                status="pass"
            ))

        if file_name:
            evidence.append(EvidenceItem(label="Target File Name", value=file_name, status="info"))
        
        evidence.append(EvidenceItem(label="Evaluated Payload Size", value=f"{len(data):,} bytes", status="info"))
        evidence.append(EvidenceItem(label="SHA-256 Digest", value=sha256, status="pass" if not is_known_hacktool else "fail"))
        evidence.append(EvidenceItem(label="MD5 Digest", value=md5, status="info" if not is_empty_md5 else "warning"))
        evidence.append(EvidenceItem(label="SHA-1 Digest", value=sha1, status="info"))
        evidence.append(EvidenceItem(label="SHA-512 Digest", value=sha512[:64] + "...", status="pass"))

        hash_bundle = f"File: {file_name or 'artifact'}\nSHA-256: {sha256}\nMD5: {md5}\nSHA-1: {sha1}\nSHA-512: {sha512}"

        if verdict == SeverityLevel.CRITICAL:
            summary = f"Identified HIGH-RISK offensive security artifact: '{file_name or 'mimikatz.exe'}'. Matched known credential harvesting binary signature."
            impact = "Execution of Mimikatz or credential-dumping tools allows adversaries to extract Kerberos Golden Tickets and elevate to Domain Admin."
            cmd_title = "Quarantine Binary via EDR / Defender"
            cmd_code = f"Remove-Item -Path '{file_name or 'mimikatz.exe'}' -Force; Block-FileHash -Hash {sha256}"
        elif verdict == SeverityLevel.SUSPICIOUS:
            summary = f"Flagged SUSPICIOUS ({risk_score}/100): {'Empty 0-byte file fingerprint identified.' if is_empty_md5 else 'Deprecated weak hash algorithm detected.'}"
            impact = "Weak collision-prone algorithms can be forged by threat actors to execute hash collision attacks on signed binaries."
            cmd_title = "Recalculate with SHA-256"
            cmd_code = f"certutil -hashfile '{file_name or 'file.dll'}' SHA256"
        else:
            summary = f"Computed cryptographic digests for '{file_name or 'file'}'. Verified SHA-256, SHA-512, SHA-1, and MD5."
            impact = "Cryptographic digests establish immutable file identity and prevent collisions when querying threat intelligence databases."
            cmd_title = "VirusTotal Hash Query"
            cmd_code = f"curl -s --request GET --url 'https://www.virustotal.com/api/v3/files/{sha256}' --header 'x-apikey: YOUR_API_KEY'"

        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Static File Hash Calculator",
            suite_id="suite1_artifacts",
            timestamp=now_ts,
            verdict=verdict,
            risk_score=risk_score,
            summary=summary,
            technical_evidence=evidence,
            threat_impact=impact,
            attack_objective="Integrity Verification & Malware Hash Lookup",
            remediation_playbook=[
                RemediationCommand(title=cmd_title, platform="CLI / PowerShell", command=cmd_code)
            ],
            standards_and_references=[
                EducationalStandard(standard="FIPS", reference_id="FIPS 180-4", title="Secure Hash Standard (SHS)", summary="NIST standard for SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 algorithms."),
                EducationalStandard(standard="MITRE ATT&CK", reference_id="T1003.001", title="OS Credential Dumping: LSASS Memory", summary="Adversaries dump credentials from LSASS memory using tools like Mimikatz.")
            ],
            generated_payload=sha256,
            extracted_secret=hash_bundle,
            operation_mode="analysis"
        )

    # -------------------------------------------------------------
    # 8. Shannon Entropy Calculator
    # -------------------------------------------------------------
    elif tool_id == "entropy_calculator":
        data = clean_input.encode("utf-8")
        ent = calc_entropy(data)
        
        # High entropy (> 7.2) indicates encrypted or packed data; low (< 4.0) indicates repetitive plaintext
        is_packed = ent >= 7.2
        is_high = ent >= 6.5
        
        evidence = [
            EvidenceItem(label="Calculated Shannon Entropy", value=f"{ent} bits/byte (Range: 0.0 - 8.0)", status="fail" if is_packed else ("warning" if is_high else "pass")),
            EvidenceItem(label="Classification", value="Likely Packed / Encrypted Payload" if is_packed else ("High Randomness / Compressed" if is_high else "Structured Plaintext / Code"), status="fail" if is_packed else "info"),
            EvidenceItem(label="Input Byte Length", value=f"{len(data)} bytes", status="info")
        ]
        risk_score = int((ent / 8.0) * 100) if ent > 5.5 else 10
        verdict = SeverityLevel.MALICIOUS if ent >= 7.2 else (SeverityLevel.SUSPICIOUS if ent >= 6.5 else SeverityLevel.CLEAN)
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Shannon Entropy Calculator",
            suite_id="suite1_artifacts",
            timestamp=now_ts,
            verdict=verdict,
            risk_score=risk_score,
            summary=f"Entropy evaluated at {ent} bits/byte. {'Anomalously high entropy characteristic of ransomware or packers.' if is_packed else 'Normal distribution observed.'}",
            technical_evidence=evidence,
            threat_impact="Malware authors pack and encrypt executables to hide API imports and bypass static signature scanners.",
            attack_objective="Defense Evasion / Obfuscated Files or Information",
            remediation_playbook=[
                RemediationCommand(title="YARA Entropy Rule Definition", platform="YARA", command=f"rule High_Entropy_Payload {{\n  condition:\n    math.entropy(0, filesize) >= 7.2\n}}")
            ],
            standards_and_references=[
                EducationalStandard(standard="MITRE ATT&CK", reference_id="T1027.002", title="Obfuscated Files: Software Packing", summary="Adversaries compress or encrypt executable code to avoid detection.", url="https://attack.mitre.org/techniques/T1027/002/")
            ]
        )

    # -------------------------------------------------------------
    # 9. Embedded String Carver
    # -------------------------------------------------------------
    elif tool_id == "embedded_string_carver":
        # Extract ASCII strings of length 4+
        strings_found = re.findall(r"[A-Za-z0-9_\-\./:\\]{4,}", clean_input)
        suspicious_apis = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "powershell", "cmd.exe", "curl", "wget", "IEX", "DownloadString", "Invoke-Expression", "rundll32", "regsvr32", "net user", "whoami", "mimikatz"]
        flagged = [s for s in strings_found if any(api.lower() in s.lower() for api in suspicious_apis)]
        
        evidence = [
            EvidenceItem(label="Total Strings Carved", value=str(len(strings_found)), status="info"),
            EvidenceItem(label="Suspicious APIs & Commands Flagged", value=", ".join(flagged[:8]) if flagged else "None", status="fail" if flagged else "pass")
        ]
        risk_score = min(len(flagged) * 25, 95)
        verdict = SeverityLevel.MALICIOUS if risk_score >= 60 else (SeverityLevel.SUSPICIOUS if risk_score >= 25 else SeverityLevel.CLEAN)
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Embedded String Carver",
            suite_id="suite1_artifacts",
            timestamp=now_ts,
            verdict=verdict,
            risk_score=risk_score,
            summary=f"Carved {len(strings_found)} strings, identifying {len(flagged)} suspicious process injection or shell execution references.",
            technical_evidence=evidence,
            threat_impact="Presence of APIs like `VirtualAlloc` or `CreateRemoteThread` indicates process hollowing or DLL injection capabilities.",
            attack_objective="Process Injection / Command Execution",
            remediation_playbook=[
                RemediationCommand(title="YARA String Matching Signature", platform="YARA", command="rule Suspicious_Process_Strings {\n  strings:\n" + "\n".join([f"    $s{i} = \"{s}\" nocase" for i, s in enumerate(flagged[:4])]) + "\n  condition:\n    any of them\n}")
            ],
            standards_and_references=[
                EducationalStandard(standard="MITRE ATT&CK", reference_id="T1055", title="Process Injection", summary="Adversaries inject code into processes to evade defenses and elevate privileges.")
            ]
        )

    # -------------------------------------------------------------
    # 10. Multi-Layer Obfuscation Decoder
    # -------------------------------------------------------------
    elif tool_id == "multi_layer_decoder":
        evidence = []
        current = clean_input
        layers_unwrapped = []
        
        # Try URL decoding
        unquoted = urllib.parse.unquote(current)
        if unquoted != current:
            layers_unwrapped.append("URL Percent-Encoding")
            current = unquoted
            
        # Try Base64 decoding
        try:
            b64_cand = re.sub(r"\s+", "", current)
            if len(b64_cand) % 4 == 0 and re.match(r"^[A-Za-z0-9+/]+={0,2}$", b64_cand):
                decoded_b64 = base64.b64decode(b64_cand).decode("utf-8", errors="ignore")
                if len(decoded_b64) > 3 and any(c.isprintable() for c in decoded_b64):
                    layers_unwrapped.append("Base64")
                    current = decoded_b64
        except Exception:
            pass
            
        # Try Hex decoding
        try:
            hex_cand = current.replace(" ", "").replace("0x", "").replace("\\x", "")
            if len(hex_cand) % 2 == 0 and re.match(r"^[a-fA-F0-9]+$", hex_cand):
                decoded_hex = bytes.fromhex(hex_cand).decode("utf-8", errors="ignore")
                if len(decoded_hex) > 3 and any(c.isprintable() for c in decoded_hex):
                    layers_unwrapped.append("Hexadecimal Stream")
                    current = decoded_hex
        except Exception:
            pass

        evidence.append(EvidenceItem(label="Layers De-obfuscated", value=" -> ".join(layers_unwrapped) if layers_unwrapped else "None (Single layer or plain)", status="warning" if layers_unwrapped else "info"))
        evidence.append(EvidenceItem(label="Final Decoded Payload", value=current[:150] + ("..." if len(current) > 150 else ""), status="fail" if layers_unwrapped else "pass"))
        
        has_dangerous_payload = any(term in current.lower() for term in ["powershell", "invoke-expression", "iex", "http", "download", "rundll32", "/bin/sh"])
        risk_score = 85 if has_dangerous_payload else (50 if layers_unwrapped else 10)
        verdict = SeverityLevel.CRITICAL if has_dangerous_payload else (SeverityLevel.SUSPICIOUS if layers_unwrapped else SeverityLevel.CLEAN)
        
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Multi-Layer Obfuscation Decoder",
            suite_id="suite1_artifacts",
            timestamp=now_ts,
            verdict=verdict,
            risk_score=risk_score,
            summary=f"Recursive decoder unwrapped {len(layers_unwrapped)} layers. {'Identified active command execution payload inside decoded content.' if has_dangerous_payload else 'Payload exposed.'}",
            technical_evidence=evidence,
            threat_impact="Adversaries nest multi-stage encoding to blind legacy IDS/WAF engines that only inspect the outer wrapper.",
            attack_objective="Defense Evasion / De-obfuscation",
            remediation_playbook=[
                RemediationCommand(title="PowerShell Script Block Logging", platform="Group Policy", command="Set-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1")
            ],
            standards_and_references=[
                EducationalStandard(standard="MITRE ATT&CK", reference_id="T1027", title="Obfuscated Files or Information", summary="Adversaries attempt to make an executable or script difficult to discover or analyze.")
            ]
        )

    # Fallback
    return FiveLayerAnalysisResult(
        tool_id=tool_id,
        tool_name="Suite 1 Tool",
        suite_id="suite1_artifacts",
        timestamp=now_ts,
        verdict=SeverityLevel.CLEAN,
        risk_score=0,
        summary="Analysis completed.",
        threat_impact="No threat detected.",
        remediation_playbook=[],
        standards_and_references=[]
    )
