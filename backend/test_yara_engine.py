import re
import hashlib
from datetime import datetime, timezone

def generate_or_analyze_yara(input_text: str, params: dict = None):
    params = params or {}
    now_ts = datetime.now(timezone.utc).isoformat()
    clean_input = input_text.strip()
    low_input = clean_input.lower()
    lines = [l.strip() for l in clean_input.splitlines() if l.strip()]

    # Check if input is already a YARA rule (Analysis Mode)
    is_existing_rule = (
        clean_input.startswith("rule ") or 
        ("strings:" in low_input and "condition:" in low_input)
    )

    if is_existing_rule:
        # Validate YARA rule structure
        has_meta = "meta:" in low_input
        has_strings = "strings:" in low_input
        has_condition = "condition:" in low_input

        string_vars = re.findall(r'(\$[a-zA-Z0-9_]+)\s*=', clean_input)
        condition_block = ""
        cond_m = re.search(r'condition:\s*(.+)$', clean_input, re.DOTALL | re.IGNORECASE)
        if cond_m:
            condition_block = cond_m.group(1).strip().split('}')[0].strip()

        # Check for common YARA traps/warnings
        warnings = []
        if "any of them" in condition_block.lower() and len(string_vars) > 1:
            short_strings = [s for s in re.findall(r'=\s*"([^"]+)"', clean_input) if len(s) < 5]
            if short_strings:
                warnings.append(f"High false-positive risk: 'any of them' used with short strings ({short_strings})")
        if "filesize" not in condition_block.lower():
            warnings.append("Performance recommendation: Add filesize constraint (e.g. 'filesize < 10MB') to prevent scanner timeouts")

        is_valid = has_condition and (has_strings or "filesize" in condition_block.lower() or "uint" in condition_block.lower())
        verdict = "SUSPICIOUS" if warnings else "CLEAN"
        risk_score = 45 if warnings else 0
        
        return {
            "mode": "analysis",
            "verdict": verdict,
            "risk_score": risk_score,
            "rule_name": re.search(r'rule\s+([a-zA-Z0-9_]+)', clean_input).group(1) if re.search(r'rule\s+([a-zA-Z0-9_]+)', clean_input) else "Parsed_Rule",
            "string_count": len(string_vars),
            "warnings": warnings,
            "condition": condition_block,
            "yara_code": clean_input
        }

    # Generation Mode
    # 1. Determine Dynamic Rule Name
    rule_name = params.get("rule_name")
    mitre_technique = "T1027"
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
            # Derive sanitized name from first line
            first_clean = re.sub(r'[^a-zA-Z0-9_]', '_', lines[0][:25]).strip('_')
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

        # Check for explicit hex block: e.g. { 4D 5A 90 00 } or 4D 5A 90 00
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
            # Regex pattern
            strings_entries.append(f'        $re{idx} = {line} nocase')
            idx += 1
        else:
            # Text string
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
        # For multiple strings: require majority or all
        conditions.append(f"{min(3, total_strings)} of them")

    condition_str = " and\n        ".join(conditions)

    # 4. Generate YARA Rule
    input_hash = hashlib.sha256(clean_input.encode('utf-8')).hexdigest()[:16]
    yara_code = f"""rule {rule_name} {{
    meta:
        description = "Automated threat detection signature for {category}"
        author = "CipherGuard SOC Workbench"
        date = "{now_ts[:10]}"
        mitre_technique = "{mitre_technique}"
        rule_hash = "{input_hash}"
        severity = "{severity}"
    strings:
{chr(10).join(strings_entries)}
    condition:
        {condition_str}
}}"""

    return {
        "mode": "generation",
        "verdict": "CLEAN",
        "risk_score": 0,
        "rule_name": rule_name,
        "category": category,
        "mitre_technique": mitre_technique,
        "strings_count": total_strings,
        "yara_code": yara_code
    }

# Test Cases
t1 = """sekurlsa::logonpasswords
wdigest.dll
lsass.exe"""

t2 = """vssadmin.exe delete shadows /all /quiet
wbadmin delete catalog -quiet
bcdedit /set {default} recoveryenabled No"""

t3 = """{ 6A 40 68 00 30 00 00 6A 14 8D 95 }
VirtualAlloc
CreateRemoteThread"""

t4 = """rule Suspicious_Rule {
    meta:
        author = "Attacker"
    strings:
        $s1 = "cmd"
        $s2 = "net"
    condition:
        any of them
}"""

for idx, t in enumerate([t1, t2, t3, t4], 1):
    r = generate_or_analyze_yara(t)
    print(f"--- Case {idx}: {r['rule_name']} ({r['mode']}) ---")
    print(r['yara_code'])
    print()
