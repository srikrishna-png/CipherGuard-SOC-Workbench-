import os
import re
from typing import List, Dict, Any, Optional
from app.core.registry import TOOL_TO_SUITE

SYSTEM_INSTRUCTION = """You are A.E.G.I.S. (Autonomous Expert Guide for Incident Security), the defensive cybersecurity AI copilot inside the CipherGuard SOC Workbench.
Your primary role is to guide SOC analysts and cybersecurity students on how to use CipherGuard's 80 specialized tools across its 8 suites, understand tool capabilities, interpret verdicts, explain mathematical models, and recommend triage workflows.

CIPHERGUARD SUITE & TOOL CATALOG (8 Suites, 80 Tools):
- Suite 1 (Artifacts & Phishing): url_analyzer, email_header_tracer, spf_dkim_validator, phishing_lure_scorer, ioc_extractor, defanger_refanger, file_hash_calculator, entropy_calculator, embedded_string_carver, multi_layer_decoder.
- Suite 2 (Telemetry & Log Analysis): access_log_parser, web_attack_scanner, brute_force_detector, bot_fingerprinter, windows_event_analyzer, sigma_evaluator, statistical_anomaly, useragent_inspector, log_timeline_merger, beaconing_analyzer.
- Suite 3 (Defense, Hardening & Mitigation): yara_generator, suricata_rule_builder, firewall_rule_synthesizer, csp_generator, password_policy_tester, linux_hardening_audit, windows_audit_policy, waf_rule_generator, dns_rpz_generator, honeytoken_generator.
- Suite 4 (Cryptography & Identity Forensics): cert_decoder, jwt_inspector, hash_identifier, secret_leak_scanner, tls_cipher_auditor, entropy_density, diffie_hellman_params, ssh_key_auditor, password_hash_cracker, rsa_key_validator.
- Suite 5 (Incident Response & Alert Engineering): alert_deduplicator, triage_scorer, case_timeline_builder, report_generator, containment_playbook, false_positive_analyzer, forensic_artifact_collector, evidence_hash_verifier, severity_calculator, escalation_matrix.
- Suite 6 (Network Protocol & Traffic Forensics): subnet_calculator, bandwidth_estimator, port_reference, dns_tunnel_detector, packet_loss_estimator, mtu_overhead_calculator, dhcp_lease_parser, vlan_hopping_analyzer, tls_sni_inspector, tcp_handshake_auditor.
- Suite 7 (Threat Intelligence & Adversary Profiling): diamond_model_classifier, mitre_technique_mapper, cvss_calculator, threat_actor_profiler, cisa_kev_lookup, cve_search, kill_chain_mapper, asn_geo_lookup, ct_log_search, darkweb_mention_monitor.
- Suite 8 (Reverse Engineering & Malware Triage): pe_header_inspector, opcode_disassembler, imphash_calculator, section_entropy_mapper, dll_dependency_walker, string_obfuscation_detector, packed_executable_detector, syscall_tracer, function_prologue_detector, yara_rule_tester.

5-LAYER ANALYTICAL STANDARD:
1. Verdict: Categorical state (CLEAN, SUSPICIOUS, MALICIOUS, CRITICAL).
2. Risk Score: 0-100 numerical index.
3. Technical Evidence: Key-value empirical indicators (entropy, inter-arrival intervals, decoded payloads).
4. Actionable Remediation Playbook: Step-by-step SOC containment procedures.
5. Educational References & Regulatory: NIST SP 800-61r2, MITRE ATT&CK, RFC protocols, ISO 27001.

CRYPTOGRAPHIC AUDIT LEDGER:
All analysis events are anchored into a SHA-256 hash-chained block ledger (H_k = SHA256(k || timestamp || tool || verdict || H_k-1)), guaranteeing forensic non-repudiation and zero-tamper verification.

GUIDANCE RULES:
1. Always be concise, highly technical, and practical.
2. Whenever recommending a tool, explicitly name the tool id (e.g. `beaconing_analyzer`, `yara_generator`, `url_analyzer`) so the analyst knows which tool to open.
3. Provide brief sample payloads when explaining how to test a tool.
4. Format responses in clean Markdown with bullet points and code blocks.
"""

def generate_local_knowledge_reply(user_query: str, current_tool_id: Optional[str] = None) -> str:
    """Fallback intelligent knowledge base engine when no Gemini API key is configured."""
    q = user_query.lower()

    if "beacon" in q or "c2" in q or "heartbeat" in q or "jitter" in q:
        return (
            "### 📡 Beaconing & Heartbeat Analysis (`beaconing_analyzer`)\n\n"
            "**Tool ID:** `beaconing_analyzer` (Suite 2: Telemetry & Log Analysis)\n\n"
            "**How it works:**\n"
            "Evaluates time-series timestamps or HTTP/DNS event intervals. Computes the **Coefficient of Variation ($CV = \\frac{\\sigma}{\\mu}$)** across inter-arrival deltas:\n"
            "- **Fixed Heartbeat ($CV < 0.05$):** Identifies automated C2 malware callback scripts (e.g., requests exactly every 60s).\n"
            "- **Jittered Beaconing ($0.05 \\le CV \\le 0.20$):** Detects randomized intervals designed to evade static thresholds.\n"
            "- **Human Browsing ($CV > 0.20$):** Clean user traffic with irregular pauses.\n\n"
            "**Sample Test Input:**\n"
            "```text\n"
            "14:00:00 -> 198.51.100.22:443 (128 bytes)\n"
            "14:01:00 -> 198.51.100.22:443 (128 bytes)\n"
            "14:02:00 -> 198.51.100.22:443 (128 bytes)\n"
            "```"
        )

    if "entropy" in q or "packer" in q or "shannon" in q or "obfuscat" in q:
        return (
            "### 🎲 Shannon Entropy Calculation (`entropy_calculator`)\n\n"
            "**Tool ID:** `entropy_calculator` (Suite 1) and `section_entropy_mapper` (Suite 8)\n\n"
            "**Mathematical Model:**\n"
            "$$H(X) = -\\sum_{i=1}^n P(x_i) \\log_2 P(x_i)$$\n\n"
            "**Interpretation Thresholds:**\n"
            "- **$H > 7.2$ bits/byte:** Highly compressed, packed, or encrypted payload (e.g., Cobalt Strike beacon, packed shellcode).\n"
            "- **$4.5 \\le H \\le 7.2$ bits/byte:** Typical compiled binary code (`.text` sections) or mixed base64.\n"
            "- **$H < 4.5$ bits/byte:** Plaintext English, JSON, source code, or repetitive zero padding.\n\n"
            "**Usage:** Paste raw hex strings, base64 payloads, or binary byte dumps into `entropy_calculator`."
        )

    if "yara" in q or "signature" in q:
        return (
            "### 🧬 YARA Detection Rule Generator (`yara_generator`)\n\n"
            "**Tool ID:** `yara_generator` (Suite 3: Defense, Hardening & Mitigation)\n\n"
            "**Capability:**\n"
            "Automatically tokenizes suspicious strings, imported APIs, or hex patterns and synthesizes a production-ready YARA rule. Output is placed directly into the 1-click **Output Buffer** for instant deployment.\n\n"
            "**Sample Input:**\n"
            "```text\n"
            "sekurlsa::logonpasswords\n"
            "wdigest.dll\n"
            "lsass.exe\n"
            "```\n\n"
            "**Generated Rule Example:**\n"
            "```yara\n"
            "rule Detect_Threat_Payload {\n"
            "    strings:\n"
            "        $s1 = \"sekurlsa::logonpasswords\" ascii wide\n"
            "        $s2 = \"wdigest.dll\" ascii wide\n"
            "    condition:\n"
            "        all of them\n"
            "}\n"
            "```"
        )

    if "subnet" in q or "cidr" in q or "route" in q or "ip" in q:
        return (
            "### 🌐 Subnet & CIDR Route Calculator (`subnet_calculator`)\n\n"
            "**Tool ID:** `subnet_calculator` (Suite 6: Network Protocol & Traffic Forensics)\n\n"
            "**Capability:**\n"
            "Sanitizes network descriptions and extracts canonical CIDR notation (e.g., `192.168.10.0/24`). Calculates usable host ranges, broadcast address, netmask, and wildcard mask, and outputs ready-to-run routing commands:\n"
            "- **Linux:** `ip route add 192.168.10.0/24 via 10.0.0.1`\n"
            "- **Windows PowerShell:** `New-NetRoute -DestinationPrefix 192.168.10.0/24 -NextHop 10.0.0.1`\n"
            "- **Cisco IOS:** `ip route 192.168.10.0 255.255.255.0 10.0.0.1`"
        )

    if "bandwidth" in q or "flow" in q or "pps" in q or "volumetric" in q:
        return (
            "### ⚡ Volumetric Flow & Bandwidth Estimator (`bandwidth_estimator`)\n\n"
            "**Tool ID:** `bandwidth_estimator` (Suite 6)\n\n"
            "**Formulas:**\n"
            "- **L3/L4 Bandwidth:** $\\text{PPS} \\times \\text{Packet Size (Bytes)} \\times 8$\n"
            "- **Physical Wire Rate:** $\\text{PPS} \\times (\\text{Packet Size} + 38 \\text{ bytes overhead}) \\times 8$\n"
            "- **Verification Example:** $10,000\\text{ PPS} \\times 1500\\text{ Bytes} = 120.00\\text{ Mbps}$."
        )

    if "ledger" in q or "blockchain" in q or "audit" in q or "tamper" in q:
        return (
            "### 🔒 SHA-256 Tamper-Evident Cryptographic Ledger\n\n"
            "CipherGuard guarantees legal non-repudiation and evidence integrity through an internal blockchain-modeled ledger:\n\n"
            "- **Genesis Block Anchor:** `SHA256(\"0000...0000\")`.\n"
            "- **Chain Invariant:** Every event block $k$ links to block $k-1$:\n"
            "  $$H_k = \\text{SHA256}(k \\parallel \\text{timestamp} \\parallel \\text{tool} \\parallel \\text{verdict} \\parallel H_{k-1})$$\n"
            "- **Verification Engine:** Traverses all records on demand to confirm 0 tampered blocks. Click **'Audit Ledger'** in the top navigation bar to inspect the live chain."
        )

    # General fallback overview
    return (
        "### 🛡️ A.E.G.I.S. SOC Assistant\n\n"
        f"I am ready to help you navigate CipherGuard's **80 cybersecurity tools** across **8 specialized suites**.\n\n"
        "**Popular Questions You Can Ask:**\n"
        "- *'Which tool analyzes C2 beaconing intervals?'* &rarr; `beaconing_analyzer`\n"
        "- *'How do I generate multi-platform firewall rules?'* &rarr; `firewall_rule_synthesizer`\n"
        "- *'How does the Shannon entropy calculator work?'* &rarr; `entropy_calculator`\n"
        "- *'What tool parses out-of-order security incident logs into a timeline?'* &rarr; `case_timeline_builder`\n"
        "- *'How does the cryptographic SHA-256 ledger prevent evidence tampering?'*\n\n"
        "*Tip: You can also enter your personal **Gemini API Key** in the Assistant Settings to unlock unrestricted generative AI capabilities.*"
    )

def ask_gemini_assistant(messages: List[Dict[str, str]], api_key: Optional[str] = None, current_tool_id: Optional[str] = None) -> str:
    """Invokes Gemini API via google-genai SDK if key is present, otherwise falls back to local knowledge engine."""
    resolved_key = api_key or os.environ.get("GEMINI_API_KEY")
    user_latest = messages[-1]["content"] if messages else "Hello"

    if not resolved_key:
        return generate_local_knowledge_reply(user_latest, current_tool_id)

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=resolved_key)
        
        # Build prompt context
        tool_ctx = f"\nUser is currently viewing tool: `{current_tool_id}`" if current_tool_id else ""
        system_prompt = SYSTEM_INSTRUCTION + tool_ctx

        # Format conversation history for Gemini
        conversation_contents = []
        for msg in messages:
            role = "user" if msg.get("role") in ["user", "human"] else "model"
            conversation_contents.append(
                types.Content(
                    role=role,
                    parts=[types.Part.from_text(text=msg.get("content", ""))]
                )
            )

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=conversation_contents,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                temperature=0.3,
                max_output_tokens=1500
            )
        )

        if response and response.text:
            return response.text
        return generate_local_knowledge_reply(user_latest, current_tool_id)

    except Exception as e:
        # If Gemini API returns an error (e.g. quota, invalid key), provide helpful error and fallback
        fallback = generate_local_knowledge_reply(user_latest, current_tool_id)
        return f"{fallback}\n\n*(Note: Gemini live API encountered: `{str(e)}`. Returned verified offline SOC response.)*"
