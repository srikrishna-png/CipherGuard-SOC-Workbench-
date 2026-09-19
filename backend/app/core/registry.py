import time
from typing import Dict, Any, Tuple
from app.models.schemas import FiveLayerAnalysisResult, SeverityLevel
from app.core.ledger import record_analysis_event
from app.suites.suite1_artifacts import run_suite1_tool
from app.suites.suite2_telemetry import run_suite2_tool
from app.suites.suite3_defense import run_suite3_tool
from app.suites.suite4_crypto import run_suite4_tool
from app.suites.suite5_alerting import run_suite5_tool
from app.suites.suite6_network import run_suite6_tool
from app.suites.suite7_forensics import run_suite7_tool
from app.suites.suite8_threatintel import run_suite8_tool

TOOL_TO_SUITE = {
    # Suite 1
    "url_analyzer": "suite1_artifacts",
    "email_header_tracer": "suite1_artifacts",
    "spf_dkim_validator": "suite1_artifacts",
    "phishing_lure_scorer": "suite1_artifacts",
    "ioc_extractor": "suite1_artifacts",
    "defanger_refanger": "suite1_artifacts",
    "file_hash_calculator": "suite1_artifacts",
    "entropy_calculator": "suite1_artifacts",
    "embedded_string_carver": "suite1_artifacts",
    "multi_layer_decoder": "suite1_artifacts",
    
    # Suite 2
    "access_log_parser": "suite2_telemetry",
    "web_attack_scanner": "suite2_telemetry",
    "brute_force_detector": "suite2_telemetry",
    "bot_fingerprinter": "suite2_telemetry",
    "windows_event_analyzer": "suite2_telemetry",
    "sigma_evaluator": "suite2_telemetry",
    "statistical_anomaly": "suite2_telemetry",
    "useragent_inspector": "suite2_telemetry",
    "log_timeline_merger": "suite2_telemetry",
    "beaconing_analyzer": "suite2_telemetry",
    
    # Suite 3
    "yara_generator": "suite3_defense",
    "sigma_synthesizer": "suite3_defense",
    "suricata_builder": "suite3_defense",
    "suricata_rule_builder": "suite3_defense",
    "firewall_synthesizer": "suite3_defense",
    "firewall_rule_synthesizer": "suite3_defense",
    "security_headers_auditor": "suite3_defense",
    "server_hardener": "suite3_defense",
    "password_validator": "suite3_defense",
    "password_policy_tester": "suite3_defense",
    "cors_checker": "suite3_defense",
    "security_txt_gen": "suite3_defense",
    "cis_checklist_gen": "suite3_defense",
    "csp_generator": "suite3_defense",
    "linux_hardening_audit": "suite3_defense",
    "windows_audit_policy": "suite3_defense",
    "waf_rule_generator": "suite3_defense",
    "dns_rpz_generator": "suite3_defense",
    "honeytoken_generator": "suite3_defense",
    
    # Suite 4
    "fim_engine": "suite4_crypto",
    "aes_gcm_suite": "suite4_crypto",
    "rsa_signature_suite": "suite4_crypto",
    "crypto_benchmark": "suite4_crypto",
    "secret_leak_scanner": "suite4_crypto",
    "hmac_authenticator": "suite4_crypto",
    "x509_decoder": "suite4_crypto",
    "cert_decoder": "suite4_crypto",
    "stego_detector": "suite4_crypto",
    "hash_identifier": "suite4_crypto",
    "diffie_hellman_sim": "suite4_crypto",
    "diffie_hellman_params": "suite4_crypto",
    "jwt_inspector": "suite4_crypto",
    "entropy_density": "suite4_crypto",
    "ssh_key_auditor": "suite4_crypto",
    "password_hash_cracker": "suite4_crypto",
    "rsa_key_validator": "suite4_crypto",
    
    # Suite 5
    "alert_scorer": "suite5_alerting",
    "triage_scorer": "suite5_alerting",
    "dedup_flapping_filter": "suite5_alerting",
    "alert_deduplicator": "suite5_alerting",
    "webhook_dispatcher": "suite5_alerting",
    "email_dispatcher": "suite5_alerting",
    "mitre_tagger": "suite5_alerting",
    "case_timeline_builder": "suite5_alerting",
    "runbook_selector": "suite5_alerting",
    "containment_playbook": "suite5_alerting",
    "evidence_locker": "suite5_alerting",
    "evidence_hash_verifier": "suite5_alerting",
    "report_generator": "suite5_alerting",
    "shift_handover_gen": "suite5_alerting",
    "false_positive_analyzer": "suite5_alerting",
    "forensic_artifact_collector": "suite5_alerting",
    "severity_calculator": "suite5_alerting",
    "escalation_matrix": "suite5_alerting",
    
    # Suite 6
    "pcap_inspector": "suite6_network",
    "dns_inspector": "suite6_network",
    "dns_tunnel_detector": "suite6_network",
    "http_dissector": "suite6_network",
    "subnet_calculator": "suite6_network",
    "port_risk_catalog": "suite6_network",
    "port_reference": "suite6_network",
    "tcp_flag_analyzer": "suite6_network",
    "tls_cipher_auditor": "suite6_network",
    "tls_sni_inspector": "suite6_network",
    "mac_oui_resolver": "suite6_network",
    "bandwidth_estimator": "suite6_network",
    "proxy_header_validator": "suite6_network",
    "packet_loss_estimator": "suite6_network",
    "mtu_overhead_calculator": "suite6_network",
    "dhcp_lease_parser": "suite6_network",
    "vlan_hopping_analyzer": "suite6_network",
    "tcp_handshake_auditor": "suite6_network",
    
    # Suite 7
    "prefetch_parser": "suite7_forensics",
    "shimcache_inspector": "suite7_forensics",
    "browser_carver": "suite7_forensics",
    "usb_auditor": "suite7_forensics",
    "task_cron_inspector": "suite7_forensics",
    "autorun_analyzer": "suite7_forensics",
    "metadata_exif_extractor": "suite7_forensics",
    "magic_byte_identifier": "suite7_forensics",
    "lnk_parser": "suite7_forensics",
    "process_tree_detector": "suite7_forensics",
    "diamond_model_classifier": "suite8_threatintel",
    "mitre_technique_mapper": "suite8_threatintel",
    "cvss_calculator": "suite8_threatintel",
    "threat_actor_profiler": "suite8_threatintel",
    "cisa_kev_lookup": "suite8_threatintel",
    "kill_chain_mapper": "suite8_threatintel",
    "asn_geo_lookup": "suite8_threatintel",
    "darkweb_mention_monitor": "suite8_threatintel",
    
    # Suite 8
    "cve_search": "suite8_threatintel",
    "mitre_navigator": "suite8_threatintel",
    "asn_resolver": "suite8_threatintel",
    "whois_auditor": "suite8_threatintel",
    "ct_log_search": "suite8_threatintel",
    "apt_profile_viewer": "suite8_threatintel",
    "cisa_kev_checker": "suite8_threatintel",
    "dnsbl_checker": "suite8_threatintel",
    "advisory_library": "suite8_threatintel",
    "stix_feed_parser": "suite8_threatintel",
    "pe_header_inspector": "suite7_forensics",
    "opcode_disassembler": "suite7_forensics",
    "imphash_calculator": "suite7_forensics",
    "section_entropy_mapper": "suite7_forensics",
    "dll_dependency_walker": "suite7_forensics",
    "string_obfuscation_detector": "suite7_forensics",
    "packed_executable_detector": "suite7_forensics",
    "syscall_tracer": "suite7_forensics",
    "function_prologue_detector": "suite7_forensics",
    "yara_rule_tester": "suite7_forensics",
}

TOOL_ALIASES = {
    # Suite 1
    "punycode_detector": "url_analyzer",
    "file_entropy_calculator": "entropy_calculator",
    "macro_vba_scanner": "embedded_string_carver",
    "pdf_stream_dissector": "embedded_string_carver",
    "powershell_deobfuscator": "multi_layer_decoder",

    # Suite 2
    "sigma_rule_linter": "sigma_evaluator",
    "suricata_snort_verifier": "suricata_builder",
    "linux_audit_inspector": "access_log_parser",
    "dns_tunnel_detector": "dns_inspector",
    "waf_bypass_tester": "web_attack_scanner",
    "user_agent_auditor": "useragent_inspector",

    # Suite 3
    "iam_policy_analyzer": "server_hardener",
    "s3_bucket_checker": "server_hardener",
    "dockerfile_linter": "server_hardener",
    "k8s_manifest_auditor": "server_hardener",
    "linux_kernel_checker": "server_hardener",
    "cors_misconfig_tester": "cors_checker",
    "security_headers_scorer": "security_headers_auditor",
    "open_port_mapper": "port_risk_catalog",
    "ssh_config_hardener": "server_hardener",
    "ad_gpo_auditor": "server_hardener",

    # Suite 4
    "x509_cert_validator": "x509_decoder",
    "password_entropy_meter": "password_validator",
    "tls_cipher_evaluator": "tls_cipher_auditor",
    "totp_generator_validator": "hmac_authenticator",
    "jwt_security_inspector": "secret_leak_scanner",
    "pgp_key_inspector": "rsa_signature_suite",
    "ssh_key_strength_auditor": "rsa_signature_suite",
    "weak_hash_identifier": "hash_identifier",
    "ntlm_kerberos_auditor": "secret_leak_scanner",

    # Suite 5
    "pe_header_parser": "magic_byte_identifier",
    "elf_header_analyzer": "magic_byte_identifier",
    "yara_compiler_tester": "yara_generator",
    "shellcode_emulator": "multi_layer_decoder",
    "xor_decoder": "multi_layer_decoder",
    "string_packer_detector": "embedded_string_carver",
    "ghidra_script_formatter": "embedded_string_carver",
    "import_table_auditor": "embedded_string_carver",
    "android_manifest_linter": "server_hardener",
    "firmware_header_scanner": "magic_byte_identifier",

    # Suite 6
    "pcap_dns_extractor": "dns_inspector",
    "http_request_reassembler": "http_dissector",
    "tcp_syn_sweep_detector": "statistical_anomaly",
    "arp_spoof_detector": "pcap_inspector",
    "tls_sni_inspector": "tls_cipher_auditor",
    "icmp_tunnel_detector": "pcap_inspector",
    "dhcp_starvation_detector": "statistical_anomaly",
    "snmp_community_auditor": "secret_leak_scanner",
    "ntp_monlist_detector": "statistical_anomaly",

    # Suite 7
    "mft_entry_parser": "task_cron_inspector",
    "shimcache_amcache_parser": "shimcache_inspector",
    "lnk_file_dissector": "lnk_parser",
    "browser_history_extractor": "browser_carver",
    "scheduled_task_auditor": "task_cron_inspector",
    "memory_dump_string_extractor": "embedded_string_carver",
    "ransom_note_classifier": "phishing_lure_scorer",

    # Suite 8
    "cve_scoring_calculator": "cve_search",
    "epss_score_lookup": "cve_search",
    "threat_actor_profiler": "apt_profile_viewer",
    "mitre_matrix_mapper": "mitre_navigator",
    "asn_ip_reputation_checker": "asn_resolver",
    "whois_age_scorer": "whois_auditor",
    "stix_taxii_linter": "stix_feed_parser",
    "vuln_remediation_prioritizer": "cve_search"
}

# Register aliases into TOOL_TO_SUITE
for alias, target in TOOL_ALIASES.items():
    if target in TOOL_TO_SUITE:
        TOOL_TO_SUITE[alias] = TOOL_TO_SUITE[target]

SUITE_HANDLERS = {
    "suite1_artifacts": run_suite1_tool,
    "suite2_telemetry": run_suite2_tool,
    "suite3_defense": run_suite3_tool,
    "suite4_crypto": run_suite4_tool,
    "suite5_alerting": run_suite5_tool,
    "suite6_network": run_suite6_tool,
    "suite7_forensics": run_suite7_tool,
    "suite8_threatintel": run_suite8_tool,
}

def execute_tool(tool_id: str, input_text: str, params: Dict[str, Any], actor: str = "SOC_ANALYST_01") -> FiveLayerAnalysisResult:
    start_time = time.perf_counter()
    target_id = TOOL_ALIASES.get(tool_id, tool_id)
    suite_id = TOOL_TO_SUITE.get(tool_id, TOOL_TO_SUITE.get(target_id, "suite1_artifacts"))
    handler = SUITE_HANDLERS.get(suite_id, run_suite1_tool)
    
    # Execute analysis engine
    result = handler(target_id, input_text, params)
    result.tool_id = tool_id

    # Apply specialized threat heuristics for all 80 tools
    try:
        from app.core.threat_engine import evaluate_specialized_threat
        result = evaluate_specialized_threat(tool_id, input_text, result)
    except Exception:
        pass
    
    exec_time = round((time.perf_counter() - start_time) * 1000, 2)
    result.execution_time_ms = exec_time
    
    # Record event into cryptographic SHA-256 tamper-evident ledger
    audit_hash = record_analysis_event(
        tool_id=tool_id,
        input_data=input_text,
        verdict=result.verdict.value,
        risk_score=result.risk_score,
        actor=actor
    )
    result.audit_hash = audit_hash
    
    return result
