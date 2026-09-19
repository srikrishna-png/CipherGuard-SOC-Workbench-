import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from pathlib import Path

out_dir = Path(__file__).resolve().parent / "diagrams"
out_dir.mkdir(parents=True, exist_ok=True)

# -------------------------------------------------------------
# 1. System Architecture Diagram
# -------------------------------------------------------------
def create_architecture_diagram():
    fig, ax = plt.subplots(figsize=(12, 7.5), dpi=300)
    fig.patch.set_facecolor('#0f172a')  # Dark slate
    ax.set_facecolor('#0f172a')
    ax.axis('off')

    # Title Banner
    ax.text(6, 7.1, "CIPHERGUARD SYSTEM ARCHITECTURE", fontsize=18, fontweight='bold', color='#38bdf8', ha='center', fontfamily='sans-serif')
    ax.text(6, 6.75, "Modular 80-Tool Defensive Cybersecurity Analysis & Autonomous SOC Workbench", fontsize=10, color='#94a3b8', ha='center')

    # Top Layer: Presentation Tier
    ui_box = patches.FancyBboxPatch((0.5, 5.2), 11, 1.2, boxstyle="round,pad=0.1,rounding_size=0.15", facecolor='#1e293b', edgecolor='#38bdf8', linewidth=2)
    ax.add_patch(ui_box)
    ax.text(0.8, 6.0, "FRONTEND WORKBENCH LAYER (React 18 + TypeScript + Vite + Tailwind CSS)", fontsize=11, fontweight='bold', color='#f8fafc')
    ax.text(0.8, 5.6, "• 8-Suite Dynamic Tool Navigation Grid    • Glassmorphic Cyber Dark UI    • Real-Time Preset Loader\n• 5-Layer Visual Analysis Cards            • 1-Click Clipboard Output Buffer • Audit Chain Inspector Modal", fontsize=8.5, color='#cbd5e1')

    # Middle Connection Arrow
    ax.annotate('', xy=(6, 4.7), xytext=(6, 5.1), arrowprops=dict(facecolor='#38bdf8', edgecolor='#38bdf8', arrowstyle='<|-|>', lw=2))
    ax.text(6.2, 4.9, "REST API (JSON / WebSockets)", fontsize=8, color='#38bdf8', fontweight='bold')

    # Application / Core Layer
    app_box = patches.FancyBboxPatch((0.5, 3.4), 11, 1.2, boxstyle="round,pad=0.1,rounding_size=0.15", facecolor='#1e293b', edgecolor='#a855f7', linewidth=2)
    ax.add_patch(app_box)
    ax.text(0.8, 4.2, "CORE DISPATCHER & ASYNCHRONOUS BACKEND (FastAPI / Python 3.10+)", fontsize=11, fontweight='bold', color='#f8fafc')
    ax.text(0.8, 3.75, "• Asynchronous Request Router    • Pydantic v2 Schema Enforcement    • Real-Time Output Buffer Synthesizer\n• Heuristic & Regex Threat Engine • Sub-15ms Local Execution Pipeline    • Centralized Tool Registry", fontsize=8.5, color='#cbd5e1')

    # Middle Connection Arrow
    ax.annotate('', xy=(6, 2.9), xytext=(6, 3.3), arrowprops=dict(facecolor='#a855f7', edgecolor='#a855f7', arrowstyle='<|-|>', lw=2))
    ax.text(6.2, 3.1, "Internal Modular Bus", fontsize=8, color='#a855f7', fontweight='bold')

    # 8 Forensic Tool Suites Grid
    suites_box = patches.FancyBboxPatch((0.5, 1.4), 7.5, 1.4, boxstyle="round,pad=0.1,rounding_size=0.15", facecolor='#1e293b', edgecolor='#10b981', linewidth=2)
    ax.add_patch(suites_box)
    ax.text(0.8, 2.45, "80 SPECIALIZED FORENSIC DEFENSIVE TOOLS (8 SUITES)", fontsize=10.5, fontweight='bold', color='#34d399')
    ax.text(0.8, 1.6, "1. Artifacts & Phishing Analysis        5. Alerting & Incident Case Timelines\n2. Telemetry & Log Anomaly Analytics   6. Network Protocol & Volumetric Forensics\n3. Defense & Firewall Rule Synthesis    7. Threat Intelligence & MITRE Matrix\n4. Cryptography & Identity Forensics    8. Malware Triage & Opcode Disassembly", fontsize=8, color='#e2e8f0')

    # Cryptographic Ledger Box
    ledger_box = patches.FancyBboxPatch((8.3, 1.4), 3.2, 1.4, boxstyle="round,pad=0.1,rounding_size=0.15", facecolor='#1e293b', edgecolor='#f59e0b', linewidth=2)
    ax.add_patch(ledger_box)
    ax.text(8.5, 2.45, "SHA-256 AUDIT LEDGER", fontsize=10.5, fontweight='bold', color='#fbbf24')
    ax.text(8.5, 1.6, "• Genesis Block Anchor\n• Continuous Hash Chaining\n• Zero-Tamper Verification\n• SQLite3 WAL Data Store\n• Non-Repudiation Audit", fontsize=7.5, color='#fde68a')

    # Connect Suites to Ledger
    ax.annotate('', xy=(8.2, 2.1), xytext=(8.0, 2.1), arrowprops=dict(facecolor='#f59e0b', edgecolor='#f59e0b', arrowstyle='->', lw=2))

    # Bottom Synthesis Buffer Bar
    buf_box = patches.FancyBboxPatch((0.5, 0.2), 11, 0.8, boxstyle="round,pad=0.1,rounding_size=0.15", facecolor='#1e293b', edgecolor='#06b6d4', linewidth=1.5)
    ax.add_patch(buf_box)
    ax.text(0.8, 0.65, "DYNAMIC OUTPUT BUFFER & DEFENSIVE RULE SYNTHESIS ENGINE", fontsize=9.5, fontweight='bold', color='#22d3ee')
    ax.text(0.8, 0.35, "• YARA Detection Signatures • Suricata / Snort IDS Rules • Multi-Platform Firewall ACLs (iptables, nftables, PowerShell) • CISO Reports", fontsize=7.5, color='#94a3b8')

    ax.set_xlim(0, 12)
    ax.set_ylim(0, 7.5)
    plt.tight_layout()
    plt.savefig(out_dir / "cipherguard_architecture.png", dpi=300, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print("[+] Created cipherguard_architecture.png")

# -------------------------------------------------------------
# 2. Five Layer Analytical Standard Diagram
# -------------------------------------------------------------
def create_five_layer_diagram():
    fig, ax = plt.subplots(figsize=(11, 6.5), dpi=300)
    fig.patch.set_facecolor('#0f172a')
    ax.set_facecolor('#0f172a')
    ax.axis('off')

    ax.text(5.5, 6.0, "CIPHERGUARD 5-LAYER ANALYTICAL STANDARD", fontsize=16, fontweight='bold', color='#38bdf8', ha='center')
    ax.text(5.5, 5.65, "Standardized Multi-Tier Forensic Triage & Explanation Model", fontsize=9.5, color='#94a3b8', ha='center')

    layers = [
        ("LAYER 1: CATEGORICAL VERDICT", "CLEAN | SUSPICIOUS | MALICIOUS | CRITICAL", "#ef4444", 4.7),
        ("LAYER 2: MATHEMATICAL RISK SCORE", "Calibrated Numerical Index: 0 to 100 with Dynamic Threat Weighting", "#f97316", 3.7),
        ("LAYER 3: EMPIRICAL TECHNICAL EVIDENCE", "Key-Value Forensic Indicators: Entropy (bits), Inter-Arrival Deltas, Decoded IOCs", "#eab308", 2.7),
        ("LAYER 4: ACTIONABLE REMEDIATION PLAYBOOK", "Step-by-Step Incident Response Protocol: Containment, Isolation, Eradication", "#10b981", 1.7),
        ("LAYER 5: STANDARDS & EDUCATIONAL REFERENCES", "Direct Mapping: NIST SP 800-61r2, MITRE ATT&CK Matrix, RFC Protocols, ISO 27001", "#3b82f6", 0.7),
    ]

    for title, desc, color, y in layers:
        box = patches.FancyBboxPatch((0.8, y), 9.4, 0.75, boxstyle="round,pad=0.08,rounding_size=0.12", facecolor='#1e293b', edgecolor=color, linewidth=2)
        ax.add_patch(box)
        badge = patches.FancyBboxPatch((0.95, y + 0.1), 0.25, 0.55, boxstyle="round,pad=0.02", facecolor=color, edgecolor='none')
        ax.add_patch(badge)
        ax.text(1.4, y + 0.45, title, fontsize=10.5, fontweight='bold', color=color)
        ax.text(1.4, y + 0.18, desc, fontsize=8.5, color='#cbd5e1')

    ax.set_xlim(0, 11)
    ax.set_ylim(0, 6.5)
    plt.tight_layout()
    plt.savefig(out_dir / "five_layer_model.png", dpi=300, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print("[+] Created five_layer_model.png")

# -------------------------------------------------------------
# 3. Cryptographic Ledger Hash-Chaining Diagram
# -------------------------------------------------------------
def create_ledger_diagram():
    fig, ax = plt.subplots(figsize=(11, 5.5), dpi=300)
    fig.patch.set_facecolor('#0f172a')
    ax.set_facecolor('#0f172a')
    ax.axis('off')

    ax.text(5.5, 4.9, "SHA-256 HASH-CHAINED CRYPTOGRAPHIC AUDIT LEDGER", fontsize=15, fontweight='bold', color='#fbbf24', ha='center')
    ax.text(5.5, 4.55, "Mathematical Non-Repudiation & Tamper-Evident Forensic Chain of Custody", fontsize=9, color='#94a3b8', ha='center')

    blocks = [
        ("GENESIS BLOCK #0", "PrevHash: 0000...0000\nPayload: Root Anchor\nHash: 5e884898da28...", "#64748b", 0.5),
        ("BLOCK #1", "PrevHash: 5e884898da28...\nTool: url_analyzer\nVerdict: MALICIOUS (95)\nHash: a3c19f2b87e4...", "#38bdf8", 3.8),
        ("BLOCK #k (CURRENT)", "PrevHash: a3c19f2b87e4...\nTool: beaconing_analyzer\nVerdict: SUSPICIOUS (75)\nHash: 7f83b1657ff1...", "#10b981", 7.1),
    ]

    for title, content, color, x in blocks:
        box = patches.FancyBboxPatch((x, 1.5), 3.0, 2.4, boxstyle="round,pad=0.1,rounding_size=0.15", facecolor='#1e293b', edgecolor=color, linewidth=2)
        ax.add_patch(box)
        header_bar = patches.FancyBboxPatch((x, 3.3), 3.0, 0.6, boxstyle="round,pad=0.05,rounding_size=0.1", facecolor=color, edgecolor='none')
        ax.add_patch(header_bar)
        ax.text(x + 1.5, 3.55, title, fontsize=9.5, fontweight='bold', color='#0f172a', ha='center')
        ax.text(x + 0.2, 2.3, content, fontsize=7.5, color='#e2e8f0', linespacing=1.6)

    # Arrows between blocks
    ax.annotate('', xy=(3.7, 2.6), xytext=(3.55, 2.6), arrowprops=dict(facecolor='#fbbf24', edgecolor='#fbbf24', arrowstyle='->', lw=2.5))
    ax.annotate('', xy=(7.0, 2.6), xytext=(6.85, 2.6), arrowprops=dict(facecolor='#fbbf24', edgecolor='#fbbf24', arrowstyle='->', lw=2.5))

    # Verification banner at bottom
    ver_box = patches.FancyBboxPatch((0.5, 0.3), 9.6, 0.8, boxstyle="round,pad=0.08,rounding_size=0.1", facecolor='#064e3b', edgecolor='#34d399', linewidth=1.5)
    ax.add_patch(ver_box)
    ax.text(5.3, 0.75, "VERIFICATION ENGINE: Recalculates H_i = SHA256(i || Timestamp || Tool || H_{i-1}) across all blocks", fontsize=8.5, fontweight='bold', color='#6ee7b7', ha='center')
    ax.text(5.3, 0.45, "Result: 0 Tampered Blocks | 100% Valid Chain Integrity | Legally Admissible Digital Audit Trail", fontsize=8, color='#a7f3d0', ha='center')

    ax.set_xlim(0, 11)
    ax.set_ylim(0, 5.5)
    plt.tight_layout()
    plt.savefig(out_dir / "ledger_blockchain_flow.png", dpi=300, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print("[+] Created ledger_blockchain_flow.png")

# -------------------------------------------------------------
# 4. 8-Suite Ecosystem Infographic
# -------------------------------------------------------------
def create_suite_ecosystem_diagram():
    fig, ax = plt.subplots(figsize=(12, 7.0), dpi=300)
    fig.patch.set_facecolor('#0f172a')
    ax.set_facecolor('#0f172a')
    ax.axis('off')

    ax.text(6, 6.5, "CIPHERGUARD 8-SUITE DEFENSIVE ECOSYSTEM", fontsize=16, fontweight='bold', color='#38bdf8', ha='center')
    ax.text(6, 6.15, "80 Specialized Tools Spanning the Entire Incident Detection & Response Lifecycle", fontsize=9.5, color='#94a3b8', ha='center')

    suites_data = [
        ("Suite 1: Artifacts & Phishing", "10 Tools: URL analyzer, email header tracer, SPF/DKIM, IOC extractor, decoders", "#38bdf8", 0.5, 4.4),
        ("Suite 2: Telemetry & Logs", "10 Tools: Access logs, brute-force detector, bot fingerprinter, beaconing analyzer", "#06b6d4", 6.2, 4.4),
        ("Suite 3: Defense & Mitigation", "10 Tools: YARA generator, Suricata/Snort builder, multi-target firewall synthesizer", "#10b981", 0.5, 3.0),
        ("Suite 4: Crypto & Identity", "10 Tools: Cert decoder, JWT tamper inspector, Shannon entropy, secret leak scanner", "#8b5cf6", 6.2, 3.0),
        ("Suite 5: Alerting & Incident", "10 Tools: Case timeline builder, CISO executive report generator, alert dedup", "#f59e0b", 0.5, 1.6),
        ("Suite 6: Network Protocol", "10 Tools: Subnet/CIDR router, bandwidth flow estimator, DNS tunnel detector", "#ec4899", 6.2, 1.6),
        ("Suite 7: Threat Intelligence", "10 Tools: Diamond Model classifier, MITRE ATT&CK mapper, CVSS v3.1 scorer", "#f97316", 0.5, 0.2),
        ("Suite 8: Malware & RE", "10 Tools: PE header inspector, opcode disassembly triage, string carver", "#ef4444", 6.2, 0.2),
    ]

    for title, desc, color, x, y in suites_data:
        box = patches.FancyBboxPatch((x, y), 5.3, 1.0, boxstyle="round,pad=0.08,rounding_size=0.12", facecolor='#1e293b', edgecolor=color, linewidth=1.8)
        ax.add_patch(box)
        dot = patches.Circle((x + 0.35, y + 0.5), 0.15, facecolor=color, edgecolor='none')
        ax.add_patch(dot)
        ax.text(x + 0.7, y + 0.65, title, fontsize=9.5, fontweight='bold', color=color)
        ax.text(x + 0.7, y + 0.25, desc, fontsize=7.5, color='#cbd5e1')

    ax.set_xlim(0, 12)
    ax.set_ylim(0, 7.0)
    plt.tight_layout()
    plt.savefig(out_dir / "suite_ecosystem.png", dpi=300, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print("[+] Created suite_ecosystem.png")

if __name__ == "__main__":
    create_architecture_diagram()
    create_five_layer_diagram()
    create_ledger_diagram()
    create_suite_ecosystem_diagram()
    print("[✓] All 4 diagrams successfully generated!")
