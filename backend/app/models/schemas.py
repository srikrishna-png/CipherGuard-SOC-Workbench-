from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from enum import Enum

class SeverityLevel(str, Enum):
    CLEAN = "CLEAN"
    LOW = "LOW"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    CRITICAL = "CRITICAL"

class EvidenceItem(BaseModel):
    label: str
    value: str
    status: str = "info"  # "pass", "warning", "fail", "info"
    description: Optional[str] = None

class RemediationCommand(BaseModel):
    title: str
    platform: str  # "Linux (iptables)", "Windows (PowerShell)", "YARA", "Sigma", "Nginx", "Generic"
    command: str
    description: Optional[str] = None

class EducationalStandard(BaseModel):
    standard: str  # "MITRE ATT&CK", "NIST SP 800-61", "RFC 822", "CIS Benchmark", "OWASP"
    reference_id: str  # e.g., "T1059.001", "RFC 5321", "NIST PR.AC-1"
    title: str = "Standard Reference"
    url: Optional[str] = None
    summary: str = ""

class FiveLayerAnalysisResult(BaseModel):
    tool_id: str
    tool_name: str
    suite_id: str
    timestamp: str

    # Layer 1: Executive Verdict & Severity
    verdict: SeverityLevel
    risk_score: int = Field(ge=0, le=100, description="Risk Score from 0 to 100")
    summary: str

    # Layer 2: Technical Evidence Breakdown
    technical_evidence: List[EvidenceItem] = Field(default_factory=list)

    # Layer 3: Threat Impact ("Why It Matters")
    threat_impact: str
    attack_objective: Optional[str] = None

    # Layer 4: Actionable Remediation Playbook
    remediation_playbook: List[RemediationCommand] = Field(default_factory=list)

    # Layer 5: Educational Deep Dive & Standards
    standards_and_references: List[EducationalStandard] = Field(default_factory=list)

    # Cryptographic verification info
    audit_hash: Optional[str] = None
    execution_time_ms: float = 0.0

    # Payload buffer & cryptographic artifact exchange
    generated_payload: Optional[str] = None
    extracted_secret: Optional[str] = None
    operation_mode: Optional[str] = None

class ToolExecutionRequest(BaseModel):
    input_text: str = ""
    payload: Optional[str] = None
    params: Dict[str, Any] = Field(default_factory=dict)
    options: Dict[str, Any] = Field(default_factory=dict)

    @property
    def effective_input(self) -> str:
        return self.input_text if self.input_text else (self.payload or "")

class AuditLedgerEntry(BaseModel):
    id: int
    timestamp: str
    tool_id: str
    actor: str
    input_hash: str
    verdict: str
    risk_score: int
    entry_hash: str
    prev_hash: str

class AuditVerificationResponse(BaseModel):
    is_valid: bool
    total_records: int
    tampered_records: List[int] = Field(default_factory=list)
    root_hash: str
    verification_time: str
