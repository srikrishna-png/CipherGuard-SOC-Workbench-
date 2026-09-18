export type SeverityLevel = 'CLEAN' | 'LOW' | 'SUSPICIOUS' | 'MALICIOUS' | 'CRITICAL';

export interface EvidenceItem {
  label: string;
  value: string;
  status: 'pass' | 'warning' | 'fail' | 'info';
  description?: string;
}

export interface RemediationCommand {
  title: string;
  platform: string;
  command: string;
  description?: string;
}

export interface EducationalStandard {
  standard: string;
  reference_id: string;
  title: string;
  url?: string;
  summary: string;
}

export interface FiveLayerAnalysisResult {
  tool_id: string;
  tool_name: string;
  suite_id: string;
  timestamp: string;
  verdict: SeverityLevel;
  risk_score: number;
  summary: string;
  technical_evidence: EvidenceItem[];
  threat_impact: string;
  attack_objective?: string;
  remediation_playbook: RemediationCommand[];
  standards_and_references: EducationalStandard[];
  audit_hash?: string;
  execution_time_ms: number;
  generated_payload?: string;
  extracted_secret?: string;
  operation_mode?: string;
}

export interface ToolMetadata {
  id: string;
  name: string;
  suiteId: string;
  description: string;
  inputPlaceholder: string;
  inputType?: 'text' | 'multiline' | 'file';
  sampleInputs: {
    label: string;
    description: string;
    payload: string;
  }[];
  categoryBadge?: string;
}

export interface SuiteMetadata {
  id: string;
  name: string;
  badge: string;
  description: string;
  iconName: string;
  tools: ToolMetadata[];
}

export interface AuditLedgerEntry {
  id: number;
  timestamp: string;
  tool_id: string;
  actor: string;
  input_hash: string;
  verdict: string;
  risk_score: number;
  prev_hash: string;
  entry_hash: string;
}

export interface AuditVerificationResponse {
  is_valid: boolean;
  total_records: number;
  tampered_records: number[];
  root_hash: string;
  verification_time: string;
}
