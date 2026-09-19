import { FiveLayerAnalysisResult, AuditLedgerEntry, AuditVerificationResponse } from '../types';

const API_BASE = '/api/v1';

export async function analyzeTool(
  toolId: string, 
  inputText: string, 
  params: Record<string, any> = {},
  options: Record<string, any> = {}
): Promise<FiveLayerAnalysisResult> {
  const res = await fetch(`${API_BASE}/tools/${toolId}/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      input_text: inputText,
      params,
      options
    })
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: 'Analysis failed' }));
    throw new Error(errorData.detail || `Server error (${res.status})`);
  }

  return res.json();
}

export async function fetchAuditEntries(limit: number = 50): Promise<AuditLedgerEntry[]> {
  const res = await fetch(`${API_BASE}/audit/entries?limit=${limit}`);
  if (!res.ok) {
    throw new Error('Failed to fetch audit ledger');
  }
  return res.json();
}

export async function verifyAuditIntegrity(): Promise<AuditVerificationResponse> {
  const res = await fetch(`${API_BASE}/audit/verify`, {
    method: 'POST'
  });
  if (!res.ok) {
    throw new Error('Failed to verify audit ledger integrity');
  }
  return res.json();
}

export async function checkBackendHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`);
    return res.ok;
  } catch {
    return false;
  }
}

export interface ChatMessagePayload {
  role: string;
  content: string;
}

export async function askAssistantChat(
  messages: ChatMessagePayload[], 
  currentToolId?: string,
  apiKey?: string
): Promise<{ reply: string }> {
  const res = await fetch(`${API_BASE}/assistant/chat`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      messages,
      current_tool_id: currentToolId,
      api_key: apiKey || undefined
    })
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to contact AI Assistant' }));
    throw new Error(err.detail || `Server error (${res.status})`);
  }

  return res.json();
}

