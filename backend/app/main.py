from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List
from app.models.schemas import (
    FiveLayerAnalysisResult, 
    ToolExecutionRequest, 
    AuditLedgerEntry, 
    AuditVerificationResponse
)
from app.core.registry import execute_tool, TOOL_TO_SUITE
from app.core.ledger import get_ledger_entries, verify_ledger_integrity, init_db

app = FastAPI(
    title="CipherGuard Defensive Cybersecurity & SOC Workbench API",
    description="Real-world practical cybersecurity analysis platform with 8 suites, 80 tools, and a 5-layer explanation model backed by a SHA-256 tamper-evident ledger.",
    version="2.0.0"
)

# CORS configuration for local React / Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    init_db()

@app.get("/api/v1/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": "CipherGuard Defensive Workbench API",
        "total_suites": 8,
        "total_tools": 80,
        "engine_version": "2.0.0"
    }

@app.post("/api/v1/tools/{tool_id}/analyze", response_model=FiveLayerAnalysisResult, tags=["Analysis Workbench"])
def analyze_input(tool_id: str, request: ToolExecutionRequest):
    if tool_id not in TOOL_TO_SUITE:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_id}' not found in CipherGuard catalog.")
    
    result = execute_tool(
        tool_id=tool_id,
        input_text=request.effective_input,
        params=request.params,
        actor=request.options.get("actor", "SOC_ANALYST_01")
    )
    return result

@app.get("/api/v1/audit/entries", response_model=List[AuditLedgerEntry], tags=["Cryptographic Audit Ledger"])
def list_audit_entries(limit: int = 50):
    return get_ledger_entries(limit=limit)

@app.post("/api/v1/audit/verify", response_model=AuditVerificationResponse, tags=["Cryptographic Audit Ledger"])
def verify_audit_chain():
    return verify_ledger_integrity()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
