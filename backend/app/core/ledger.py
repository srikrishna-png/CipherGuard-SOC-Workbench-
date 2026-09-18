import sqlite3
import hashlib
import datetime
import os
from pathlib import Path
from typing import List, Dict, Any, Tuple
from app.models.schemas import AuditLedgerEntry, AuditVerificationResponse

DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "cyber_suite.db"

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

def get_db_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_ledger (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        tool_id TEXT NOT NULL,
        actor TEXT NOT NULL,
        input_hash TEXT NOT NULL,
        verdict TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        prev_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def compute_hash(entry_id: int, timestamp: str, tool_id: str, actor: str, 
                 input_hash: str, verdict: str, risk_score: int, prev_hash: str) -> str:
    raw = f"{entry_id}|{timestamp}|{tool_id}|{actor}|{input_hash}|{verdict}|{risk_score}|{prev_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def record_analysis_event(tool_id: str, input_data: str, verdict: str, risk_score: int, actor: str = "SOC_ANALYST_01") -> str:
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Calculate input hash
    input_hash = hashlib.sha256(input_data.encode("utf-8", errors="ignore")).hexdigest()
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    # Get last entry hash
    cursor.execute("SELECT id, entry_hash FROM audit_ledger ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    
    if row is None:
        prev_hash = GENESIS_HASH
        next_id = 1
    else:
        prev_hash = row["entry_hash"]
        next_id = row["id"] + 1
        
    entry_hash = compute_hash(next_id, timestamp, tool_id, actor, input_hash, verdict, risk_score, prev_hash)
    
    cursor.execute("""
        INSERT INTO audit_ledger (id, timestamp, tool_id, actor, input_hash, verdict, risk_score, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (next_id, timestamp, tool_id, actor, input_hash, verdict, risk_score, prev_hash, entry_hash))
    
    conn.commit()
    conn.close()
    return entry_hash

def get_ledger_entries(limit: int = 50) -> List[AuditLedgerEntry]:
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_ledger ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    return [
        AuditLedgerEntry(
            id=r["id"],
            timestamp=r["timestamp"],
            tool_id=r["tool_id"],
            actor=r["actor"],
            input_hash=r["input_hash"],
            verdict=r["verdict"],
            risk_score=r["risk_score"],
            prev_hash=r["prev_hash"],
            entry_hash=r["entry_hash"]
        ) for r in rows
    ]

def verify_ledger_integrity() -> AuditVerificationResponse:
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_ledger ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        return AuditVerificationResponse(
            is_valid=True,
            total_records=0,
            tampered_records=[],
            root_hash=GENESIS_HASH,
            verification_time=datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
        
    expected_prev_hash = GENESIS_HASH
    tampered_ids = []
    
    for r in rows:
        # Check previous hash continuity
        if r["prev_hash"] != expected_prev_hash:
            tampered_ids.append(r["id"])
            
        # Recompute entry hash
        recomputed = compute_hash(
            r["id"], r["timestamp"], r["tool_id"], r["actor"],
            r["input_hash"], r["verdict"], r["risk_score"], r["prev_hash"]
        )
        if recomputed != r["entry_hash"]:
            tampered_ids.append(r["id"])
            
        expected_prev_hash = r["entry_hash"]
        
    tampered_ids = sorted(list(set(tampered_ids)))
    root_hash = rows[-1]["entry_hash"] if rows else GENESIS_HASH
    
    return AuditVerificationResponse(
        is_valid=len(tampered_ids) == 0,
        total_records=len(rows),
        tampered_records=tampered_ids,
        root_hash=root_hash,
        verification_time=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
