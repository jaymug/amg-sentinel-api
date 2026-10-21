import sqlite3
import uuid
import secrets
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel
from fastapi import FastAPI, Header, HTTPException, Security, Depends, status
from fastapi.security.api_key import APIKeyHeader

app = FastAPI(
    title="AMG Sentinel API",
    description="Multi-tenant AI Guardrail & Security Infrastructure",
    version="0.3.0"
)

# Database Setup
DB_FILE = "sentinel.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Clients table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    # Audit logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            log_id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            action TEXT NOT NULL,
            risk_score REAL NOT NULL,
            status TEXT NOT NULL,
            reason TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Security Schemes for Swagger UI
# This creates the green "Authorize" button in Swagger Docs for client keys
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

ADMIN_MASTER_KEY = "amg_master_secret_key_change_me"  # Replace with your actual secure master key

# Models
class ClientCreateRequest(BaseModel):
    name: str

class RiskCheckRequest(BaseModel):
    action: str
    context: Optional[Dict[str, Any]] = None

# Helper Functions
def get_client_by_key(api_key: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT client_id, name FROM clients WHERE api_key = ?", (api_key,))
    client = cursor.fetchone()
    conn.close()
    return client

def log_audit_event(client_id: str, action: str, risk_score: float, status_res: str, reason: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    log_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()
    cursor.execute(
        "INSERT INTO audit_logs VALUES (?, ?, ?, ?, ?, ?, ?)",
        (log_id, client_id, action, risk_score, status_res, reason, timestamp)
    )
    conn.commit()
    conn.close()

# Endpoints
@app.get("/")
def read_root():
    return {"message": "AMG Sentinel API is operational.", "docs": "/docs"}

@app.post("/admin/clients")
def create_client(
    payload: ClientCreateRequest, 
    x_master_key: Optional[str] = Header(None)
):
    if x_master_key != ADMIN_MASTER_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid Admin Master Key"
        )
    
    client_id = str(uuid.uuid4())
    api_key = f"amg_live_{secrets.token_hex(16)}"
    created_at = datetime.utcnow().isoformat()

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO clients VALUES (?, ?, ?, ?)",
        (client_id, payload.name, api_key, created_at)
    )
    conn.commit()
    conn.close()

    return {
        "status": "SUCCESS",
        "client_id": client_id,
        "name": payload.name,
        "api_key": api_key
    }

@app.post("/risk")
def evaluate_risk(
    payload: RiskCheckRequest,
    api_key: Optional[str] = Security(api_key_header)
):
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header"
        )

    client = get_client_by_key(api_key)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key"
        )

    client_id, client_name = client
    action = payload.action.lower()

    # Simple Risk Rule Engine
    high_risk_keywords = ["delete", "drop", "truncate", "shutdown", "format", "wipe"]
    
    if any(keyword in action for keyword in high_risk_keywords):
        risk_score = 0.95
        status_res = "BLOCKED"
        reason = f"High-risk action detected ('{action}'). Execution prevented."
    else:
        risk_score = 0.10
        status_res = "APPROVED"
        reason = "Action within normal risk parameters."

    log_audit_event(client_id, action, risk_score, status_res, reason)

    return {
        "status": status_res,
        "risk_score": risk_score,
        "reason": reason,
        "client": client_name
    }