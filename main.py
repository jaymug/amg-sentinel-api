import sqlite3
import secrets
import uuid
import httpx
import asyncio
from datetime import datetime, timezone
from fastapi import FastAPI, Header, HTTPException, Query, Path, BackgroundTasks
from pydantic import BaseModel
from typing import Optional

app = FastAPI(
    title="AMG Sentinel API",
    version="0.8.0",
    description="Enterprise AI Guardrail & Governance Platform with Dynamic Tier Upgrades & Webhooks"
)

DB_FILE = "sentinel.db"
ADMIN_MASTER_KEY = "amg_master_admin_secret_999"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            api_key TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            client_name TEXT NOT NULL,
            monthly_quota INTEGER DEFAULT 1000,
            usage_count INTEGER DEFAULT 0,
            webhook_url TEXT,
            created_at TEXT NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            action_id TEXT NOT NULL,
            agent TEXT NOT NULL,
            action TEXT NOT NULL,
            amount REAL,
            risk TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pending_actions (
            action_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            agent TEXT NOT NULL,
            action TEXT NOT NULL,
            amount REAL,
            risk TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)
    
    cursor.execute("SELECT api_key FROM api_keys WHERE api_key = ?", ("amg_test_key_123",))
    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO api_keys (api_key, tenant_id, client_name, monthly_quota, usage_count, webhook_url, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, ("amg_test_key_123", "tenant_default", "Default Test Client", 1000, 0, None, datetime.now(timezone.utc).isoformat()))
    
    conn.commit()
    conn.close()

init_db()

async def trigger_webhook(webhook_url: str, payload: dict):
    if not webhook_url:
        return
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(webhook_url, json=payload)
    except Exception as e:
        print(f"[WEBHOOK ERROR] Failed to dispatch alert to {webhook_url}: {e}")

def authenticate_and_check_quota(x_api_key: str):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key header (x-api-key) is required.")
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT tenant_id, client_name, monthly_quota, usage_count, webhook_url FROM api_keys WHERE api_key = ?", (x_api_key,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        raise HTTPException(status_code=403, detail="Invalid API Key.")
    
    tenant_id, client_name, monthly_quota, usage_count, webhook_url = row
    
    if usage_count >= monthly_quota:
        conn.close()
        raise HTTPException(status_code=429, detail=f"Monthly usage quota ({monthly_quota} calls) exceeded for client: {client_name}. Upgrade tier required.")
    
    cursor.execute("UPDATE api_keys SET usage_count = usage_count + 1 WHERE api_key = ?", (x_api_key,))
    conn.commit()
    conn.close()
    
    return {
        "tenant_id": tenant_id,
        "client_name": client_name,
        "monthly_quota": monthly_quota,
        "usage_count": usage_count + 1,
        "webhook_url": webhook_url
    }

@app.get("/")
def home():
    return {
        "platform": "AMG Sentinel API",
        "version": "0.8.0",
        "status": "ONLINE",
        "features": ["Multi-Tenant Isolation", "Usage Metering", "Dynamic Tier Upgrades", "Human-in-the-Loop", "Real-Time Webhooks"]
    }

@app.post("/admin/clients")
def create_client(
    client_name: str = Query(..., description="Enterprise Client Name"),
    monthly_quota: int = Query(1000, description="Monthly API request quota limit"),
    webhook_url: Optional[str] = Query(None, description="Security Webhook Endpoint URL"),
    admin_key: str = Header(..., alias="admin-key")
):
    if admin_key != ADMIN_MASTER_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized Admin Key.")
    
    tenant_id = f"tenant_{secrets.token_hex(4)}"
    new_api_key = f"amg_live_{secrets.token_hex(16)}"
    created_at = datetime.now(timezone.utc).isoformat()
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO api_keys (api_key, tenant_id, client_name, monthly_quota, usage_count, webhook_url, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (new_api_key, tenant_id, client_name, monthly_quota, 0, webhook_url, created_at))
    conn.commit()
    conn.close()
    
    return {
        "message": "Enterprise client successfully onboarded.",
        "client_name": client_name,
        "tenant_id": tenant_id,
        "api_key": new_api_key,
        "monthly_quota": monthly_quota,
        "webhook_url": webhook_url
    }

@app.patch("/admin/clients/{tenant_id}/quota")
def update_client_quota(
    tenant_id: str = Path(..., description="Enterprise Tenant ID"),
    new_quota: int = Query(..., description="New Monthly Quota Limit"),
    reset_usage: bool = Query(False, description="Set usage count back to zero"),
    admin_key: str = Header(..., alias="admin-key")
):
    """Dynamically upgrade or modify an enterprise client's tier and quota limits."""
    if admin_key != ADMIN_MASTER_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized Admin Key.")
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT client_name, usage_count FROM api_keys WHERE tenant_id = ?", (tenant_id,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Tenant ID not found.")
    
    client_name, current_usage = row
    
    if reset_usage:
        cursor.execute("UPDATE api_keys SET monthly_quota = ?, usage_count = 0 WHERE tenant_id = ?", (new_quota, tenant_id))
        updated_usage = 0
    else:
        cursor.execute("UPDATE api_keys SET monthly_quota = ? WHERE tenant_id = ?", (new_quota, tenant_id))
        updated_usage = current_usage
        
    conn.commit()
    conn.close()
    
    return {
        "message": "Enterprise tier/quota successfully updated.",
        "tenant_id": tenant_id,
        "client_name": client_name,
        "new_monthly_quota": new_quota,
        "current_usage_count": updated_usage
    }

@app.get("/admin/usage")
def get_tenant_usage(
    admin_key: str = Header(..., alias="admin-key")
):
    if admin_key != ADMIN_MASTER_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized Admin Key.")
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT tenant_id, client_name, api_key, monthly_quota, usage_count, webhook_url FROM api_keys")
    rows = cursor.fetchall()
    conn.close()
    
    usage_report = []
    for r in rows:
        usage_report.append({
            "tenant_id": r[0],
            "client_name": r[1],
            "api_key": r[2],
            "monthly_quota": r[3],
            "usage_count": r[4],
            "remaining_quota": r[3] - r[4],
            "webhook_url": r[5]
        })
        
    return {
        "tenant_count": len(usage_report),
        "clients": usage_report
    }

@app.get("/risk/{agent}/{action}")
def check_risk(
    background_tasks: BackgroundTasks,
    agent: str = Path(...),
    action: str = Path(...),
    amount: Optional[float] = Query(None),
    x_api_key: str = Header(..., alias="x-api-key")
):
    client_info = authenticate_and_check_quota(x_api_key)
    tenant_id = client_info["tenant_id"]
    client_name = client_info["client_name"]
    webhook_url = client_info["webhook_url"]
    
    action_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    
    risk = "LOW"
    decision = "ALLOWED"
    reason = "Low-risk action passed policy check."
    
    if action == "refund_money":
        if amount is not None and amount > 50:
            risk = "HIGH"
            decision = "PENDING_APPROVAL"
            reason = "High-risk refund requires human approval."
    elif action == "delete_database":
        risk = "CRITICAL"
        decision = "BLOCKED"
        reason = "Critical operation strictly forbidden."
        
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_log (tenant_id, timestamp, action_id, agent, action, amount, risk, decision, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (tenant_id, timestamp, action_id, agent, action, amount, risk, decision, reason))
    
    if decision == "PENDING_APPROVAL":
        cursor.execute("""
            INSERT INTO pending_actions (action_id, tenant_id, timestamp, agent, action, amount, risk, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (action_id, tenant_id, timestamp, agent, action, amount, risk, "PENDING"))
        
    conn.commit()
    conn.close()
    
    if risk in ["HIGH", "CRITICAL"] and webhook_url:
        alert_payload = {
            "event": "SECURITY_ALERT",
            "client": client_name,
            "tenant_id": tenant_id,
            "action_id": action_id,
            "agent": agent,
            "action": action,
            "risk_level": risk,
            "decision": decision,
            "reason": reason,
            "timestamp": timestamp
        }
        background_tasks.add_task(trigger_webhook, webhook_url, alert_payload)
    
    return {
        "client": client_name,
        "action_id": action_id,
        "agent": agent,
        "action": action,
        "amount": amount,
        "risk": risk,
        "decision": decision,
        "reason": reason,
        "usage_count": client_info["usage_count"],
        "monthly_quota": client_info["monthly_quota"]
    }

@app.post("/approve/{action_id}")
def approve_action(
    action_id: str = Path(...),
    x_api_key: str = Header(..., alias="x-api-key")
):
    client_info = authenticate_and_check_quota(x_api_key)
    tenant_id = client_info["tenant_id"]
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT agent, action, amount, risk FROM pending_actions WHERE action_id = ? AND tenant_id = ? AND status = 'PENDING'", (action_id, tenant_id))
    pending = cursor.fetchone()
    
    if not pending:
        conn.close()
        raise HTTPException(status_code=404, detail="Pending action not found or already processed.")
    
    agent, action, amount, risk = pending
    timestamp = datetime.now(timezone.utc).isoformat()
    
    cursor.execute("UPDATE pending_actions SET status = 'APPROVED' WHERE action_id = ? AND tenant_id = ?", (action_id, tenant_id))
    cursor.execute("""
        INSERT INTO audit_log (tenant_id, timestamp, action_id, agent, action, amount, risk, decision, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (tenant_id, timestamp, action_id, agent, action, amount, risk, "APPROVED", "Human approval recorded."))
    
    conn.commit()
    conn.close()
    
    return {
        "client": client_info["client_name"],
        "action_id": action_id,
        "agent": agent,
        "action": action,
        "amount": amount,
        "risk": risk,
        "decision": "APPROVED",
        "message": "Approval recorded."
    }

@app.post("/deny/{action_id}")
def deny_action(
    action_id: str = Path(...),
    x_api_key: str = Header(..., alias="x-api-key")
):
    client_info = authenticate_and_check_quota(x_api_key)
    tenant_id = client_info["tenant_id"]
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT agent, action, amount, risk FROM pending_actions WHERE action_id = ? AND tenant_id = ? AND status = 'PENDING'", (action_id, tenant_id))
    pending = cursor.fetchone()
    
    if not pending:
        conn.close()
        raise HTTPException(status_code=404, detail="Pending action not found or already processed.")
    
    agent, action, amount, risk = pending
    timestamp = datetime.now(timezone.utc).isoformat()
    
    cursor.execute("UPDATE pending_actions SET status = 'DENIED' WHERE action_id = ? AND tenant_id = ?", (action_id, tenant_id))
    cursor.execute("""
        INSERT INTO audit_log (tenant_id, timestamp, action_id, agent, action, amount, risk, decision, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (tenant_id, timestamp, action_id, agent, action, amount, risk, "DENIED", "Human denial recorded."))
    
    conn.commit()
    conn.close()
    
    return {
        "client": client_info["client_name"],
        "action_id": action_id,
        "agent": agent,
        "action": action,
        "amount": amount,
        "risk": risk,
        "decision": "DENIED",
        "message": "Denial recorded."
    }

@app.get("/pending")
def get_pending_actions(
    x_api_key: str = Header(..., alias="x-api-key")
):
    client_info = authenticate_and_check_quota(x_api_key)
    tenant_id = client_info["tenant_id"]
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT action_id, timestamp, agent, action, amount, risk FROM pending_actions WHERE tenant_id = ? AND status = 'PENDING'", (tenant_id,))
    rows = cursor.fetchall()
    conn.close()
    
    pending_list = []
    for r in rows:
        pending_list.append({
            "action_id": r[0],
            "timestamp": r[1],
            "agent": r[2],
            "action": r[3],
            "amount": r[4],
            "risk": r[5]
        })
        
    return {
        "client": client_info["client_name"],
        "count": len(pending_list),
        "pending_actions": pending_list
    }

@app.get("/audit")
def get_audit_log(
    x_api_key: str = Header(..., alias="x-api-key")
):
    client_info = authenticate_and_check_quota(x_api_key)
    tenant_id = client_info["tenant_id"]
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, action_id, agent, action, amount, risk, decision, reason 
        FROM audit_log 
        WHERE tenant_id = ? 
        ORDER BY id DESC
    """, (tenant_id,))
    rows = cursor.fetchall()
    conn.close()
    
    logs = []
    for r in rows:
        logs.append({
            "timestamp": r[0],
            "action_id": r[1],
            "agent": r[2],
            "action": r[3],
            "amount": r[4],
            "risk": r[5],
            "decision": r[6],
            "reason": r[7]
        })
        
    return {
        "client": client_info["client_name"],
        "count": len(logs),
        "audit_log": logs
    }