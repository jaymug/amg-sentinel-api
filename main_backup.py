
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI, HTTPException

app = FastAPI(
    title="AMG Sentinel API",
    version="0.2.0"
)

PENDING_ACTIONS = {}
AUDIT_LOG = []

AGENT_PERMISSIONS = {
    "customer_support_agent": [
        "read_email",
        "search_files",
        "send_email",
        "refund_money"
    ],
    "finance_agent": [
        "read_email",
        "search_files",
        "refund_money"
    ],
    "restricted_agent": [
        "read_email"
    ]
}


def current_timestamp():
    return datetime.now(timezone.utc).isoformat()


def record_audit(
    action_id,
    agent,
    action,
    amount,
    risk,
    decision,
    reason
):
    AUDIT_LOG.append({
        "timestamp": current_timestamp(),
        "action_id": action_id,
        "agent": agent,
        "action": action,
        "amount": amount,
        "risk": risk,
        "decision": decision,
        "reason": reason
    })


@app.get("/")
def home():
    return {
        "message": "AMG Sentinel API is online",
        "version": app.version
    }


@app.get("/risk/{agent}/{action}")
def check_risk(
    agent: str,
    action: str,
    amount: float = 0
):
    action_id = None

    if action == "refund_money" and amount < 0:
        risk = "CRITICAL"
        decision = "BLOCKED"
        reason = "Refund amount cannot be negative."

    elif agent not in AGENT_PERMISSIONS:
        risk = "CRITICAL"
        decision = "BLOCKED"
        reason = "Unknown agent."

    elif action not in AGENT_PERMISSIONS[agent]:
        risk = "CRITICAL"
        decision = "BLOCKED"
        reason = "Agent does not have permission for this action."

    elif action in ["read_email", "search_files"]:
        risk = "LOW"
        decision = "ALLOWED"
        reason = "Low-risk action within policy."

    elif action == "send_email":
        risk = "MEDIUM"
        decision = "PENDING_APPROVAL"
        reason = "Human approval required."

    elif action == "refund_money":
        if amount <= 50:
            risk = "LOW"
            decision = "ALLOWED"
            reason = "Refund is within the low-risk limit."
        else:
            risk = "HIGH"
            decision = "PENDING_APPROVAL"
            reason = "High-risk refund requires human approval."

    else:
        risk = "CRITICAL"
        decision = "BLOCKED"
        reason = "Action is not recognized by policy."

    if decision == "PENDING_APPROVAL":
        action_id = str(uuid4())

        PENDING_ACTIONS[action_id] = {
            "action_id": action_id,
            "agent": agent,
            "action": action,
            "amount": amount,
            "risk": risk,
            "decision": decision,
            "created_at": current_timestamp()
        }

    record_audit(
        action_id=action_id,
        agent=agent,
        action=action,
        amount=amount,
        risk=risk,
        decision=decision,
        reason=reason
    )

    return {
        "action_id": action_id,
        "agent": agent,
        "action": action,
        "amount": amount,
        "risk": risk,
        "decision": decision,
        "reason": reason
    }


@app.post("/approve/{action_id}")
def approve_action(action_id: str):
    if action_id not in PENDING_ACTIONS:
        raise HTTPException(
            status_code=404,
            detail="Pending action not found."
        )

    action = PENDING_ACTIONS.pop(action_id)

    record_audit(
        action_id=action_id,
        agent=action["agent"],
        action=action["action"],
        amount=action["amount"],
        risk=action["risk"],
        decision="APPROVED",
        reason="Human approval recorded."
    )

    return {
        "action_id": action_id,
        "agent": action["agent"],
        "action": action["action"],
        "amount": action["amount"],
        "risk": action["risk"],
        "decision": "APPROVED",
        "message": (
            "Approval recorded. "
            "The requested action has not been executed."
        )
    }


@app.post("/deny/{action_id}")
def deny_action(action_id: str):
    if action_id not in PENDING_ACTIONS:
        raise HTTPException(
            status_code=404,
            detail="Pending action not found."
        )

    action = PENDING_ACTIONS.pop(action_id)

    record_audit(
        action_id=action_id,
        agent=action["agent"],
        action=action["action"],
        amount=action["amount"],
        risk=action["risk"],
        decision="DENIED",
        reason="Human approval denied."
    )

    return {
        "action_id": action_id,
        "agent": action["agent"],
        "action": action["action"],
        "amount": action["amount"],
        "risk": action["risk"],
        "decision": "DENIED",
        "message": "Human approval denied."
    }


@app.get("/pending")
def get_pending_actions():
    return {
        "count": len(PENDING_ACTIONS),
        "pending_actions": list(PENDING_ACTIONS.values())
    }


@app.get("/pending/{action_id}")
def get_pending_action(action_id: str):
    if action_id not in PENDING_ACTIONS:
        raise HTTPException(
            status_code=404,
            detail="Pending action not found."
        )

    return PENDING_ACTIONS[action_id]


@app.get("/audit")
def get_audit_log():
    return {
        "count": len(AUDIT_LOG),
        "audit_log": AUDIT_LOG
    }
