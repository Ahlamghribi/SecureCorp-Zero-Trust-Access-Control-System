<<<<<<< HEAD
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json, datetime, logging, os

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/pdp.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PDP")

def audit(username: str, action: str, resource: str, decision: str, reason: str, event: str = "POLICY_DECISION"):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "server": "PDP",
        "event": event,
        "username": username,
        "action": action,
        "resource": resource,
        "decision": decision,
        "reason": reason
    }
    with open("logs/audit.log", "a") as f:
        f.write(json.dumps(entry) + "\n")
    level = logging.WARNING if decision in ("DENY", "ATTACK") else logging.INFO
    logger.log(level, f"[{event}] user={username} action={action} resource={resource} → {decision} | {reason}")

app = FastAPI(title="PDP - Policy Decision Point")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

=======
# pdp.py - Policy Decision Point (Port 8001)
from fastapi import FastAPI
from pydantic import BaseModel
import json, datetime

app = FastAPI(title="PDP - Policy Decision Point")

>>>>>>> 1d045c1acece75acf0bc7117375f5136cc51d08c
def load_policies():
    with open("policies.json") as f:
        return json.load(f)

class AccessRequest(BaseModel):
    username: str
    role: str
    department: str
    clearance: str
    location: str
<<<<<<< HEAD
    action: str                   # read / write / delete
=======
    action: str          # read / write / delete
>>>>>>> 1d045c1acece75acf0bc7117375f5136cc51d08c
    resource_id: str
    resource_department: str
    resource_classification: str  # public / confidential / secret

# RBAC permissions
RBAC = {
    "Admin":    ["read", "write", "delete"],
    "Manager":  ["read", "write"],
    "Employee": ["read"],
}

<<<<<<< HEAD
# Role hierarchy: b niveau 
=======
# Role hierarchy: Admin > Manager > Employee
>>>>>>> 1d045c1acece75acf0bc7117375f5136cc51d08c
ROLE_HIERARCHY = {
    "Admin":    ["Admin", "Manager", "Employee"],
    "Manager":  ["Manager", "Employee"],
    "Employee": ["Employee"],
}

CLEARANCE_LEVEL = {"public": 1, "confidential": 2, "secret": 3}

@app.post("/decide")
def decide(req: AccessRequest):
    """Evaluate access request → ALLOW or DENY"""
    reasons = []
<<<<<<< HEAD
    current_hour = datetime.datetime.now().hour

    # 1. RBAC check — detect privilege escalation attempts
    allowed_actions = RBAC.get(req.role, [])
    if req.action not in allowed_actions:
        reason = f"PRIVILEGE_ESCALATION: Role '{req.role}' attempted unauthorized action '{req.action}' (allowed: {allowed_actions})"
        audit(req.username, req.action, req.resource_id, "ATTACK", reason, event="PRIVILEGE_ESCALATION")
        return {"decision": "DENY", "reason": reason}

    # 2. Load and evaluate ABAC policies
    policies = load_policies()
=======

    # 1. RBAC check
    allowed_actions = RBAC.get(req.role, [])
    if req.action not in allowed_actions:
        return {"decision": "DENY", "reason": f"RBAC: Role '{req.role}' cannot perform '{req.action}'"}

    # 2. Load and evaluate ABAC policies
    policies = load_policies()
    current_hour = datetime.datetime.now().hour
>>>>>>> 1d045c1acece75acf0bc7117375f5136cc51d08c

    for policy in policies:
        cond = policy["condition"]
        matched = True

<<<<<<< HEAD
        # policy-1: secret + external location
        if "resource.classification" in cond and "user.location" in cond:
            if (req.resource_classification != cond["resource.classification"]
                    or req.location != cond["user.location"]):
                matched = False

        # policy-2: department isolation (Admins are exempt)
        elif cond.get("resource.department_mismatch"):
            if req.department == req.resource_department or req.role == "Admin":
                matched = False

        # policy-3 & policy-5: clearance check
        elif "resource.classification" in cond and "user.clearance" in cond:
            if (req.resource_classification != cond["resource.classification"]
                    or req.clearance != cond["user.clearance"]):
                matched = False

        # policy-4: time-based access (08:00 - 18:00)
        elif cond.get("time_outside_hours"):
            if 8 <= current_hour < 24:
                matched = False  # within allowed hours → rule does NOT fire

        # policy-6: Separation of Duties
        elif cond.get("separation_of_duties"):
            if req.role != cond.get("role") or req.action != cond.get("action"):
                matched = False

        if matched and policy["effect"] == "deny":
            # Tag as PRIVILEGE_ESCALATION if:
            # - SoD violation (manager deletes)
            # - user tries write/delete on resource they have no business accessing
            is_priv_esc_policy = (
                cond.get("separation_of_duties") or
                (cond.get("resource.department_mismatch") and req.action in ["write", "delete"]) or
                (req.action in ["write", "delete"])
            )
            if is_priv_esc_policy:
                reasons.append(f"PRIVILEGE_ESCALATION|Policy [{policy['id']}]: {policy['description']}")
            else:
                reasons.append(f"Policy [{policy['id']}]: {policy['description']}")

    if reasons:
        is_priv_esc = any(r.startswith("PRIVILEGE_ESCALATION|") for r in reasons)
        clean_reasons = [r.replace("PRIVILEGE_ESCALATION|", "") for r in reasons]
        reason_str = " | ".join(clean_reasons)
        if is_priv_esc:
            reason_str = f"PRIVILEGE_ESCALATION: {reason_str}"
            audit(req.username, req.action, req.resource_id, "ATTACK", reason_str, event="PRIVILEGE_ESCALATION")
        else:
            audit(req.username, req.action, req.resource_id, "DENY", reason_str)
        return {"decision": "DENY", "reason": reason_str}

    reason_ok = f"RBAC + ABAC passed. Role={req.role}, Clearance={req.clearance}, Action={req.action}"
    audit(req.username, req.action, req.resource_id, "ALLOW", reason_ok)
    return {"decision": "ALLOW", "reason": reason_ok}

@app.get("/policies")
def list_policies():
    """Return current loaded policies"""
    return {"policies": load_policies()}

if __name__ == "__main__":
    import uvicorn
    logger.info("PDP Policy Decision Point starting on port 8001")
    uvicorn.run(app, host="0.0.0.0", port=8001)
=======
        # Check secret + external
        if "resource.classification" in cond and "user.location" in cond:
            if req.resource_classification != cond["resource.classification"] or req.location != cond["user.location"]:
                matched = False

        # Check department mismatch
        elif cond.get("resource.department_mismatch"):
            if req.department == req.resource_department:
                matched = False  # same department = ok

        # Check clearance
        elif "resource.classification" in cond and "user.clearance" in cond:
            if req.resource_classification != cond["resource.classification"] or req.clearance != cond["user.clearance"]:
                matched = False

        # Check time
        elif cond.get("time_outside_hours"):
            if 8 <= current_hour < 18:
                matched = False  # within hours = ok

        if matched and policy["effect"] == "deny":
            reasons.append(f"Policy [{policy['id']}]: {policy['description']}")

    if reasons:
        return {"decision": "DENY", "reason": " | ".join(reasons)}

    return {
        "decision": "ALLOW",
        "reason": f"RBAC + ABAC passed. Role={req.role}, Clearance={req.clearance}, Action={req.action}"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
>>>>>>> 1d045c1acece75acf0bc7117375f5136cc51d08c
