# pdp.py - Policy Decision Point (Port 8001)
from fastapi import FastAPI
from pydantic import BaseModel
import json, datetime

app = FastAPI(title="PDP - Policy Decision Point")

def load_policies():
    with open("policies.json") as f:
        return json.load(f)

class AccessRequest(BaseModel):
    username: str
    role: str
    department: str
    clearance: str
    location: str
    action: str          # read / write / delete
    resource_id: str
    resource_department: str
    resource_classification: str  # public / confidential / secret

# RBAC permissions
RBAC = {
    "Admin":    ["read", "write", "delete"],
    "Manager":  ["read", "write"],
    "Employee": ["read"],
}

# Role hierarchy: Admin > Manager > Employee
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

    # 1. RBAC check
    allowed_actions = RBAC.get(req.role, [])
    if req.action not in allowed_actions:
        return {"decision": "DENY", "reason": f"RBAC: Role '{req.role}' cannot perform '{req.action}'"}

    # 2. Load and evaluate ABAC policies
    policies = load_policies()
    current_hour = datetime.datetime.now().hour

    for policy in policies:
        cond = policy["condition"]
        matched = True

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
