# resource_server.py - Resource Server (Port 8002)
<<<<<<< HEAD
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from config import SECRET_KEY, ALGORITHM
import jwt, httpx, logging, datetime, json, os

# ── Logging setup ──────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/resource.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ResourceServer")

def resolve_status(reason: str) -> str:
    """If PDP flagged privilege escalation, propagate ATTACK status instead of DENY."""
    if "PRIVILEGE_ESCALATION" in reason:
        return "ATTACK"
    return "DENY"

def resolve_event(event: str, reason: str) -> str:
    """If it's an attack, use the attack type as event name instead of generic ACCESS."""
    if "PRIVILEGE_ESCALATION" in reason:
        return "PRIVILEGE_ESCALATION"
    return event

def audit(event: str, username: str, action: str, resource: str, status: str, detail: str = "", ip: str = ""):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "server": "ResourceServer",
        "event": event,
        "username": username,
        "action": action,
        "resource": resource,
        "status": status,
        "detail": detail,
        "ip": ip
    }
    with open("logs/audit.log", "a") as f:
        f.write(json.dumps(entry) + "\n")
    level = logging.WARNING if status in ("DENY", "ATTACK") else logging.INFO
    logger.log(level, f"[{event}] user={username} {action} {resource} → {status} | {detail}")

# ── App ────────────────────────────────────────────────────
app = FastAPI(title="Resource Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PDP_URL = "http://localhost:8001"

RESOURCES = {
    "res-001": {"name": "HR Policy Document",   "department": "HR",         "classification": "confidential"},
    "res-002": {"name": "Finance Report Q4",    "department": "Finance",    "classification": "secret"},
    "res-003": {"name": "IT Network Diagram",   "department": "IT",         "classification": "secret"},
    "res-004": {"name": "Company Handbook",     "department": "HR",         "classification": "public"},
    "res-005": {"name": "Salary Database",      "department": "Finance",    "classification": "secret"},
=======
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from config import SECRET_KEY, ALGORITHM
import jwt, httpx

app = FastAPI(title="Resource Server")

PDP_URL = "http://localhost:8001"

RESOURCES = {
    "res-001": {"name": "HR Policy Document",   "department": "HR",      "classification": "confidential"},
    "res-002": {"name": "Finance Report Q4",    "department": "Finance", "classification": "secret"},
    "res-003": {"name": "IT Network Diagram",   "department": "IT",      "classification": "secret"},
    "res-004": {"name": "Company Handbook",     "department": "HR",      "classification": "public"},
    "res-005": {"name": "Salary Database",      "department": "Finance", "classification": "secret"},
>>>>>>> 1d045c1acece75acf0bc7117375f5136cc51d08c
    "res-006": {"name": "Operations Manual",    "department": "Operations", "classification": "confidential"},
}

class CreateResourceRequest(BaseModel):
    name: str
    department: str
    classification: str

<<<<<<< HEAD
def get_user_from_ticket(ticket: str, ip: str = ""):
    try:
        data = jwt.decode(ticket, SECRET_KEY, algorithms=[ALGORITHM])
        if data.get("type") != "SERVICE_TICKET":
            audit("TICKET_VALIDATE", "unknown", "-", "-", "ATTACK", "Not a service ticket", ip)
            raise HTTPException(status_code=401, detail="Not a service ticket")
        return data
    except jwt.ExpiredSignatureError:
        audit("TICKET_VALIDATE", "unknown", "-", "-", "FAIL", "Ticket expired", ip)
        raise HTTPException(status_code=401, detail="Ticket expired")
    except jwt.InvalidTokenError:
        audit("TICKET_VALIDATE", "unknown", "-", "-", "ATTACK", "Invalid ticket - tampering detected!", ip)
        raise HTTPException(status_code=401, detail="Invalid ticket - tampering detected!")

def check_authorization(user_data: dict, action: str, resource: dict, resource_id: str = "unknown"):
    payload = {
        "username":               user_data["username"],
        "role":                   user_data["role"],
        "department":             user_data["department"],
        "clearance":              user_data["clearance"],
        "location":               user_data["location"],
        "action":                 action,
        "resource_id":            resource_id,
        "resource_department":    resource["department"],
        "resource_classification":resource["classification"],
=======
def get_user_from_ticket(ticket: str):
    try:
        data = jwt.decode(ticket, SECRET_KEY, algorithms=[ALGORITHM])
        if data.get("type") != "SERVICE_TICKET":
            raise HTTPException(status_code=401, detail="Not a service ticket")
        return data
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Ticket expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid ticket - tampering detected!")

def check_authorization(user_data: dict, action: str, resource: dict):
    payload = {
        "username": user_data["username"],
        "role": user_data["role"],
        "department": user_data["department"],
        "clearance": user_data["clearance"],
        "location": user_data["location"],
        "action": action,
        "resource_id": "unknown",
        "resource_department": resource["department"],
        "resource_classification": resource["classification"],
>>>>>>> 1d045c1acece75acf0bc7117375f5136cc51d08c
    }
    resp = httpx.post(f"{PDP_URL}/decide", json=payload)
    return resp.json()

@app.get("/resource/{resource_id}")
<<<<<<< HEAD
def get_resource(resource_id: str, request: Request, authorization: str = Header(...)):
    ip = request.client.host if request.client else "unknown"
    ticket = authorization.replace("Bearer ", "")
    user_data = get_user_from_ticket(ticket, ip)
    resource = RESOURCES.get(resource_id)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    decision = check_authorization(user_data, "read", resource, resource_id)
    username = user_data["username"]
    if decision["decision"] == "DENY":
        audit(resolve_event("ACCESS", decision["reason"]), username, "READ", resource_id, resolve_status(decision["reason"]), decision["reason"], ip)
        raise HTTPException(status_code=403, detail=f"ACCESS DENIED: {decision['reason']}")
    audit("ACCESS", username, "READ", resource_id, "ALLOW", resource["name"], ip)
    return {"access": "GRANTED", "user": username, "resource": resource}

@app.post("/resource")
def create_resource(req: CreateResourceRequest, request: Request, authorization: str = Header(...)):
    ip = request.client.host if request.client else "unknown"
    ticket = authorization.replace("Bearer ", "")
    user_data = get_user_from_ticket(ticket, ip)
    decision = check_authorization(user_data, "write", req.dict(), "new")
    username = user_data["username"]
    if decision["decision"] == "DENY":
        audit(resolve_event("ACCESS", decision["reason"]), username, "WRITE", "new-resource", resolve_status(decision["reason"]), decision["reason"], ip)
        raise HTTPException(status_code=403, detail=f"ACCESS DENIED: {decision['reason']}")
    new_id = f"res-{len(RESOURCES)+1:03d}"
    RESOURCES[new_id] = req.dict()
    audit("ACCESS", username, "WRITE", new_id, "ALLOW", f"Created: {req.name}", ip)
    return {"access": "GRANTED", "created": new_id, "resource": req.dict()}

@app.delete("/resource/{resource_id}")
def delete_resource(resource_id: str, request: Request, authorization: str = Header(...)):
    ip = request.client.host if request.client else "unknown"
    ticket = authorization.replace("Bearer ", "")
    user_data = get_user_from_ticket(ticket, ip)
    resource = RESOURCES.get(resource_id)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    decision = check_authorization(user_data, "delete", resource, resource_id)
    username = user_data["username"]
    if decision["decision"] == "DENY":
        audit(resolve_event("ACCESS", decision["reason"]), username, "DELETE", resource_id, resolve_status(decision["reason"]), decision["reason"], ip)
        raise HTTPException(status_code=403, detail=f"ACCESS DENIED: {decision['reason']}")
    del RESOURCES[resource_id]
    audit("ACCESS", username, "DELETE", resource_id, "ALLOW", f"Deleted: {resource['name']}", ip)
=======
def get_resource(resource_id: str, authorization: str = Header(...)):
    ticket = authorization.replace("Bearer ", "")
    user_data = get_user_from_ticket(ticket)
    resource = RESOURCES.get(resource_id)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    decision = check_authorization(user_data, "read", resource)
    if decision["decision"] == "DENY":
        raise HTTPException(status_code=403, detail=f"ACCESS DENIED: {decision['reason']}")
    return {"access": "GRANTED", "user": user_data["username"], "resource": resource}

@app.post("/resource")
def create_resource(req: CreateResourceRequest, authorization: str = Header(...)):
    ticket = authorization.replace("Bearer ", "")
    user_data = get_user_from_ticket(ticket)
    decision = check_authorization(user_data, "write", req.dict())
    if decision["decision"] == "DENY":
        raise HTTPException(status_code=403, detail=f"ACCESS DENIED: {decision['reason']}")
    new_id = f"res-{len(RESOURCES)+1:03d}"
    RESOURCES[new_id] = req.dict()
    return {"access": "GRANTED", "created": new_id, "resource": req.dict()}

@app.delete("/resource/{resource_id}")
def delete_resource(resource_id: str, authorization: str = Header(...)):
    ticket = authorization.replace("Bearer ", "")
    user_data = get_user_from_ticket(ticket)
    resource = RESOURCES.get(resource_id)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    decision = check_authorization(user_data, "delete", resource)
    if decision["decision"] == "DENY":
        raise HTTPException(status_code=403, detail=f"ACCESS DENIED: {decision['reason']}")
    del RESOURCES[resource_id]
>>>>>>> 1d045c1acece75acf0bc7117375f5136cc51d08c
    return {"access": "GRANTED", "deleted": resource_id}

@app.get("/resources")
def list_resources():
    return RESOURCES

if __name__ == "__main__":
    import uvicorn
<<<<<<< HEAD
    logger.info("Resource Server starting on port 8002")
=======
>>>>>>> 1d045c1acece75acf0bc7117375f5136cc51d08c
    uvicorn.run(app, host="0.0.0.0", port=8002)