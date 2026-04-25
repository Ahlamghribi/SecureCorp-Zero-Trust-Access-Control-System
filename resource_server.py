# resource_server.py - Resource Server (Port 8002)
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
    "res-006": {"name": "Operations Manual",    "department": "Operations", "classification": "confidential"},
}

class CreateResourceRequest(BaseModel):
    name: str
    department: str
    classification: str

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
    }
    resp = httpx.post(f"{PDP_URL}/decide", json=payload)
    return resp.json()

@app.get("/resource/{resource_id}")
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
    return {"access": "GRANTED", "deleted": resource_id}

@app.get("/resources")
def list_resources():
    return RESOURCES

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)