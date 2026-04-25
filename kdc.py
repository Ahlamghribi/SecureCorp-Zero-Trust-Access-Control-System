# kdc.py - Authentication Server (Port 8000)
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from config import SECRET_KEY, ALGORITHM
import jwt, datetime, hashlib, uuid

app = FastAPI(title="KDC - Authentication Server")

USERS = {
    "alice": {"password": hashlib.sha256("password123".encode()).hexdigest(), "role": "Admin",    "department": "IT",      "clearance": "secret",       "location": "internal"},
    "bob":   {"password": hashlib.sha256("password123".encode()).hexdigest(), "role": "Manager",  "department": "Finance", "clearance": "confidential", "location": "internal"},
    "carol": {"password": hashlib.sha256("password123".encode()).hexdigest(), "role": "Employee", "department": "HR",      "clearance": "public",       "location": "internal"},
    "dave":  {"password": hashlib.sha256("password123".encode()).hexdigest(), "role": "Employee", "department": "Finance", "clearance": "public",       "location": "external"},
}

ISSUED_TGTS = set()
USED_NONCES = set()

class LoginRequest(BaseModel):
    username: str
    password: str

class TicketRequest(BaseModel):
    tgt: str
    service: str
    nonce: str

@app.post("/login")
def login(req: LoginRequest):
    user = USERS.get(req.username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if hashlib.sha256(req.password.encode()).hexdigest() != user["password"]:
        raise HTTPException(status_code=401, detail="Wrong password")

    tgt_id = str(uuid.uuid4())
    tgt_payload = {
        "type": "TGT",
        "tgt_id": tgt_id,
        "username": req.username,
        "role": user["role"],
        "department": user["department"],
        "clearance": user["clearance"],
        "location": user["location"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=8),
    }
    tgt = jwt.encode(tgt_payload, SECRET_KEY, algorithm=ALGORITHM)
    ISSUED_TGTS.add(tgt_id)
    return {"tgt": tgt, "message": f"Welcome {req.username}! TGT issued."}

@app.post("/request-ticket")
def request_ticket(req: TicketRequest):
    if req.nonce in USED_NONCES:
        raise HTTPException(status_code=401, detail="Replay attack detected! Nonce already used.")
    USED_NONCES.add(req.nonce)

    try:
        tgt_data = jwt.decode(req.tgt, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="TGT expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid TGT - possible tampering!")

    if tgt_data.get("type") != "TGT":
        raise HTTPException(status_code=401, detail="Not a valid TGT")
    if tgt_data["tgt_id"] not in ISSUED_TGTS:
        raise HTTPException(status_code=401, detail="TGT not recognized")

    ticket_payload = {
        "type": "SERVICE_TICKET",
        "username": tgt_data["username"],
        "role": tgt_data["role"],
        "department": tgt_data["department"],
        "clearance": tgt_data["clearance"],
        "location": tgt_data["location"],
        "service": req.service,
        "nonce": req.nonce,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
    }
    ticket = jwt.encode(ticket_payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"service_ticket": ticket, "service": req.service}

@app.get("/verify-ticket")
def verify_ticket(token: str):
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if data.get("type") != "SERVICE_TICKET":
            raise HTTPException(status_code=401, detail="Not a service ticket")
        return data
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Ticket expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid ticket - tampering detected!")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)