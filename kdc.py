# kdc.py - Authentication Server (Port 8000)
<<<<<<< HEAD
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from config import SECRET_KEY, ALGORITHM
import jwt, datetime, hashlib, uuid, logging, json, os

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/kdc.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("KDC")

def audit(event: str, username: str, status: str, detail: str = "", ip: str = ""):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "server": "KDC",
        "event": event,
        "username": username,
        "status": status,
        "detail": detail,
        "ip": ip
    }
    with open("logs/audit.log", "a") as f:
        f.write(json.dumps(entry) + "\n")
    level = logging.WARNING if status in ("FAIL", "ATTACK") else logging.INFO
    logger.log(level, f"[{event}] user={username} status={status} {detail}")

app = FastAPI(title="KDC - Authentication Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

=======
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from config import SECRET_KEY, ALGORITHM
import jwt, datetime, hashlib, uuid

app = FastAPI(title="KDC - Authentication Server")

>>>>>>> 1d045c1acece75acf0bc7117375f5136cc51d08c
USERS = {
    "alice": {"password": hashlib.sha256("password123".encode()).hexdigest(), "role": "Admin",    "department": "IT",      "clearance": "secret",       "location": "internal"},
    "bob":   {"password": hashlib.sha256("password123".encode()).hexdigest(), "role": "Manager",  "department": "Finance", "clearance": "confidential", "location": "internal"},
    "carol": {"password": hashlib.sha256("password123".encode()).hexdigest(), "role": "Employee", "department": "HR",      "clearance": "public",       "location": "internal"},
    "dave":  {"password": hashlib.sha256("password123".encode()).hexdigest(), "role": "Employee", "department": "Finance", "clearance": "public",       "location": "external"},
}

ISSUED_TGTS = set()
USED_NONCES = set()
<<<<<<< HEAD
FAILED_LOGINS = {}   # hadi ndiroha brute force 
=======
>>>>>>> 1d045c1acece75acf0bc7117375f5136cc51d08c

class LoginRequest(BaseModel):
    username: str
    password: str

class TicketRequest(BaseModel):
    tgt: str
    service: str
    nonce: str

@app.post("/login")
<<<<<<< HEAD
def login(req: LoginRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    user = USERS.get(req.username)

    if not user:
        FAILED_LOGINS[req.username] = FAILED_LOGINS.get(req.username, 0) + 1
        audit("LOGIN", req.username, "FAIL", "User not found", ip)
        raise HTTPException(status_code=401, detail="User not found")

    if hashlib.sha256(req.password.encode()).hexdigest() != user["password"]:
        FAILED_LOGINS[req.username] = FAILED_LOGINS.get(req.username, 0) + 1
        count = FAILED_LOGINS[req.username]
        if count >= 3:
            audit("BRUTE_FORCE", req.username, "ATTACK", f"{count} failed attempts", ip)
        else:
            audit("LOGIN", req.username, "FAIL", "Wrong password", ip)
        raise HTTPException(status_code=401, detail="Wrong password")

    FAILED_LOGINS[req.username] = 0

=======
def login(req: LoginRequest):
    user = USERS.get(req.username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if hashlib.sha256(req.password.encode()).hexdigest() != user["password"]:
        raise HTTPException(status_code=401, detail="Wrong password")

>>>>>>> 1d045c1acece75acf0bc7117375f5136cc51d08c
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
<<<<<<< HEAD
    audit("LOGIN", req.username, "OK", f"TGT issued. Role={user['role']} Dept={user['department']}", ip)
    return {"tgt": tgt, "message": f"Welcome {req.username}! TGT issued."}

@app.post("/request-ticket")
def request_ticket(req: TicketRequest, request: Request):
    ip = request.client.host if request.client else "unknown"

    # Decode TGT first to get username for accurate attack logging
    try:
        tgt_data = jwt.decode(req.tgt, SECRET_KEY, algorithms=[ALGORITHM])
        tgt_username = tgt_data.get("username", "unknown")
    except jwt.ExpiredSignatureError:
        audit("TICKET", "unknown", "FAIL", "TGT expired", ip)
        raise HTTPException(status_code=401, detail="TGT expired")
    except jwt.InvalidTokenError:
        audit("TICKET", "unknown", "ATTACK", "Invalid TGT - possible tampering!", ip)
        raise HTTPException(status_code=401, detail="Invalid TGT - possible tampering!")

    if req.nonce in USED_NONCES:
        audit("REPLAY_ATTACK", tgt_username, "ATTACK", f"Replay attack! Nonce reused: {req.nonce[:16]}...", ip)
        raise HTTPException(status_code=401, detail="Replay attack detected! Nonce already used.")
    USED_NONCES.add(req.nonce)

    if tgt_data.get("type") != "TGT":
        audit("TICKET", tgt_data.get("username","?"), "FAIL", "Not a valid TGT", ip)
        raise HTTPException(status_code=401, detail="Not a valid TGT")
    if tgt_data["tgt_id"] not in ISSUED_TGTS:
        audit("TICKET", tgt_data.get("username","?"), "ATTACK", "TGT not in registry - forged?", ip)
        raise HTTPException(status_code=401, detail="TGT not recognized")

    username = tgt_data["username"]
    ticket_payload = {
        "type": "SERVICE_TICKET",
        "username": username,
=======
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
>>>>>>> 1d045c1acece75acf0bc7117375f5136cc51d08c
        "role": tgt_data["role"],
        "department": tgt_data["department"],
        "clearance": tgt_data["clearance"],
        "location": tgt_data["location"],
        "service": req.service,
        "nonce": req.nonce,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
    }
    ticket = jwt.encode(ticket_payload, SECRET_KEY, algorithm=ALGORITHM)
<<<<<<< HEAD
    audit("TICKET", username, "OK", f"Service ticket issued for service={req.service}", ip)
=======
>>>>>>> 1d045c1acece75acf0bc7117375f5136cc51d08c
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

<<<<<<< HEAD
@app.get("/audit-log")
def get_audit_log():
    """Return last 50 audit entries (admin tool)"""
    try:
        with open("logs/audit.log") as f:
            lines = f.readlines()
        return {"entries": [json.loads(l) for l in lines[-50:]]}
    except FileNotFoundError:
        return {"entries": []}

if __name__ == "__main__":
    import uvicorn
    logger.info("KDC Authentication Server starting on port 8000")
=======
if __name__ == "__main__":
    import uvicorn
>>>>>>> 1d045c1acece75acf0bc7117375f5136cc51d08c
    uvicorn.run(app, host="0.0.0.0", port=8000)