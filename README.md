# SecureCorp - Zero-Trust Access Control System

## Install (once)
```bash
pip install fastapi uvicorn pyjwt cryptography httpx
```

## Run (3 terminals)

**Terminal 1:**
```bash
python kdc.py
```

**Terminal 2:**
```bash
python pdp.py
```

**Terminal 3:**
```bash
python resource_server.py
```

## Demo (4th terminal)
```bash
python demo.py
```

## API Docs (browser)
- KDC:      http://localhost:8000/docs
- PDP:      http://localhost:8001/docs
- Resource: http://localhost:8002/docs

## Users
| User  | Role     | Dept     | Clearance    | Location |
|-------|----------|----------|--------------|----------|
| alice | Admin    | IT       | secret       | internal |
| bob   | Manager  | Finance  | confidential | internal |
| carol | Employee | HR       | public       | internal |
| dave  | Employee | Finance  | public       | external |

Password for all: `password123`

## Attacks Demonstrated
1. Replay Attack → nonce reuse detection
2. Ticket Tampering → JWT signature check
3. Privilege Escalation → RBAC blocks Employee from DELETE
4. Unauthorized Access → ABAC blocks external user from secret resources
