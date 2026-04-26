<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Poppins&weight=700&size=40&duration=3000&pause=1000&color=6C63FF&center=true&vCenter=true&width=600&lines=SecureCorp+Zero-Trust;Access+Control+System" alt="SecureCorp" />

<br/>

![Python](https://img.shields.io/badge/Python-3.11-6C63FF?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)
![Zero Trust](https://img.shields.io/badge/Zero--Trust-Architecture-FF6B6B?style=for-the-badge)

<br/>

> *"Never trust, always verify."*
> 
> A fully interactive, production-grade **Zero-Trust Access Control System** built from scratch — alone — with RBAC, ABAC, JWT authentication, real-time attack detection, and a live security dashboard.

<br/>

---

</div>

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT / BROWSER                         │
│              platform.html + attack.html                    │
└───────────────────────┬─────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│  🔑 KDC       │ │  ⚖️  PDP      │ │  📁 Resource  │
│  Port 8000    │ │  Port 8001    │ │  Port 8002    │
│               │ │               │ │               │
│ • Login       │ │ • RBAC Engine │ │ • REST API    │
│ • TGT Issue   │ │ • ABAC Engine │ │ • JWT Verify  │
│ • Nonce Store │ │ • 6 Policies  │ │ • PDP Client  │
│ • Brute Force │ │ • Audit Log   │ │ • Audit Log   │
│   Detection   │ │               │ │               │
└───────────────┘ └───────────────┘ └───────────────┘
        │               ▲               │
        └───────────────┴───────────────┘
                   logs/audit.log
```

---

## ✨ Features

| Feature | Description |
|--------|-------------|
| 🔐 **Kerberos-inspired Auth** | TGT + Service Ticket flow with HMAC-SHA256 signed JWTs |
| 🧠 **Dual Access Control** | RBAC (role-based) + ABAC (attribute-based) combined |
| 🛡️ **Real Attack Detection** | Replay, Tampering, Privilege Escalation, Brute Force |
| 📊 **Live Audit Log** | Every action traced — who, what, when, from where, result |
| 🌐 **Interactive Platform** | Full web dashboard with live attack labs |
| 🐳 **Dockerized** | 3 isolated microservices with docker-compose |
| 🕐 **Time-Based Access** | ABAC policy blocks access outside business hours |
| 🏢 **Department Isolation** | Users can only access their own department's resources |

---

## 👥 Users & Roles

| User | Role | Department | Clearance | Location |
|------|------|-----------|-----------|----------|
| `alice` | Admin | IT | 🔴 Secret | Internal |
| `bob` | Manager | Finance | 🟠 Confidential | Internal |
| `carol` | Employee | HR | 🟢 Public | Internal |
| `dave` | Employee | Finance | 🟢 Public | 🌍 External |

> Password for all: `password123`

---

## 🚀 Quick Start

### Option 1 — Docker (Recommended)

```bash
git clone https://github.com/Ahlamghribi/SecureCorp-Zero-Trust-Access-Control-System.git
cd SecureCorp-Zero-Trust-Access-Control-System
docker compose up --build
```

### Option 2 — Manual (3 terminals)

```bash
# Install dependencies
pip install fastapi uvicorn pyjwt cryptography httpx

# Terminal 1 — Authentication Server
python kdc.py

# Terminal 2 — Policy Decision Point
python pdp.py

# Terminal 3 — Resource Server
python resource_server.py
```

Then open `platform.html` in your browser. ✅

---

## 🔐 Security Policies (ABAC)

```json
policy-1  →  Secret resources blocked for external users
policy-2  →  Department isolation (HR ≠ Finance ≠ IT)
policy-3  →  Confidential resources require confidential clearance
policy-4  →  Time-based access: only 08:00–18:00
policy-5  →  Secret resources require at least confidential clearance
policy-6  →  Separation of Duties: Managers cannot DELETE
```

---

## 💥 Attack Scenarios

### 1. Replay Attack
```
Bob logs in → gets nonce "abc123" → sends ticket request
Attacker replays the SAME nonce → KDC checks USED_NONCES → 401 BLOCKED
```

### 2. Ticket Tampering
```
Carol gets JWT: header.payload.SIGNATURE
Attacker changes payload (role → Admin) → signature invalid
Resource Server: jwt.decode() → InvalidTokenError → 401 BLOCKED
```

### 3. Privilege Escalation
```
Carol (Employee) attempts DELETE operation
PDP RBAC check: Employee allowed = ["read"]
"delete" not in ["read"] → PRIVILEGE_ESCALATION logged → 403 BLOCKED
```

### 4. Brute Force
```
Alice enters wrong password × 3
KDC: FAILED_LOGINS["alice"] >= 3 → BRUTE_FORCE event → audit log ATTACK
```

---

## 📡 API Endpoints

```
KDC  (8000)    POST /login              →  Get TGT
               POST /request-ticket     →  Get Service Ticket
               GET  /audit-log          →  View all events

PDP  (8001)    POST /decide             →  ALLOW or DENY decision
               GET  /policies           →  List all ABAC policies

RES  (8002)    GET  /resource/{id}      →  Read resource
               POST /resource           →  Create resource
               DELETE /resource/{id}    →  Delete resource
               GET  /resources          →  List all resources
```

---

## 📁 Project Structure

```
SecureCorp/
├── kdc.py                  # Authentication Server (Port 8000)
├── pdp.py                  # Policy Decision Point (Port 8001)
├── resource_server.py      # Resource Server (Port 8002)
├── config.py               # Shared JWT config
├── policies.json           # ABAC policies
├── demo.py                 # Full demo script (10 scenarios)
├── platform.html           # Interactive security dashboard
├── attack.html             # Live attack lab interface
├── docker-compose.yml      # Orchestration
├── Dockerfile.kdc          # KDC container
├── Dockerfile.pdp          # PDP container
├── Dockerfile.resource     # Resource Server container
└── logs/
    ├── audit.log           # Combined audit trail
    ├── kdc.log
    ├── pdp.log
    └── resource.log
```

---

## 🧠 Key Concepts

**Zero Trust** — Never trust, always verify. Every request is authenticated and authorized, regardless of network location.

**JWT (JSON Web Token)** — 3-part token: `Header.Payload.Signature`. Signed with HMAC-SHA256. Any modification invalidates the signature instantly.

**Nonce** — A unique identifier used exactly once. Stored in `USED_NONCES`. Reuse = Replay Attack detected.

**RBAC** — Role-Based Access Control. Admin > Manager > Employee. Defines *what actions* are allowed.

**ABAC** — Attribute-Based Access Control. Checks context: time, location, clearance, department. Defines *under what conditions*.

---

<div align="center">

---

**Built with 💜 by Ahlam Ghribi**

![visitors](https://visitor-badge.laobi.icu/badge?page_id=Ahlamghribi.SecureCorp)

</div>
