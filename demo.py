# demo.py - Complete demo script (run AFTER starting all 3 servers)
import requests, uuid, sys

KDC = "http://localhost:8000"
PDP = "http://localhost:8001"
RES = "http://localhost:8002"

def separator(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)

def check_servers():
    for name, url in [("KDC", KDC), ("PDP", PDP), ("Resource Server", RES)]:
        try:
            requests.get(f"{url}/docs", timeout=2)
            print(f"  OK {name} is running at {url}")
        except Exception:
            print(f"  ERROR {name} is NOT running at {url} -- start it first!")
            sys.exit(1)

def login(username, password="password123"):
    r = requests.post(f"{KDC}/login", json={"username": username, "password": password})
    return r.json()

def get_ticket(tgt, service="resource_server"):
    nonce = str(uuid.uuid4())
    r = requests.post(f"{KDC}/request-ticket", json={
        "tgt": tgt, "service": service, "nonce": nonce
    })
    return r.json(), nonce

def get_token(username, password="password123"):
    tgt_resp = login(username, password)
    if "tgt" not in tgt_resp:
        print(f"  Login failed: {tgt_resp}")
        return None
    ticket_resp, _ = get_ticket(tgt_resp["tgt"])
    if "service_ticket" not in ticket_resp:
        print(f"  Ticket failed: {ticket_resp}")
        return None
    return ticket_resp["service_ticket"]

def access_resource(ticket, resource_id):
    r = requests.get(f"{RES}/resource/{resource_id}",
                     headers={"Authorization": f"Bearer {ticket}"})
    return r.status_code, r.json()

print("\nChecking servers...")
check_servers()

separator("SCENARIO 1 - Valid Access (Alice/Admin reads public HR doc)")
ticket = get_token("alice")
code, result = access_resource(ticket, "res-004")
print(f"Status {code}: {result.get('access')} - {result.get('resource', result.get('detail'))}")

separator("SCENARIO 2 - Access Denied (Carol/Employee tries secret Finance doc)")
ticket = get_token("carol")
code, result = access_resource(ticket, "res-002")
print(f"Status {code}: {result.get('detail', result)}")

separator("SCENARIO 3 - External user denied secret resource (Dave)")
ticket = get_token("dave")
code, result = access_resource(ticket, "res-002")
print(f"Status {code}: {result.get('detail', result)}")

separator("SCENARIO 4 - ATTACK: Replay Attack (same nonce reused)")
tgt_resp = login("bob")
nonce = str(uuid.uuid4())
r1 = requests.post(f"{KDC}/request-ticket", json={"tgt": tgt_resp["tgt"], "service": "res", "nonce": nonce})
print(f"  First request:  {r1.status_code} OK")
r2 = requests.post(f"{KDC}/request-ticket", json={"tgt": tgt_resp["tgt"], "service": "res", "nonce": nonce})
print(f"  Replay attempt: {r2.status_code} - {r2.json().get('detail')}")

separator("SCENARIO 5 - ATTACK: Ticket Tampering")
ticket = get_token("carol")
tampered = ticket[:-10] + "TAMPERED!!"
code, result = access_resource(tampered, "res-001")
print(f"Status {code}: {result.get('detail')}")

separator("SCENARIO 6 - ATTACK: Privilege Escalation (Employee tries DELETE)")
ticket = get_token("carol")
r = requests.delete(f"{RES}/resource/res-004", headers={"Authorization": f"Bearer {ticket}"})
print(f"Status {r.status_code}: {r.json().get('detail')}")

separator("SCENARIO 7 - ATTACK: Wrong Password")
result = login("alice", "wrongpassword")
print(f"Result: {result.get('detail')}")

separator("SCENARIO 8 - Admin creates a new resource")
ticket = get_token("alice")
r = requests.post(f"{RES}/resource",
    headers={"Authorization": f"Bearer {ticket}"},
    json={"name": "New IT Security Policy", "department": "IT", "classification": "confidential"})
print(f"Status {r.status_code}: {r.json()}")

separator("SCENARIO 9 - Bob (Manager/Finance) reads Finance secret")
ticket = get_token("bob")
code, result = access_resource(ticket, "res-002")
print(f"Status {code}: {result.get('access', result.get('detail'))}")

print("\nDemo complete!")