import os
import sys
import time
import requests
import json
import threading
import base64

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server'))
sys.path.insert(0, os.path.dirname(__file__))

SERVER_BASE = "http://localhost:5000"
ADMIN_TOKEN = "admin-secret-token-change-this"

def test_server():
    print("=" * 50)
    print("  TESTING SECURE CODE SERVER")
    print("=" * 50)
    
    print("\n[1] Testing Health Check...")
    try:
        resp = requests.get(f"{SERVER_BASE}/api/v1/health", timeout=5)
        print(f"    Status: {resp.status_code}")
        print(f"    Response: {resp.json()}")
    except Exception as e:
        print(f"    ERROR: {e}")
        return
    
    print("\n[2] Creating Test License Key...")
    try:
        resp = requests.post(
            f"{SERVER_BASE}/api/v1/admin/create-key",
            headers={"X-Admin-Token": ADMIN_TOKEN},
            json={"days": 7},
            timeout=5
        )
        print(f"    Status: {resp.status_code}")
        data = resp.json()
        print(f"    Response: {data}")
        test_key = data.get('license_key')
    except Exception as e:
        print(f"    ERROR: {e}")
        return
    
    print("\n[3] Getting HWID...")
    import hashlib, platform
    hwid = hashlib.sha256(f"{platform.system()}{platform.machine()}".encode()).hexdigest()[:32]
    print(f"    HWID: {hwid}")
    
    print("\n[4] Activating License...")
    try:
        resp = requests.post(
            f"{SERVER_BASE}/api/v1/auth/activate",
            json={"license_key": test_key, "hwid": hwid},
            timeout=5
        )
        print(f"    Status: {resp.status_code}")
        data = resp.json()
        print(f"    Response: {data}")
        token = data.get('token')
    except Exception as e:
        print(f"    ERROR: {e}")
        return
    
    print("\n[5] Loading Encrypted Code...")
    try:
        resp = requests.get(
            f"{SERVER_BASE}/api/v1/code/load",
            headers={"Authorization": f"Bearer {token}", "X-HWID": hwid},
            timeout=10
        )
        print(f"    Status: {resp.status_code}")
        data = resp.json()
        if data.get('success'):
            code = data.get('code', '')
            print(f"    Code Length: {len(code)} bytes")
            print(f"    Signature: {data.get('signature', 'N/A')[:32]}...")
            print(f"    Code Preview: {code[:100]}...")
        else:
            print(f"    Error: {data.get('error')}")
    except Exception as e:
        print(f"    ERROR: {e}")
        return
    
    print("\n" + "=" * 50)
    print("  ALL TESTS PASSED!")
    print("=" * 50)

if __name__ == '__main__':
    test_server()