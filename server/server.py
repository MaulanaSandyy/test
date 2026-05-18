from flask import Flask, request, jsonify, abort, render_template
from flask_cors import CORS
import hashlib
import uuid
import time
import os
import json
import secrets
from license_manager import LicenseManager
from security import SecureEncryptor, CodeIntegrity
from functools import wraps

app = Flask(__name__, template_folder='templates')
CORS(app)

lm = LicenseManager()
MASTER_KEY = "c1a12885165e153725782ba039ee645f12997cde9c93aa1266193d50404e4786"
encryptor = SecureEncryptor(MASTER_KEY)

ENCRYPTED_CODE_FILE = "encrypted_code.bin"
LICENSE_SERVER_KEY = "your-secret-server-key-change-this"
ADMIN_TOKEN = "admin-secret-token-change-this"

def require_license():
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                abort(401, description="No authorization header")
            
            try:
                auth_type, credentials = auth_header.split(' ', 1)
                if auth_type.lower() != 'bearer':
                    abort(401, description="Invalid auth type")
                
                token_data = decrypt_token(credentials)
                if not token_data:
                    abort(401, description="Invalid token")
                
                license_key = token_data.get('license_key')
                hwid = token_data.get('hwid')
                
                if not license_key or not hwid:
                    abort(401, description="Missing credentials")
                
                is_valid, message = lm.verify_license(license_key, hwid)
                if not is_valid:
                    abort(403, description=message)
                
            except Exception as e:
                abort(401, description=str(e))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_hwid():
    hwid = request.headers.get('X-HWID')
    if not hwid:
        hwid_data = {
            'user_agent': request.headers.get('User-Agent', ''),
            'ip': request.remote_addr,
            'timestamp': str(int(time.time()))
        }
        hwid = hashlib.sha256(str(hwid_data).encode()).hexdigest()[:32]
    return hwid

def create_token(license_key: str, hwid: str) -> str:
    token_data = {
        'license_key': license_key,
        'hwid': hwid,
        'timestamp': int(time.time()),
        'nonce': secrets.token_hex(16)
    }
    return encrypt_token(token_data)

def encrypt_token(data: dict) -> str:
    import base64
    import json
    return base64.b64encode(json.dumps(data).encode()).decode()

def decrypt_token(token: str) -> dict:
    import base64
    import json
    try:
        return json.loads(base64.b64decode(token.encode()).decode())
    except:
        return {}

@app.route('/api/v1/auth/activate', methods=['POST'])
def activate_license():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'Invalid request'}), 400
    
    license_key = data.get('license_key')
    hwid = data.get('hwid')
    
    if not license_key or not hwid:
        return jsonify({'success': False, 'error': 'Missing credentials'}), 400
    
    is_valid, message = lm.verify_license(license_key, hwid)
    
    if not is_valid:
        return jsonify({'success': False, 'error': message}), 403
    
    token = create_token(license_key, hwid)
    
    return jsonify({
        'success': True,
        'token': token,
        'expires_in': 3600
    })

@app.route('/api/v1/code/load', methods=['GET'])
@require_license()
def load_code():
    code_file = ENCRYPTED_CODE_FILE
    
    if not os.path.exists(code_file):
        return jsonify({'success': False, 'error': 'Code not available'}), 503
    
    hwid = get_hwid()
    token_data = decrypt_token(request.headers.get('Authorization', '').split(' ', 1)[1])
    license_key = token_data.get('license_key')
    
    with open(code_file, 'r') as f:
        encrypted_payload = json.load(f)
    
    try:
        decrypted = encryptor.decrypt_code(encrypted_payload)
        if not decrypted:
            return jsonify({'success': False, 'error': 'Decryption failed'}), 500
        
        return jsonify({
            'success': True,
            'code': decrypted,
            'signature': CodeIntegrity.generate_hash(decrypted)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/v1/admin/create-key', methods=['POST'])
def admin_create_key():
    data = request.get_json()
    admin_token = request.headers.get('X-Admin-Token')
    
    if admin_token != ADMIN_TOKEN:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    days = data.get('days', 30) if data else 30
    
    key, info = lm.create_license(days=days)
    
    return jsonify({
        'success': True,
        'license_key': key,
        'expires_in_days': days
    })

@app.route('/api/v1/admin/revoke-key', methods=['POST'])
def admin_revoke_key():
    admin_token = request.headers.get('X-Admin-Token')
    if admin_token != ADMIN_TOKEN:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    if not data or 'license_key' not in data:
        return jsonify({'success': False, 'error': 'Missing license_key'}), 400
    
    lm.revoke_license(data['license_key'])
    
    return jsonify({'success': True})

@app.route('/api/v1/admin/ban-hwid', methods=['POST'])
def admin_ban_hwid():
    admin_token = request.headers.get('X-Admin-Token')
    if admin_token != ADMIN_TOKEN:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    if not data or 'hwid' not in data:
        return jsonify({'success': False, 'error': 'Missing hwid'}), 400
    
    lm.ban_hwid(data['hwid'], data.get('reason', ''))
    
    return jsonify({'success': True})

@app.route('/api/v1/status', methods=['GET'])
def server_status():
    return jsonify({
        'status': 'online',
        'version': '1.0.0',
        'timestamp': int(time.time())
    })

@app.route('/api/v1/health', methods=['GET'])
def health_check():
    return jsonify({'healthy': True})

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    print("=" * 50)
    print("  SECURE CODE SERVER")
    print("  Version: 1.0.0")
    print("=" * 50)
    print("\nAdmin Commands:")
    print("  Create Key: curl -X POST -H 'X-Admin-Token: admin-secret-token-change-this' \\")
    print("               -d '{\"days\": 30}' http://localhost:5000/api/v1/admin/create-key")
    print("")
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)