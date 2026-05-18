import os
import hashlib
import secrets
import time
import gzip
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Optional
import json

class SecureEncryptor:
    def __init__(self, master_key: Optional[str] = None):
        if master_key is None:
            master_key = secrets.token_hex(32)
        self.master_key = master_key
    
    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.master_key.encode())
    
    def _generate_salt(self) -> bytes:
        return secrets.token_bytes(16)
    
    def encrypt_code(self, python_code: str) -> Tuple[bytes, dict]:
        salt = self._generate_salt()
        iv = secrets.token_bytes(16)
        key = self._derive_key(salt)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        compressed = gzip.compress(python_code.encode('utf-8'))
        padding = 16 - (len(compressed) % 16)
        padded_data = compressed + bytes([padding] * padding)
        
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        payload = {
            'encrypted': base64.b64encode(encrypted).decode(),
            'salt': base64.b64encode(salt).decode(),
            'iv': base64.b64encode(iv).decode(),
            'timestamp': int(time.time()),
            'version': '1.0'
        }
        
        return encrypted, payload
    
    def decrypt_code(self, payload: dict) -> Optional[str]:
        try:
            encrypted = base64.b64decode(payload['encrypted'])
            salt = base64.b64decode(payload['salt'])
            iv = base64.b64decode(payload['iv'])
            
            key = self._derive_key(salt)
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted = decryptor.update(encrypted) + decryptor.finalize()
            padding = decrypted[-1]
            decompressed = gzip.decompress(decrypted[:-padding])
            
            return decompressed.decode('utf-8')
        except Exception as e:
            return None
    
    def save_encrypted(self, payload: dict, filepath: str):
        with open(filepath, 'w') as f:
            json.dump(payload, f)
    
    def load_encrypted(self, filepath: str) -> dict:
        with open(filepath, 'r') as f:
            return json.load(f)

class CodeIntegrity:
    @staticmethod
    def generate_hash(code: str) -> str:
        return hashlib.sha256(code.encode()).hexdigest()
    
    @staticmethod
    def verify_hash(code: str, expected_hash: str) -> bool:
        return hashlib.sha256(code.encode()).hexdigest() == expected_hash

def obfuscate_code(code: str) -> str:
    replacements = {
        'import': '_i_',
        'from': '_f_',
        'class': '_c_',
        'def': '_d_',
        'True': '_T_',
        'False': '_F_',
        'None': '_N_',
        'and': '_a_',
        'or': '_o_',
        'not': '_n_',
    }
    
    for old, new in replacements.items():
        code = code.replace(old, new)
    
    return code