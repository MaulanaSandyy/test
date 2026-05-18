import os
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Tuple
import bcrypt

class LicenseManager:
    def __init__(self, db_path: str = "licenses.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS licenses (
                license_key TEXT PRIMARY KEY,
                hwid TEXT,
                created_at TEXT,
                expires_at TEXT,
                is_active INTEGER DEFAULT 1,
                last_used TEXT,
                uses_count INTEGER DEFAULT 0
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS banned_hwids (
                hwid TEXT PRIMARY KEY,
                banned_at TEXT,
                reason TEXT
            )
        ''')
        conn.commit()
        conn.close()
    
    def generate_key(self, length: int = 23) -> str:
        chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def create_license(self, days: int = 30, max_hwids: int = 1) -> Tuple[str, dict]:
        license_key = self.generate_key()
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            INSERT INTO licenses (license_key, created_at, expires_at)
            VALUES (?, ?, ?)
        ''', (
            license_key,
            datetime.now().isoformat(),
            (datetime.now() + timedelta(days=days)).isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        return license_key, {"days": days, "key": license_key}
    
    def verify_license(self, license_key: str, hwid: str) -> Tuple[bool, str]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('SELECT * FROM banned_hwids WHERE hwid = ?', (hwid,))
        if c.fetchone():
            conn.close()
            return False, "Hardware banned"
        
        c.execute('SELECT * FROM licenses WHERE license_key = ?', (license_key,))
        row = c.fetchone()
        
        if not row:
            conn.close()
            return False, "Invalid license key"
        
        _, _, created_at, expires_at, is_active, last_used, uses_count = row
        
        if not is_active:
            conn.close()
            return False, "License deactivated"
        
        if datetime.now() > datetime.fromisoformat(expires_at):
            conn.close()
            return False, "License expired"
        
        c.execute('''
            UPDATE licenses 
            SET last_used = ?, uses_count = uses_count + 1 
            WHERE license_key = ?
        ''', (datetime.now().isoformat(), license_key))
        
        conn.commit()
        conn.close()
        
        return True, "Valid"
    
    def ban_hwid(self, hwid: str, reason: str = ""):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('INSERT OR REPLACE INTO banned_hwids (hwid, banned_at, reason) VALUES (?, ?, ?)',
                  (hwid, datetime.now().isoformat(), reason))
        conn.commit()
        conn.close()
    
    def revoke_license(self, license_key: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('UPDATE licenses SET is_active = 0 WHERE license_key = ?', (license_key,))
        conn.commit()
        conn.close()
    
    def get_license_info(self, license_key: str) -> Optional[dict]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT * FROM licenses WHERE license_key = ?', (license_key,))
        row = c.fetchone()
        conn.close()
        
        if row:
            return {
                "key": row[0],
                "created_at": row[2],
                "expires_at": row[3],
                "is_active": bool(row[4]),
                "last_used": row[5],
                "uses_count": row[6]
            }
        return None