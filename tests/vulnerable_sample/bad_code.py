# tests/vulnerable_sample/bad_code.py
# Yeh FILE INTENTIONALLY VULNERABLE HAI — testing ke liye
# Is file pe scanners run karte hain yeh verify karne ke liye ke
# wo actually vulnerabilities pakd rahe hain
# PRODUCTION CODE MEIN KABHI AISA MAT KARO

import os
import sqlite3
import subprocess
import random
import hashlib
import pickle

# ❌ SQL Injection — user input directly query mein
# Semgrep aur Bandit dono yeh pakdenge
def get_user(username):
    conn = sqlite3.connect("users.db")
    # GALAT: f-string mein user input — SQLi vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()


# ❌ Command Injection — user input shell command mein
def ping_host(hostname):
    # GALAT: user-controlled input shell mein — RCE possible
    result = os.system(f"ping -c 1 {hostname}")
    return result


# ❌ Hardcoded Secret — Gitleaks yeh pakdega
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_PASSWORD = "super_secret_password_123"
GITHUB_TOKEN = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"


# ❌ Weak Cryptography — MD5 for password hashing
def hash_password(password: str) -> str:
    # GALAT: MD5 passwords ke liye use nahi karna chahiye
    return hashlib.md5(password.encode()).hexdigest()


# ❌ Insecure Random — security ke liye random.random() use nahi karna
def generate_token():
    # GALAT: predictable random — use secrets.token_hex() instead
    return str(random.randint(100000, 999999))


# ❌ Pickle Deserialization — arbitrary code execution possible
def load_user_data(data: bytes):
    # GALAT: untrusted data unpickle karna dangerous hai
    return pickle.loads(data)


# ❌ Path Traversal
def read_file(filename: str) -> str:
    # GALAT: user input se file path banana — directory traversal possible
    # Attacker "../../etc/passwd" de sakta hai
    with open(f"uploads/{filename}", "r") as f:
        return f.read()


# ❌ Shell=True with user input
def run_command(cmd: str):
    # GALAT: shell=True ke saath user input — command injection
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout