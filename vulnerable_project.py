"""
vulnerable_demo.py

Deliberately insecure code for demo purposes:
- hard-coded credentials
- unsafe subprocess usage (shell=True + unsanitized input)
- use of eval/exec on uncontrolled input
- insecure pickle loading (RCE risk)
- disabled TLS verification
- SQL query constructed via string formatting (SQL injection)
- weak hashing (MD5) for "password" checks
- insecure temp file handling
- logging secrets
"""

import os
import subprocess
import pickle
import hashlib
import tempfile
import sqlite3
import logging
import requests

# ---------- 1) Hard-coded credentials (sensitive data in source) ----------
DB_USER = "admin"
DB_PASS = "Sup3rS3cret!"     # Sonar should flag hard-coded credentials

# ---------- 2) Unsafe subprocess call with shell=True and unsanitized input ----------
def list_files(user_input):
   # Bad: building shell command from user input, shell=True enables injection
   cmd = f"dir {user_input}"
   return subprocess.check_output(cmd, shell=True, text=True)

# ---------- 3) Use of eval on potentially unsafe input ----------
def calculate(expression):
   # Extremely dangerous if expression comes from an untrusted source
   return eval(expression)

# ---------- 4) Unpickling untrusted data (RCE) ----------
def load_state(pickle_path):
   with open(pickle_path, "rb") as f:
       # Dangerous: untrusted pickle contents can execute arbitrary code
       return pickle.load(f)

# ---------- 5) Insecure TLS usage ----------
def fetch_url_insecure(url):
   # Disables certificate verification -> MITM risk
   return requests.get(url, verify=False).text

# ---------- 6) SQL built via string formatting (SQL injection) ----------
def find_user_by_name(conn, name):
   # Dangerous: name is interpolated directly, allows SQL injection
   query = f"SELECT * FROM users WHERE name = '{name}'"
   cur = conn.cursor()
   cur.execute(query)
   return cur.fetchall()

# ---------- 7) Weak hashing for passwords ----------
def check_password(password):
   # Using MD5 is broken for password hashing
   hashed = hashlib.md5(password.encode('utf-8')).hexdigest()
   # pretend we compare with stored hash
   return hashed == "e99a18c428cb38d5f260853678922e03"  # md5('abc123')

# ---------- 8) Insecure temporary file usage ----------
def write_temp_secret(secret):
   # This creates a predictable filename in the system temp dir
   path = os.path.join(tempfile.gettempdir(), "mysecret.txt")
   with open(path, "w") as f:
       f.write(secret)
   return path

# ---------- 9) Logging sensitive information ----------
logging.basicConfig(level=logging.DEBUG)
def do_sensitive_operation(token):
   logging.debug(f"Using API token: {token}")   # logs secret in cleartext
   # pretend to call remote service
   return True

# ---------- 10) Exec with unvalidated input ----------
def run_code_snippet(snippet):
   # Exec can run arbitrary code
   exec(snippet, {})

# ---------- Demo / main ----------
if __name__ == "__main__":
   # Demonstrate multiple issues in action (for demo only)
   print("1) Hard-coded creds:", DB_USER, DB_PASS)
   try:
       print("2) list_files (unsafe):")
       print(list_files("*.py"))
   except Exception as e:
       print("list_files failed:", e)

   print("3) eval demo:", calculate("2 + 2"))

   # create a sqlite db for SQL demo
   conn = sqlite3.connect(":memory:")
   conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
   conn.executemany("INSERT INTO users (name) VALUES (?)", [("alice",), ("bob",)])
   print("4) SQL injection demo (safe name):", find_user_by_name(conn, "alice"))
   print("4b) SQL injection demo (malicious):")
   try:
       # malicious payload that would drop the table in a vulnerable DB
       print(find_user_by_name(conn, "alice'; DROP TABLE users; --"))
   except Exception as e:
       print("SQL injection attempt caused:", e)

   print("5) Weak hash check for 'abc123':", check_password("abc123"))
   print("6) insecure temp path written to:", write_temp_secret("top-secret"))
   do_sensitive_operation("very-sensitive-token")
   # DO NOT run load_state or exec with untrusted data in real environments

