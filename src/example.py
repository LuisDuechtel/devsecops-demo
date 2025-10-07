
#!/usr/bin/env python3
"""
Beispiel Python-Code mit verschiedenen Sicherheitslücken
für DevSecOps Pipeline Testing
"""

import os
import sqlite3
import hashlib
import pickle
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded Credentials
DATABASE_PASSWORD = "admin123"  # Gitleaks wird das finden
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvw"  # API Key im Code
SECRET_TOKEN = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"  # GitHub Token

# VULNERABILITY 2: Weak Cryptography
def weak_hash_password(password):
    """MD5 ist unsicher für Passwort-Hashing"""
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABILITY 3: SQL Injection
@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Unsichere String-Concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)  # SQL Injection möglich!
    
    return str(cursor.fetchall())

# VULNERABILITY 4: Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host', 'google.com')
    
    # Unsichere Kommando-Ausführung
    result = os.system(f"ping -c 1 {host}")  # Command Injection!
    
    # Alternative unsichere Methode
    output = subprocess.check_output(f"nslookup {host}", shell=True)
    
    return str(output)

# VULNERABILITY 5: Path Traversal
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    
    # Unsicherer Dateizugriff
    with open(f"/var/www/files/{filename}", 'r') as f:  # Path Traversal möglich!
        content = f.read()
    
    return content

# VULNERABILITY 6: Insecure Deserialization
@app.route('/load')
def load_data():
    data = request.args.get('data')
    
    # Unsichere Deserialisierung
    obj = pickle.loads(data.encode())  # Arbitrary Code Execution möglich!
    
    return str(obj)

# VULNERABILITY 7: Cross-Site Scripting (XSS)
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    
    # Unsicheres Template Rendering
    template = f"<h1>Hello {name}!</h1>"  # XSS möglich!
    return render_template_string(template)

# VULNERABILITY 8: XXE (XML External Entity) Injection
import xml.etree.ElementTree as ET

@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    xml_data = request.data
    
    # Unsicheres XML Parsing
    root = ET.fromstring(xml_data)  # XXE möglich!
    return str(root.tag)

# VULNERABILITY 9: Weak Random Number Generation
import random

def generate_token():
    """Unsichere Token-Generierung"""
    token = ''
    for _ in range(16):
        token += str(random.randint(0, 9))  # Vorhersagbare Zufallszahlen!
    return token

# VULNERABILITY 10: Debug Mode in Production
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)  # Debug Mode aktiviert!

# VULNERABILITY 11: Eval Usage
def calculate(expression):
    """Unsichere Verwendung von eval"""
    result = eval(expression)  # Code Injection möglich!
    return result

# VULNERABILITY 12: Insecure File Permissions
def create_sensitive_file():
    """Erstellt Datei mit unsicheren Berechtigungen"""
    with open('/tmp/sensitive_data.txt', 'w') as f:
        f.write("Sensitive information")
    os.chmod('/tmp/sensitive_data.txt', 0o777)  # Jeder kann lesen/schreiben!

# VULNERABILITY 13: Missing Input Validation
@app.route('/age')
def check_age():
    age = request.args.get('age')
    
    # Keine Validierung
    if int(age) >= 18:  # Kann ValueError werfen
        return "Access granted"
    return "Access denied"

# VULNERABILITY 14: Insecure Temporary File
import tempfile

def process_upload():
    """Unsichere temporäre Datei"""
    # Vorhersagbarer Dateiname
    temp_file = '/tmp/upload_temp.txt'  # Race Condition möglich!
    with open(temp_file, 'w') as f:
        f.write("temp data")

# VULNERABILITY 15: Information Disclosure
@app.errorhandler(Exception)
def handle_error(e):
    # Stack Trace wird angezeigt
    return f"Error: {str(e)}\n\nStack trace: {traceback.format_exc()}"  # Information Leak!