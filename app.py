from flask import Flask, request, jsonify, send_from_directory, make_response, session, redirect
import bcrypt
import logging
import urllib.parse
import urllib.request
import hashlib
import sqlite3
import re
import secrets
import os
import shutil
from datetime import datetime, timezone, timedelta
from contextlib import contextmanager
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Налаштування Rate Limiting з явним in-memory storage
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Налаштування логування
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# WAF правила
WAF_RULES = {
    'sql_injection': r'(\b(union|select|from|where)\b|\'--|--|;|\/\*|\*\/)',
    'xss': r'(<script>|on\w+=|javascript:)',
    'path_traversal': r'(\.\./|\.\.)',
}

# Симуляція файлової системи
SIMULATED_FILES = {
    "public.txt": "This is a public file.",
    "secret.txt": "This is a secret file! Sensitive data here.",
    "D:/opv1224/tech_learn/cybersecurity/дипломна/secret.txt": "Simulated sensitive file from your directory!"
}

# Папка для резервних копій
BACKUP_DIR = "backups"
if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)

@contextmanager
def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def backup_db():
    try:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(BACKUP_DIR, f"users_backup_{timestamp}.db")
        shutil.copy2('users.db', backup_path)
        logging.info(f"Backup created: {backup_path}")
    except Exception as e:
        logging.error(f"Failed to create backup: {str(e)}")

def init_db():
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if not c.fetchone():
                logging.info("Creating users table in users.db")
                c.execute('''CREATE TABLE users
                             (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                              username TEXT UNIQUE, 
                              password TEXT, 
                              role TEXT, 
                              is_current BOOLEAN DEFAULT 0)''')
                conn.commit()
                logging.info("Users table created successfully")
            else:
                logging.info("Users table already exists")
    except Exception as e:
        logging.error(f"Failed to initialize database: {str(e)}")
        raise

try:
    init_db()
except Exception as e:
    logging.error(f"Database initialization failed on startup: {str(e)}")
    raise SystemExit("Cannot start application: Database initialization failed")

def check_table_exists():
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            return c.fetchone() is not None
    except Exception as e:
        logging.error(f"Error checking table existence: {str(e)}")
        return False

def is_authenticated():
    if not check_table_exists():
        logging.warning("is_authenticated failed: users table not found")
        return False
    try:
        username = session.get('username')
        if not username:
            logging.warning("is_authenticated failed: No username in session")
            return False
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT username FROM users WHERE is_current = 1")
            user = c.fetchone()
            if user and user['username'] == username:
                logging.info(f"is_authenticated succeeded for user: {username}")
                return True
            logging.warning(f"is_authenticated failed: Session user ({username}) does not match current user in DB ({user['username'] if user else 'none'})")
            return False
    except Exception as e:
        logging.error(f"Error in is_authenticated: {str(e)}")
        return False

def is_admin():
    if not check_table_exists():
        logging.warning("is_admin failed: users table not found")
        return False
    try:
        username = session.get('username')
        if not username:
            logging.warning("is_admin failed: No username in session")
            return False
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT role FROM users WHERE username = ? AND is_current = 1", (username,))
            user = c.fetchone()
            if user and user['role'] == "admin":
                logging.info(f"is_admin succeeded for user: {username}")
                return True
            logging.warning(f"is_admin failed for user: {username}, role: {user['role'] if user else 'none'}")
            return False
    except Exception as e:
        logging.error(f"Error in is_admin: {str(e)}")
        return False
    
def is_manager():
    if not check_table_exists():
        logging.warning("is_manager failed: users table not found")
        return False
    try:
        username = session.get('username')
        if not username:
            logging.warning("is_manager failed: No username in session")
            return False
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT role FROM users WHERE username = ? AND is_current = 1", (username,))
            user = c.fetchone()
            if user and user['role'] == "manager":
                logging.info(f"is_manager succeeded for user: {username}")
                return True
            logging.warning(f"is_manager failed for user: {username}, role: {user['role'] if user else 'none'}")
            return False
    except Exception as e:
        logging.error(f"Error in is_manager: {str(e)}")
        return False    


def simulate_waf_check(input_data):
    for rule_name, pattern in WAF_RULES.items():
        if re.search(pattern, input_data, re.IGNORECASE):
            logging.warning(f"WAF blocked request: {rule_name} pattern detected in input: {input_data}")
            return False, f"WAF blocked request: Potential {rule_name} attack detected."
    return True, None

@app.before_request
def enforce_ssl():
    if request.scheme != 'https' and not app.debug:
        url = request.url.replace('http://', 'https://', 1)
        logging.info(f"Redirecting HTTP to HTTPS: {url}")
        return make_response(redirect(url), 301)

@app.before_request
def check_ip_for_session():
    if 'user_ip' in session and session['user_ip'] != get_remote_address():
        logging.warning(f"Session hijacking attempt detected: IP mismatch. Session IP: {session['user_ip']}, Current IP: {get_remote_address()}")
        session.clear()
        return jsonify({"status": "error", "message": "Session invalidated: IP address mismatch."}), 403

@app.route('/')
def serve_index():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
        logging.info(f"Generated new CSRF token: {session['csrf_token']}")
    response = send_from_directory('static', 'index.html')
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.route("/vulnerable_access")
def vulnerable_access():
    user_id = request.args.get("user_id")
    waf_pass, waf_message = simulate_waf_check(user_id or "")
    if not waf_pass:
        return jsonify({"status": "error", "message": waf_message}), 403
    if not check_table_exists():
        return jsonify({"status": "error", "message": "Database error: users table not found"}), 500
    with get_db() as conn:
        c = conn.cursor()
        try:
            c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            user = c.fetchone()
            logging.info(f"Vulnerable access attempt: user_id={user_id}")
            return jsonify({"status": "success", "message": f"User data: {user['username']}"}) if user else jsonify({"status": "error", "message": "User not found"})
        except Exception as e:
            logging.error(f"Error in vulnerable_access: {str(e)}")
            return jsonify({"status": "error", "message": f"Database error: {str(e)}"}), 500

@app.route("/protected_access")
def protected_access():
    if not is_authenticated():
        logging.warning("Unauthorized access attempt to protected_access")
        return jsonify({"status": "error", "message": "Access denied: Not authenticated."}), 401
    user_id = request.args.get("user_id")
    waf_pass, waf_message = simulate_waf_check(user_id or "")
    if not waf_pass:
        return jsonify({"status": "error", "message": waf_message}), 403
    if not check_table_exists():
        return jsonify({"status": "error", "message": "Database error: users table not found"}), 500
    with get_db() as conn:
        c = conn.cursor()
        try:
            c.execute("SELECT id FROM users WHERE is_current = 1")
            current_user = c.fetchone()
            if not current_user or user_id != str(current_user['id']):
                logging.warning(f"Access denied: user_id={user_id}, current_user={current_user['id'] if current_user else 'none'}")
                return jsonify({"status": "error", "message": f"Access denied: Requested user_id={user_id}, but logged-in user_id={current_user['id'] if current_user else 'none'}."}), 403
            c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            user = c.fetchone()
            return jsonify({"status": "success", "message": f"User data: {user['username']}"}) if user else jsonify({"status": "error", "message": "User not found"})
        except Exception as e:
            logging.error(f"Error in protected_access: {str(e)}")
            return jsonify({"status": "error", "message": f"Database error: {str(e)}"}), 500

@app.route("/vulnerable_sql_injection")
def vulnerable_sql_injection():
    username = request.args.get("username")
    if not username:
        return jsonify({"status": "error", "message": "Error: Enter a username!"}), 400
    waf_pass, waf_message = simulate_waf_check(username)
    if not waf_pass:
        return jsonify({"status": "error", "message": waf_message}), 403
    if not check_table_exists():
        return jsonify({"status": "error", "message": "Database error: users table not found"}), 500
    with get_db() as conn:
        c = conn.cursor()
        try:
            query = f"SELECT id, username, password, role FROM users WHERE username = '{username}'"
            c.execute(query)
            users = c.fetchall()
            logging.warning(f"Vulnerable SQL query executed: {query}")
            if users:
                result = "Found users:\n" + "\n".join(f"ID: {user['id']}, Username: {user['username']}, Password: {user['password']}, Role: {user['role']}" for user in users)
                return jsonify({"status": "success", "message": result})
            return jsonify({"status": "error", "message": "User not found"})
        except Exception as e:
            logging.error(f"SQL Error in vulnerable_sql_injection: {str(e)}")
            return jsonify({"status": "error", "message": f"SQL Error: {str(e)}"}), 500

@app.route("/protected_sql_injection")
def protected_sql_injection():
    if not is_authenticated():
        logging.warning("Unauthorized SQL injection attempt")
        return jsonify({"status": "error", "message": "Access denied: Not authenticated."}), 401
    username = request.args.get("username")
    if not username:
        return jsonify({"status": "error", "message": "Error: Enter a username!"}), 400
    waf_pass, waf_message = simulate_waf_check(username)
    if not waf_pass:
        return jsonify({"status": "error", "message": waf_message}), 403
    if not check_table_exists():
        return jsonify({"status": "error", "message": "Database error: users table not found"}), 500
    with get_db() as conn:
        c = conn.cursor()
        try:
            c.execute("SELECT username FROM users WHERE is_current = 1")
            current_user = c.fetchone()
            if not current_user or username != current_user['username']:
                logging.warning(f"SQL access denied: username={username}, current_user={current_user['username'] if current_user else 'none'}")
                return jsonify({"status": "error", "message": f"Access denied: Requested username={username}, but logged-in username={current_user['username'] if current_user else 'none'}."}), 403
            c.execute("SELECT id, username, role FROM users WHERE username = ? AND is_current = 1", (username,))
            users = c.fetchall()
            if users:
                result = "Found user:\n" + "\n".join(f"ID: {user['id']}, Username: {user['username']}, Role: {user['role']}" for user in users)
                return jsonify({"status": "success", "message": result})
            return jsonify({"status": "error", "message": "User not found or not current"})
        except Exception as e:
            logging.error(f"SQL Error in protected_sql_injection: {str(e)}")
            return jsonify({"status": "error", "message": f"SQL Error: {str(e)}"}), 500

@app.route("/vulnerable_xss")
def vulnerable_xss():
    input_text = request.args.get("input")
    if not input_text:
        return jsonify({"status": "error", "message": "Error: Input is required!"}), 400
    demo_mode = request.args.get("demo", "false").lower() == "true"
    if not demo_mode:
        waf_pass, waf_message = simulate_waf_check(input_text)
        if not waf_pass:
            return jsonify({"status": "error", "message": waf_message}), 403
    logging.warning(f"Vulnerable XSS input: {input_text} (demo_mode={demo_mode})")
    response = make_response(f"<div>{input_text}</div>")
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    if demo_mode:
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-inline' 'self'"
    return response

@app.route("/protected_xss")
def protected_xss():
    input_text = request.args.get("input")
    if not input_text:
        return jsonify({"status": "error", "message": "Error: Input is required!"}), 400
    waf_pass, waf_message = simulate_waf_check(input_text)
    if not waf_pass:
        return jsonify({
            "status": "error",
            "message": f"\nLayer 1: WAF blocked the request: {waf_message}. "
                       "\nLayer 2: Input sanitization would have escaped the input. "
                       "\nLayer 3: Content Security Policy would have restricted script execution."
        }), 403
    escaped_text = input_text.replace("&", "&").replace("<", "<").replace(">", ">").replace('"', '"').replace("'", "'")
    response = make_response(f"<div>{escaped_text}</div>")
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
    logging.info(f"Protected XSS input escaped: {escaped_text}")
    return response

@app.route("/waf_demo", methods=["POST"])
def waf_demo():
    data = request.get_json()
    input_text = data.get("input")
    if not input_text:
        return jsonify({"status": "error", "message": "Input is required!"}), 400
    waf_pass, waf_message = simulate_waf_check(input_text)
    if not waf_pass:
        return jsonify({"status": "error", "message": waf_message}), 403
    return jsonify({"status": "success", "message": "Input passed WAF check."})

@app.route("/vulnerable_ddos")
def vulnerable_ddos():
    return jsonify({"status": "success", "message": "Request processed (vulnerable to DDoS)."})

@app.route("/protected_ddos")
@limiter.limit("10 per minute")
def protected_ddos():
    return jsonify({"status": "success", "message": "Request processed (protected from DDoS)."})

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required!"}), 400
    waf_pass, waf_message = simulate_waf_check(username + password)
    if not waf_pass:
        return jsonify({"status": "error", "message": waf_message}), 403
    if not check_table_exists():
        return jsonify({"status": "error", "message": "Database error: users table not found"}), 500
    with get_db() as conn:
        c = conn.cursor()
        try:
            c.execute("SELECT id, password, role FROM users WHERE username = ?", (username,))
            user = c.fetchone()
            if user:
                stored_password = user['password']
                if stored_password.startswith('$2b$'):
                    password_match = bcrypt.checkpw(password.encode("utf-8"), stored_password.encode("utf-8"))
                else:
                    password_match = password == stored_password
                if password_match:
                    conn.execute("BEGIN TRANSACTION")
                    c.execute("UPDATE users SET is_current = 0 WHERE is_current = 1")
                    c.execute("UPDATE users SET is_current = 1 WHERE id = ?", (user['id'],))
                    conn.commit()
                    session['username'] = username
                    session['csrf_token'] = secrets.token_hex(16)
                    session['user_ip'] = get_remote_address()
                    logging.info(f"User logged in: {username}, Role: {user['role']}, IP: {session['user_ip']}")
                    return jsonify({"status": "success", "message": f"Login successful! Current user: {username} (Role: {user['role']})"})
            logging.warning(f"Failed login attempt for username: {username}")
            return jsonify({"status": "error", "message": "Login failed! Invalid credentials."}), 401
        except Exception as e:
            conn.rollback()
            logging.error(f"Login error: {str(e)}")
            return jsonify({"status": "error", "message": f"Database error: {str(e)}"}), 500

@app.route("/logout", methods=["POST"])
def logout():
    username = session.get('username', 'unknown')
    if not check_table_exists():
        logging.error("Logout failed: users table not found")
        return jsonify({"status": "error", "message": "Database error: users table not found"}), 500
    with get_db() as conn:
        c = conn.cursor()
        try:
            conn.execute("BEGIN TRANSACTION")
            c.execute("UPDATE users SET is_current = 0 WHERE is_current = 1")
            conn.commit()
            session.clear()
            logging.info(f"User logged out successfully: {username}")
            return jsonify({"status": "success", "message": "Logout successful! No current user."})
        except Exception as e:
            conn.rollback()
            logging.error(f"Logout error: {str(e)}")
            return jsonify({"status": "error", "message": f"Database error: {str(e)}"}), 500

@app.route("/vulnerable_error")
def vulnerable_error():
    try:
        raise Exception("Internal server error")
    except Exception as e:
        stack_trace = (
            "Traceback (most recent call last):\n"
            "  File '/app/app.py', line 123, in vulnerable_error\n"
            "    raise Exception('Internal server error')\n"
            "Exception: Internal server error\n\n"
            "Tech Stack Details:\n"
            "- Application: Flask 2.0.1\n"
            "- Python Version: 3.12.1\n"
            "- WSGI Server: Werkzeug 2.0.0\n"
            "- Config File: /app/config.py\n"
            "- Server: Gunicorn 20.1.0\n"
            "- Environment: DATABASE_URL=sqlite:///users.db\n"
            "- Debug Mode: Enabled"
        )
        logging.error(f"Vulnerable error exposed: {str(e)}")
        return jsonify({"status": "error", "message": stack_trace}), 500

@app.route("/protected_error")
def protected_error():
    try:
        raise Exception("Error")
    except Exception:
        logging.error("Protected error handled")
        return jsonify({"status": "error", "message": "Something went wrong, contact support."}), 500

@app.route("/vulnerable_create_account", methods=["POST"])
def vulnerable_create_account():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")
    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required!"}), 400
    demo_mode = request.args.get("demo", "false").lower() == "true"
    if not demo_mode:
        waf_pass, waf_message = simulate_waf_check(username + password)
        if not waf_pass:
            return jsonify({"status": "error", "message": waf_message}), 403
    if not check_table_exists():
        return jsonify({"status": "error", "message": "Database error: users table not found"}), 500
    with get_db() as conn:
        c = conn.cursor()
        try:
            c.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            if c.fetchone():
                return jsonify({"status": "error", "message": f"Username '{username}' already exists!"}), 400
            backup_db()
            conn.execute("BEGIN TRANSACTION")
            c.execute("INSERT INTO users (username, password, role, is_current) VALUES (?, ?, ?, ?)", 
                     (username, password, role, 1))
            c.execute("UPDATE users SET is_current = 0 WHERE username != ?", (username,))
            conn.commit()
            session['username'] = username
            session['csrf_token'] = secrets.token_hex(16)
            session['user_ip'] = get_remote_address()
            logging.warning(f"Vulnerable account created and logged in: {username} with plain text password (demo_mode={demo_mode})")
            return jsonify({"status": "success", "message": f"Account {username} created and logged in successfully (Vulnerable: password stored in plain text)!"})
        except Exception as e:
            conn.rollback()
            logging.error(f"Error creating vulnerable account: {str(e)}")
            return jsonify({"status": "error", "message": f"Database error: {str(e)}"}), 500

@app.route("/create_account", methods=["POST"])
def create_account():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")
    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required!"}), 400
    demo_mode = request.args.get("demo", "false").lower() == "true"
    if not demo_mode:
        waf_pass, waf_message = simulate_waf_check(username + password)
        if not waf_pass:
            return jsonify({"status": "error", "message": waf_message}), 403
    if not check_table_exists():
        return jsonify({"status": "error", "message": "Database error: users table not found"}), 500
    with get_db() as conn:
        c = conn.cursor()
        try:
            c.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            if c.fetchone():
                return jsonify({"status": "error", "message": f"Username '{username}' already exists!"}), 400
            password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$"
            logging.info(f"Checking password against regex: {password_regex}")
            if not re.match(password_regex, password):
                logging.warning(f"Weak password attempt for username: {username}")
                return jsonify({
                    "status": "error",
                    "message": "Password does not meet requirements. Must be at least 8 characters, include one uppercase letter, one lowercase letter, one number, and one special character from @$!%*?&#."
                }), 400
            hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
            backup_db()
            conn.execute("BEGIN TRANSACTION")
            c.execute("INSERT INTO users (username, password, role, is_current) VALUES (?, ?, ?, ?)", 
                     (username, hashed_password.decode('utf-8'), role, 1))
            c.execute("UPDATE users SET is_current = 0 WHERE username != ?", (username,))
            conn.commit()
            session['username'] = username
            session['csrf_token'] = secrets.token_hex(16)
            session['user_ip'] = get_remote_address()
            logging.info(f"Protected account created and logged in: {username}, Role: {role} (demo_mode={demo_mode})")
            return jsonify({"status": "success", "message": f"Account {username} created and logged in successfully (Protected: password hashed with bcrypt)!"})
        except Exception as e:
            conn.rollback()
            logging.error(f"Error creating protected account: {str(e)}")
            return jsonify({"status": "error", "message": f"Database error: {str(e)}"}), 500

@app.route("/protected_data", methods=["POST"])
def protected_data():
    data = request.get_json().get("data")
    if not data:
        return jsonify({"status": "error", "message": "Data is missing"}), 400
    waf_pass, waf_message = simulate_waf_check(data)
    if not waf_pass:
        return jsonify({"status": "error", "message": waf_message}), 403
    hash_value = hashlib.sha256(data.encode("utf-8")).hexdigest()
    logging.info(f"Data hashed: {hash_value}")
    return jsonify({"status": "success", "message": f"Data saved with hash: {hash_value}"})

@app.route("/vulnerable_ssrf_path")
def vulnerable_ssrf_path():
    resource = request.args.get("resource")
    if not resource:
        return jsonify({"status": "error", "message": "Resource (URL or filepath) is required!"}), 400
    waf_pass, waf_message = simulate_waf_check(resource)
    if not waf_pass:
        return jsonify({"status": "error", "message": waf_message}), 403
    try:
        parsed = urllib.parse.urlparse(resource)
        if parsed.scheme == 'file':
            file_path = urllib.parse.unquote(parsed.path)
            if os.name == 'nt':
                file_path = file_path.lstrip('/')
                if file_path.startswith(':'):
                    file_path = file_path[1:]
            else:
                file_path = '/' + file_path.lstrip('/')
            if file_path in SIMULATED_FILES:
                logging.warning(f"Vulnerable SSRF accessed simulated file: {file_path}")
                return jsonify({"status": "success", "message": f"File content: {SIMULATED_FILES[file_path]}"})
            if os.path.exists(file_path) and os.path.isfile(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                logging.warning(f"Vulnerable SSRF accessed file: {file_path}")
                return jsonify({"status": "success", "message": f"File content: {content}"})
            else:
                logging.warning(f"Vulnerable SSRF failed to access file: {file_path} (not found)")
                return jsonify({"status": "error", "message": f"File not found: {file_path}"}), 404
        elif parsed.scheme in ('http', 'https'):
            response = urllib.request.urlopen(resource).read().decode("utf-8")
            logging.warning(f"Vulnerable SSRF request to: {resource}")
            return jsonify({"status": "success", "message": f"Data retrieved: {response[:100]}..."})
        else:
            logging.warning(f"Invalid scheme in vulnerable SSRF: {parsed.scheme}")
            return jsonify({"status": "error", "message": "Only http, https, or file schemes are allowed"}), 400
    except Exception as e:
        logging.error(f"Vulnerable SSRF error: {str(e)}")
        return jsonify({"status": "error", "message": f"Error accessing resource: {str(e)}"}), 500

@app.route("/protected_ssrf_path")
def protected_ssrf_path():
    resource = request.args.get("resource")
    if not resource:
        return jsonify({"status": "error", "message": "Resource (URL or filepath) is required!"}), 400
    waf_pass, waf_message = simulate_waf_check(resource)
    if not waf_pass:
        return jsonify({"status": "error", "message": waf_message}), 403
    parsed = urllib.parse.urlparse(resource)
    if parsed.scheme == 'file':
        file_path = urllib.parse.unquote(parsed.path)
        if os.name == 'nt':
            file_path = file_path.lstrip('/')
            if file_path.startswith(':'):
                file_path = file_path[1:]
        else:
            file_path = '/' + file_path.lstrip('/')
        allowed_files = ["public.txt"]
        if file_path not in allowed_files:
            logging.warning(f"Unauthorized file access attempt: {file_path}")
            return jsonify({"status": "error", "message": f"Access to file {file_path} is not allowed."}), 403
        if file_path in SIMULATED_FILES:
            logging.info(f"Protected SSRF accessed allowed file: {file_path}")
            return jsonify({"status": "success", "message": f"File content: {SIMULATED_FILES[file_path]}"})
        return jsonify({"status": "error", "message": f"File not found: {file_path}"}), 404
    elif parsed.scheme in ('http', 'https'):
        if parsed.hostname not in ["example.com"]:
            logging.warning(f"Unauthorized SSRF attempt to: {parsed.hostname}")
            return jsonify({"status": "error", "message": f"Unauthorized domain: {parsed.hostname}. Only example.com is allowed."}), 403
        try:
            response = urllib.request.urlopen(resource).read().decode("utf-8")
            logging.info(f"Protected SSRF request to: {resource}")
            return jsonify({"status": "success", "message": f"Data retrieved: {response[:100]}"})
        except Exception as e:
            logging.error(f"Protected SSRF error: {str(e)}")
            return jsonify({"status": "error", "message": f"Error: {str(e)}"}), 500
    else:
        logging.warning(f"Invalid scheme in protected SSRF: {parsed.scheme}")
        return jsonify({"status": "error", "message": "Only http, https, or file schemes are allowed"}), 400

@app.route("/vulnerable_csrf", methods=["POST"])
def vulnerable_csrf():
    data = request.get_json()
    user_id = data.get("user_id")
    new_role = data.get("role")
    if not user_id or not new_role:
        return jsonify({"status": "error", "message": "User ID and role are required!"}), 400
    waf_pass, waf_message = simulate_waf_check(user_id + new_role)
    if not waf_pass:
        return jsonify({"status": "error", "message": waf_message}), 403
    if not check_table_exists():
        return jsonify({"status": "error", "message": "Database error: users table not found"}), 500
    with get_db() as conn:
        c = conn.cursor()
        try:
            backup_db()
            c.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
            conn.commit()
            logging.warning(f"Vulnerable CSRF: Updated role for user_id={user_id} to {new_role}")
            return jsonify({"status": "success", "message": f"User ID {user_id} role updated to {new_role}"})
        except Exception as e:
            logging.error(f"Error in vulnerable_csrf: {str(e)}")
            return jsonify({"status": "error", "message": f"Database error: {str(e)}"}), 500

@app.route("/protected_csrf", methods=["POST"])
def protected_csrf():
    if not is_authenticated():
        logging.warning("Unauthorized CSRF attempt")
        return jsonify({"status": "error", "message": "Access denied: Not authenticated."}), 401
    data = request.get_json()
    user_id = data.get("user_id")
    new_role = data.get("role")
    client_csrf_token = data.get("csrf_token")
    if not user_id or not new_role or not client_csrf_token:
        return jsonify({"status": "error", "message": "User ID, role, and CSRF token are required!"}), 400
    waf_pass, waf_message = simulate_waf_check(user_id + new_role + client_csrf_token)
    if not waf_pass:
        return jsonify({"status": "error", "message": waf_message}), 403
    if client_csrf_token != session.get('csrf_token'):
        logging.warning(f"CSRF token mismatch: received={client_csrf_token}, expected={session.get('csrf_token')}")
        return jsonify({"status": "error", "message": "CSRF token validation failed!"}), 403
    if not is_admin():
        logging.warning(f"Role change attempt by non-admin user: user_id={user_id}, new_role={new_role}")
        return jsonify({"status": "error", "message": "Access denied: Only admins can change roles."}), 403
    if not check_table_exists():
        return jsonify({"status": "error", "message": "Database error: users table not found"}), 500
    with get_db() as conn:
        c = conn.cursor()
        try:
            backup_db()
            conn.execute("BEGIN TRANSACTION")
            c.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
            c.execute("SELECT username FROM users WHERE id = ? AND is_current = 1", (user_id,))
            current_user = c.fetchone()
            if current_user:
                session['csrf_token'] = secrets.token_hex(16)
                logging.info(f"User {current_user['username']} downgraded their role to {new_role}, CSRF token refreshed")
            conn.commit()
            logging.info(f"Protected CSRF: Updated role for user_id={user_id} to {new_role}")
            return jsonify({"status": "success", "message": f"User ID {user_id} role updated to {new_role}"})
        except Exception as e:
            conn.rollback()
            logging.error(f"CSRF update error: {str(e)}")
            return jsonify({"status": "error", "message": f"Database error: {str(e)}"}), 500

@app.route("/get_csrf_token", methods=["GET"])
def get_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return jsonify({"csrf_token": session['csrf_token']})

@app.route("/get_users", methods=["GET"])
def get_users():
    if not is_authenticated():
        logging.warning("Unauthorized attempt to access user list")
        return jsonify({"status": "error", "message": "Access denied: Not authenticated."}), 401
    if not check_table_exists():
        return jsonify({"status": "error", "message": "Database error: users table not found"}), 500
    with get_db() as conn:
        c = conn.cursor()
        try:
            c.execute("SELECT id, username, role, is_current FROM users")
            users = c.fetchall()
            user_list = [
                {
                    "id": user['id'],
                    "username": user['username'],
                    "role": user['role'],
                    "is_current": bool(user['is_current'])
                }
                for user in users
            ]
            logging.info("User list retrieved")
            return jsonify({"status": "success", "data": user_list})
        except Exception as e:
            logging.error(f"Error retrieving users: {str(e)}")
            return jsonify({"status": "error", "message": f"Database error: {str(e)}"}), 500

@app.route("/get_user_details", methods=["GET"])
def get_user_details():
    if not is_authenticated():
        logging.warning("Unauthorized attempt to access user details")
        return jsonify({"status": "error", "message": "Access denied: Not authenticated."}), 401
    if not is_admin():
        logging.warning("Non-admin attempt to access user details")
        return jsonify({"status": "error", "message": "Access denied: Only admins can view user details."}), 403
    if not check_table_exists():
        return jsonify({"status": "error", "message": "Database error: users table not found"}), 500
    with get_db() as conn:
        c = conn.cursor()
        try:
            c.execute("SELECT id, username, role, password FROM users")
            users = c.fetchall()
            user_list = [
                {
                    "id": user['id'],
                    "username": user['username'],
                    "role": user['role'],
                    "password": user['password']
                }
                for user in users
            ]
            logging.info("User details retrieved by admin")
            return jsonify({"status": "success", "data": user_list})
        except Exception as e:
            logging.error(f"Error retrieving user details: {str(e)}")
            return jsonify({"status": "error", "message": f"Database error: {str(e)}"}), 500

@app.route("/delete_user", methods=["POST"])
def delete_user():
    if not is_authenticated():
        logging.warning("Unauthorized attempt to delete user")
        return jsonify({"status": "error", "message": "Access denied: Not authenticated."}), 401
    current_user = session.get('username', 'unknown')
    if not is_admin():
        logging.warning(f"Non-admin attempt to delete user by: {current_user}")
        return jsonify({"status": "error", "message": "Access denied: Only admins can delete users."}), 403
    data = request.get_json()
    user_id = data.get("user_id")
    if not user_id:
        logging.warning("Missing user_id in delete_user request")
        return jsonify({"status": "error", "message": "User ID is required!"}), 400
    if not check_table_exists():
        logging.error("Delete user failed: users table not found")
        return jsonify({"status": "error", "message": "Database error: users table not found"}), 500
    with get_db() as conn:
        c = conn.cursor()
        try:
            c.execute("SELECT username, is_current FROM users WHERE id = ?", (user_id,))
            user = c.fetchone()
            if not user:
                logging.warning(f"User not found for deletion: user_id={user_id}")
                return jsonify({"status": "error", "message": "User not found."}), 404
            if user['is_current']:
                logging.warning(f"Attempt to delete current user: {user['username']}")
                return jsonify({"status": "error", "message": "Cannot delete the currently logged-in user."}), 400
            backup_db()
            conn.execute("BEGIN TRANSACTION")
            c.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            logging.info(f"User deleted: ID={user_id}, Username={user['username']}")
            return jsonify({"status": "success", "message": f"User ID {user_id} deleted successfully."})
        except Exception as e:
            conn.rollback()
            logging.error(f"Error deleting user: {str(e)}")
            return jsonify({"status": "error", "message": f"Database error: {str(e)}"}), 500

def generate_self_signed_cert():
    try:
        # Generate a private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Generate a self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost")
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False
        ).sign(key, hashes.SHA256())
        
        # Serialize certificate and key
        cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
        key_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Create temporary files
        cert_file = os.path.join(os.path.dirname(__file__), 'temp_cert.pem')
        key_file = os.path.join(os.path.dirname(__file__), 'temp_key.pem')
        
        with open(cert_file, 'wb') as f:
            f.write(cert_bytes)
        with open(key_file, 'wb') as f:
            f.write(key_bytes)
        
        logging.info(f"Ad hoc self-signed certificate generated: {cert_file}, {key_file}")
        return cert_file, key_file
    except Exception as e:
        logging.error(f"Failed to generate ad hoc certificate: {str(e)}")
        raise

def is_auditor():
    if not check_table_exists():
        logging.warning("is_auditor failed: users table not found")
        return False
    try:
        username = session.get('username')
        if not username:
            logging.warning("is_auditor failed: No username in session")
            return False
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT role FROM users WHERE username = ? AND is_current = 1", (username,))
            user = c.fetchone()
            if user and user['role'] == "auditor":
                logging.info(f"is_auditor succeeded for user: {username}")
                return True
            logging.warning(f"is_auditor failed for user: {username}, role: {user['role'] if user else 'none'}")
            return False
    except Exception as e:
        logging.error(f"Error in is_auditor: {str(e)}")
        return False

@app.route("/get_logs", methods=["GET"])
def get_logs():
    if not is_authenticated():
        logging.warning("Unauthorized attempt to access logs")
        return jsonify({"status": "error", "message": "Access denied: Not authenticated."}), 401
    if not is_admin() and not is_auditor():
        logging.warning("Non-auditor/admin attempt to access logs")
        return jsonify({"status": "error", "message": "Access denied: Only admins and auditors can view logs."}), 403
    try:
        with open('app.log', 'r') as f:
            logs = f.read()
        return jsonify({"status": "success", "data": logs})
    except Exception as e:
        logging.error(f"Error reading logs: {str(e)}")
        return jsonify({"status": "error", "message": f"Error reading logs: {str(e)}"}), 500

if __name__ == "__main__":
    cert_file = None
    key_file = None
    try:
        # Generate temporary self-signed certificate
        cert_file, key_file = generate_self_signed_cert()
        
        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        
        # Run Flask app with HTTPS on port 5000
        app.run(host="0.0.0.0", port=5000, debug=True, ssl_context=context)
    except Exception as e:
        logging.error(f"Error starting server: {str(e)}")
        print(f"Error starting server: {str(e)}")
        raise
    finally:
        # Clean up temporary certificate files
        for f in [cert_file, key_file]:
            if f and os.path.exists(f):
                try:
                    os.remove(f)
                    logging.info(f"Removed temporary certificate file: {f}")
                except Exception as e:
                    logging.error(f"Failed to remove temporary file {f}: {str(e)}")